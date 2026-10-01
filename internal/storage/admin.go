// Package storage provides Layerleak scan persistence and schema management.
package storage

import (
	"context"
	"fmt"
)

const rawSecretPurgeAdvisoryKey = int64(5503803602222863714)

// DefaultPurgeBatchSize is how many rows one purge transaction clears when
// PurgeOptions.BatchSize is zero. Each batch holds the exclusive purge lock
// (which blocks SaveScan's shared lock) only for its own short transaction.
const DefaultPurgeBatchSize = 5000

type RawSecretCounts struct {
	FindingValues      int64
	OccurrenceSnippets int64
}

func (c RawSecretCounts) Total() int64 {
	return c.FindingValues + c.OccurrenceSnippets
}

// PurgeOptions tunes PurgeRawSecrets.
type PurgeOptions struct {
	// BatchSize is the number of rows cleared per transaction; zero or
	// negative selects DefaultPurgeBatchSize.
	BatchSize int
	// Progress, when set, is called after every batch that cleared rows with
	// the running totals so a long purge can report where it stands.
	Progress func(PurgeProgress)
}

// PurgeProgress is one progress report: the table and the number of rows the
// last batch cleared, plus the totals cleared so far.
type PurgeProgress struct {
	Table string
	Rows  int64
	Total RawSecretCounts
}

func (o PurgeOptions) withDefaults() PurgeOptions {
	if o.BatchSize <= 0 {
		o.BatchSize = DefaultPurgeBatchSize
	}
	return o
}

func (o PurgeOptions) report(progress PurgeProgress) {
	if o.Progress != nil {
		o.Progress(progress)
	}
}

// purgeTarget names one table and the raw-material column the purge clears.
// The identifiers are these fixed values only, never operator input.
type purgeTarget struct {
	table  string
	column string
}

var (
	purgeTargetFindingValues      = purgeTarget{table: "findings", column: "value"}
	purgeTargetOccurrenceSnippets = purgeTarget{table: "finding_occurrences", column: "raw_snippet"}
)

// CountRawSecrets reports rows that still contain opt-in raw secret material.
func (s *PostgresStore) CountRawSecrets(ctx context.Context) (RawSecretCounts, error) {
	if s == nil || s.db == nil {
		return RawSecretCounts{}, fmt.Errorf("postgres store is not initialized")
	}
	ctx, cancel := withTimeout(ctx, s.queryTimeout)
	defer cancel()

	var counts RawSecretCounts
	if err := s.db.QueryRowContext(ctx, `
		SELECT
			(SELECT COUNT(*) FROM findings WHERE value <> ''),
			(SELECT COUNT(*) FROM finding_occurrences WHERE raw_snippet <> '')
	`).Scan(&counts.FindingValues, &counts.OccurrenceSnippets); err != nil {
		return RawSecretCounts{}, fmt.Errorf("count stored raw secrets: %w", err)
	}
	return counts, nil
}

// PurgeRawSecrets irreversibly clears all raw finding values and occurrence
// snippets. Redacted values, fingerprints, and scan results are retained.
//
// The work proceeds in ascending id-range batches of BatchSize rows, each in
// its own transaction bounded by the store's write timeout and holding the
// exclusive purge advisory lock only for that transaction, so concurrent
// SaveScan writers (which take the shared lock) wait for one batch rather than
// the whole purge. The caller's context bounds the whole run. Batches already
// committed stay purged when a later batch fails; the returned counts are the
// rows cleared so far in either case.
func (s *PostgresStore) PurgeRawSecrets(ctx context.Context, options PurgeOptions) (RawSecretCounts, error) {
	if s == nil || s.db == nil {
		return RawSecretCounts{}, fmt.Errorf("postgres store is not initialized")
	}
	options = options.withDefaults()
	var totals RawSecretCounts

	findingValues, err := runPurgeBatches(ctx, purgeTargetFindingValues, options.BatchSize, s.purgeBatch, func(rows int64) {
		totals.FindingValues += rows
		options.report(PurgeProgress{Table: purgeTargetFindingValues.table, Rows: rows, Total: totals})
	})
	totals.FindingValues = findingValues
	if err != nil {
		return totals, fmt.Errorf("purge raw finding values: %w", err)
	}
	occurrenceSnippets, err := runPurgeBatches(ctx, purgeTargetOccurrenceSnippets, options.BatchSize, s.purgeBatch, func(rows int64) {
		totals.OccurrenceSnippets += rows
		options.report(PurgeProgress{Table: purgeTargetOccurrenceSnippets.table, Rows: rows, Total: totals})
	})
	totals.OccurrenceSnippets = occurrenceSnippets
	if err != nil {
		return totals, fmt.Errorf("purge raw occurrence snippets: %w", err)
	}
	return totals, nil
}

// batchPurger clears up to size rows of target with id > afterID and reports
// how many rows it cleared and the highest id among them.
type batchPurger func(ctx context.Context, target purgeTarget, afterID int64, size int) (rows, lastID int64, err error)

// runPurgeBatches walks target by ascending id until a batch comes back short,
// which means no row above its last id still holds raw material. report is
// called after each batch that cleared rows. It returns the rows cleared, also
// when it stops early on a failed batch or a finished context.
func runPurgeBatches(ctx context.Context, target purgeTarget, size int, purge batchPurger, report func(rows int64)) (int64, error) {
	var total, afterID int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		rows, lastID, err := purge(ctx, target, afterID, size)
		if err != nil {
			return total, err
		}
		total += rows
		if rows > 0 && report != nil {
			report(rows)
		}
		if rows < int64(size) {
			return total, nil
		}
		afterID = lastID
	}
}

// purgeBatchSQL selects the next size ids above $1 that still hold raw
// material, clears them and returns the count and the highest cleared id.
func purgeBatchSQL(target purgeTarget) string {
	return fmt.Sprintf(`
		WITH batch AS (
			SELECT id FROM %[1]s
			WHERE %[2]s <> '' AND id > $1
			ORDER BY id
			LIMIT $2
		), cleared AS (
			UPDATE %[1]s AS t SET %[2]s = ''
			FROM batch
			WHERE t.id = batch.id
			RETURNING t.id
		)
		SELECT COUNT(*), COALESCE(MAX(id), 0) FROM cleared
	`, target.table, target.column)
}

// purgeBatch runs one batch in its own transaction under the exclusive purge
// lock and the store's write timeout.
func (s *PostgresStore) purgeBatch(ctx context.Context, target purgeTarget, afterID int64, size int) (int64, int64, error) {
	ctx, cancel := withTimeout(ctx, s.writeTimeout)
	defer cancel()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("begin raw secret purge batch: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, rawSecretPurgeAdvisoryKey); err != nil {
		return 0, 0, fmt.Errorf("lock raw secret purge: %w", err)
	}
	var rows, lastID int64
	if err := tx.QueryRowContext(ctx, purgeBatchSQL(target), afterID, size).Scan(&rows, &lastID); err != nil {
		return 0, 0, fmt.Errorf("clear %s.%s batch: %w", target.table, target.column, err)
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("commit raw secret purge batch: %w", err)
	}
	return rows, lastID, nil
}
