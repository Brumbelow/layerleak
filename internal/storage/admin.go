// Package storage provides Layerleak scan persistence and schema management.
package storage

import (
	"context"
	"fmt"
)

const rawSecretPurgeAdvisoryKey = int64(5503803602222863714)

type RawSecretCounts struct {
	FindingValues      int64
	OccurrenceSnippets int64
}

func (c RawSecretCounts) Total() int64 {
	return c.FindingValues + c.OccurrenceSnippets
}

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
func (s *PostgresStore) PurgeRawSecrets(ctx context.Context) (RawSecretCounts, error) {
	if s == nil || s.db == nil {
		return RawSecretCounts{}, fmt.Errorf("postgres store is not initialized")
	}
	ctx, cancel := withTimeout(ctx, s.writeTimeout)
	defer cancel()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RawSecretCounts{}, fmt.Errorf("begin raw secret purge: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, rawSecretPurgeAdvisoryKey); err != nil {
		return RawSecretCounts{}, fmt.Errorf("lock raw secret purge: %w", err)
	}

	findingResult, err := tx.ExecContext(ctx, `UPDATE findings SET value = '' WHERE value <> ''`)
	if err != nil {
		return RawSecretCounts{}, fmt.Errorf("purge raw finding values: %w", err)
	}
	occurrenceResult, err := tx.ExecContext(ctx, `UPDATE finding_occurrences SET raw_snippet = '' WHERE raw_snippet <> ''`)
	if err != nil {
		return RawSecretCounts{}, fmt.Errorf("purge raw occurrence snippets: %w", err)
	}
	findingCount, err := findingResult.RowsAffected()
	if err != nil {
		return RawSecretCounts{}, fmt.Errorf("count purged finding values: %w", err)
	}
	occurrenceCount, err := occurrenceResult.RowsAffected()
	if err != nil {
		return RawSecretCounts{}, fmt.Errorf("count purged occurrence snippets: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return RawSecretCounts{}, fmt.Errorf("commit raw secret purge: %w", err)
	}
	return RawSecretCounts{
		FindingValues:      findingCount,
		OccurrenceSnippets: occurrenceCount,
	}, nil
}
