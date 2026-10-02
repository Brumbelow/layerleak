package storage

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"
	"time"
)

// MigrationStatusEntry describes one shipped migration file against the
// database's migration ledger.
type MigrationStatusEntry struct {
	Version string
	Name    string
	// Checksum is the SHA-256 of the shipped file; when Applied it also equals
	// the ledger's recorded checksum, because a mismatch is reported as an
	// error rather than as a status.
	Checksum  string
	Applied   bool
	AppliedAt time.Time
	// Adoptable means the ledger is empty but the existing legacy schema
	// matches this migration, so RunMigrations would record it as applied
	// without executing the file.
	Adoptable bool
}

// MigrationStatusResult is the read-only comparison of the shipped migration
// files with the database, as printed by layerleak-migrate-up --status.
type MigrationStatusResult struct {
	// Ledger is the schema-qualified ledger table; LedgerExists reports
	// whether the database has it yet.
	Ledger       string
	LedgerExists bool
	// Current is the highest version the database is at (applied, or
	// adoptable when the ledger is empty); "" for an empty database.
	Current string
	// Expected is the version the running binary requires.
	Expected string
	Entries  []MigrationStatusEntry
	// Pending names the migrations RunMigrations would execute, in order;
	// Adoptable the ones it would merely record.
	Pending   []string
	Adoptable []string
}

// UpToDate reports whether RunMigrations would change nothing.
func (r MigrationStatusResult) UpToDate() bool {
	return len(r.Pending) == 0 && len(r.Adoptable) == 0
}

// MigrationStatus compares the shipped migration files with the database
// without changing it: no ledger is created, no legacy schema is adopted and
// no advisory lock is taken. Checksum or name drift between the ledger and the
// files is an error, as it is for RunMigrations; so is a ledger that claims
// the current version while required schema objects are missing.
func MigrationStatus(ctx context.Context, config MigrationConfig) (MigrationStatusResult, error) {
	databaseURL := strings.TrimSpace(config.DatabaseURL)
	if err := (PostgresConfig{DatabaseURL: databaseURL}).Validate(); err != nil {
		return MigrationStatusResult{}, err
	}
	migrations, err := loadValidatedMigrations(config.Directory)
	if err != nil {
		return MigrationStatusResult{}, err
	}

	db, connection, err := openMigrationConnection(ctx, databaseURL)
	if err != nil {
		return MigrationStatusResult{}, err
	}
	defer func() { _ = db.Close() }()
	defer func() { _ = connection.Close() }()

	return migrationStatusOn(ctx, connection, migrations)
}

// migrationStatusOn reads the ledger and legacy schema on an open connection
// and compares them with the shipped migrations.
func migrationStatusOn(ctx context.Context, connection *sql.Conn, migrations []migrationFile) (MigrationStatusResult, error) {
	schema, err := resolveCurrentSchema(ctx, connection)
	if err != nil {
		return MigrationStatusResult{}, err
	}
	ledger := newSchemaLedger(schema)
	state, err := readMigrationLedgerState(ctx, connection, ledger)
	if err != nil {
		return MigrationStatusResult{}, err
	}
	if err := validateAppliedMigrations(migrations, state.applied); err != nil {
		return MigrationStatusResult{}, err
	}

	result := buildMigrationStatus(migrations, state.applied, state.legacy)
	result.Ledger = ledger.table
	result.LedgerExists = state.ledgerExists
	if result.UpToDate() {
		if err := checkSchemaVersion(ctx, connection); err != nil {
			return MigrationStatusResult{}, err
		}
	}
	return result, nil
}

// migrationLedgerState is what MigrationStatus reads before comparing: whether
// the ledger exists, its applied rows, and (only when nothing is applied) the
// legacy schema versions that could be adopted.
type migrationLedgerState struct {
	ledgerExists bool
	applied      map[string]migrationRow
	legacy       []string
}

// readMigrationLedgerState only reads: it never creates the ledger.
func readMigrationLedgerState(ctx context.Context, connection *sql.Conn, ledger schemaLedger) (migrationLedgerState, error) {
	ledgerExists, err := tableExistsContext(ctx, connection, "schema_migrations")
	if err != nil {
		return migrationLedgerState{}, err
	}
	state := migrationLedgerState{ledgerExists: ledgerExists, applied: map[string]migrationRow{}}
	if ledgerExists {
		state.applied, err = readAppliedMigrations(ctx, connection, ledger)
		if err != nil {
			return migrationLedgerState{}, err
		}
	}
	if len(state.applied) == 0 {
		state.legacy, err = inspectLegacySchema(ctx, connection)
		if err != nil {
			return migrationLedgerState{}, err
		}
	}
	return state, nil
}

// buildMigrationStatus is the pure comparison behind MigrationStatus.
func buildMigrationStatus(migrations []migrationFile, applied map[string]migrationRow, legacy []string) MigrationStatusResult {
	result := MigrationStatusResult{
		Expected:  CurrentSchemaVersion,
		Entries:   make([]MigrationStatusEntry, 0, len(migrations)),
		Pending:   make([]string, 0),
		Adoptable: make([]string, 0),
	}
	for _, migration := range migrations {
		entry := MigrationStatusEntry{Version: migration.Version, Name: migration.Name, Checksum: migration.Checksum}
		switch row, ok := applied[migration.Version]; {
		case ok:
			entry.Applied = true
			entry.AppliedAt = row.AppliedAt
			result.Current = migration.Version
		case slices.Contains(legacy, migration.Version):
			entry.Adoptable = true
			result.Adoptable = append(result.Adoptable, migration.Name)
			result.Current = migration.Version
		default:
			result.Pending = append(result.Pending, migration.Name)
		}
		result.Entries = append(result.Entries, entry)
	}
	return result
}

// Describe renders one line per migration for logs and tests; the status
// command prints its own table.
func (e MigrationStatusEntry) Describe() string {
	switch {
	case e.Applied:
		return fmt.Sprintf("%s applied %s", e.Name, e.AppliedAt.UTC().Format(time.RFC3339))
	case e.Adoptable:
		return e.Name + " adoptable (legacy schema matches)"
	default:
		return e.Name + " pending"
	}
}
