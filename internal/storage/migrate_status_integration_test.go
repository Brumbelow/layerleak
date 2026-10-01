package storage

import (
	"context"
	"path/filepath"
	"slices"
	"testing"
)

// TestMigrationStatusReportsPendingAppliedAndLegacyWithoutWriting walks the
// status command's cases on a real database: an empty database (everything
// pending, no ledger created), a fully migrated one (up to date, checksums
// match the files) and a legacy 0001-0003 schema (adoptable plus pending).
func TestMigrationStatusReportsPendingAppliedAndLegacyWithoutWriting(t *testing.T) {
	db := openIntegrationDB(t)
	defer func() { _ = db.Close() }()
	config := MigrationConfig{
		DatabaseURL: integrationDatabaseURL(t),
		Directory:   filepath.Join(repoRoot(t), "migrations"),
	}

	empty, err := MigrationStatus(context.Background(), config)
	if err != nil {
		t.Fatalf("MigrationStatus(empty) error = %v", err)
	}
	if empty.LedgerExists || empty.UpToDate() || empty.Current != "" || empty.Expected != CurrentSchemaVersion || len(empty.Pending) != currentMigrationCount || len(empty.Adoptable) != 0 {
		t.Fatalf("empty status = %+v", empty)
	}
	var ledgerExists bool
	if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = 'schema_migrations')`).Scan(&ledgerExists); err != nil || ledgerExists {
		t.Fatalf("status created the ledger: exists=%t err=%v", ledgerExists, err)
	}

	applied, err := RunMigrations(context.Background(), config)
	if err != nil {
		t.Fatalf("RunMigrations() error = %v", err)
	}
	current, err := MigrationStatus(context.Background(), config)
	if err != nil {
		t.Fatalf("MigrationStatus(current) error = %v", err)
	}
	if !current.LedgerExists || !current.UpToDate() || current.Current != CurrentSchemaVersion || len(current.Entries) != currentMigrationCount {
		t.Fatalf("current status = %+v", current)
	}
	var names []string
	for _, entry := range current.Entries {
		if !entry.Applied || entry.AppliedAt.IsZero() || entry.Adoptable || len(entry.Checksum) != 64 {
			t.Fatalf("entry = %+v", entry)
		}
		names = append(names, entry.Name)
	}
	if !slices.Equal(names, applied.Applied) {
		t.Fatalf("status names %v != applied %v", names, applied.Applied)
	}

	// Legacy schema: tables from 0001-0003 applied by hand, no ledger.
	legacyDB := openIntegrationDB(t)
	defer func() { _ = legacyDB.Close() }()
	if err := applyMigrationSet(t, legacyDB, "000[1-3]_*.up.sql"); err != nil {
		t.Fatalf("applyMigrationSet(legacy) error = %v", err)
	}
	legacy, err := MigrationStatus(context.Background(), config)
	if err != nil {
		t.Fatalf("MigrationStatus(legacy) error = %v", err)
	}
	if legacy.LedgerExists || legacy.UpToDate() || legacy.Current != "0003" || len(legacy.Adoptable) != 3 || len(legacy.Pending) != 1 {
		t.Fatalf("legacy status = %+v", legacy)
	}
	if err := legacyDB.QueryRow(`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = 'schema_migrations')`).Scan(&ledgerExists); err != nil || ledgerExists {
		t.Fatalf("status adopted the legacy schema: exists=%t err=%v", ledgerExists, err)
	}
}
