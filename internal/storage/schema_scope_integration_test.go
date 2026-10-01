package storage

import (
	"context"
	"database/sql"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

// withSearchPath returns the integration URL with a different search_path so a
// test can place an extra schema ahead of or behind layerleak_test.
func withSearchPath(t *testing.T, searchPath string) string {
	t.Helper()
	parsed, err := url.Parse(integrationDatabaseURL(t))
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	values := parsed.Query()
	values.Set("search_path", searchPath)
	parsed.RawQuery = values.Encode()
	return parsed.String()
}

func createExtraSchema(t *testing.T, db *sql.DB, schema string) {
	t.Helper()
	if _, err := db.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE"); err != nil {
		t.Fatalf("drop schema %s: %v", schema, err)
	}
	if _, err := db.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatalf("create schema %s: %v", schema, err)
	}
	t.Cleanup(func() { _, _ = db.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE") })
}

func countTablesInSchema(t *testing.T, db *sql.DB, schema string) int {
	t.Helper()
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pg_tables WHERE schemaname = $1`, schema).Scan(&count); err != nil {
		t.Fatalf("count tables in %s: %v", schema, err)
	}
	return count
}

// TestSchemaDetectionResolvesEverythingInTheCurrentSchema is the first DB-10
// regression test. With a migrated layerleak_test behind an empty schema on
// the search_path, to_regclass() found the ledger through the search_path
// while the current_schema()-scoped catalog queries did not, and a healthy
// database was reported as "missing repositories.id". Every check must now
// resolve in the same schema: the empty first schema is simply uninitialised,
// and RunMigrations creates the ledger and the tables together in it.
func TestSchemaDetectionResolvesEverythingInTheCurrentSchema(t *testing.T) {
	db := openMigratedIntegrationDB(t)
	defer func() { _ = db.Close() }()
	createExtraSchema(t, db, "layerleak_first")
	mixedURL := withSearchPath(t, "layerleak_first,layerleak_test")

	_, err := NewPostgresStore(PostgresConfig{DatabaseURL: mixedURL, RequireSchema: true})
	if err == nil {
		t.Fatal("NewPostgresStore() error = nil for an uninitialised first schema")
	}
	if !strings.Contains(err.Error(), "not initialized") || strings.Contains(err.Error(), "missing") {
		t.Fatalf("NewPostgresStore() error = %v, want the uninitialised-schema diagnosis rather than drift", err)
	}

	result, err := RunMigrations(context.Background(), MigrationConfig{DatabaseURL: mixedURL, Directory: filepath.Join(repoRoot(t), "migrations")})
	if err != nil {
		t.Fatalf("RunMigrations() error = %v", err)
	}
	if len(result.Applied) != currentMigrationCount {
		t.Fatalf("result.Applied = %v, want a full fresh install in layerleak_first", result.Applied)
	}
	if got := countTablesInSchema(t, db, "layerleak_first"); got != 8 {
		t.Fatalf("layerleak_first has %d tables, want 8 (7 data tables plus the ledger)", got)
	}
	if got := countTablesInSchema(t, db, "layerleak_test"); got != 8 {
		t.Fatalf("layerleak_test has %d tables after migrating layerleak_first, want it untouched", got)
	}

	store, err := NewPostgresStore(PostgresConfig{DatabaseURL: mixedURL, RequireSchema: true})
	if err != nil {
		t.Fatalf("NewPostgresStore(after migrate) error = %v", err)
	}
	defer func() { _ = store.Close() }()
	if err := store.Ready(context.Background()); err != nil {
		t.Fatalf("Ready() error = %v", err)
	}
}

// TestRunMigrationsIgnoresForeignLedgerLaterOnSearchPath is the second DB-10
// regression test: a golang-migrate style schema_migrations(version bigint,
// dirty boolean) in a later search_path schema made tableExists skip CREATE
// TABLE and the ledger read failed with `column "name" does not exist`.
func TestRunMigrationsIgnoresForeignLedgerLaterOnSearchPath(t *testing.T) {
	db := openIntegrationDB(t)
	defer func() { _ = db.Close() }()
	createExtraSchema(t, db, "layerleak_other")
	if _, err := db.Exec(`CREATE TABLE layerleak_other.schema_migrations (version BIGINT PRIMARY KEY, dirty BOOLEAN NOT NULL)`); err != nil {
		t.Fatalf("create foreign ledger: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO layerleak_other.schema_migrations VALUES (20240101, false)`); err != nil {
		t.Fatalf("seed foreign ledger: %v", err)
	}
	mixedURL := withSearchPath(t, "layerleak_test,layerleak_other")

	result, err := RunMigrations(context.Background(), MigrationConfig{DatabaseURL: mixedURL, Directory: filepath.Join(repoRoot(t), "migrations")})
	if err != nil {
		t.Fatalf("RunMigrations() error = %v", err)
	}
	if len(result.Applied) != currentMigrationCount {
		t.Fatalf("result.Applied = %v", result.Applied)
	}
	assertCount(t, db, "SELECT COUNT(*) FROM layerleak_test.schema_migrations", currentMigrationCount)
	assertCount(t, db, "SELECT COUNT(*) FROM layerleak_other.schema_migrations", 1)

	store, err := NewPostgresStore(PostgresConfig{DatabaseURL: mixedURL, RequireSchema: true})
	if err != nil {
		t.Fatalf("NewPostgresStore() error = %v", err)
	}
	defer func() { _ = store.Close() }()
	if err := store.Ready(context.Background()); err != nil {
		t.Fatalf("Ready() error = %v", err)
	}
}

func TestRunMigrationsRejectsSearchPathWithoutUsableSchema(t *testing.T) {
	db := openIntegrationDB(t)
	defer func() { _ = db.Close() }()

	_, err := RunMigrations(context.Background(), MigrationConfig{DatabaseURL: withSearchPath(t, "layerleak_missing"), Directory: filepath.Join(repoRoot(t), "migrations")})
	if err == nil || !strings.Contains(err.Error(), "search_path") {
		t.Fatalf("RunMigrations() error = %v, want a search_path diagnosis", err)
	}
}
