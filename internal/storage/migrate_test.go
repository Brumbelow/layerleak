package storage

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadMigrationFilesSortsAndChecksums(t *testing.T) {
	directory := t.TempDir()
	writeMigrationFile(t, directory, "0002_second.up.sql", "SELECT 2;")
	writeMigrationFile(t, directory, "0001_first.up.sql", "SELECT 1;")
	writeMigrationFile(t, directory, "0001_first.down.sql", "SELECT -1;")

	files, err := loadMigrationFiles(directory)
	if err != nil {
		t.Fatalf("loadMigrationFiles() error = %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("len(files) = %d", len(files))
	}
	if files[0].Version != "0001" || files[0].Name != "0001_first" || files[1].Version != "0002" {
		t.Fatalf("files = %#v", files)
	}
	if len(files[0].Checksum) != 64 {
		t.Fatalf("checksum = %q", files[0].Checksum)
	}
}

func TestLoadMigrationFilesRejectsDuplicateVersion(t *testing.T) {
	directory := t.TempDir()
	writeMigrationFile(t, directory, "0001_first.up.sql", "SELECT 1;")
	writeMigrationFile(t, directory, "0001_duplicate.up.sql", "SELECT 2;")

	if _, err := loadMigrationFiles(directory); err == nil || !strings.Contains(err.Error(), "duplicate migration version") {
		t.Fatalf("loadMigrationFiles() error = %v", err)
	}
}

func TestRunMigrationsRejectsNonContiguousSetBeforeConnecting(t *testing.T) {
	directory := t.TempDir()
	writeMigrationFile(t, directory, "0001_first.up.sql", "SELECT 1;")
	writeMigrationFile(t, directory, "0003_third.up.sql", "SELECT 3;")
	writeMigrationFile(t, directory, "0004_fourth.up.sql", "SELECT 4;")

	_, err := RunMigrations(context.Background(), MigrationConfig{
		DatabaseURL: "postgres://localhost/layerleak",
		Directory:   directory,
	})
	if err == nil || !strings.Contains(err.Error(), "not contiguous") {
		t.Fatalf("RunMigrations() error = %v", err)
	}
}

func TestValidateAppliedMigrationsRejectsChecksumChangeAndGap(t *testing.T) {
	migrations := []migrationFile{
		{Version: "0001", Name: "0001_first", Checksum: "aaa"},
		{Version: "0002", Name: "0002_second", Checksum: "bbb"},
	}

	checksumChanged := map[string]migrationRow{
		"0001": {Version: "0001", Name: "0001_first", Checksum: "changed"},
	}
	if err := validateAppliedMigrations(migrations, checksumChanged); err == nil || !strings.Contains(err.Error(), "checksum changed") {
		t.Fatalf("checksum validation error = %v", err)
	}

	gap := map[string]migrationRow{
		"0002": {Version: "0002", Name: "0002_second", Checksum: "bbb"},
	}
	if err := validateAppliedMigrations(migrations, gap); err == nil || !strings.Contains(err.Error(), "gap") {
		t.Fatalf("gap validation error = %v", err)
	}
}

func TestStorageHardeningMigrationAllowsPartialRelationalStatus(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(repoRoot(t), "migrations", "0004_storage_hardening.up.sql"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	for _, expected := range []string{
		"manifests_scan_status_valid CHECK (last_scan_status IN ('scanned', 'partial', 'failed'))",
		"repository_manifests_scan_status_valid CHECK (last_scan_status IN ('scanned', 'partial', 'failed'))",
		"tags_status_valid CHECK (status IN ('scanned', 'partial', 'failed'))",
	} {
		if !strings.Contains(string(body), expected) {
			t.Errorf("migration does not contain %q", expected)
		}
	}
}

func TestSchemaColumnDefaultMatches(t *testing.T) {
	tests := []struct {
		name     string
		actual   sql.NullString
		expected string
		want     bool
	}{
		{name: "missing default", expected: "", want: true},
		{name: "unexpected default", actual: sql.NullString{String: "0", Valid: true}, expected: "", want: false},
		{name: "text default", actual: sql.NullString{String: "''::text", Valid: true}, expected: "''::text", want: true},
		{name: "schema qualified sequence", actual: sql.NullString{String: "nextval('layerleak_test.repositories_id_seq'::regclass)", Valid: true}, expected: sequenceDefaultPrefix + "repositories_id_seq", want: true},
		{name: "wrong sequence", actual: sql.NullString{String: "nextval('other_id_seq'::regclass)", Valid: true}, expected: sequenceDefaultPrefix + "repositories_id_seq", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := schemaColumnDefaultMatches(tt.actual, tt.expected); got != tt.want {
				t.Fatalf("schemaColumnDefaultMatches() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestNormalizeSchemaDefinitionPreservesExpressionGrouping(t *testing.T) {
	left := normalizeSchemaDefinition(`CHECK (((a >= 0) AND ((b >= 0) OR (c >= 0))))`)
	right := normalizeSchemaDefinition(`CHECK ((((a >= 0) AND (b >= 0)) OR (c >= 0)))`)
	if left == right {
		t.Fatalf("differently grouped constraints normalized to %q", left)
	}

	actual := normalizeSchemaDefinition(`CHECK ((status = ANY (ARRAY['completed'::text, 'partial'::text, 'failed'::text])))`)
	expected := normalizeSchemaDefinition(`CHECK ((status = ANY (ARRAY['completed', 'partial', 'failed'])))`)
	if actual != expected {
		t.Fatalf("canonical status constraint = %q, want %q", actual, expected)
	}
}

func TestSchemaIndexColumnsMatchChecksOrdering(t *testing.T) {
	expected := "repository_id, scanned_at DESC"
	correct := []schemaIndexColumnState{
		{
			definition: `"repository_id"`,
			descending: sql.NullBool{Valid: true},
			nullsFirst: sql.NullBool{Valid: true},
		},
		{
			definition: `"scanned_at"`,
			descending: sql.NullBool{Bool: true, Valid: true},
			nullsFirst: sql.NullBool{Bool: true, Valid: true},
		},
	}
	if !schemaIndexColumnsMatch(correct, expected) {
		t.Fatal("schemaIndexColumnsMatch() rejected the expected ordering")
	}

	tests := []struct {
		name   string
		change func([]schemaIndexColumnState)
	}{
		{
			name: "direction",
			change: func(columns []schemaIndexColumnState) {
				columns[1].descending.Bool = false
			},
		},
		{
			name: "null ordering",
			change: func(columns []schemaIndexColumnState) {
				columns[1].nullsFirst.Bool = false
			},
		},
		{
			name: "unavailable ordering metadata",
			change: func(columns []schemaIndexColumnState) {
				columns[1].descending.Valid = false
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := append([]schemaIndexColumnState(nil), correct...)
			tt.change(actual)
			if schemaIndexColumnsMatch(actual, expected) {
				t.Fatal("schemaIndexColumnsMatch() accepted index ordering drift")
			}
		})
	}
}

func writeMigrationFile(t *testing.T, directory, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, name), []byte(body), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}
}
