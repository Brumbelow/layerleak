package storage

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func statusMigrations() []migrationFile {
	return []migrationFile{
		{Version: "0001", Name: "0001_initial", Checksum: strings.Repeat("1", 64)},
		{Version: "0002", Name: "0002_history", Checksum: strings.Repeat("2", 64)},
		{Version: "0003", Name: "0003_dispositions", Checksum: strings.Repeat("3", 64)},
		{Version: "0004", Name: "0004_hardening", Checksum: strings.Repeat("4", 64)},
	}
}

func TestBuildMigrationStatusEmptyDatabase(t *testing.T) {
	result := buildMigrationStatus(statusMigrations(), map[string]migrationRow{}, nil)
	if result.UpToDate() || result.Current != "" || result.Expected != CurrentSchemaVersion {
		t.Fatalf("result = %+v", result)
	}
	if !slices.Equal(result.Pending, []string{"0001_initial", "0002_history", "0003_dispositions", "0004_hardening"}) || len(result.Adoptable) != 0 {
		t.Fatalf("pending = %v adoptable = %v", result.Pending, result.Adoptable)
	}
	for _, entry := range result.Entries {
		if entry.Applied || entry.Adoptable || entry.Checksum == "" || !strings.HasSuffix(entry.Describe(), " pending") {
			t.Fatalf("entry = %+v", entry)
		}
	}
}

func TestBuildMigrationStatusPartiallyApplied(t *testing.T) {
	appliedAt := time.Date(2026, time.September, 30, 17, 30, 0, 0, time.UTC)
	applied := map[string]migrationRow{
		"0001": {Version: "0001", Name: "0001_initial", Checksum: strings.Repeat("1", 64), AppliedAt: appliedAt},
		"0002": {Version: "0002", Name: "0002_history", Checksum: strings.Repeat("2", 64), AppliedAt: appliedAt.Add(time.Minute)},
	}
	result := buildMigrationStatus(statusMigrations(), applied, nil)
	if result.UpToDate() || result.Current != "0002" {
		t.Fatalf("result = %+v", result)
	}
	if !slices.Equal(result.Pending, []string{"0003_dispositions", "0004_hardening"}) {
		t.Fatalf("pending = %v", result.Pending)
	}
	if !result.Entries[1].Applied || !result.Entries[1].AppliedAt.Equal(appliedAt.Add(time.Minute)) || result.Entries[2].Applied {
		t.Fatalf("entries = %+v", result.Entries)
	}
	if got := result.Entries[0].Describe(); got != "0001_initial applied 2026-09-30T17:30:00Z" {
		t.Fatalf("Describe() = %q", got)
	}
}

func TestBuildMigrationStatusLegacySchemaIsAdoptable(t *testing.T) {
	result := buildMigrationStatus(statusMigrations(), map[string]migrationRow{}, []string{"0001", "0002", "0003"})
	if result.UpToDate() || result.Current != "0003" {
		t.Fatalf("result = %+v", result)
	}
	if !slices.Equal(result.Adoptable, []string{"0001_initial", "0002_history", "0003_dispositions"}) || !slices.Equal(result.Pending, []string{"0004_hardening"}) {
		t.Fatalf("adoptable = %v pending = %v", result.Adoptable, result.Pending)
	}
	if !result.Entries[0].Adoptable || result.Entries[0].Applied || !strings.Contains(result.Entries[0].Describe(), "adoptable") {
		t.Fatalf("entry = %+v", result.Entries[0])
	}
}

func TestBuildMigrationStatusUpToDate(t *testing.T) {
	applied := make(map[string]migrationRow)
	for _, migration := range statusMigrations() {
		applied[migration.Version] = migrationRow{Version: migration.Version, Name: migration.Name, Checksum: migration.Checksum, AppliedAt: time.Now()}
	}
	result := buildMigrationStatus(statusMigrations(), applied, nil)
	if !result.UpToDate() || result.Current != CurrentSchemaVersion || result.Current != result.Expected || len(result.Pending) != 0 {
		t.Fatalf("result = %+v", result)
	}
}

func TestMigrationStatusRejectsBadDirectoryBeforeConnecting(t *testing.T) {
	_, err := MigrationStatus(t.Context(), MigrationConfig{
		DatabaseURL: "postgres://layerleak@127.0.0.1:1/layerleak?sslmode=disable",
		Directory:   t.TempDir(),
	})
	if err == nil || !strings.Contains(err.Error(), "no migration files") {
		t.Fatalf("MigrationStatus() error = %v", err)
	}
	_, err = MigrationStatus(t.Context(), MigrationConfig{DatabaseURL: "", Directory: t.TempDir()})
	if err == nil {
		t.Fatal("MigrationStatus() accepted an empty database URL")
	}
}
