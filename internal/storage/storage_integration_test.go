package storage

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/brumbelow/layerleak/internal/findings"
	"github.com/brumbelow/layerleak/internal/manifest"
	_ "github.com/lib/pq"
)

func TestMigrationFilesApplyAndRollback(t *testing.T) {
	db := openIntegrationDB(t)
	defer db.Close()

	if err := applyMigrationSet(t, db, "*.up.sql"); err != nil {
		t.Fatalf("applyMigrationSet(up) error = %v", err)
	}
	if !tableExists(t, db, "repositories") {
		t.Fatal("repositories table was not created")
	}

	if err := applyMigrationSet(t, db, "*.down.sql"); err != nil {
		t.Fatalf("applyMigrationSet(down) error = %v", err)
	}
	if tableExists(t, db, "repositories") {
		t.Fatal("repositories table still exists after rollback")
	}
}

func TestPostgresStoreSaveScanUpsertsAndRetainsProvenance(t *testing.T) {
	db := openIntegrationDB(t)
	defer db.Close()
	if err := applyMigrationSet(t, db, "*.up.sql"); err != nil {
		t.Fatalf("applyMigrationSet() error = %v", err)
	}

	store, err := NewPostgresStore(PostgresConfig{DatabaseURL: integrationDatabaseURL(t)})
	if err != nil {
		t.Fatalf("NewPostgresStore() error = %v", err)
	}
	defer store.Close()

	record := integrationScanRecord(time.Date(2026, time.March, 15, 12, 0, 0, 0, time.UTC))
	if err := store.SaveScan(context.Background(), record); err != nil {
		t.Fatalf("SaveScan() error = %v", err)
	}
	record.ScannedAt = record.ScannedAt.Add(2 * time.Hour)
	if err := store.SaveScan(context.Background(), record); err != nil {
		t.Fatalf("SaveScan() second error = %v", err)
	}

	assertCount(t, db, "SELECT COUNT(*) FROM findings", 1)
	assertCount(t, db, "SELECT COUNT(*) FROM finding_occurrences", 2)

	var value string
	if err := db.QueryRow("SELECT value FROM findings").Scan(&value); err != nil {
		t.Fatalf("QueryRow(value) error = %v", err)
	}
	if value != "ghp_123456789012345678901234567890123456" {
		t.Fatalf("value = %q", value)
	}

	var rawSnippet string
	if err := db.QueryRow("SELECT raw_snippet FROM finding_occurrences ORDER BY source_location LIMIT 1").Scan(&rawSnippet); err != nil {
		t.Fatalf("QueryRow(raw_snippet) error = %v", err)
	}
	if !strings.Contains(rawSnippet, "ghp_123456789012345678901234567890123456") {
		t.Fatalf("rawSnippet = %q", rawSnippet)
	}
}

func TestPostgresStoreSaveScanReplacesTouchedTagMappings(t *testing.T) {
	db := openIntegrationDB(t)
	defer db.Close()
	if err := applyMigrationSet(t, db, "*.up.sql"); err != nil {
		t.Fatalf("applyMigrationSet() error = %v", err)
	}

	store, err := NewPostgresStore(PostgresConfig{DatabaseURL: integrationDatabaseURL(t)})
	if err != nil {
		t.Fatalf("NewPostgresStore() error = %v", err)
	}
	defer store.Close()

	first := integrationScanRecord(time.Date(2026, time.March, 15, 12, 0, 0, 0, time.UTC))
	second := integrationScanRecord(time.Date(2026, time.March, 15, 13, 0, 0, 0, time.UTC))
	second.Tags = []TagRecord{
		{
			Name:           "latest",
			RootDigest:     "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
			ManifestDigest: "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
			Platform:       manifest.Platform{OS: "linux", Architecture: "amd64"},
			Status:         "scanned",
		},
	}
	second.Targets = []TargetRecord{
		{
			Reference:       "docker.io/library/app@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
			RequestedDigest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
			Tags:            []string{"latest"},
			Manifests: []ManifestRecord{
				{
					Digest:     "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
					RootDigest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
					Platform:   manifest.Platform{OS: "linux", Architecture: "amd64"},
					Status:     "scanned",
				},
			},
		},
	}
	for index := range second.DetailedFindings {
		second.DetailedFindings[index].ManifestDigest = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
		second.DetailedFindings[index].Platform = manifest.Platform{OS: "linux", Architecture: "amd64"}
	}

	if err := store.SaveScan(context.Background(), first); err != nil {
		t.Fatalf("SaveScan(first) error = %v", err)
	}
	if err := store.SaveScan(context.Background(), second); err != nil {
		t.Fatalf("SaveScan(second) error = %v", err)
	}

	assertCount(t, db, "SELECT COUNT(*) FROM tags", 1)

	var manifestDigest string
	if err := db.QueryRow("SELECT manifest_digest FROM tags").Scan(&manifestDigest); err != nil {
		t.Fatalf("QueryRow(manifest_digest) error = %v", err)
	}
	if manifestDigest != "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" {
		t.Fatalf("manifestDigest = %q", manifestDigest)
	}
}

func openIntegrationDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := sql.Open("postgres", integrationDatabaseURL(t))
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec("DROP SCHEMA IF EXISTS layerleak_test CASCADE")
	})

	if _, err := db.Exec("CREATE SCHEMA IF NOT EXISTS layerleak_test"); err != nil {
		t.Fatalf("create schema error = %v", err)
	}
	if _, err := db.Exec("DROP SCHEMA layerleak_test CASCADE"); err != nil {
		t.Fatalf("drop schema error = %v", err)
	}
	if _, err := db.Exec("CREATE SCHEMA layerleak_test"); err != nil {
		t.Fatalf("recreate schema error = %v", err)
	}

	return db
}

func integrationDatabaseURL(t *testing.T) string {
	t.Helper()

	baseURL := strings.TrimSpace(os.Getenv("LAYERLEAK_TEST_DATABASE_URL"))
	if baseURL == "" {
		t.Skip("LAYERLEAK_TEST_DATABASE_URL is not set")
	}

	parsed, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	values := parsed.Query()
	values.Set("search_path", "layerleak_test")
	parsed.RawQuery = values.Encode()
	return parsed.String()
}

func applyMigrationSet(t *testing.T, db *sql.DB, pattern string) error {
	t.Helper()

	files, err := filepath.Glob(filepath.Join(repoRoot(t), "migrations", pattern))
	if err != nil {
		return err
	}
	slices.Sort(files)
	for _, filePath := range files {
		body, err := os.ReadFile(filePath)
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(body)) == "" {
			continue
		}
		if _, err := db.Exec(string(body)); err != nil {
			return fmt.Errorf("%s: %w", filepath.Base(filePath), err)
		}
	}
	return nil
}

func tableExists(t *testing.T, db *sql.DB, table string) bool {
	t.Helper()

	var exists bool
	if err := db.QueryRow("SELECT to_regclass($1) IS NOT NULL", table).Scan(&exists); err != nil {
		t.Fatalf("QueryRow(to_regclass) error = %v", err)
	}
	return exists
}

func repoRoot(t *testing.T) string {
	t.Helper()

	current, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}

	for {
		if _, err := os.Stat(filepath.Join(current, "go.mod")); err == nil {
			return current
		}
		parent := filepath.Dir(current)
		if parent == current {
			t.Fatal("repo root not found")
		}
		current = parent
	}
}

func assertCount(t *testing.T, db *sql.DB, query string, want int) {
	t.Helper()

	var got int
	if err := db.QueryRow(query).Scan(&got); err != nil {
		t.Fatalf("QueryRow(count) error = %v", err)
	}
	if got != want {
		t.Fatalf("%s = %d, want %d", query, got, want)
	}
}

func integrationScanRecord(scannedAt time.Time) ScanRecord {
	return ScanRecord{
		Registry:           "docker.io",
		Repository:         "library/app",
		RequestedReference: "library/app:latest",
		ResolvedReference:  "docker.io/library/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		RequestedDigest:    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Mode:               "reference",
		ScannedAt:          scannedAt.UTC(),
		Tags: []TagRecord{
			{
				Name:           "latest",
				RootDigest:     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				ManifestDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				Platform:       manifest.Platform{OS: "linux", Architecture: "amd64"},
				Status:         "scanned",
			},
		},
		Targets: []TargetRecord{
			{
				Reference:       "docker.io/library/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				RequestedDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				Tags:            []string{"latest"},
				Manifests: []ManifestRecord{
					{
						Digest:     "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
						RootDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
						Platform:   manifest.Platform{OS: "linux", Architecture: "amd64"},
						Status:     "scanned",
					},
				},
			},
		},
		DetailedFindings: []findings.DetailedFinding{
			{
				Finding: findings.Finding{
					DetectorName:        "github_token",
					Confidence:          "high",
					SourceType:          findings.SourceTypeEnv,
					ManifestDigest:      "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
					Platform:            manifest.Platform{OS: "linux", Architecture: "amd64"},
					Key:                 "GH_TOKEN",
					RedactedValue:       "ghp********************************56",
					Fingerprint:         "fingerprint-one",
					ContextSnippet:      "GH_TOKEN=ghp********************************56",
					PresentInFinalImage: true,
				},
				Value:          "ghp_123456789012345678901234567890123456",
				RawSnippet:     "GH_TOKEN=ghp_123456789012345678901234567890123456",
				SourceLocation: "env:GH_TOKEN",
				MatchStart:     9,
				MatchEnd:       49,
			},
			{
				Finding: findings.Finding{
					DetectorName:        "github_token",
					Confidence:          "high",
					SourceType:          findings.SourceTypeLabel,
					ManifestDigest:      "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
					Platform:            manifest.Platform{OS: "linux", Architecture: "amd64"},
					Key:                 "token",
					RedactedValue:       "ghp********************************56",
					Fingerprint:         "fingerprint-one",
					ContextSnippet:      "token=ghp********************************56",
					PresentInFinalImage: true,
				},
				Value:          "ghp_123456789012345678901234567890123456",
				RawSnippet:     "token=ghp_123456789012345678901234567890123456",
				SourceLocation: "label:token",
				MatchStart:     6,
				MatchEnd:       46,
			},
		},
	}
}
