package storage

import (
	"context"
	"database/sql"
	"encoding/json"
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
	if _, err := store.SaveScan(context.Background(), record); err != nil {
		t.Fatalf("SaveScan() error = %v", err)
	}
	record.ScannedAt = record.ScannedAt.Add(2 * time.Hour)
	if _, err := store.SaveScan(context.Background(), record); err != nil {
		t.Fatalf("SaveScan() second error = %v", err)
	}

	assertCount(t, db, "SELECT COUNT(*) FROM findings", 1)
	assertCount(t, db, "SELECT COUNT(*) FROM finding_occurrences", 2)

	var value string
	if err := db.QueryRow("SELECT value FROM findings").Scan(&value); err != nil {
		t.Fatalf("QueryRow(value) error = %v", err)
	}
	if value != "" {
		t.Fatalf("value = %q", value)
	}

	var rawSnippet string
	if err := db.QueryRow("SELECT raw_snippet FROM finding_occurrences ORDER BY source_location LIMIT 1").Scan(&rawSnippet); err != nil {
		t.Fatalf("QueryRow(raw_snippet) error = %v", err)
	}
	if rawSnippet != "" {
		t.Fatalf("rawSnippet = %q", rawSnippet)
	}

	var disposition, reason string
	var lineNumber int
	if err := db.QueryRow("SELECT disposition, disposition_reason, line_number FROM finding_occurrences ORDER BY source_location LIMIT 1").Scan(&disposition, &reason, &lineNumber); err != nil {
		t.Fatalf("QueryRow(disposition) error = %v", err)
	}
	if disposition != string(findings.DispositionActionable) {
		t.Fatalf("disposition = %q", disposition)
	}
	if reason != "" {
		t.Fatalf("reason = %q", reason)
	}
	if lineNumber <= 0 {
		t.Fatalf("lineNumber = %d", lineNumber)
	}
}

func TestPostgresStoreSaveScanPersistsRawSecretsWhenEnabled(t *testing.T) {
	db := openIntegrationDB(t)
	defer db.Close()
	if err := applyMigrationSet(t, db, "*.up.sql"); err != nil {
		t.Fatalf("applyMigrationSet() error = %v", err)
	}

	store, err := NewPostgresStore(PostgresConfig{
		DatabaseURL:       integrationDatabaseURL(t),
		PersistRawSecrets: true,
	})
	if err != nil {
		t.Fatalf("NewPostgresStore() error = %v", err)
	}
	defer store.Close()

	record := integrationScanRecord(time.Date(2026, time.March, 15, 12, 0, 0, 0, time.UTC))
	if _, err := store.SaveScan(context.Background(), record); err != nil {
		t.Fatalf("SaveScan() error = %v", err)
	}

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

func TestPostgresStoreSaveScanPersistsScanRunHistory(t *testing.T) {
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
	record.Status = ScanRunStatusPartial
	record.ErrorMessage = "config blob sha256:bbbb exceeded max config bytes limit of 128"

	scanRunID, err := store.SaveScan(context.Background(), record)
	if err != nil {
		t.Fatalf("SaveScan() error = %v", err)
	}
	if scanRunID <= 0 {
		t.Fatalf("scanRunID = %d", scanRunID)
	}

	assertCount(t, db, "SELECT COUNT(*) FROM scan_runs", 1)

	var status, errorMessage, resultJSON string
	if err := db.QueryRow(`
		SELECT status, error_message, result_json::text
		FROM scan_runs
		WHERE id = $1
	`, scanRunID).Scan(&status, &errorMessage, &resultJSON); err != nil {
		t.Fatalf("QueryRow(scan_runs) error = %v", err)
	}
	if status != string(ScanRunStatusPartial) {
		t.Fatalf("status = %q", status)
	}
	if errorMessage != record.ErrorMessage {
		t.Fatalf("errorMessage = %q", errorMessage)
	}
	if strings.Contains(resultJSON, "ghp_123456789012345678901234567890123456") {
		t.Fatalf("result_json leaked raw secret: %q", resultJSON)
	}
	if !strings.Contains(resultJSON, "ghp********************************56") {
		t.Fatalf("result_json missing redacted value: %q", resultJSON)
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

	if _, err := store.SaveScan(context.Background(), first); err != nil {
		t.Fatalf("SaveScan(first) error = %v", err)
	}
	if _, err := store.SaveScan(context.Background(), second); err != nil {
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

func TestPostgresStoreListRepositoriesOrdersByLastSeenAt(t *testing.T) {
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
	second.Repository = "library/zebra"
	second.RequestedReference = "library/zebra:latest"
	second.ResolvedReference = "docker.io/library/zebra@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	second.Targets[0].Reference = "docker.io/library/zebra@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	if _, err := store.SaveScan(context.Background(), first); err != nil {
		t.Fatalf("SaveScan(first) error = %v", err)
	}
	if _, err := store.SaveScan(context.Background(), second); err != nil {
		t.Fatalf("SaveScan(second) error = %v", err)
	}

	items, err := store.ListRepositories(context.Background(), 50, 0)
	if err != nil {
		t.Fatalf("ListRepositories() error = %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("len(items) = %d", len(items))
	}
	if items[0].Repository != "library/zebra" || items[1].Repository != "library/app" {
		t.Fatalf("repository order = %q, %q", items[0].Repository, items[1].Repository)
	}
}

func TestPostgresStoreListRepositoryScansOrdersByScannedAt(t *testing.T) {
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
	second.Status = ScanRunStatusPartial
	second.ErrorMessage = "target scan incomplete"

	if _, err := store.SaveScan(context.Background(), first); err != nil {
		t.Fatalf("SaveScan(first) error = %v", err)
	}
	if _, err := store.SaveScan(context.Background(), second); err != nil {
		t.Fatalf("SaveScan(second) error = %v", err)
	}

	items, err := store.ListRepositoryScans(context.Background(), "library/app", 50, 0)
	if err != nil {
		t.Fatalf("ListRepositoryScans() error = %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("len(items) = %d", len(items))
	}
	if items[0].ScannedAt.Before(items[1].ScannedAt) {
		t.Fatalf("scan order = %s then %s", items[0].ScannedAt, items[1].ScannedAt)
	}
	if items[0].Status != ScanRunStatusPartial {
		t.Fatalf("items[0].Status = %q", items[0].Status)
	}
	if items[1].Status != ScanRunStatusCompleted {
		t.Fatalf("items[1].Status = %q", items[1].Status)
	}
}

func TestPostgresStoreListRepositoryFindingsAggregatesAndFiltersDispositions(t *testing.T) {
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
	record.DetailedFindings[1].Disposition = findings.DispositionExample
	record.DetailedFindings[1].DispositionReason = findings.DispositionReasonExamplePath

	if _, err := store.SaveScan(context.Background(), record); err != nil {
		t.Fatalf("SaveScan() error = %v", err)
	}

	actionable, err := store.ListRepositoryFindings(context.Background(), "library/app", FindingDispositionActionable, 50, 0)
	if err != nil {
		t.Fatalf("ListRepositoryFindings(actionable) error = %v", err)
	}
	if len(actionable) != 1 {
		t.Fatalf("len(actionable) = %d", len(actionable))
	}
	if actionable[0].OccurrenceCount != 2 {
		t.Fatalf("OccurrenceCount = %d", actionable[0].OccurrenceCount)
	}
	if actionable[0].ActionableOccurrenceCount != 1 {
		t.Fatalf("ActionableOccurrenceCount = %d", actionable[0].ActionableOccurrenceCount)
	}
	if actionable[0].SuppressedOccurrenceCount != 1 {
		t.Fatalf("SuppressedOccurrenceCount = %d", actionable[0].SuppressedOccurrenceCount)
	}
	if len(actionable[0].Detectors) != 1 || actionable[0].Detectors[0] != "github_token" {
		t.Fatalf("Detectors = %#v", actionable[0].Detectors)
	}

	suppressed, err := store.ListRepositoryFindings(context.Background(), "library/app", FindingDispositionSuppressed, 50, 0)
	if err != nil {
		t.Fatalf("ListRepositoryFindings(suppressed) error = %v", err)
	}
	if len(suppressed) != 1 {
		t.Fatalf("len(suppressed) = %d", len(suppressed))
	}
}

func TestPostgresStoreGetFindingLoadsOccurrenceDetail(t *testing.T) {
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
	if _, err := store.SaveScan(context.Background(), record); err != nil {
		t.Fatalf("SaveScan() error = %v", err)
	}

	items, err := store.ListRepositoryFindings(context.Background(), "library/app", FindingDispositionAll, 50, 0)
	if err != nil {
		t.Fatalf("ListRepositoryFindings() error = %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("len(items) = %d", len(items))
	}

	detail, err := store.GetFinding(context.Background(), items[0].ID)
	if err != nil {
		t.Fatalf("GetFinding() error = %v", err)
	}
	if detail.ID != items[0].ID {
		t.Fatalf("detail.ID = %d", detail.ID)
	}
	if len(detail.Occurrences) != 2 {
		t.Fatalf("len(detail.Occurrences) = %d", len(detail.Occurrences))
	}
	if detail.Occurrences[0].ContextSnippet == "" {
		t.Fatal("expected occurrence context snippet")
	}
	if detail.Occurrences[0].SourceLocation == "" {
		t.Fatal("expected occurrence source location")
	}
}

func TestPostgresStoreGetScanRunLoadsRedactedSnapshot(t *testing.T) {
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
	scanRunID, err := store.SaveScan(context.Background(), record)
	if err != nil {
		t.Fatalf("SaveScan() error = %v", err)
	}

	detail, err := store.GetScanRun(context.Background(), scanRunID)
	if err != nil {
		t.Fatalf("GetScanRun() error = %v", err)
	}
	if detail.ID != scanRunID {
		t.Fatalf("detail.ID = %d", detail.ID)
	}
	if detail.Repository != "library/app" {
		t.Fatalf("detail.Repository = %q", detail.Repository)
	}
	if detail.Status != ScanRunStatusCompleted {
		t.Fatalf("detail.Status = %q", detail.Status)
	}
	if !json.Valid(detail.ResultJSON) {
		t.Fatalf("result json is invalid: %q", string(detail.ResultJSON))
	}
	if strings.Contains(string(detail.ResultJSON), "ghp_123456789012345678901234567890123456") {
		t.Fatalf("result json leaked raw secret: %q", string(detail.ResultJSON))
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
		Registry:               "docker.io",
		Repository:             "library/app",
		RequestedReference:     "library/app:latest",
		ResolvedReference:      "docker.io/library/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		RequestedDigest:        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Mode:                   "reference",
		TagsEnumerated:         1,
		TagsResolved:           1,
		TargetCount:            1,
		CompletedTargetCount:   1,
		ManifestCount:          1,
		CompletedManifestCount: 1,
		TotalFindings:          1,
		UniqueFingerprints:     1,
		Status:                 ScanRunStatusCompleted,
		ResultJSON: []byte(`{
  "requested_reference":"library/app:latest",
  "repository":"library/app",
  "mode":"reference",
  "resolved_reference":"docker.io/library/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "requested_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "target_count":1,
  "completed_target_count":1,
  "manifest_count":1,
  "completed_manifest_count":1,
  "findings":[
    {
      "detector_name":"github_token",
      "confidence":"high",
      "disposition":"actionable",
      "source_type":"env",
      "manifest_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "key":"GH_TOKEN",
      "redacted_value":"ghp********************************56",
      "fingerprint":"fingerprint-one",
      "context_snippet":"GH_TOKEN=ghp********************************56",
      "present_in_final_image":true
    }
  ],
  "total_findings":1,
  "unique_fingerprints":1
}`),
		ScannedAt: scannedAt.UTC(),
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
					Disposition:         findings.DispositionActionable,
					SourceType:          findings.SourceTypeEnv,
					ManifestDigest:      "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
					Platform:            manifest.Platform{OS: "linux", Architecture: "amd64"},
					Key:                 "GH_TOKEN",
					RedactedValue:       "ghp********************************56",
					Fingerprint:         "fingerprint-one",
					ContextSnippet:      "GH_TOKEN=ghp********************************56",
					LineNumber:          1,
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
					Disposition:         findings.DispositionActionable,
					SourceType:          findings.SourceTypeLabel,
					ManifestDigest:      "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
					Platform:            manifest.Platform{OS: "linux", Architecture: "amd64"},
					Key:                 "token",
					RedactedValue:       "ghp********************************56",
					Fingerprint:         "fingerprint-one",
					ContextSnippet:      "token=ghp********************************56",
					LineNumber:          1,
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
