package storage

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestPostgresStoreSaveScanPersistsControlCharactersInProvenance is the DB-01
// regression test: a NUL byte in an image-config Env/Label key used to abort
// the whole SaveScan transaction ("invalid byte sequence for encoding UTF8" on
// finding_occurrences.source_key and "unsupported Unicode escape sequence" on
// scan_runs.result_json), so the scan left no audit trail at all.
func TestPostgresStoreSaveScanPersistsControlCharactersInProvenance(t *testing.T) {
	db := openMigratedIntegrationDB(t)
	defer func() { _ = db.Close() }()

	store, err := NewPostgresStore(PostgresConfig{
		DatabaseURL:       integrationDatabaseURL(t),
		RequireSchema:     true,
		PersistRawSecrets: true,
	})
	if err != nil {
		t.Fatalf("NewPostgresStore() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	record := integrationScanRecord(time.Date(2026, time.September, 30, 12, 0, 0, 0, time.UTC))
	record.DetailedFindings = record.DetailedFindings[:1]
	finding := &record.DetailedFindings[0]
	finding.Key = "config.env.A\x00B"
	finding.ContextSnippet = "A\x00B=[REDACTED]\x01"
	finding.SourceLocation = "env:config.env.A\x00B"
	finding.RedactedValue = "ab\x00**********cd"
	finding.Value = "raw\x00secret"
	finding.RawSnippet = "A\x00B=raw\x00secret"
	record.Tags[0].Status = "failed"
	record.Tags[0].Error = "manifest\x00unreadable"
	record.ResultJSON = json.RawMessage(`{"requested_reference":"library/app:latest","findings":[{"key":"config.env.A\u0000B","fingerprint":"fingerprint-one","context_snippet":"A\u0000B=[REDACTED]"}],"total_findings":1}`)

	scanRunID, err := store.SaveScan(context.Background(), record)
	if err != nil {
		t.Fatalf("SaveScan() with NUL in provenance error = %v", err)
	}
	if scanRunID == 0 {
		t.Fatal("SaveScan() returned scan run id 0")
	}

	assertCount(t, db, "SELECT COUNT(*) FROM scan_runs", 1)
	assertCount(t, db, "SELECT COUNT(*) FROM repositories", 1)
	assertCount(t, db, "SELECT COUNT(*) FROM findings", 1)
	assertCount(t, db, "SELECT COUNT(*) FROM finding_occurrences", 1)

	var sourceKey, contextSnippet, sourceLocation, rawSnippet string
	if err := db.QueryRow(`SELECT source_key, context_snippet, source_location, raw_snippet FROM finding_occurrences`).Scan(&sourceKey, &contextSnippet, &sourceLocation, &rawSnippet); err != nil {
		t.Fatalf("query finding_occurrences: %v", err)
	}
	if sourceKey != "config.env.A�B" {
		t.Fatalf("source_key = %q, want NUL replaced with U+FFFD", sourceKey)
	}
	if contextSnippet != "A�B=[REDACTED]�" {
		t.Fatalf("context_snippet = %q", contextSnippet)
	}
	if sourceLocation != "env:config.env.A�B" {
		t.Fatalf("source_location = %q", sourceLocation)
	}
	if rawSnippet != "A�B=raw�secret" {
		t.Fatalf("raw_snippet = %q", rawSnippet)
	}

	var redactedValue, value, fingerprint string
	if err := db.QueryRow(`SELECT redacted_value, value, fingerprint FROM findings`).Scan(&redactedValue, &value, &fingerprint); err != nil {
		t.Fatalf("query findings: %v", err)
	}
	if redactedValue != "ab�**********cd" || value != "raw�secret" {
		t.Fatalf("findings row = (%q, %q)", redactedValue, value)
	}
	if fingerprint != "fingerprint-one" {
		t.Fatalf("fingerprint = %q, identity must not change", fingerprint)
	}

	var tagError string
	if err := db.QueryRow(`SELECT error FROM tags`).Scan(&tagError); err != nil {
		t.Fatalf("query tags: %v", err)
	}
	if tagError != "manifest�unreadable" {
		t.Fatalf("tags.error = %q", tagError)
	}

	var storedKey string
	if err := db.QueryRow(`SELECT result_json->'findings'->0->>'key' FROM scan_runs WHERE id = $1`, scanRunID).Scan(&storedKey); err != nil {
		t.Fatalf("query result_json: %v", err)
	}
	if storedKey != "config.env.A�B" {
		t.Fatalf("result_json finding key = %q", storedKey)
	}

	detail, err := store.GetScanRun(context.Background(), scanRunID)
	if err != nil {
		t.Fatalf("GetScanRun() error = %v", err)
	}
	if !json.Valid(detail.ResultJSON) || strings.Contains(string(detail.ResultJSON), `\u0000`) {
		t.Fatalf("GetScanRun().ResultJSON = %s", detail.ResultJSON)
	}
	findingDetail, err := store.GetFinding(context.Background(), 1)
	if err != nil {
		t.Fatalf("GetFinding() error = %v", err)
	}
	if len(findingDetail.Occurrences) != 1 || findingDetail.Occurrences[0].Key != "config.env.A�B" {
		t.Fatalf("GetFinding().Occurrences = %+v", findingDetail.Occurrences)
	}
}
