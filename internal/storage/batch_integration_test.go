package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/findings"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
)

const batchManifestDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

// bulkScanRecord builds a scan with `count` distinct findings on one manifest,
// each with two occurrences (env and label) and, every tenth finding, a
// repeated occurrence identity so the batch path has to collapse duplicates.
func bulkScanRecord(scannedAt time.Time, count int) ScanRecord {
	record := ScanRecord{
		Registry:               "docker.io",
		Repository:             "library/bulk",
		RequestedReference:     "library/bulk:latest",
		Mode:                   "reference",
		TargetCount:            1,
		CompletedTargetCount:   1,
		ManifestCount:          1,
		CompletedManifestCount: 1,
		TotalFindings:          count,
		UniqueFingerprints:     count,
		Status:                 ScanRunStatusCompleted,
		ResultJSON:             json.RawMessage(`{"requested_reference":"library/bulk:latest"}`),
		ScannedAt:              scannedAt.UTC(),
		Targets: []TargetRecord{{
			Reference:       "docker.io/library/bulk@" + batchManifestDigest,
			RequestedDigest: batchManifestDigest,
			Manifests:       []ManifestRecord{{Digest: batchManifestDigest, Status: "scanned", Platform: manifest.Platform{OS: "linux", Architecture: "amd64"}}},
		}},
	}
	record.DetailedFindings = make([]findings.DetailedFinding, 0, 3*count)
	for index := 0; index < count; index++ {
		fingerprint := fmt.Sprintf("fp-%06d", index)
		redacted := fmt.Sprintf("val%06d***", index)
		base := findings.Finding{
			DetectorName:        "generic_secret",
			Confidence:          "high",
			Disposition:         findings.DispositionActionable,
			ManifestDigest:      batchManifestDigest,
			Platform:            manifest.Platform{OS: "linux", Architecture: "amd64"},
			RedactedValue:       redacted,
			Fingerprint:         fingerprint,
			LineNumber:          1,
			PresentInFinalImage: true,
		}
		env := base
		env.SourceType = findings.SourceTypeEnv
		env.Key = fmt.Sprintf("config.env.KEY_%06d", index)
		env.ContextSnippet = env.Key + "=[REDACTED]"
		label := base
		label.SourceType = findings.SourceTypeLabel
		label.Key = fmt.Sprintf("config.label.key-%06d", index)
		label.ContextSnippet = label.Key + "=[REDACTED]"
		record.DetailedFindings = append(record.DetailedFindings,
			findings.DetailedFinding{Finding: env, Value: "raw-" + fingerprint, RawSnippet: env.Key + "=raw-" + fingerprint, SourceLocation: "env:" + env.Key},
			findings.DetailedFinding{Finding: label, Value: "raw-" + fingerprint, RawSnippet: label.Key + "=raw-" + fingerprint, SourceLocation: "label:" + label.Key},
		)
		if index%10 == 0 {
			// Same 15-column occurrence identity as the env row (line_number is
			// not part of it) but a different dedup key: DeduplicateDetailed
			// keeps both, the database identity collapses them and the
			// last row in sorted order (line 2) supplies line_number and the
			// raw snippet, exactly as the serial upsert did.
			duplicate := record.DetailedFindings[len(record.DetailedFindings)-2]
			duplicate.LineNumber = 2
			duplicate.RawSnippet = "alt " + duplicate.RawSnippet
			record.DetailedFindings = append(record.DetailedFindings, duplicate)
		}
	}
	return record
}

// TestPostgresStoreSaveScanTenThousandFindingsWithinBudget persists the
// default LAYERLEAK_MAX_FINDINGS_PER_SCAN worth of findings (DB-02) and logs
// the elapsed time so the serial and batched implementations can be compared.
func TestPostgresStoreSaveScanTenThousandFindingsWithinBudget(t *testing.T) {
	db := openMigratedIntegrationDB(t)
	defer func() { _ = db.Close() }()
	store, err := NewPostgresStore(PostgresConfig{DatabaseURL: integrationDatabaseURL(t), RequireSchema: true, PersistRawSecrets: true})
	if err != nil {
		t.Fatalf("NewPostgresStore() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	const count = 10000
	record := bulkScanRecord(time.Date(2026, time.September, 30, 12, 0, 0, 0, time.UTC), count)
	started := time.Now()
	scanRunID, err := store.SaveScan(context.Background(), record)
	elapsed := time.Since(started)
	if err != nil {
		t.Fatalf("SaveScan(%d findings) error = %v", count, err)
	}
	t.Logf("SaveScan(%d findings, %d occurrences) took %s (%.3f ms/finding)", count, 2*count, elapsed.Round(time.Millisecond), float64(elapsed.Microseconds())/1000/float64(count))
	if scanRunID == 0 {
		t.Fatal("SaveScan() returned scan run id 0")
	}
	assertCount(t, db, "SELECT COUNT(*) FROM findings", count)
	assertCount(t, db, "SELECT COUNT(*) FROM finding_occurrences", 2*count)
	assertCount(t, db, "SELECT COUNT(*) FROM finding_occurrences WHERE raw_snippet LIKE 'alt %'", count/10)
	assertCount(t, db, "SELECT COUNT(DISTINCT finding_id) FROM finding_occurrences", count)
	if elapsed > time.Minute {
		t.Fatalf("SaveScan(%d findings) took %s, budget is one minute", count, elapsed)
	}
}

// TestPostgresStoreSaveScanBatchMatchesSerialSemantics pins the stored results
// a batched SaveScan must reproduce: one findings row per (manifest,
// fingerprint) with the last sorted value, one occurrence per identity with the
// last raw snippet, rescans that only bump last_seen_at, and the same ids
// handed back to GetFinding.
func TestPostgresStoreSaveScanBatchMatchesSerialSemantics(t *testing.T) {
	db := openMigratedIntegrationDB(t)
	defer func() { _ = db.Close() }()
	store, err := NewPostgresStore(PostgresConfig{DatabaseURL: integrationDatabaseURL(t), RequireSchema: true, PersistRawSecrets: true})
	if err != nil {
		t.Fatalf("NewPostgresStore() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	first := time.Date(2026, time.September, 30, 12, 0, 0, 0, time.UTC)
	record := bulkScanRecord(first, 25)
	if _, err := store.SaveScan(context.Background(), record); err != nil {
		t.Fatalf("SaveScan(first) error = %v", err)
	}
	assertCount(t, db, "SELECT COUNT(*) FROM findings", 25)
	assertCount(t, db, "SELECT COUNT(*) FROM finding_occurrences", 50)
	assertCount(t, db, "SELECT COUNT(*) FROM finding_occurrences WHERE raw_snippet LIKE 'alt %'", 3)

	// The env occurrence of finding 0 appears twice with different raw
	// snippets; in sorted order the "alt" rendering sorts after the plain one
	// and therefore wins, exactly as the serial upsert did.
	var rawSnippet string
	var lineNumber int
	if err := db.QueryRow(`SELECT fo.raw_snippet, fo.line_number FROM finding_occurrences fo JOIN findings f ON f.id = fo.finding_id WHERE f.fingerprint = 'fp-000000' AND fo.source_type = 'env'`).Scan(&rawSnippet, &lineNumber); err != nil {
		t.Fatalf("query raw_snippet: %v", err)
	}
	if !strings.HasPrefix(rawSnippet, "alt ") || lineNumber != 2 {
		t.Fatalf("occurrence = (%q, line %d), want the last sorted rendering on line 2", rawSnippet, lineNumber)
	}

	// A later rescan with the same findings must not add rows and must move
	// last_seen_at forward while keeping first_seen_at.
	second := first.Add(time.Hour)
	rescan := bulkScanRecord(second, 25)
	for index := range rescan.DetailedFindings {
		rescan.DetailedFindings[index].RedactedValue = "new" + rescan.DetailedFindings[index].RedactedValue
	}
	if _, err := store.SaveScan(context.Background(), rescan); err != nil {
		t.Fatalf("SaveScan(rescan) error = %v", err)
	}
	assertCount(t, db, "SELECT COUNT(*) FROM findings", 25)
	assertCount(t, db, "SELECT COUNT(*) FROM finding_occurrences", 50)
	assertCount(t, db, "SELECT COUNT(*) FROM findings WHERE first_seen_at = '2026-09-30T12:00:00Z' AND last_seen_at = '2026-09-30T13:00:00Z' AND redacted_value LIKE 'newval%'", 25)
	assertCount(t, db, "SELECT COUNT(*) FROM finding_occurrences WHERE first_seen_at = '2026-09-30T12:00:00Z' AND last_seen_at = '2026-09-30T13:00:00Z'", 50)
	assertCount(t, db, "SELECT COUNT(*) FROM scan_runs", 2)

	// An older write must not regress anything.
	older := bulkScanRecord(first.Add(-time.Hour), 25)
	for index := range older.DetailedFindings {
		older.DetailedFindings[index].RedactedValue = "old" + older.DetailedFindings[index].RedactedValue
	}
	if _, err := store.SaveScan(context.Background(), older); err != nil {
		t.Fatalf("SaveScan(older) error = %v", err)
	}
	assertCount(t, db, "SELECT COUNT(*) FROM findings WHERE first_seen_at = '2026-09-30T11:00:00Z' AND last_seen_at = '2026-09-30T13:00:00Z' AND redacted_value LIKE 'newval%'", 25)

	summaries, err := store.ListRepositoryFindings(context.Background(), "docker.io", "library/bulk", FindingDispositionAll, 100, 0)
	if err != nil {
		t.Fatalf("ListRepositoryFindings() error = %v", err)
	}
	if len(summaries) != 25 {
		t.Fatalf("len(summaries) = %d", len(summaries))
	}
	for _, summary := range summaries {
		if summary.OccurrenceCount != 2 {
			t.Fatalf("finding %s occurrence count = %d", summary.Fingerprint, summary.OccurrenceCount)
		}
		detail, err := store.GetFinding(context.Background(), summary.ID)
		if err != nil {
			t.Fatalf("GetFinding(%d) error = %v", summary.ID, err)
		}
		if len(detail.Occurrences) != 2 || detail.Fingerprint != summary.Fingerprint {
			t.Fatalf("GetFinding(%d) = %+v", summary.ID, detail)
		}
	}
}
