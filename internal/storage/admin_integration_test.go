package storage

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestPostgresStorePurgeRawSecretsInSmallBatches purges eighteen findings
// (nine scans with two unique fingerprints each) and eighteen occurrences with
// a batch size of four and checks the batch walk, the running totals and that
// redacted rows survive.
func TestPostgresStorePurgeRawSecretsInSmallBatches(t *testing.T) {
	db := openIntegrationDB(t)
	defer func() { _ = db.Close() }()
	if err := applyMigrationSet(t, db, "*.up.sql"); err != nil {
		t.Fatalf("applyMigrationSet() error = %v", err)
	}
	store, err := NewPostgresStore(PostgresConfig{DatabaseURL: integrationDatabaseURL(t), PersistRawSecrets: true})
	if err != nil {
		t.Fatalf("NewPostgresStore() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	scannedAt := time.Date(2026, time.March, 15, 12, 0, 0, 0, time.UTC)
	for index := 0; index < 9; index++ {
		record := integrationScanRecord(scannedAt.Add(time.Duration(index) * time.Minute))
		for position := range record.DetailedFindings {
			record.DetailedFindings[position].Fingerprint = fmt.Sprintf("%02d-%062d", index, position)
		}
		if _, err := store.SaveScan(context.Background(), record); err != nil {
			t.Fatalf("SaveScan(%d) error = %v", index, err)
		}
	}
	before, err := store.CountRawSecrets(context.Background())
	if err != nil || before.FindingValues != 18 || before.OccurrenceSnippets != 18 {
		t.Fatalf("CountRawSecrets() = %#v, %v", before, err)
	}

	var reports []PurgeProgress
	purged, err := store.PurgeRawSecrets(context.Background(), PurgeOptions{
		BatchSize: 4,
		Progress:  func(progress PurgeProgress) { reports = append(reports, progress) },
	})
	if err != nil {
		t.Fatalf("PurgeRawSecrets() error = %v", err)
	}
	if purged != before {
		t.Fatalf("purged = %#v, before = %#v", purged, before)
	}
	// 18 values in batches of 4 -> 4, 4, 4, 4, 2; 18 snippets -> the same.
	wantRows := []int64{4, 4, 4, 4, 2, 4, 4, 4, 4, 2}
	if len(reports) != len(wantRows) {
		t.Fatalf("progress reports = %+v", reports)
	}
	var running RawSecretCounts
	for index, report := range reports {
		if report.Rows != wantRows[index] {
			t.Fatalf("report %d rows = %d, want %d (%+v)", index, report.Rows, wantRows[index], reports)
		}
		if index < 5 {
			running.FindingValues += report.Rows
			if report.Table != "findings" {
				t.Fatalf("report %d table = %q", index, report.Table)
			}
		} else {
			running.OccurrenceSnippets += report.Rows
			if report.Table != "finding_occurrences" {
				t.Fatalf("report %d table = %q", index, report.Table)
			}
		}
		if report.Total != running {
			t.Fatalf("report %d total = %#v, want %#v", index, report.Total, running)
		}
	}

	after, err := store.CountRawSecrets(context.Background())
	if err != nil || after.Total() != 0 {
		t.Fatalf("CountRawSecrets(after) = %#v, %v", after, err)
	}
	assertCount(t, db, "SELECT COUNT(*) FROM findings", 18)
	assertCount(t, db, "SELECT COUNT(*) FROM finding_occurrences", 18)
	assertCount(t, db, "SELECT COUNT(*) FROM findings WHERE redacted_value <> ''", 18)

	// A second run finds nothing and reports nothing.
	reports = nil
	again, err := store.PurgeRawSecrets(context.Background(), PurgeOptions{BatchSize: 4, Progress: func(progress PurgeProgress) { reports = append(reports, progress) }})
	if err != nil || again.Total() != 0 || len(reports) != 0 {
		t.Fatalf("second purge = %#v, %v, reports %+v", again, err, reports)
	}
}
