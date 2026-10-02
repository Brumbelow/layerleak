package storage

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// The tests in this file port the audit's probe tests into the suite (DB-07):
// behaviours that were verified by hand but never guarded in-repo.

func TestPostgresStoreConcurrentSaveScanAcrossRepositoriesSharingManifest(t *testing.T) {
	db := openMigratedIntegrationDB(t)
	defer func() { _ = db.Close() }()
	store, err := NewPostgresStore(PostgresConfig{DatabaseURL: integrationDatabaseURL(t), RequireSchema: true, MaxOpenConns: 8})
	if err != nil {
		t.Fatalf("NewPostgresStore() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	const writers = 24
	scannedAt := time.Date(2026, time.September, 30, 12, 0, 0, 0, time.UTC)
	errs := make(chan error, writers)
	var wg sync.WaitGroup
	for index := 0; index < writers; index++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			record := integrationScanRecord(scannedAt.Add(time.Duration(index) * time.Second))
			// Two repositories share the same manifest and the same finding,
			// so writers race on manifests and findings rows while holding
			// different repository advisory locks.
			record.Repository = []string{"library/alpha", "library/beta"}[index%2]
			record.RequestedReference = record.Repository + ":latest"
			if _, err := store.SaveScan(context.Background(), record); err != nil {
				errs <- fmt.Errorf("writer %d: %w", index, err)
			}
		}(index)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if t.Failed() {
		t.FailNow()
	}

	assertCount(t, db, "SELECT COUNT(*) FROM repositories", 2)
	assertCount(t, db, "SELECT COUNT(*) FROM manifests", 1)
	assertCount(t, db, "SELECT COUNT(*) FROM repository_manifests", 2)
	assertCount(t, db, "SELECT COUNT(*) FROM findings", 1)
	assertCount(t, db, "SELECT COUNT(*) FROM finding_occurrences", 2)
	assertCount(t, db, "SELECT COUNT(*) FROM scan_runs", writers)
	assertCount(t, db, "SELECT COUNT(*) FROM findings WHERE last_seen_at = '2026-09-30T12:00:23Z' AND first_seen_at = '2026-09-30T12:00:00Z'", 1)
}

func TestPostgresStoreListRepositoryScansPaginatesTiedScannedAt(t *testing.T) {
	db := openMigratedIntegrationDB(t)
	defer func() { _ = db.Close() }()
	store, err := NewPostgresStore(PostgresConfig{DatabaseURL: integrationDatabaseURL(t), RequireSchema: true})
	if err != nil {
		t.Fatalf("NewPostgresStore() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	scannedAt := time.Date(2026, time.September, 30, 12, 0, 0, 0, time.UTC)
	const runs = 7
	for index := 0; index < runs; index++ {
		if _, err := store.SaveScan(context.Background(), integrationScanRecord(scannedAt)); err != nil {
			t.Fatalf("SaveScan(%d) error = %v", index, err)
		}
	}

	var ids []int64
	for offset := 0; offset < runs; offset += 3 {
		page, err := store.ListRepositoryScans(context.Background(), "docker.io", "library/app", 3, offset, nil)
		if err != nil {
			t.Fatalf("ListRepositoryScans(offset %d) error = %v", offset, err)
		}
		for _, item := range page {
			ids = append(ids, item.ID)
		}
	}
	if len(ids) != runs {
		t.Fatalf("paginated %d scan runs, want %d: %v", len(ids), runs, ids)
	}
	for index := 1; index < len(ids); index++ {
		if ids[index] >= ids[index-1] {
			t.Fatalf("tied scanned_at pages are not strictly ordered by id DESC: %v", ids)
		}
	}
}

func TestPostgresStoreListRepositoryFindingsPaginatesTiedLastSeenAt(t *testing.T) {
	db := openMigratedIntegrationDB(t)
	defer func() { _ = db.Close() }()
	store, err := NewPostgresStore(PostgresConfig{DatabaseURL: integrationDatabaseURL(t), RequireSchema: true})
	if err != nil {
		t.Fatalf("NewPostgresStore() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	record := integrationScanRecord(time.Date(2026, time.September, 30, 12, 0, 0, 0, time.UTC))
	template := record.DetailedFindings[0]
	record.DetailedFindings = nil
	const count = 7
	for index := 0; index < count; index++ {
		item := template
		item.Fingerprint = fmt.Sprintf("fingerprint-%02d", index)
		item.Key = fmt.Sprintf("KEY_%02d", index)
		item.SourceLocation = "env:" + item.Key
		item.ContextSnippet = item.Key + "=[REDACTED]"
		record.DetailedFindings = append(record.DetailedFindings, item)
	}
	record.TotalFindings = count
	record.UniqueFingerprints = count
	if _, err := store.SaveScan(context.Background(), record); err != nil {
		t.Fatalf("SaveScan() error = %v", err)
	}

	var ids []int64
	for offset := 0; offset < count; offset += 3 {
		page, err := store.ListRepositoryFindings(context.Background(), "docker.io", "library/app", FindingDispositionAll, 3, offset, nil)
		if err != nil {
			t.Fatalf("ListRepositoryFindings(offset %d) error = %v", offset, err)
		}
		for _, item := range page {
			ids = append(ids, item.ID)
		}
	}
	if len(ids) != count {
		t.Fatalf("paginated %d findings, want %d: %v", len(ids), count, ids)
	}
	for index := 1; index < len(ids); index++ {
		if ids[index] >= ids[index-1] {
			t.Fatalf("tied last_seen_at pages are not strictly ordered by id DESC: %v", ids)
		}
	}
}

func TestPostgresStoreGetFindingOrdersTiedOccurrencesBySourceLocation(t *testing.T) {
	db := openMigratedIntegrationDB(t)
	defer func() { _ = db.Close() }()
	store, err := NewPostgresStore(PostgresConfig{DatabaseURL: integrationDatabaseURL(t), RequireSchema: true})
	if err != nil {
		t.Fatalf("NewPostgresStore() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	record := integrationScanRecord(time.Date(2026, time.September, 30, 12, 0, 0, 0, time.UTC))
	template := record.DetailedFindings[0]
	record.DetailedFindings = nil
	keys := []string{"ZETA", "ALPHA", "MIKE", "BRAVO", "YANKEE"}
	for _, key := range keys {
		item := template
		item.Key = key
		item.SourceLocation = "env:" + key
		item.ContextSnippet = key + "=[REDACTED]"
		record.DetailedFindings = append(record.DetailedFindings, item)
	}
	if _, err := store.SaveScan(context.Background(), record); err != nil {
		t.Fatalf("SaveScan() error = %v", err)
	}

	summaries, err := store.ListRepositoryFindings(context.Background(), "docker.io", "library/app", FindingDispositionAll, 10, 0, nil)
	if err != nil || len(summaries) != 1 {
		t.Fatalf("ListRepositoryFindings() = %v, %v", summaries, err)
	}
	detail, err := store.GetFinding(context.Background(), summaries[0].ID)
	if err != nil {
		t.Fatalf("GetFinding() error = %v", err)
	}
	got := make([]string, 0, len(detail.Occurrences))
	for _, occurrence := range detail.Occurrences {
		got = append(got, occurrence.Key)
	}
	want := slices.Clone(keys)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("occurrence order = %v, want source_location ASC %v", got, want)
	}
}

func TestSchemaVersionChecksRejectNewerLedger(t *testing.T) {
	db := openMigratedIntegrationDB(t)
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`INSERT INTO schema_migrations (version, name, sha256) VALUES ('0005', '0005_future', 'abc')`); err != nil {
		t.Fatalf("insert future ledger row: %v", err)
	}

	if err := checkSchemaVersion(context.Background(), db); err == nil || !strings.Contains(err.Error(), "0005") {
		t.Fatalf("checkSchemaVersion() error = %v, want the unexpected 0005 row named", err)
	}
	if _, err := NewPostgresStore(PostgresConfig{DatabaseURL: integrationDatabaseURL(t), RequireSchema: true}); err == nil {
		t.Fatal("NewPostgresStore(RequireSchema) error = nil with a newer ledger")
	}
	_, err := RunMigrations(context.Background(), MigrationConfig{DatabaseURL: integrationDatabaseURL(t), Directory: filepath.Join(repoRoot(t), "migrations")})
	if err == nil || !strings.Contains(err.Error(), "unknown migration version 0005") {
		t.Fatalf("RunMigrations() error = %v", err)
	}
	assertCount(t, db, "SELECT COUNT(*) FROM schema_migrations", 5)
}

// TestSchemaVersionChecksWrapLedgerReadErrors pins the message prefix of a
// ledger that cannot be read and of one whose versions are not the current
// sequence.
func TestSchemaVersionChecksWrapLedgerReadErrors(t *testing.T) {
	t.Run("unreadable ledger", func(t *testing.T) {
		db := openMigratedIntegrationDB(t)
		defer func() { _ = db.Close() }()
		if _, err := db.Exec(`ALTER TABLE schema_migrations RENAME COLUMN version TO renamed_version`); err != nil {
			t.Fatalf("rename ledger column: %v", err)
		}
		err := checkSchemaVersion(context.Background(), db)
		if err == nil || !strings.HasPrefix(err.Error(), "read database schema version: ") {
			t.Fatalf("checkSchemaVersion() error = %v", err)
		}
	})
	t.Run("missing ledger row", func(t *testing.T) {
		db := openMigratedIntegrationDB(t)
		defer func() { _ = db.Close() }()
		if _, err := db.Exec(`DELETE FROM schema_migrations WHERE version = '0002'`); err != nil {
			t.Fatalf("delete ledger row: %v", err)
		}
		err := checkSchemaVersion(context.Background(), db)
		if err == nil || !strings.HasPrefix(err.Error(), "database schema ledger has versions [0001 0003") || !strings.HasSuffix(err.Error(), "; run layerleak-migrate-up") {
			t.Fatalf("checkSchemaVersion() error = %v", err)
		}
	})
}

func TestRunMigrationsReadoptsAfterStorageHardeningRollback(t *testing.T) {
	db := openMigratedIntegrationDB(t)
	defer func() { _ = db.Close() }()
	if err := applyMigrationSet(t, db, "0004*.down.sql"); err != nil {
		t.Fatalf("applyMigrationSet(0004 down) error = %v", err)
	}
	if tableExists(t, db, "schema_migrations") {
		t.Fatal("0004 down should have dropped the ledger")
	}

	result, err := RunMigrations(context.Background(), MigrationConfig{DatabaseURL: integrationDatabaseURL(t), Directory: filepath.Join(repoRoot(t), "migrations")})
	if err != nil {
		t.Fatalf("RunMigrations() error = %v", err)
	}
	if !slices.Equal(result.Applied, []string{"0004_storage_hardening"}) {
		t.Fatalf("result.Applied = %v, want 0001-0003 re-adopted and only 0004 re-applied", result.Applied)
	}
	assertCount(t, db, "SELECT COUNT(*) FROM schema_migrations", currentMigrationCount)
	if err := checkSchemaVersion(context.Background(), db); err != nil {
		t.Fatalf("checkSchemaVersion() error = %v", err)
	}
}

func TestRunMigrationsReleasesAdvisoryLockWhenContextEndsWhileWaiting(t *testing.T) {
	db := openIntegrationDB(t)
	defer func() { _ = db.Close() }()
	holder, err := db.Conn(context.Background())
	if err != nil {
		t.Fatalf("db.Conn() error = %v", err)
	}
	defer func() { _ = holder.Close() }()
	if _, err := holder.ExecContext(context.Background(), `SELECT pg_advisory_lock($1)`, migrationAdvisoryKey); err != nil {
		t.Fatalf("hold migration lock: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	started := time.Now()
	_, err = RunMigrations(ctx, MigrationConfig{DatabaseURL: integrationDatabaseURL(t), Directory: filepath.Join(repoRoot(t), "migrations")})
	if err == nil || !strings.Contains(err.Error(), "acquire migration lock") {
		t.Fatalf("RunMigrations() error = %v after %s, want the lock acquisition to be cancelled", err, time.Since(started))
	}
	if time.Since(started) > 10*time.Second {
		t.Fatalf("RunMigrations() took %s to honour a 1s context", time.Since(started))
	}
	// Only the holder's lock remains; the cancelled waiter left nothing behind.
	deadline := time.Now().Add(5 * time.Second)
	for {
		var advisory int
		if err := db.QueryRow(`SELECT COUNT(*) FROM pg_locks WHERE locktype = 'advisory'`).Scan(&advisory); err != nil {
			t.Fatalf("count advisory locks: %v", err)
		}
		if advisory == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("advisory locks = %d, want only the holder's", advisory)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if tableExists(t, db, "schema_migrations") {
		t.Fatal("cancelled migration created the ledger")
	}

	if _, err := holder.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, migrationAdvisoryKey); err != nil {
		t.Fatalf("release migration lock: %v", err)
	}
	result, err := RunMigrations(context.Background(), MigrationConfig{DatabaseURL: integrationDatabaseURL(t), Directory: filepath.Join(repoRoot(t), "migrations")})
	if err != nil || len(result.Applied) != currentMigrationCount {
		t.Fatalf("RunMigrations(after release) = %+v, %v", result, err)
	}
	assertCount(t, db, "SELECT COUNT(*) FROM pg_locks WHERE locktype = 'advisory'", 0)
}

func TestRunMigrationsRejectsPartialStorageHardening(t *testing.T) {
	db := openIntegrationDB(t)
	defer func() { _ = db.Close() }()
	if err := applyMigrationSet(t, db, "000[1-3]*.up.sql"); err != nil {
		t.Fatalf("applyMigrationSet(0001-0003) error = %v", err)
	}
	// One 0004 constraint exists but the column, the other constraints and the
	// indexes do not: a hand-applied half of the hardening migration.
	if _, err := db.Exec(`ALTER TABLE repositories ADD CONSTRAINT repositories_registry_not_blank CHECK (btrim(registry) <> '')`); err != nil {
		t.Fatalf("add partial 0004 constraint: %v", err)
	}

	_, err := RunMigrations(context.Background(), MigrationConfig{DatabaseURL: integrationDatabaseURL(t), Directory: filepath.Join(repoRoot(t), "migrations")})
	if err == nil {
		t.Fatal("RunMigrations() error = nil for a partially hardened legacy schema")
	}
	if !strings.Contains(err.Error(), "legacy schema") || !strings.Contains(err.Error(), "partial_target_count") {
		t.Fatalf("RunMigrations() error = %v, want the partial 0004 state diagnosed", err)
	}
	if tableExists(t, db, "schema_migrations") {
		var rows int
		if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&rows); err != nil {
			t.Fatalf("count ledger rows: %v", err)
		}
		if rows != 0 {
			t.Fatalf("ledger has %d rows after a rejected adoption, want none", rows)
		}
	}
}
