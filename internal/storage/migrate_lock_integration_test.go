package storage

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// holdAccessShareLock opens a second session that holds an ACCESS SHARE lock on
// finding_occurrences inside an idle transaction, which is exactly what a live
// v2.5.0 API replica does between statements. It returns a release function.
func holdAccessShareLock(t *testing.T) func() {
	t.Helper()
	holder, err := sql.Open("postgres", integrationDatabaseURL(t))
	if err != nil {
		t.Fatalf("sql.Open(holder) error = %v", err)
	}
	tx, err := holder.Begin()
	if err != nil {
		t.Fatalf("holder.Begin() error = %v", err)
	}
	if _, err := tx.Exec(`SELECT COUNT(*) FROM finding_occurrences`); err != nil {
		t.Fatalf("holder select error = %v", err)
	}
	var once sync.Once
	release := func() {
		once.Do(func() {
			_ = tx.Rollback()
			_ = holder.Close()
		})
	}
	t.Cleanup(release)
	return release
}

// TestRunMigrationsFailsFastWhenMigrationLockIsHeld is the DB-03 regression
// test: with no lock_timeout, 0004's ALTER TABLE ... ADD CONSTRAINT queued
// behind the idle reader forever (and every later reader queued behind it),
// returning only when the caller's context expired.
func TestRunMigrationsFailsFastWhenMigrationLockIsHeld(t *testing.T) {
	db := openIntegrationDB(t)
	defer func() { _ = db.Close() }()
	if err := applyMigrationSet(t, db, "000[1-3]*.up.sql"); err != nil {
		t.Fatalf("applyMigrationSet(0001-0003) error = %v", err)
	}
	release := holdAccessShareLock(t)

	var messages []string
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	started := time.Now()
	_, err := RunMigrations(ctx, MigrationConfig{
		DatabaseURL:  integrationDatabaseURL(t),
		Directory:    filepath.Join(repoRoot(t), "migrations"),
		LockTimeout:  200 * time.Millisecond,
		LockAttempts: 2,
		Progress:     func(message string) { messages = append(messages, message) },
	})
	elapsed := time.Since(started)
	if err == nil {
		t.Fatal("RunMigrations() error = nil while another session held finding_occurrences")
	}
	if !strings.Contains(err.Error(), "0004_storage_hardening") || !strings.Contains(err.Error(), "lock") {
		t.Fatalf("RunMigrations() error = %v, want a lock timeout on 0004", err)
	}
	if ctx.Err() != nil || elapsed > 10*time.Second {
		t.Fatalf("RunMigrations() took %s and ended with ctx error %v; want a bounded lock timeout, not the caller's deadline", elapsed, ctx.Err())
	}
	if len(messages) == 0 || !strings.Contains(strings.Join(messages, "\n"), "waiting") {
		t.Fatalf("progress messages = %q, want a waiting-for-lock notice", messages)
	}

	// The adoption of 0001-0003 committed; 0004 rolled back cleanly and the
	// advisory lock was released.
	assertCount(t, db, "SELECT COUNT(*) FROM schema_migrations", 3)
	assertCount(t, db, "SELECT COUNT(*) FROM pg_locks WHERE locktype = 'advisory'", 0)

	release()
	result, err := RunMigrations(context.Background(), MigrationConfig{
		DatabaseURL: integrationDatabaseURL(t),
		Directory:   filepath.Join(repoRoot(t), "migrations"),
	})
	if err != nil {
		t.Fatalf("RunMigrations(after release) error = %v", err)
	}
	if len(result.Applied) != 1 || result.Applied[0] != "0004_storage_hardening" {
		t.Fatalf("result.Applied = %v", result.Applied)
	}
}

func TestRunMigrationsRetriesAfterLockTimeoutAndSucceedsOnceLockIsReleased(t *testing.T) {
	db := openIntegrationDB(t)
	defer func() { _ = db.Close() }()
	if err := applyMigrationSet(t, db, "000[1-3]*.up.sql"); err != nil {
		t.Fatalf("applyMigrationSet(0001-0003) error = %v", err)
	}
	release := holdAccessShareLock(t)

	var messages []string
	result, err := RunMigrations(context.Background(), MigrationConfig{
		DatabaseURL:  integrationDatabaseURL(t),
		Directory:    filepath.Join(repoRoot(t), "migrations"),
		LockTimeout:  200 * time.Millisecond,
		LockAttempts: 3,
		Progress: func(message string) {
			messages = append(messages, message)
			if strings.Contains(message, "waiting") {
				release()
			}
		},
	})
	if err != nil {
		t.Fatalf("RunMigrations() error = %v (messages %q)", err, messages)
	}
	if len(result.Applied) != 1 || result.Applied[0] != "0004_storage_hardening" || result.Current != CurrentSchemaVersion {
		t.Fatalf("result = %+v", result)
	}
	joined := strings.Join(messages, "\n")
	if !strings.Contains(joined, "waiting") || !strings.Contains(joined, "attempt 1 of 3") {
		t.Fatalf("progress messages = %q", messages)
	}
	assertCount(t, db, "SELECT COUNT(*) FROM schema_migrations", 4)
	assertCount(t, db, "SELECT COUNT(*) FROM pg_locks WHERE locktype = 'advisory'", 0)
	if err := checkSchemaVersion(context.Background(), db); err != nil {
		t.Fatalf("checkSchemaVersion() error = %v", err)
	}
}
