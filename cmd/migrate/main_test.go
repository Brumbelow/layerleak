package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRunRequiresDatabaseURL(t *testing.T) {
	t.Setenv("LAYERLEAK_DATABASE_URL", "")
	oldArgs := os.Args
	os.Args = []string{"layerleak-migrate-up"}
	t.Cleanup(func() { os.Args = oldArgs })

	if err := run(); err == nil || !strings.Contains(err.Error(), "LAYERLEAK_DATABASE_URL") {
		t.Fatalf("run() error = %v", err)
	}
}

func TestRunRejectsArguments(t *testing.T) {
	oldArgs := os.Args
	os.Args = []string{"layerleak-migrate-up", "extra"}
	t.Cleanup(func() { os.Args = oldArgs })

	if err := run(); err == nil {
		t.Fatal("run() error = nil")
	}
}

func TestRunRejectsInvalidTimeoutsBeforeConnecting(t *testing.T) {
	oldArgs := os.Args
	os.Args = []string{"layerleak-migrate-up"}
	t.Cleanup(func() { os.Args = oldArgs })
	t.Setenv("LAYERLEAK_DATABASE_URL", "postgres://layerleak@127.0.0.1:1/layerleak?sslmode=disable")

	t.Setenv("LAYERLEAK_MIGRATION_TIMEOUT", "soon")
	if err := run(); err == nil || !strings.Contains(err.Error(), "LAYERLEAK_MIGRATION_TIMEOUT") {
		t.Fatalf("run() with invalid timeout error = %v", err)
	}

	t.Setenv("LAYERLEAK_MIGRATION_TIMEOUT", "")
	t.Setenv("LAYERLEAK_MIGRATION_LOCK_TIMEOUT", "-5s")
	if err := run(); err == nil || !strings.Contains(err.Error(), "LAYERLEAK_MIGRATION_LOCK_TIMEOUT") {
		t.Fatalf("run() with negative lock timeout error = %v", err)
	}
}

func TestDurationFromEnv(t *testing.T) {
	t.Setenv("LAYERLEAK_TEST_DURATION", "")
	if got, err := durationFromEnv("LAYERLEAK_TEST_DURATION", 30*time.Minute); err != nil || got != 30*time.Minute {
		t.Fatalf("unset = (%s, %v)", got, err)
	}
	t.Setenv("LAYERLEAK_TEST_DURATION", " 90s ")
	if got, err := durationFromEnv("LAYERLEAK_TEST_DURATION", time.Minute); err != nil || got != 90*time.Second {
		t.Fatalf("90s = (%s, %v)", got, err)
	}
	t.Setenv("LAYERLEAK_TEST_DURATION", "0")
	if got, err := durationFromEnv("LAYERLEAK_TEST_DURATION", time.Minute); err != nil || got != 0 {
		t.Fatalf("0 = (%s, %v)", got, err)
	}
	t.Setenv("LAYERLEAK_TEST_DURATION", "5 minutes")
	if _, err := durationFromEnv("LAYERLEAK_TEST_DURATION", time.Minute); err == nil || strings.Contains(err.Error(), "5 minutes") {
		t.Fatalf("invalid duration error = %v (must name the variable without echoing the value)", err)
	}
}

func TestMigrationContextAppliesDeadlineOnlyWhenPositive(t *testing.T) {
	ctx, cancel := migrationContext(context.Background(), 0)
	defer cancel()
	if _, ok := ctx.Deadline(); ok {
		t.Fatal("zero timeout set a deadline")
	}

	bounded, cancelBounded := migrationContext(context.Background(), 30*time.Minute)
	defer cancelBounded()
	deadline, ok := bounded.Deadline()
	if !ok || time.Until(deadline) > 30*time.Minute || time.Until(deadline) < 29*time.Minute {
		t.Fatalf("deadline = %v (ok=%t)", deadline, ok)
	}
}
