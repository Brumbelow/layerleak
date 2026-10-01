package storage

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/lib/pq"
)

func TestMigrationConfigDefaults(t *testing.T) {
	config := (MigrationConfig{}).withDefaults()
	if config.LockTimeout != 15*time.Second || config.LockAttempts != 3 {
		t.Fatalf("defaults = (%s, %d)", config.LockTimeout, config.LockAttempts)
	}
	custom := (MigrationConfig{LockTimeout: time.Second, LockAttempts: 1}).withDefaults()
	if custom.LockTimeout != time.Second || custom.LockAttempts != 1 {
		t.Fatalf("custom = (%s, %d)", custom.LockTimeout, custom.LockAttempts)
	}
}

func TestLockTimeoutStatementUsesIntegerMilliseconds(t *testing.T) {
	tests := []struct {
		timeout time.Duration
		want    string
	}{
		{timeout: 15 * time.Second, want: "SET LOCAL lock_timeout = '15000ms'"},
		{timeout: 200 * time.Millisecond, want: "SET LOCAL lock_timeout = '200ms'"},
		{timeout: 1500 * time.Microsecond, want: "SET LOCAL lock_timeout = '1ms'"},
		{timeout: time.Microsecond, want: "SET LOCAL lock_timeout = '1ms'"},
	}
	for _, tt := range tests {
		if got := lockTimeoutStatement(tt.timeout); got != tt.want {
			t.Fatalf("lockTimeoutStatement(%s) = %q, want %q", tt.timeout, got, tt.want)
		}
	}
}

func TestIsLockNotAvailable(t *testing.T) {
	lockTimeout := &pq.Error{Code: lockNotAvailableSQLState, Message: "canceling statement due to lock timeout"}
	if !isLockNotAvailable(lockTimeout) || !isLockNotAvailable(fmt.Errorf("apply: %w", lockTimeout)) {
		t.Fatal("isLockNotAvailable() = false for SQLSTATE 55P03")
	}
	if isLockNotAvailable(&pq.Error{Code: "57014"}) || isLockNotAvailable(errors.New("boom")) || isLockNotAvailable(nil) {
		t.Fatal("isLockNotAvailable() = true for a non-lock error")
	}
}
