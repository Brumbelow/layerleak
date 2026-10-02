package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/storage"
)

// TestPurgeFailureMessages pins both failure texts: the deadline variant names
// the timeout variable only when the run deadline expired and a timeout is
// set, and both keep the cause wrapped.
func TestPurgeFailureMessages(t *testing.T) {
	cause := errors.New("batch failed")
	counts := storage.RawSecretCounts{FindingValues: 3, OccurrenceSnippets: 4}

	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	err := purgeFailure(expired, cause, 30*time.Minute, counts)
	want := "batch failed (LAYERLEAK_PURGE_TIMEOUT=30m0s elapsed after clearing 3 finding value(s) and 4 occurrence snippet(s); completed batches stay purged, rerun to continue)"
	if err.Error() != want || !errors.Is(err, cause) {
		t.Fatalf("deadline failure = %v, want %q", err, want)
	}

	generic := "batch failed (cleared 3 finding value(s) and 4 occurrence snippet(s) before stopping; completed batches stay purged)"
	canceled, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	for name, ctx := range map[string]context.Context{"live": context.Background(), "canceled": canceled, "expired without timeout": expired} {
		timeout := 30 * time.Minute
		if name == "expired without timeout" {
			timeout = 0
		}
		if err := purgeFailure(ctx, cause, timeout, counts); err.Error() != generic || !errors.Is(err, cause) {
			t.Errorf("%s: failure = %v, want %q", name, err, generic)
		}
	}
}
