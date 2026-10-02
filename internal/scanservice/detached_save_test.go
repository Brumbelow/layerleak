package scanservice

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/jobs"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
	"github.com/brumbelow/layerleak/v3/internal/storage"
)

// contextObservingStore records the context SaveScan was handed so tests can
// prove the persistence phase is detached from the caller's cancellation.
type contextObservingStore struct {
	calls       int
	ctxErr      error
	hasDeadline bool
	deadlineIn  time.Duration
	records     []storage.ScanRecord
}

func (s *contextObservingStore) SaveScan(ctx context.Context, record storage.ScanRecord) (int64, error) {
	s.calls++
	s.ctxErr = ctx.Err()
	deadline, ok := ctx.Deadline()
	s.hasDeadline = ok
	if ok {
		s.deadlineIn = time.Until(deadline)
	}
	s.records = append(s.records, record)
	return 7, nil
}

func (s *contextObservingStore) Name() string { return "context-observing" }

// TestScanAndSavePersistsCompletedScanAfterCallerCancels is the DB-19/API-23
// regression test: the HTTP client disconnecting (or the scan deadline
// expiring) between scan completion and SaveScan used to cancel the write and
// discard the finished scan.
func TestScanAndSavePersistsCompletedScanAfterCallerCancels(t *testing.T) {
	store := &contextObservingStore{}
	service := outcomeTestService(t, store, jobs.ResultStatusCompleted)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reference, err := manifest.ParseReference("library/app:latest")
	if err != nil {
		t.Fatalf("ParseReference() error = %v", err)
	}

	outcome, err := service.ScanAndSave(ctx, Request{
		Reference: reference,
		BeforeSave: func(jobs.Result) error {
			cancel()
			return nil
		},
	})
	if err != nil {
		t.Fatalf("ScanAndSave() error = %v", err)
	}
	if outcome.ScanError != nil || outcome.SaveError != nil {
		t.Fatalf("outcome errors: scan=%v save=%v", outcome.ScanError, outcome.SaveError)
	}
	if outcome.ScanRunID != 7 || store.calls != 1 || len(store.records) != 1 {
		t.Fatalf("completed scan was not persisted: outcome=%+v calls=%d", outcome, store.calls)
	}
	if store.ctxErr != nil {
		t.Fatalf("SaveScan received an already-cancelled context: %v", store.ctxErr)
	}
	if !store.hasDeadline || store.deadlineIn <= 0 || store.deadlineIn > storage.DefaultWriteTimeout {
		t.Fatalf("save context deadline = %v (has=%t), want within (0, %v]", store.deadlineIn, store.hasDeadline, storage.DefaultWriteTimeout)
	}
	if store.records[0].Status != storage.ScanRunStatusCompleted {
		t.Fatalf("persisted status = %q", store.records[0].Status)
	}
}

func TestScanAndSaveBoundsDetachedSaveByConfiguredWriteTimeout(t *testing.T) {
	store := &contextObservingStore{}
	service := outcomeTestService(t, store, jobs.ResultStatusCompleted)
	service.config.DatabaseWriteTimeout = 3 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reference, err := manifest.ParseReference("library/app:latest")
	if err != nil {
		t.Fatalf("ParseReference() error = %v", err)
	}

	// The scan itself ran to completion before the cancellation is observed
	// (the fixture serves everything from memory), so the result is kept.
	completedCtx, completedCancel := context.WithCancel(context.Background())
	defer completedCancel()
	_, err = service.ScanAndSave(completedCtx, Request{
		Reference:  reference,
		BeforeSave: func(jobs.Result) error { completedCancel(); return nil },
	})
	if err != nil {
		t.Fatalf("ScanAndSave() error = %v", err)
	}
	if store.calls != 1 || store.ctxErr != nil {
		t.Fatalf("SaveScan calls=%d ctxErr=%v", store.calls, store.ctxErr)
	}
	if !store.hasDeadline || store.deadlineIn <= 0 || store.deadlineIn > 3*time.Second {
		t.Fatalf("save deadline = %v, want within (0, 3s]", store.deadlineIn)
	}

	// A context that ended while the scan was still running keeps today's
	// behaviour: the interrupted scan is reported and nothing is persisted.
	_, err = service.ScanAndSave(ctx, Request{Reference: reference})
	if !errors.Is(err, context.Canceled) || IsSaveError(err) {
		t.Fatalf("interrupted scan error = %v", err)
	}
	if store.calls != 1 {
		t.Fatalf("interrupted scan was persisted: calls=%d", store.calls)
	}
}
