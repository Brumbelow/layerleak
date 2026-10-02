package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/version"
)

// TestHealthEndpointsReportVersion pins API-20: /health, /livez and a ready
// /readyz carry the build version so operators can ask a running instance
// which build it is.
func TestHealthEndpointsReportVersion(t *testing.T) {
	tests := []struct {
		path   string
		status string
	}{
		{path: "/health", status: "ok"},
		{path: "/livez", status: "ok"},
		{path: "/readyz", status: "ready"},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			NewHandler(&stubScanner{}, &stubReadStore{}).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, test.path, nil))

			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
			}
			var body map[string]string
			if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if body["status"] != test.status {
				t.Fatalf("status field = %q", body["status"])
			}
			if body["version"] == "" || body["version"] != version.Effective() {
				t.Fatalf("version = %q, want %q", body["version"], version.Effective())
			}
			if len(body) != 2 {
				t.Fatalf("unexpected fields: %v", body)
			}
		})
	}
}

// countingReadyStore counts readiness checks so the cache can be observed.
type countingReadyStore struct {
	*stubReadStore
	readyCalls int
}

func (s *countingReadyStore) Ready(ctx context.Context) error {
	s.readyCalls++
	return s.stubReadStore.Ready(ctx)
}

func probeReadiness(handler http.Handler) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	return recorder
}

// TestReadinessResultIsCachedForTTL pins API-10: within the TTL, probes reuse
// the last schema-contract validation instead of hitting pg_catalog again,
// and the cache holds failures as well as successes.
func TestReadinessResultIsCachedForTTL(t *testing.T) {
	store := &countingReadyStore{stubReadStore: &stubReadStore{}}
	handler := NewHandlerWithOptions(&stubScanner{}, store, HandlerOptions{ReadinessCacheTTL: time.Hour})

	for i := 0; i < 3; i++ {
		if recorder := probeReadiness(handler); recorder.Code != http.StatusOK {
			t.Fatalf("probe %d: status = %d body=%s", i, recorder.Code, recorder.Body.String())
		}
	}
	if store.readyCalls != 1 {
		t.Fatalf("readyCalls = %d, want 1", store.readyCalls)
	}

	store.readyErr = errors.New("synthetic outage")
	if recorder := probeReadiness(handler); recorder.Code != http.StatusOK {
		t.Fatalf("cached success not reused: status = %d", recorder.Code)
	}

	failing := &countingReadyStore{stubReadStore: &stubReadStore{readyErr: errors.New("synthetic outage")}}
	handler = NewHandlerWithOptions(&stubScanner{}, failing, HandlerOptions{ReadinessCacheTTL: time.Hour})
	if recorder := probeReadiness(handler); recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d", recorder.Code)
	}
	failing.readyErr = nil
	if recorder := probeReadiness(handler); recorder.Code != http.StatusServiceUnavailable || failing.readyCalls != 1 {
		t.Fatalf("cached failure not reused: status = %d calls = %d", recorder.Code, failing.readyCalls)
	}
}

// TestReadinessCacheCanBeDisabled: a zero TTL checks the store on every probe.
func TestReadinessCacheCanBeDisabled(t *testing.T) {
	store := &countingReadyStore{stubReadStore: &stubReadStore{}}
	handler := NewHandlerWithOptions(&stubScanner{}, store, HandlerOptions{ReadinessCacheTTL: 0})

	for i := 0; i < 3; i++ {
		probeReadiness(handler)
	}
	if store.readyCalls != 3 {
		t.Fatalf("readyCalls = %d, want 3", store.readyCalls)
	}
}

// TestReadinessCacheExpires: after the TTL the store is consulted again.
func TestReadinessCacheExpires(t *testing.T) {
	store := &countingReadyStore{stubReadStore: &stubReadStore{}}
	handler := NewHandlerWithOptions(&stubScanner{}, store, HandlerOptions{ReadinessCacheTTL: 20 * time.Millisecond})

	probeReadiness(handler)
	time.Sleep(40 * time.Millisecond)
	probeReadiness(handler)
	if store.readyCalls != 2 {
		t.Fatalf("readyCalls = %d, want 2", store.readyCalls)
	}
}

// TestReadinessWithoutCheckerIsUnavailable: a store without Ready() reports
// 503 not_ready rather than pretending to be ready.
func TestReadinessWithoutCheckerIsUnavailable(t *testing.T) {
	recorder := probeReadiness(NewHandler(&stubScanner{}, &readStoreWithoutReady{stubReadStore: &stubReadStore{}}))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	var body map[string]map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil || body["error"]["code"] != "not_ready" {
		t.Fatalf("body = %s (%v)", recorder.Body.String(), err)
	}
}

// readStoreWithoutReady hides the embedded Ready method.
type readStoreWithoutReady struct {
	*stubReadStore
}

func (readStoreWithoutReady) Ready() {}
