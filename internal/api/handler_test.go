package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/brumbelow/layerleak/internal/findings"
	"github.com/brumbelow/layerleak/internal/jobs"
	"github.com/brumbelow/layerleak/internal/limits"
	"github.com/brumbelow/layerleak/internal/manifest"
	"github.com/brumbelow/layerleak/internal/scanservice"
	"github.com/brumbelow/layerleak/internal/storage"
)

func TestHandleHealthReturnsOK(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/health", nil)
	recorder := httptest.NewRecorder()

	NewHandler(&stubScanner{}, &stubReadStore{}).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"status": "ok"`) {
		t.Fatalf("body = %s", recorder.Body.String())
	}
}

func TestHandleScanSuccess(t *testing.T) {
	scanner := &stubScanner{
		outcome: scanservice.Outcome{
			ScanRunID: 17,
			Result: jobs.Result{
				RequestedReference: "library/app:latest",
				Repository:         "library/app",
				ResolvedReference:  "docker.io/library/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				Findings: []findings.Finding{
					{
						DetectorName:   "github_token",
						Confidence:     "high",
						Disposition:    findings.DispositionActionable,
						SourceType:     findings.SourceTypeEnv,
						ManifestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
						RedactedValue:  "ghp********************************56",
						Fingerprint:    "fingerprint",
						ContextSnippet: "GH_TOKEN=ghp********************************56",
					},
				},
				TotalFindings:      1,
				UniqueFingerprints: 1,
			},
		},
	}

	request := newJSONScanRequest(`{"reference":"library/app:latest"}`)
	recorder := httptest.NewRecorder()

	NewHandler(scanner, &stubReadStore{}).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if scanner.request.Reference.Repository != "library/app" {
		t.Fatalf("scanner.request.Reference.Repository = %q", scanner.request.Reference.Repository)
	}
	if scanner.request.Logger == nil {
		t.Fatal("scanner.request.Logger = nil")
	}
	if strings.Contains(recorder.Body.String(), "ghp_123456789012345678901234567890123456") {
		t.Fatalf("response leaked raw secret: %s", recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"scan_run_id": 17`) {
		t.Fatalf("body = %s", recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"requested_reference": "library/app:latest"`) {
		t.Fatalf("body = %s", recorder.Body.String())
	}
}

func TestHandleScanRejectsInvalidReference(t *testing.T) {
	request := newJSONScanRequest(`{"reference":"https://example.com/app"}`)
	recorder := httptest.NewRecorder()

	NewHandler(&stubScanner{}, &stubReadStore{}).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"code": "invalid_request"`) {
		t.Fatalf("body = %s", recorder.Body.String())
	}
}

func TestHandleScanReturnsPartialResultOnLimitError(t *testing.T) {
	scanner := &stubScanner{
		outcome: scanservice.Outcome{
			ScanRunID: 42,
			Result: jobs.Result{
				RequestedReference: "library/app:latest",
				Repository:         "library/app",
				TotalFindings:      1,
			},
		},
		err: &scanservice.Error{
			Phase: scanservice.ErrorPhaseScan,
			Err:   limits.NewExceeded(limits.KindConfigBytes, 128, "config blob sha256:bbbb"),
		},
	}

	request := newJSONScanRequest(`{"reference":"library/app:latest"}`)
	recorder := httptest.NewRecorder()

	NewHandler(scanner, &stubReadStore{}).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"code": "scan_limit_exceeded"`) {
		t.Fatalf("body = %s", recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"scan_run_id": 42`) {
		t.Fatalf("body = %s", recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"total_findings": 1`) {
		t.Fatalf("body = %s", recorder.Body.String())
	}
}

func TestHandleScanAcceptsAllTagsForBareRepository(t *testing.T) {
	scanner := &stubScanner{}
	request := newJSONScanRequest(`{"reference":"library/app","all_tags":true}`)
	recorder := httptest.NewRecorder()

	NewHandler(scanner, &stubReadStore{}).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if !scanner.request.AllTags {
		t.Fatal("scanner.request.AllTags = false")
	}
}

func TestHandleScanRejectsAllTagsWithTaggedReference(t *testing.T) {
	request := newJSONScanRequest(`{"reference":"library/app:latest","all_tags":true}`)
	recorder := httptest.NewRecorder()

	NewHandler(&stubScanner{}, &stubReadStore{}).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestHandleScanRejectsUnsupportedContentType(t *testing.T) {
	request := newJSONScanRequest(`{"reference":"library/app:latest"}`)
	request.Header.Set("Content-Type", "text/plain")
	recorder := httptest.NewRecorder()

	NewHandler(&stubScanner{}, &stubReadStore{}).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestHandleScanRejectsOversizeBody(t *testing.T) {
	request := newJSONScanRequest(`{"reference":"library/app:latest"}`)
	recorder := httptest.NewRecorder()
	handler := NewHandlerWithOptions(&stubScanner{}, &stubReadStore{}, HandlerOptions{MaxRequestBytes: 16})

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"code": "request_too_large"`) {
		t.Fatalf("body = %s", recorder.Body.String())
	}
}

func TestHandleScanMapsIncompleteResult(t *testing.T) {
	var logs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	scanner := &stubScanner{
		outcome: scanservice.Outcome{Result: jobs.Result{RequestedReference: "library/app:latest"}},
		err: &scanservice.Error{Phase: scanservice.ErrorPhaseScan, Err: &jobs.IncompleteError{
			Status:                 jobs.ResultStatusPartial,
			CompletedManifestCount: 1,
			FailedManifestCount:    1,
			Cause:                  errors.New("Authorization: Bearer sentinel-secret"),
		}},
	}
	request := newJSONScanRequest(`{"reference":"library/app:latest"}`)
	recorder := httptest.NewRecorder()

	NewHandler(scanner, &stubReadStore{}).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"code": "scan_incomplete"`) {
		t.Fatalf("body = %s", recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "sentinel-secret") || strings.Contains(recorder.Body.String(), "Authorization") {
		t.Fatalf("body leaked incomplete cause: %s", recorder.Body.String())
	}
	if strings.Contains(logs.String(), "sentinel-secret") || strings.Contains(logs.String(), "Authorization") {
		t.Fatalf("logs leaked incomplete cause: %s", logs.String())
	}
}

func TestHandleScanEnforcesTimeout(t *testing.T) {
	request := newJSONScanRequest(`{"reference":"library/app:latest"}`)
	recorder := httptest.NewRecorder()
	handler := NewHandlerWithOptions(contextScanner{}, &stubReadStore{}, HandlerOptions{ScanTimeout: time.Millisecond})

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestHandleScanRejectsWhenConcurrencyIsExhausted(t *testing.T) {
	scanner := &blockingScanner{started: make(chan struct{}), release: make(chan struct{})}
	handler := NewHandlerWithOptions(scanner, &stubReadStore{}, HandlerOptions{MaxConcurrentScans: 1})
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		handler.ServeHTTP(httptest.NewRecorder(), newJSONScanRequest(`{"reference":"library/app:latest"}`))
	}()
	<-scanner.started

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, newJSONScanRequest(`{"reference":"library/app:latest"}`))
	close(scanner.release)
	<-firstDone

	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Retry-After") != "5" {
		t.Fatalf("Retry-After = %q", recorder.Header().Get("Retry-After"))
	}
}

func TestRequestIDIsReturnedInHeaderAndError(t *testing.T) {
	request := newJSONScanRequest(`{}`)
	request.Header.Set("X-Request-ID", "client-request-7")
	recorder := httptest.NewRecorder()

	NewHandler(&stubScanner{}, &stubReadStore{}).ServeHTTP(recorder, request)

	if recorder.Header().Get("X-Request-ID") != "client-request-7" {
		t.Fatalf("X-Request-ID = %q", recorder.Header().Get("X-Request-ID"))
	}
	if !strings.Contains(recorder.Body.String(), `"request_id": "client-request-7"`) {
		t.Fatalf("body = %s", recorder.Body.String())
	}
}

func TestReadyChecksStore(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	recorder := httptest.NewRecorder()

	NewHandler(&stubScanner{}, &stubReadStore{}).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"status": "ready"`) {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestReadyReturnsUnavailableWithoutDatabase(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	recorder := httptest.NewRecorder()

	NewHandler(&stubScanner{}, &stubReadStore{readyErr: context.DeadlineExceeded}).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestUnknownEndpointAndWrongMethodReturnJSONErrors(t *testing.T) {
	tests := []struct {
		method string
		path   string
		status int
	}{
		{method: http.MethodGet, path: "/missing", status: http.StatusNotFound},
		{method: http.MethodPut, path: "/api/v1/scans", status: http.StatusMethodNotAllowed},
	}
	for _, test := range tests {
		recorder := httptest.NewRecorder()
		NewHandler(&stubScanner{}, &stubReadStore{}).ServeHTTP(recorder, httptest.NewRequest(test.method, test.path, nil))
		if recorder.Code != test.status || !strings.Contains(recorder.Header().Get("Content-Type"), "application/json") {
			t.Fatalf("%s %s: status = %d content-type=%q body=%s", test.method, test.path, recorder.Code, recorder.Header().Get("Content-Type"), recorder.Body.String())
		}
	}
}

func TestHandleListRepositoriesUsesDefaultPagination(t *testing.T) {
	store := &stubReadStore{
		repositories: []storage.RepositorySummary{
			{
				Registry:    "docker.io",
				Repository:  "library/app",
				FirstSeenAt: time.Date(2026, time.March, 28, 14, 0, 0, 0, time.UTC),
				LastSeenAt:  time.Date(2026, time.March, 28, 15, 0, 0, 0, time.UTC),
			},
		},
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/repositories", nil)
	recorder := httptest.NewRecorder()

	NewHandler(&stubScanner{}, store).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if store.limit != 50 || store.offset != 0 {
		t.Fatalf("pagination = (%d,%d)", store.limit, store.offset)
	}
	if !strings.Contains(recorder.Body.String(), `"repository": "library/app"`) {
		t.Fatalf("body = %s", recorder.Body.String())
	}
}

func TestHandleListRepositoryFindingsSupportsDispositionFilter(t *testing.T) {
	store := &stubReadStore{
		findings: []storage.FindingSummary{
			{
				ID:                        42,
				ManifestDigest:            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				Fingerprint:               "fingerprint",
				RedactedValue:             "ghp********************************56",
				FirstSeenAt:               time.Date(2026, time.March, 28, 14, 0, 0, 0, time.UTC),
				LastSeenAt:                time.Date(2026, time.March, 28, 15, 0, 0, 0, time.UTC),
				OccurrenceCount:           3,
				ActionableOccurrenceCount: 0,
				SuppressedOccurrenceCount: 3,
				Detectors:                 []string{"github_token"},
			},
		},
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/repositories/library/app/findings?disposition=suppressed&limit=500&offset=2", nil)
	recorder := httptest.NewRecorder()

	NewHandler(&stubScanner{}, store).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if store.repository != "library/app" {
		t.Fatalf("store.repository = %q", store.repository)
	}
	if store.disposition != storage.FindingDispositionSuppressed {
		t.Fatalf("store.disposition = %q", store.disposition)
	}
	if store.limit != 200 || store.offset != 2 {
		t.Fatalf("pagination = (%d,%d)", store.limit, store.offset)
	}
	if !strings.Contains(recorder.Body.String(), `"disposition": "suppressed"`) {
		t.Fatalf("body = %s", recorder.Body.String())
	}
}

func TestHandleListRepositoryScansUsesPagination(t *testing.T) {
	store := &stubReadStore{
		scans: []storage.ScanRunSummary{
			{
				ID:                 8,
				RequestedReference: "library/app:latest",
				Mode:               "reference",
				Status:             storage.ScanRunStatusPartial,
				ErrorMessage:       "manifest scan incomplete",
				ScannedAt:          time.Date(2026, time.March, 28, 15, 0, 0, 0, time.UTC),
				TotalFindings:      1,
			},
		},
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/repositories/library/app/scans?limit=500&offset=3", nil)
	recorder := httptest.NewRecorder()

	NewHandler(&stubScanner{}, store).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if store.repository != "library/app" {
		t.Fatalf("store.repository = %q", store.repository)
	}
	if store.limit != 200 || store.offset != 3 {
		t.Fatalf("pagination = (%d,%d)", store.limit, store.offset)
	}
	if !strings.Contains(recorder.Body.String(), `"status": "partial"`) {
		t.Fatalf("body = %s", recorder.Body.String())
	}
}

func TestHandleListRepositoryScansForwardsRegistryQuery(t *testing.T) {
	store := &stubReadStore{}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/repositories/brumbelow/layerleak/scans?registry=ghcr.io", nil)
	recorder := httptest.NewRecorder()

	NewHandler(&stubScanner{}, store).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if store.registry != "ghcr.io" {
		t.Fatalf("store.registry = %q", store.registry)
	}
	if store.repository != "brumbelow/layerleak" {
		t.Fatalf("store.repository = %q", store.repository)
	}
}

func TestHandleListRepositoryFindingsForwardsRegistryQuery(t *testing.T) {
	store := &stubReadStore{}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/repositories/prometheus/busybox/findings?registry=quay.io", nil)
	recorder := httptest.NewRecorder()

	NewHandler(&stubScanner{}, store).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if store.registry != "quay.io" {
		t.Fatalf("store.registry = %q", store.registry)
	}
	if store.repository != "prometheus/busybox" {
		t.Fatalf("store.repository = %q", store.repository)
	}
}

func TestHandleGetScanReturnsDetail(t *testing.T) {
	store := &stubReadStore{
		scanDetail: storage.ScanRunDetail{
			ScanRunSummary: storage.ScanRunSummary{
				ID:                 11,
				RequestedReference: "library/app:latest",
				ResolvedReference:  "docker.io/library/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				Mode:               "reference",
				Status:             storage.ScanRunStatusCompleted,
				ScannedAt:          time.Date(2026, time.March, 28, 15, 0, 0, 0, time.UTC),
				TotalFindings:      1,
			},
			Registry:   "docker.io",
			Repository: "library/app",
			ResultJSON: json.RawMessage(`{"requested_reference":"library/app:latest","findings":[{"redacted_value":"ghp********************************56"}]}`),
		},
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/scans/11", nil)
	recorder := httptest.NewRecorder()

	NewHandler(&stubScanner{}, store).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if store.scanID != 11 {
		t.Fatalf("store.scanID = %d", store.scanID)
	}
	if !strings.Contains(recorder.Body.String(), `"repository": "library/app"`) {
		t.Fatalf("body = %s", recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "ghp_123456789012345678901234567890123456") {
		t.Fatalf("response leaked raw secret: %s", recorder.Body.String())
	}
}

func TestHandleGetFindingReturnsDetail(t *testing.T) {
	store := &stubReadStore{
		detail: storage.FindingDetail{
			FindingSummary: storage.FindingSummary{
				ID:                        7,
				ManifestDigest:            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				Fingerprint:               "fingerprint",
				RedactedValue:             "ghp********************************56",
				FirstSeenAt:               time.Date(2026, time.March, 28, 14, 0, 0, 0, time.UTC),
				LastSeenAt:                time.Date(2026, time.March, 28, 15, 0, 0, 0, time.UTC),
				OccurrenceCount:           1,
				ActionableOccurrenceCount: 1,
				SuppressedOccurrenceCount: 0,
				Detectors:                 []string{"github_token"},
			},
			Occurrences: []storage.FindingOccurrence{
				{
					DetectorName:        "github_token",
					Confidence:          "high",
					Disposition:         findings.DispositionActionable,
					SourceType:          findings.SourceTypeEnv,
					Platform:            manifest.Platform{OS: "linux", Architecture: "amd64"},
					Key:                 "GH_TOKEN",
					LineNumber:          3,
					ContextSnippet:      "GH_TOKEN=ghp********************************56",
					SourceLocation:      "env:GH_TOKEN",
					MatchStart:          9,
					MatchEnd:            49,
					PresentInFinalImage: true,
					FirstSeenAt:         time.Date(2026, time.March, 28, 14, 0, 0, 0, time.UTC),
					LastSeenAt:          time.Date(2026, time.March, 28, 15, 0, 0, 0, time.UTC),
				},
			},
		},
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/findings/7", nil)
	recorder := httptest.NewRecorder()

	NewHandler(&stubScanner{}, store).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if store.findingID != 7 {
		t.Fatalf("store.findingID = %d", store.findingID)
	}
	if !strings.Contains(recorder.Body.String(), `"detector_name": "github_token"`) {
		t.Fatalf("body = %s", recorder.Body.String())
	}
}

func TestHandleGetFindingReturnsNotFound(t *testing.T) {
	store := &stubReadStore{detailErr: storage.ErrNotFound}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/findings/999", nil)
	recorder := httptest.NewRecorder()

	NewHandler(&stubScanner{}, store).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"code": "not_found"`) {
		t.Fatalf("body = %s", recorder.Body.String())
	}
}

type stubScanner struct {
	outcome scanservice.Outcome
	err     error
	request scanservice.Request
}

type contextScanner struct{}

func (contextScanner) ScanAndSave(ctx context.Context, _ scanservice.Request) (scanservice.Outcome, error) {
	<-ctx.Done()
	return scanservice.Outcome{}, ctx.Err()
}

type blockingScanner struct {
	started chan struct{}
	release chan struct{}
}

func (s *blockingScanner) ScanAndSave(_ context.Context, _ scanservice.Request) (scanservice.Outcome, error) {
	close(s.started)
	<-s.release
	return scanservice.Outcome{}, nil
}

func (s *stubScanner) ScanAndSave(_ context.Context, request scanservice.Request) (scanservice.Outcome, error) {
	s.request = request
	return s.outcome, s.err
}

type stubReadStore struct {
	repositories  []storage.RepositorySummary
	scans         []storage.ScanRunSummary
	findings      []storage.FindingSummary
	scanDetail    storage.ScanRunDetail
	detail        storage.FindingDetail
	scanDetailErr error
	detailErr     error
	readyErr      error

	limit       int
	offset      int
	registry    string
	repository  string
	disposition storage.FindingDispositionFilter
	scanID      int64
	findingID   int64
}

func (s *stubReadStore) Ready(_ context.Context) error {
	return s.readyErr
}

func (s *stubReadStore) ListRepositories(_ context.Context, limit, offset int) ([]storage.RepositorySummary, error) {
	s.limit = limit
	s.offset = offset
	return s.repositories, nil
}

func (s *stubReadStore) ListRepositoryFindings(_ context.Context, registry, repository string, disposition storage.FindingDispositionFilter, limit, offset int) ([]storage.FindingSummary, error) {
	s.registry = registry
	s.repository = repository
	s.disposition = disposition
	s.limit = limit
	s.offset = offset
	return s.findings, nil
}

func (s *stubReadStore) ListRepositoryScans(_ context.Context, registry, repository string, limit, offset int) ([]storage.ScanRunSummary, error) {
	s.registry = registry
	s.repository = repository
	s.limit = limit
	s.offset = offset
	return s.scans, nil
}

func (s *stubReadStore) GetScanRun(_ context.Context, id int64) (storage.ScanRunDetail, error) {
	s.scanID = id
	if s.scanDetailErr != nil {
		return storage.ScanRunDetail{}, s.scanDetailErr
	}
	return s.scanDetail, nil
}

func (s *stubReadStore) GetFinding(_ context.Context, id int64) (storage.FindingDetail, error) {
	s.findingID = id
	if s.detailErr != nil {
		return storage.FindingDetail{}, s.detailErr
	}
	return s.detail, nil
}

func TestWriteJSONProducesValidJSON(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeJSON(recorder, http.StatusOK, map[string]string{"status": "ok"})

	var body map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("body = %#v", body)
	}
}

func TestSanitizeResultJSONRemovesNestedOperationalErrors(t *testing.T) {
	body, err := sanitizeResultJSON([]byte(`{
		"error_message":"upstream body contained token=secret",
		"large_counter":9007199254740993,
		"targets":[{"error":"dial registry.internal:5000"}],
		"diagnostics":[{"code":"upstream_failed","message":"Authorization: Bearer secret"}]
	}`))
	if err != nil {
		t.Fatalf("sanitizeResultJSON() error = %v", err)
	}
	if strings.Contains(string(body), "secret") || strings.Contains(string(body), "registry.internal") {
		t.Fatalf("body leaked operational detail: %s", body)
	}
	if !strings.Contains(string(body), `"message":"scan step failed"`) {
		t.Fatalf("body = %s", body)
	}
	if !strings.Contains(string(body), `"large_counter":9007199254740993`) {
		t.Fatalf("body lost integer precision: %s", body)
	}
}

func TestSanitizeResultJSONPreservesSafeRawFindingLimitMessage(t *testing.T) {
	body, err := sanitizeResultJSON([]byte(`{
		"diagnostics":[{
			"code":"max_raw_finding_bytes_exceeded",
			"message":"raw context contained secret"
		}]
	}`))
	if err != nil {
		t.Fatalf("sanitizeResultJSON() error = %v", err)
	}
	if strings.Contains(string(body), "secret") {
		t.Fatalf("body leaked operational detail: %s", body)
	}
	if !strings.Contains(string(body), `"message":"the scan exceeded the configured raw finding byte limit"`) {
		t.Fatalf("body = %s", body)
	}
}

func newJSONScanRequest(body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/scans", bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	return request
}
