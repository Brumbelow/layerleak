package api

import (
	"bytes"
	"context"
	"encoding/json"
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

	request := httptest.NewRequest(http.MethodPost, "/api/v1/scans", bytes.NewBufferString(`{"reference":"library/app:latest"}`))
	recorder := httptest.NewRecorder()

	NewHandler(scanner, &stubReadStore{}).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if scanner.request.Reference.Repository != "library/app" {
		t.Fatalf("scanner.request.Reference.Repository = %q", scanner.request.Reference.Repository)
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
	request := httptest.NewRequest(http.MethodPost, "/api/v1/scans", bytes.NewBufferString(`{"reference":"https://example.com/app"}`))
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

	request := httptest.NewRequest(http.MethodPost, "/api/v1/scans", bytes.NewBufferString(`{"reference":"library/app:latest"}`))
	recorder := httptest.NewRecorder()

	NewHandler(scanner, &stubReadStore{}).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"code": "scan_failed"`) {
		t.Fatalf("body = %s", recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"scan_run_id": 42`) {
		t.Fatalf("body = %s", recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"total_findings": 1`) {
		t.Fatalf("body = %s", recorder.Body.String())
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

	limit       int
	offset      int
	repository  string
	disposition storage.FindingDispositionFilter
	scanID      int64
	findingID   int64
}

func (s *stubReadStore) ListRepositories(_ context.Context, limit, offset int) ([]storage.RepositorySummary, error) {
	s.limit = limit
	s.offset = offset
	return s.repositories, nil
}

func (s *stubReadStore) ListRepositoryFindings(_ context.Context, repository string, disposition storage.FindingDispositionFilter, limit, offset int) ([]storage.FindingSummary, error) {
	s.repository = repository
	s.disposition = disposition
	s.limit = limit
	s.offset = offset
	return s.findings, nil
}

func (s *stubReadStore) ListRepositoryScans(_ context.Context, repository string, limit, offset int) ([]storage.ScanRunSummary, error) {
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
