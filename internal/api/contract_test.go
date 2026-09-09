package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/brumbelow/layerleak/internal/findings"
	"github.com/brumbelow/layerleak/internal/jobs"
	"github.com/brumbelow/layerleak/internal/scanner"
	"github.com/brumbelow/layerleak/internal/scanservice"
)

func TestDocumentedScanResponsesMatchHandler(t *testing.T) {
	tests := []struct {
		name       string
		fixture    string
		outcome    scanservice.Outcome
		err        error
		wantStatus int
	}{
		{
			name:       "completed",
			fixture:    "scan-completed.json",
			outcome:    scanservice.Outcome{ScanRunID: 41, Result: contractResult(jobs.ResultStatusCompleted)},
			wantStatus: http.StatusOK,
		},
		{
			name:    "partial",
			fixture: "scan-partial.json",
			outcome: scanservice.Outcome{ScanRunID: 42, Result: contractResult(jobs.ResultStatusPartial)},
			err: &scanservice.Error{Phase: scanservice.ErrorPhaseScan, Err: &jobs.IncompleteError{
				Status:                 jobs.ResultStatusPartial,
				CompletedManifestCount: 0,
				FailedManifestCount:    1,
			}},
			wantStatus: http.StatusUnprocessableEntity,
		},
		{
			name:       "failed",
			fixture:    "scan-failed.json",
			outcome:    scanservice.Outcome{Result: contractResult(jobs.ResultStatusFailed)},
			err:        &scanservice.Error{Phase: scanservice.ErrorPhaseScan, Err: errors.New("synthetic upstream detail")},
			wantStatus: http.StatusBadGateway,
		},
		{
			name:       "storage error",
			fixture:    "scan-storage-error.json",
			outcome:    scanservice.Outcome{Result: contractResult(jobs.ResultStatusCompleted)},
			err:        &scanservice.Error{Phase: scanservice.ErrorPhaseSave, Err: errors.New("synthetic storage detail")},
			wantStatus: http.StatusServiceUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := newJSONScanRequest(`{"reference":"library/example:latest","platform":"linux/amd64"}`)
			request.Header.Set("X-Request-ID", "contract-"+tt.fixture[:len(tt.fixture)-len(".json")])
			recorder := httptest.NewRecorder()
			handler := NewHandler(&stubScanner{outcome: tt.outcome, err: tt.err}, &stubReadStore{})

			handler.ServeHTTP(recorder, request)

			if recorder.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", recorder.Code, tt.wantStatus, recorder.Body.String())
			}
			assertContractFixture(t, tt.fixture, recorder.Body.Bytes())
		})
	}
}

const contractDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func contractResult(status jobs.ResultStatus) jobs.Result {
	target := contractTargetResult(status)
	result := jobs.Result{
		ResultSchemaVersion:    1,
		Status:                 status,
		RequestedReference:     "library/example:latest",
		Repository:             "library/example",
		Mode:                   "reference",
		ResolvedReference:      "docker.io/library/example@" + contractDigest,
		RequestedDigest:        contractDigest,
		TargetCount:            1,
		ManifestCount:          target.ManifestCount,
		CompletedManifestCount: target.CompletedManifestCount,
		FailedManifestCount:    target.FailedManifestCount,
		Targets:                []jobs.TargetResult{target},
		Findings:               []findings.Finding{},
		Coverage:               contractCoverage(status),
	}
	switch status {
	case jobs.ResultStatusCompleted:
		result.CompletedTargetCount = 1
	case jobs.ResultStatusPartial:
		result.PartialTargetCount = 1
	case jobs.ResultStatusFailed:
		result.FailedTargetCount = 1
	}
	if status != jobs.ResultStatusFailed {
		result.Findings = []findings.Finding{contractFinding()}
		result.TotalFindings = 1
		result.UniqueFingerprints = 1
	}
	if !result.Coverage.Complete {
		result.Diagnostics = []scanner.Diagnostic{{
			Code:    "manifest_scan_failed",
			Scope:   "manifest",
			Subject: contractDigest,
			Message: "one selected manifest could not be scanned",
		}}
	}
	return result
}

func contractTargetResult(status jobs.ResultStatus) jobs.TargetResult {
	target := jobs.TargetResult{
		Status:              status,
		Reference:           "docker.io/library/example@" + contractDigest,
		ResolvedReference:   "docker.io/library/example@" + contractDigest,
		RequestedDigest:     contractDigest,
		ManifestCount:       1,
		FailedManifestCount: 1,
		FindingsCount:       1,
	}
	switch status {
	case jobs.ResultStatusCompleted:
		target.CompletedManifestCount = 1
		target.FailedManifestCount = 0
	case jobs.ResultStatusPartial:
		target.ManifestCount = 2
		target.CompletedManifestCount = 1
	case jobs.ResultStatusFailed:
		target.FindingsCount = 0
	}
	return target
}

func contractCoverage(status jobs.ResultStatus) scanner.Coverage {
	coverage := scanner.Coverage{
		Complete:                  status == jobs.ResultStatusCompleted,
		LayersSeen:                1,
		FilesSeen:                 2,
		MetadataValuesScanned:     1,
		ExpandedLayerBytes:        128,
		RetainedBytes:             64,
		DetectorInputBytesScanned: 32,
	}
	switch status {
	case jobs.ResultStatusCompleted:
		coverage.LayersCompleted = 1
		coverage.FilesScanned = 2
	case jobs.ResultStatusPartial:
		coverage.LayersSeen = 2
		coverage.LayersCompleted = 1
		coverage.FilesScanned = 1
	}
	return coverage
}

func contractFinding() findings.Finding {
	return findings.Finding{
		DetectorName:        "github_token",
		Confidence:          "high",
		Disposition:         findings.DispositionActionable,
		SourceType:          findings.SourceTypeEnv,
		ManifestDigest:      contractDigest,
		RedactedValue:       "ghp********************************56",
		Fingerprint:         "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ContextSnippet:      "GH_TOKEN=ghp********************************56",
		MatchStart:          9,
		MatchEnd:            49,
		PresentInFinalImage: true,
	}
}

func assertContractFixture(t *testing.T, name string, actual []byte) {
	t.Helper()
	path := filepath.Join("..", "..", "web", "testdata", "api", name)
	if os.Getenv("LAYERLEAK_UPDATE_CONTRACT_FIXTURES") == "1" {
		var value any
		if err := json.Unmarshal(actual, &value); err != nil {
			t.Fatalf("decode handler response: %v", err)
		}
		body, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			t.Fatalf("format handler response: %v", err)
		}
		body = append(body, '\n')
		if err := os.WriteFile(path, body, 0o644); err != nil {
			t.Fatalf("write contract fixture: %v", err)
		}
		return
	}

	expected, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read contract fixture: %v", err)
	}
	var actualValue, expectedValue any
	if err := json.Unmarshal(actual, &actualValue); err != nil {
		t.Fatalf("decode handler response: %v", err)
	}
	if err := json.Unmarshal(expected, &expectedValue); err != nil {
		t.Fatalf("decode contract fixture: %v", err)
	}
	if !jsonValuesEqual(actualValue, expectedValue) {
		t.Fatalf("handler response does not match %s; regenerate with LAYERLEAK_UPDATE_CONTRACT_FIXTURES=1", path)
	}
}

func jsonValuesEqual(left, right any) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftJSON) == string(rightJSON)
}
