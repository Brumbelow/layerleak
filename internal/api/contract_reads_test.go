package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/findings"
	"github.com/brumbelow/layerleak/v3/internal/jobs"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
	"github.com/brumbelow/layerleak/v3/internal/storage"
)

// TestDocumentedReadResponsesMatchHandler pins the read endpoints to the
// example documents referenced from web/docs/openapi.yaml, which
// scripts/validate_docs.py validates against the response schemas. Together
// they keep ScanSummary, FindingSummary and the detail shapes honest.
// Regenerate with LAYERLEAK_UPDATE_CONTRACT_FIXTURES=1.
func TestDocumentedReadResponsesMatchHandler(t *testing.T) {
	store := contractReadStore()
	tests := []struct {
		name    string
		fixture string
		target  string
	}{
		{name: "repositories", fixture: "repositories.json", target: "/api/v1/repositories?limit=2"},
		{name: "repository scans", fixture: "repository-scans.json", target: "/api/v1/repositories/library/example/scans?registry=Index.Docker.io&limit=2"},
		{name: "repository findings", fixture: "repository-findings.json", target: "/api/v1/repositories/library/example/findings?disposition=all"},
		{name: "scan detail", fixture: "scan-detail.json", target: "/api/v1/scans/41"},
		{name: "finding detail", fixture: "finding-detail.json", target: "/api/v1/findings/7"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, tt.target, nil)
			request.Header.Set("X-Request-ID", "contract-"+tt.fixture[:len(tt.fixture)-len(".json")])
			recorder := httptest.NewRecorder()
			NewHandler(&stubScanner{}, store).ServeHTTP(recorder, request)

			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
			}
			assertContractFixture(t, tt.fixture, recorder.Body.Bytes())
		})
	}
}

func contractReadStore() *stubReadStore {
	firstSeen := time.Date(2026, time.September, 1, 8, 0, 0, 0, time.UTC)
	lastSeen := time.Date(2026, time.September, 30, 17, 30, 0, 0, time.UTC)
	completed := storage.ScanRunSummary{
		ID:                     41,
		RequestedReference:     "library/example:latest",
		ResolvedReference:      "docker.io/library/example@" + contractDigest,
		RequestedDigest:        contractDigest,
		Mode:                   "reference",
		Status:                 storage.ScanRunStatus(jobs.ResultStatusCompleted),
		ScannedAt:              lastSeen,
		TargetCount:            1,
		CompletedTargetCount:   1,
		ManifestCount:          1,
		CompletedManifestCount: 1,
		TotalFindings:          1,
		UniqueFingerprints:     1,
	}
	failedSweep := storage.ScanRunSummary{
		ID:                  40,
		RequestedReference:  "library/example",
		Mode:                "repository",
		Status:              storage.ScanRunStatus(jobs.ResultStatusFailed),
		ErrorMessage:        "stored operational detail that the API never returns",
		ScannedAt:           firstSeen,
		TagsEnumerated:      3,
		TagsResolved:        2,
		TagsFailed:          1,
		TargetCount:         2,
		FailedTargetCount:   2,
		ManifestCount:       2,
		FailedManifestCount: 2,
	}
	finding := storage.FindingSummary{
		ID:                        7,
		ManifestDigest:            contractDigest,
		Fingerprint:               "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		RedactedValue:             "ghp********************************56",
		FirstSeenAt:               firstSeen,
		LastSeenAt:                lastSeen,
		OccurrenceCount:           2,
		ActionableOccurrenceCount: 1,
		SuppressedOccurrenceCount: 1,
		Detectors:                 []string{"github_token"},
	}
	resultJSON, _ := json.Marshal(contractResult(jobs.ResultStatusCompleted))
	return &stubReadStore{
		repositories: []storage.RepositorySummary{
			{Registry: "docker.io", Repository: "library/example", FirstSeenAt: firstSeen, LastSeenAt: lastSeen},
			{Registry: "ghcr.io", Repository: "brumbelow/layerleak", FirstSeenAt: firstSeen, LastSeenAt: firstSeen},
		},
		scans:    []storage.ScanRunSummary{completed, failedSweep},
		findings: []storage.FindingSummary{finding},
		scanDetail: storage.ScanRunDetail{
			ScanRunSummary: completed,
			Registry:       "docker.io",
			Repository:     "library/example",
			ResultJSON:     resultJSON,
		},
		detail: storage.FindingDetail{
			FindingSummary: finding,
			Occurrences: []storage.FindingOccurrence{
				{
					DetectorName:        "github_token",
					Confidence:          "high",
					Disposition:         findings.DispositionActionable,
					SourceType:          findings.SourceTypeEnv,
					Platform:            manifest.Platform{OS: "linux", Architecture: "amd64"},
					Key:                 "GH_TOKEN",
					ContextSnippet:      "GH_TOKEN=ghp********************************56",
					SourceLocation:      "config.env[GH_TOKEN]",
					MatchStart:          9,
					MatchEnd:            49,
					PresentInFinalImage: true,
					FirstSeenAt:         firstSeen,
					LastSeenAt:          lastSeen,
				},
				{
					DetectorName:        "github_token",
					Confidence:          "high",
					Disposition:         findings.DispositionExample,
					DispositionReason:   findings.DispositionReasonExamplePath,
					SourceType:          findings.SourceTypeFileFinal,
					Platform:            manifest.Platform{OS: "linux", Architecture: "amd64"},
					FilePath:            "/usr/share/doc/example/README.md",
					LayerDigest:         contractDigest,
					LineNumber:          12,
					ContextSnippet:      "token: ghp********************************56",
					SourceLocation:      "/usr/share/doc/example/README.md:12",
					MatchStart:          7,
					MatchEnd:            47,
					PresentInFinalImage: true,
					FirstSeenAt:         firstSeen,
					LastSeenAt:          firstSeen,
				},
			},
		},
	}
}
