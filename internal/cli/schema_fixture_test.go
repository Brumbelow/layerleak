package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/findings"
	"github.com/brumbelow/layerleak/v3/internal/jobs"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
	"github.com/brumbelow/layerleak/v3/internal/scanner"
	"github.com/brumbelow/layerleak/v3/internal/scanservice"
)

var updateGolden = flag.Bool("update", false, "rewrite the golden result and scan-record fixtures under testdata")

// TestGoldenResultAndScanRecordFixtures pins the exact JSON the CLI prints
// (--format json) and writes (the scan record) for a representative scan.
// scripts/validate_schemas.py validates these fixtures against
// web/docs/schemas/*.schema.json in `make docs-verify` and the verify
// workflow. Regenerate with
// `go test ./internal/cli -run TestGoldenResultAndScanRecordFixtures -update`.
func TestGoldenResultAndScanRecordFixtures(t *testing.T) {
	outcome := goldenOutcome()
	createdAt := time.Date(2026, time.October, 1, 12, 0, 7, 0, time.UTC)
	record := buildLocalScanRecord(outcome, "postgres", createdAt)

	resultJSON := goldenJSON(t, scanservice.PublicResult(outcome.Result))
	recordJSON := goldenJSON(t, record)
	for _, body := range [][]byte{resultJSON, recordJSON} {
		if bytes.Contains(body, []byte("synthetic-raw")) {
			t.Fatalf("golden fixture carries raw material: %s", body)
		}
	}
	compareGolden(t, filepath.Join("testdata", "result-v2.json"), resultJSON)
	compareGolden(t, filepath.Join("testdata", "scan-record-v2.json"), recordJSON)
}

func goldenJSON(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(body, '\n')
}

func compareGolden(t *testing.T, path string, actual []byte) {
	t.Helper()
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, actual, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	expected, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		t.Fatalf("golden fixture %s is missing; run `go test ./internal/cli -run TestGoldenResultAndScanRecordFixtures -update`", path)
	}
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(expected, actual) {
		t.Fatalf("%s differs from the current output; review the schema impact, then run `go test ./internal/cli -run TestGoldenResultAndScanRecordFixtures -update`.\n--- got ---\n%s", path, actual)
	}
}

// goldenOutcome is a repository sweep with one scanned, one partial and one
// unresolvable tag, two targets, actionable and suppressed findings from a
// file and from image metadata, and diagnostics at both levels.
func goldenOutcome() scanservice.Outcome {
	const (
		rootOne     = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
		rootTwo     = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
		amd64Man    = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
		arm64Man    = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
		layerOne    = "sha256:5555555555555555555555555555555555555555555555555555555555555555"
		fpToken     = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		fpAWS       = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		fpExample   = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
		fpBaselined = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	)
	amd64 := manifest.Platform{OS: "linux", Architecture: "amd64"}
	arm64 := manifest.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}
	coverage := func(complete bool, files int) scanner.Coverage {
		return scanner.Coverage{Complete: complete, LayersSeen: 2, LayersCompleted: 2, FilesSeen: files + 1, FilesScanned: files, FilesSkippedOversize: 1, MetadataValuesScanned: 3, ExpandedLayerBytes: 4096, RetainedBytes: 128, DetectorInputBytesScanned: 2048}
	}
	tokenFinding := findings.DetailedFinding{
		Finding: findings.Finding{
			DetectorName: "github_token", Confidence: "high", Disposition: findings.DispositionActionable,
			SourceType: findings.SourceTypeEnv, ManifestDigest: amd64Man, Platform: amd64, Key: "GH_TOKEN",
			RedactedValue: "ghp********", Fingerprint: fpToken, ContextSnippet: "GH_TOKEN=ghp********",
			MatchStart: 9, MatchEnd: 49, PresentInFinalImage: true,
		},
		Value: "synthetic-raw-token", RawSnippet: "GH_TOKEN=synthetic-raw-token", SourceLocation: "env:GH_TOKEN",
	}
	awsFinding := findings.DetailedFinding{
		Finding: findings.Finding{
			DetectorName: "aws_secret_access_key", Confidence: "medium", Disposition: findings.DispositionActionable,
			SourceType: findings.SourceTypeFileDeletedLayer, ManifestDigest: amd64Man, Platform: amd64,
			FilePath: "app/.env", LayerDigest: layerOne, LineNumber: 12,
			RedactedValue: "wJa********", Fingerprint: fpAWS, ContextSnippet: "AWS_SECRET_ACCESS_KEY=wJa********",
			MatchStart: 22, MatchEnd: 62, PresentInFinalImage: false,
		},
		Value: "synthetic-raw-aws", RawSnippet: "AWS_SECRET_ACCESS_KEY=synthetic-raw-aws", SourceLocation: "file:app/.env:12",
	}
	exampleFinding := findings.DetailedFinding{
		Finding: findings.Finding{
			DetectorName: "basic_auth_url", Confidence: "low", Disposition: findings.DispositionExample,
			DispositionReason: findings.DispositionReasonTestPath, SourceType: findings.SourceTypeFileFinal,
			ManifestDigest: amd64Man, Platform: amd64, FilePath: "test/fixtures/config.yaml", LayerDigest: layerOne, LineNumber: 3,
			RedactedValue: "***********", Fingerprint: fpExample, ContextSnippet: "url: https://user:***********@example.test/",
			MatchStart: 18, MatchEnd: 29, PresentInFinalImage: true,
		},
		Value: "synthetic-raw-example", RawSnippet: "url: https://user:synthetic-raw-example@example.test/", SourceLocation: "file:test/fixtures/config.yaml:3",
	}
	// A finding the caller accepted through --baseline: it keeps every field of
	// the actionable finding it was, with the baselined disposition and no
	// disposition_reason, and is listed among the suppressed findings.
	baselinedFinding := findings.DetailedFinding{
		Finding: findings.Finding{
			DetectorName: "keyword_entropy", Confidence: "low", Disposition: findings.DispositionBaselined,
			SourceType: findings.SourceTypeFileFinal, ManifestDigest: amd64Man, Platform: amd64,
			FilePath: "app/config.yaml", LayerDigest: layerOne, LineNumber: 7,
			RedactedValue: "9f2********", Fingerprint: fpBaselined, ContextSnippet: "legacy_api_secret: 9f2********",
			MatchStart: 19, MatchEnd: 51, PresentInFinalImage: true,
		},
		Value: "synthetic-raw-baselined", RawSnippet: "legacy_api_secret: synthetic-raw-baselined", SourceLocation: "file:app/config.yaml:7",
	}
	oversize := scanner.Diagnostic{Code: "files_skipped_oversize", Scope: "manifest", Subject: amd64Man, Message: "1 file(s) exceeded the per-file scan limit", Limit: 1048576, Observed: 1}
	unsupported := scanner.Diagnostic{Code: "manifest_unsupported", Scope: "manifest", Subject: arm64Man, Message: "layer uses a non-distributable (foreign) media type and cannot be scanned"}

	result := jobs.Result{
		ResultSchemaVersion: jobs.ResultSchemaVersion,
		ScannedAt:           time.Date(2026, time.October, 1, 12, 0, 0, 0, time.UTC),
		DurationMS:          4210,
		Scanner:             jobs.ScannerInfo{Name: jobs.ScannerName, Version: "v3.0.0", DetectorSetVersion: "sha256:" + strings.Repeat("d", 64)},
		Status:              jobs.ResultStatusPartial,
		RequestedReference:  "ghcr.io/example/app",
		Repository:          "example/app",
		Mode:                "repository",
		ResolvedReference:   "ghcr.io/example/app",
		TagsEnumerated:      3, TagsResolved: 2, TagsFailed: 1,
		TargetCount: 2, CompletedTargetCount: 1, FailedTargetCount: 0, PartialTargetCount: 1,
		ManifestCount: 3, CompletedManifestCount: 2, FailedManifestCount: 1,
		TagResults: []jobs.TagResult{
			{Tag: "1.0", RootDigest: rootOne, TargetReference: "ghcr.io/example/app@" + rootOne, Status: jobs.TagStatusScanned},
			{Tag: "2.0", RootDigest: rootTwo, TargetReference: "ghcr.io/example/app@" + rootTwo, Status: jobs.TagStatusPartial},
			{Tag: "broken", Status: jobs.TagStatusFailed, Error: "registry request failed: status=404 Not Found"},
		},
		Targets: []jobs.TargetResult{
			{
				Status: jobs.ResultStatusCompleted, Reference: "ghcr.io/example/app@" + rootOne, Tags: []string{"1.0"},
				ResolvedReference: "ghcr.io/example/app@" + rootOne, RequestedDigest: rootOne,
				ManifestCount: 1, CompletedManifestCount: 1, FindingsCount: 2,
				PlatformResults: []scanner.PlatformResult{{Status: scanner.ResultStatusCompleted, Platform: amd64, ManifestDigest: amd64Man, FindingsCount: 2, Coverage: coverage(true, 40), Diagnostics: []scanner.Diagnostic{oversize}}},
			},
			{
				Status: jobs.ResultStatusPartial, Reference: "ghcr.io/example/app@" + rootTwo, Tags: []string{"2.0"},
				ResolvedReference: "ghcr.io/example/app@" + rootTwo, RequestedDigest: rootTwo,
				ManifestCount: 2, CompletedManifestCount: 1, FailedManifestCount: 1, FindingsCount: 0,
				Error: "scan coverage is partial: 1 manifest(s) completed, 1 failed",
				PlatformResults: []scanner.PlatformResult{
					{Status: scanner.ResultStatusCompleted, Platform: amd64, ManifestDigest: amd64Man, FindingsCount: 0, Coverage: coverage(true, 12)},
					{Status: scanner.ResultStatusFailed, Platform: arm64, ManifestDigest: arm64Man, Error: "unsupported manifest " + arm64Man + ": " + unsupported.Message, Coverage: scanner.Coverage{}, Diagnostics: []scanner.Diagnostic{unsupported}},
				},
			},
		},
		DetailedFindings:           []findings.DetailedFinding{awsFinding, tokenFinding},
		SuppressedDetailedFindings: []findings.DetailedFinding{exampleFinding, baselinedFinding},
		Findings:                   []findings.Finding{awsFinding.Finding, tokenFinding.Finding},
		SuppressedFindings:         []findings.Finding{exampleFinding.Finding, baselinedFinding.Finding},
		TotalFindings:              2, UniqueFingerprints: 2, SuppressedFindingsCount: 2, SuppressedUniqueFingerprints: 2,
		Coverage:    coverage(false, 52),
		Diagnostics: []scanner.Diagnostic{oversize, unsupported},
	}
	return scanservice.Outcome{Result: result, ScanRunID: 41}
}

func TestGoldenFixturesStayFreeOfRawValues(t *testing.T) {
	for _, name := range []string{"result-v2.json", "scan-record-v2.json"} {
		body, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Skipf("fixture not generated yet: %v", err)
		}
		if strings.Contains(string(body), "synthetic-raw") || strings.Contains(string(body), `"value"`) || strings.Contains(string(body), "raw_context_snippet") {
			t.Fatalf("%s carries raw material", name)
		}
	}
}
