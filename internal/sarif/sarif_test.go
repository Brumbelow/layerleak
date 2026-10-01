package sarif

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brumbelow/layerleak/v3/internal/findings"
	"github.com/brumbelow/layerleak/v3/internal/jobs"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
	"github.com/brumbelow/layerleak/v3/internal/scanner"
)

var update = flag.Bool("update", false, "rewrite the golden SARIF fixture")

func fixtureResult() jobs.Result {
	manifestDigest := "sha256:" + strings.Repeat("b", 64)
	return jobs.Result{
		ResultSchemaVersion:    1,
		Status:                 jobs.ResultStatusPartial,
		RequestedReference:     "ghcr.io/example/app:1.2.3",
		Repository:             "ghcr.io/example/app",
		Mode:                   "reference",
		ResolvedReference:      "ghcr.io/example/app@sha256:" + strings.Repeat("a", 64),
		TargetCount:            1,
		CompletedTargetCount:   0,
		PartialTargetCount:     1,
		ManifestCount:          1,
		CompletedManifestCount: 1,
		Findings: []findings.Finding{
			{
				DetectorName:        "github_token",
				Confidence:          "high",
				Disposition:         findings.DispositionActionable,
				SourceType:          findings.SourceTypeFileFinal,
				ManifestDigest:      manifestDigest,
				Platform:            manifest.Platform{OS: "linux", Architecture: "amd64"},
				FilePath:            "/app/config/.env production#1",
				LayerDigest:         "sha256:" + strings.Repeat("c", 64),
				LineNumber:          3,
				RedactedValue:       "ghp_********",
				Fingerprint:         strings.Repeat("1", 64),
				ContextSnippet:      "GITHUB_TOKEN=[REDACTED]",
				MatchStart:          13,
				MatchEnd:            53,
				PresentInFinalImage: true,
			},
			{
				DetectorName:        "keyword_entropy",
				Confidence:          "low",
				Disposition:         findings.DispositionActionable,
				SourceType:          findings.SourceTypeEnv,
				ManifestDigest:      manifestDigest,
				Platform:            manifest.Platform{OS: "linux", Architecture: "amd64"},
				Key:                 "DB_PASSWORD",
				RedactedValue:       "********",
				Fingerprint:         strings.Repeat("2", 64),
				ContextSnippet:      "DB_PASSWORD=[REDACTED]",
				MatchStart:          12,
				MatchEnd:            28,
				PresentInFinalImage: true,
			},
		},
		SuppressedFindings: []findings.Finding{
			{
				DetectorName:        "basic_auth_url",
				Confidence:          "medium",
				Disposition:         findings.DispositionExample,
				DispositionReason:   findings.DispositionReasonExamplePath,
				SourceType:          findings.SourceTypeFileDeletedLayer,
				ManifestDigest:      manifestDigest,
				Platform:            manifest.Platform{OS: "linux", Architecture: "amd64"},
				FilePath:            "/usr/share/doc/example/README",
				LayerDigest:         "sha256:" + strings.Repeat("d", 64),
				LineNumber:          12,
				RedactedValue:       "********",
				Fingerprint:         strings.Repeat("3", 64),
				ContextSnippet:      "https://user:[REDACTED]@example.com",
				MatchStart:          0,
				MatchEnd:            40,
				PresentInFinalImage: false,
			},
		},
		TotalFindings:                2,
		UniqueFingerprints:           2,
		SuppressedFindingsCount:      1,
		SuppressedUniqueFingerprints: 1,
		Coverage: scanner.Coverage{
			Complete:                  false,
			LayersSeen:                3,
			LayersCompleted:           3,
			FilesSeen:                 120,
			FilesScanned:              118,
			FilesSkippedOversize:      2,
			MetadataValuesScanned:     9,
			ExpandedLayerBytes:        4096,
			RetainedBytes:             2048,
			DetectorInputBytesScanned: 1024,
		},
		Diagnostics: []scanner.Diagnostic{{
			Code:     "files_skipped_oversize",
			Scope:    "manifest",
			Subject:  manifestDigest,
			Message:  "2 files exceeded the per-file byte bound and were not scanned",
			Limit:    1048576,
			Observed: 2,
		}},
	}
}

func TestFromResultMatchesGolden(t *testing.T) {
	log := FromResult(fixtureResult(), Options{ToolVersion: "v3.0.0", Rules: []Rule{{ID: "aws_access_key_id", Description: "AWS access key identifier."}}})
	var buffer bytes.Buffer
	if err := Encode(&buffer, log); err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	golden := filepath.Join("testdata", "example.sarif.json")
	if *update {
		if err := os.WriteFile(golden, buffer.Bytes(), 0o600); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden: %v (run with -update to create it)", err)
	}
	if !bytes.Equal(want, buffer.Bytes()) {
		t.Fatalf("SARIF output differs from %s; run `go test ./internal/sarif -update` after reviewing the change.\n--- got ---\n%s", golden, buffer.String())
	}
}

func TestFromResultStructure(t *testing.T) {
	log := FromResult(fixtureResult(), Options{ToolVersion: "v3.0.0-rc.1"})
	if log.Schema != SchemaURI || log.Version != Version || len(log.Runs) != 1 {
		t.Fatalf("unexpected log envelope %+v", log)
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != ToolName || run.Tool.Driver.Version != "v3.0.0-rc.1" || run.Tool.Driver.SemanticVersion != "3.0.0-rc.1" {
		t.Fatalf("unexpected driver %+v", run.Tool.Driver)
	}
	if len(run.Results) != 3 {
		t.Fatalf("expected 3 results (2 actionable + 1 suppressed), got %d", len(run.Results))
	}
	ruleIDs := make([]string, 0, len(run.Tool.Driver.Rules))
	for _, rule := range run.Tool.Driver.Rules {
		ruleIDs = append(ruleIDs, rule.ID)
	}
	if strings.Join(ruleIDs, ",") != "basic_auth_url,github_token,keyword_entropy" {
		t.Fatalf("rules = %v", ruleIDs)
	}
	for _, result := range run.Results {
		if run.Tool.Driver.Rules[result.RuleIndex].ID != result.RuleID {
			t.Fatalf("ruleIndex %d does not point at %s", result.RuleIndex, result.RuleID)
		}
		if result.PartialFingerprints[FingerprintKey] == "" {
			t.Fatalf("result %s lacks a fingerprint", result.RuleID)
		}
		if len(result.Locations) != 1 {
			t.Fatalf("result %s has %d locations", result.RuleID, len(result.Locations))
		}
	}
	file := run.Results[0]
	if file.Level != "error" || file.Locations[0].PhysicalLocation == nil {
		t.Fatalf("file finding encoded as %+v", file)
	}
	if uri := file.Locations[0].PhysicalLocation.ArtifactLocation.URI; uri != "app/config/.env%20production%231" {
		t.Fatalf("artifact uri = %q", uri)
	}
	if file.Locations[0].PhysicalLocation.ArtifactLocation.URIBaseID != ImageBaseID || file.Locations[0].PhysicalLocation.Region.StartLine != 3 {
		t.Fatalf("file location = %+v", file.Locations[0].PhysicalLocation)
	}
	env := run.Results[1]
	if env.Level != "note" || env.Locations[0].LogicalLocations == nil || env.Locations[0].LogicalLocations[0].Kind != "environmentVariable" || env.Locations[0].LogicalLocations[0].Name != "DB_PASSWORD" {
		t.Fatalf("env finding encoded as %+v", env)
	}
	suppressed := run.Results[2]
	if suppressed.Level != "warning" || len(suppressed.Suppressions) != 1 || suppressed.Suppressions[0].Kind != "external" || suppressed.Suppressions[0].Status != "accepted" || !strings.Contains(suppressed.Suppressions[0].Justification, "example_path") {
		t.Fatalf("suppressed finding encoded as %+v", suppressed)
	}
	base, ok := run.OriginalURIBaseIDs[ImageBaseID]
	if !ok || base.URI != "oci://ghcr.io/example/app@sha256:"+strings.Repeat("a", 64)+"/" {
		t.Fatalf("base uri = %+v", base)
	}
	if run.AutomationDetails == nil || !strings.HasPrefix(run.AutomationDetails.ID, "layerleak/ghcr.io/example/app@") {
		t.Fatalf("automation details = %+v", run.AutomationDetails)
	}
	if len(run.Invocations) != 1 || !run.Invocations[0].ExecutionSuccessful {
		t.Fatalf("invocations = %+v", run.Invocations)
	}
	if run.Properties["status"] != "partial" {
		t.Fatalf("run status property = %v", run.Properties["status"])
	}
}

func TestFromResultNeverContainsRawMaterial(t *testing.T) {
	result := fixtureResult()
	result.DetailedFindings = []findings.DetailedFinding{{Finding: result.Findings[0], Value: "RAWSECRETVALUE-aaaaaaaa", RawSnippet: "GITHUB_TOKEN=RAWSECRETVALUE-aaaaaaaa"}}
	var buffer bytes.Buffer
	if err := Encode(&buffer, FromResult(result, Options{})); err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if strings.Contains(buffer.String(), "RAWSECRETVALUE") {
		t.Fatal("raw secret material leaked into the SARIF log")
	}
}

func TestExcludeSuppressedAndEmptyResult(t *testing.T) {
	log := FromResult(fixtureResult(), Options{ExcludeSuppressed: true})
	if len(log.Runs[0].Results) != 2 || len(log.Runs[0].Tool.Driver.Rules) != 2 {
		t.Fatalf("expected suppressed findings to be dropped, got %d results and %d rules", len(log.Runs[0].Results), len(log.Runs[0].Tool.Driver.Rules))
	}

	empty := FromResult(jobs.Result{Status: jobs.ResultStatusFailed, RequestedReference: "alpine"}, Options{ToolVersion: "dev"})
	var buffer bytes.Buffer
	if err := Encode(&buffer, empty); err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(buffer.Bytes(), &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	run := decoded["runs"].([]any)[0].(map[string]any)
	if results, ok := run["results"].([]any); !ok || len(results) != 0 {
		t.Fatalf("results must be an empty array, got %v", run["results"])
	}
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	if rules, ok := driver["rules"].([]any); !ok || len(rules) != 0 {
		t.Fatalf("rules must be an empty array, got %v", driver["rules"])
	}
	if _, present := driver["semanticVersion"]; present {
		t.Fatal("dev builds must not claim a semantic version")
	}
	if empty.Runs[0].Invocations[0].ExecutionSuccessful {
		t.Fatal("failed scans must report executionSuccessful=false")
	}
	if empty.Runs[0].OriginalURIBaseIDs[ImageBaseID].URI != "oci://alpine/" {
		t.Fatalf("base uri = %q", empty.Runs[0].OriginalURIBaseIDs[ImageBaseID].URI)
	}
}

func TestLevelForConfidence(t *testing.T) {
	for input, want := range map[string]string{"high": "error", "HIGH": "error", "medium": "warning", " Medium ": "warning", "low": "note", "": "note", "weird": "note"} {
		if got := LevelForConfidence(input); got != want {
			t.Fatalf("LevelForConfidence(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestArtifactURI(t *testing.T) {
	cases := map[string]string{
		"/etc/passwd":            "etc/passwd",
		"//double/slash":         "double/slash",
		"":                       ".",
		"/":                      ".",
		"/path with space/a b":   "path%20with%20space/a%20b",
		"/q?mark#hash":           "q%3Fmark%23hash",
		"/c:/windows/secret.txt": "./c:/windows/secret.txt",
		"/app/日本/秘密.txt":         "app/%E6%97%A5%E6%9C%AC/%E7%A7%98%E5%AF%86.txt",
		"relative/already":       "relative/already",
	}
	for input, want := range cases {
		if got := ArtifactURI(input); got != want {
			t.Fatalf("ArtifactURI(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestSemanticVersion(t *testing.T) {
	for input, want := range map[string]string{"v3.0.0": "3.0.0", "v3.0.0-rc.1": "3.0.0-rc.1", "3.1.2+build.5": "3.1.2+build.5", "dev": "", "v3.0.0-20261001040311-a4b2b10fd07a+dirty": "3.0.0-20261001040311-a4b2b10fd07a+dirty", "": ""} {
		if got := semanticVersion(input); got != want {
			t.Fatalf("semanticVersion(%q) = %q, want %q", input, got, want)
		}
	}
}
