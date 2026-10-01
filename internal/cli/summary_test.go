package cli

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/brumbelow/layerleak/v3/internal/findings"
	"github.com/brumbelow/layerleak/v3/internal/jobs"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
	"github.com/brumbelow/layerleak/v3/internal/scanner"
)

func summaryTestResult() jobs.Result {
	return jobs.Result{
		RequestedReference: "library/app:latest", Repository: "library/app", Status: jobs.ResultStatusPartial,
		TargetCount: 4, CompletedTargetCount: 1, PartialTargetCount: 2, FailedTargetCount: 1,
		ManifestCount: 6, CompletedManifestCount: 5, FailedManifestCount: 1,
		Coverage:      scanner.Coverage{FilesScanned: 12, FilesSkippedOversize: 7},
		TotalFindings: 8, UniqueFingerprints: 5, SuppressedFindingsCount: 3,
	}
}

func TestRenderSummaryRepositoryExactOutput(t *testing.T) {
	result := summaryTestResult()
	result.Mode = "repository"
	result.ResolvedReference = "library/app@sha256:root"
	result.RequestedDigest = "sha256:requested"
	result.TagsEnumerated, result.TagsResolved, result.TagsFailed = 3, 2, 1
	result.Targets = []jobs.TargetResult{
		{Reference: "library/app:first", ResolvedReference: "library/app@sha256:first", Tags: []string{"first", "latest"}, FindingsCount: 5},
		{Reference: "library/app:second", FindingsCount: 3, Error: "failed\nrequest"},
	}
	const want = `Requested Reference:          library/app:latest
Repository:                   library/app
Status:                       partial
Resolved Reference:           library/app@sha256:root
Requested Digest:             sha256:requested
Tags Enumerated:              3
Tags Resolved:                2
Tags Failed:                  1
Targets Selected:             4
Targets Completed:            1
Targets Partial:              2
Targets Failed:               1
Manifests Selected:           6
Manifests Completed:          5
Manifests Failed:             1
Coverage Complete:            false
Files Scanned:                12
Files Skipped Oversize:       7
Total Findings:               8
Unique Fingerprints:          5
Suppressed Example Findings:  3

Reference                 Tags  Findings  Status
library/app@sha256:first  2     5         ok
library/app:second        0     3         failed request
`
	var output bytes.Buffer
	if err := renderSummary(&output, result); err != nil {
		t.Fatal(err)
	}
	if output.String() != want {
		t.Fatalf("summary output mismatch\ngot:\n%s\nwant:\n%s", output.String(), want)
	}
}

func TestRenderSummaryReferenceExactOutput(t *testing.T) {
	result := summaryTestResult()
	result.Mode = "reference"
	result.Targets = []jobs.TargetResult{{PlatformResults: []scanner.PlatformResult{
		{Platform: manifest.Platform{OS: "linux", Architecture: "amd64"}, ManifestDigest: "sha256:first", FindingsCount: 5},
		{Platform: manifest.Platform{OS: "linux", Architecture: "arm64"}, ManifestDigest: "sha256:second", FindingsCount: 3, Error: "failed\trequest"},
	}}}
	const want = `Requested Reference:          library/app:latest
Repository:                   library/app
Status:                       partial
Targets Selected:             4
Targets Completed:            1
Targets Partial:              2
Targets Failed:               1
Manifests Selected:           6
Manifests Completed:          5
Manifests Failed:             1
Coverage Complete:            false
Files Scanned:                12
Files Skipped Oversize:       7
Total Findings:               8
Unique Fingerprints:          5
Suppressed Example Findings:  3

Platform     Manifest Digest  Findings  Status
linux/amd64  sha256:first     5         ok
linux/arm64  sha256:second    3         failed request
`
	var output bytes.Buffer
	if err := renderSummary(&output, result); err != nil {
		t.Fatal(err)
	}
	if output.String() != want {
		t.Fatalf("summary output mismatch\ngot:\n%s\nwant:\n%s", output.String(), want)
	}
}

func TestRenderSummaryConditionalRows(t *testing.T) {
	tests := []struct {
		name, mode              string
		tags                    int
		targets                 []jobs.TargetResult
		wantTags, wantPlatforms bool
	}{
		{"empty repository", "repository", 0, nil, true, false},
		{"empty reference", "reference", 0, nil, false, false},
		{"enumerated reference", "reference", 1, []jobs.TargetResult{{}}, true, true},
		{"multiple reference targets", "reference", 0, []jobs.TargetResult{{}, {}}, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			err := renderSummary(&output, jobs.Result{Mode: tt.mode, TagsEnumerated: tt.tags, Targets: tt.targets})
			if err != nil {
				t.Fatal(err)
			}
			for _, label := range []string{"Tags Enumerated:", "Tags Resolved:", "Tags Failed:"} {
				if strings.Contains(output.String(), label) != tt.wantTags {
					t.Errorf("unexpected presence of %q in %q", label, output.String())
				}
			}
			if strings.Contains(output.String(), "Platform") != tt.wantPlatforms {
				t.Errorf("wrong table in %q", output.String())
			}
		})
	}
}

func TestRenderSummaryListsFindingsExactOutput(t *testing.T) {
	result := summaryTestResult()
	result.Mode = "reference"
	result.Targets = []jobs.TargetResult{{PlatformResults: []scanner.PlatformResult{
		{Platform: manifest.Platform{OS: "linux", Architecture: "amd64"}, ManifestDigest: "sha256:first", FindingsCount: 3},
	}}}
	result.Findings = []findings.Finding{
		{DetectorName: "github_token", Confidence: "high", SourceType: findings.SourceTypeEnv, Key: "GH_TOKEN", RedactedValue: "ghp********", Platform: manifest.Platform{OS: "linux", Architecture: "amd64"}},
		{DetectorName: "aws_secret_access_key", Confidence: "medium", SourceType: findings.SourceTypeFileFinal, FilePath: "app/.env", LineNumber: 12, RedactedValue: "wJa********", Platform: manifest.Platform{OS: "linux", Architecture: "amd64"}},
		{DetectorName: "keyword_entropy", Confidence: "low", SourceType: findings.SourceTypeFileDeletedLayer, FilePath: "tmp/bad\tname\x1b[2J", RedactedValue: "***********", Platform: manifest.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}},
	}
	const want = `Requested Reference:          library/app:latest
Repository:                   library/app
Status:                       partial
Targets Selected:             4
Targets Completed:            1
Targets Partial:              2
Targets Failed:               1
Manifests Selected:           6
Manifests Completed:          5
Manifests Failed:             1
Coverage Complete:            false
Files Scanned:                12
Files Skipped Oversize:       7
Total Findings:               8
Unique Fingerprints:          5
Suppressed Example Findings:  3

Platform     Manifest Digest  Findings  Status
linux/amd64  sha256:first     3         ok

Detector               Confidence  Location          Redacted Value  Platform
github_token           high        env:GH_TOKEN      ghp********     linux/amd64
aws_secret_access_key  medium      app/.env:12       wJa********     linux/amd64
keyword_entropy        low         tmp/bad name [2J  ***********     linux/arm64/v8
`
	var output bytes.Buffer
	if err := renderSummary(&output, result); err != nil {
		t.Fatal(err)
	}
	if output.String() != want {
		t.Fatalf("summary output mismatch\ngot:\n%s\nwant:\n%s", output.String(), want)
	}
}

func TestRenderSummaryCapsFindingsTable(t *testing.T) {
	result := summaryTestResult()
	result.Mode = "reference"
	result.Targets = []jobs.TargetResult{{}}
	for i := 0; i < summaryFindingsCap+7; i++ {
		result.Findings = append(result.Findings, findings.Finding{DetectorName: "keyword_entropy", Confidence: "low", SourceType: findings.SourceTypeFileFinal, FilePath: fmt.Sprintf("file-%02d", i), RedactedValue: "***********"})
	}
	var output bytes.Buffer
	if err := renderSummary(&output, result); err != nil {
		t.Fatal(err)
	}
	if strings.Count(output.String(), "keyword_entropy") != summaryFindingsCap || !strings.HasSuffix(output.String(), "and 7 more\n") {
		t.Fatalf("findings table not capped at %d: %s", summaryFindingsCap, output.String())
	}
}

type summaryFailWriter struct {
	remaining int
	err       error
}

func (w *summaryFailWriter) Write(p []byte) (int, error) {
	if len(p) > w.remaining {
		n := w.remaining
		w.remaining = 0
		return n, w.err
	}
	w.remaining -= len(p)
	return len(p), nil
}

func TestRenderSummaryPropagatesWriterErrors(t *testing.T) {
	failure := errors.New("summary output unavailable")
	for _, mode := range []string{"reference", "repository"} {
		t.Run(mode, func(t *testing.T) {
			result := summaryTestResult()
			result.Mode = mode
			result.Targets = []jobs.TargetResult{{PlatformResults: []scanner.PlatformResult{{}}}}
			var complete bytes.Buffer
			if err := renderSummary(&complete, result); err != nil {
				t.Fatal(err)
			}
			for _, remaining := range []int{0, complete.Len() / 2, complete.Len() - 1} {
				writer := &summaryFailWriter{remaining: remaining, err: failure}
				if err := renderSummary(writer, result); !errors.Is(err, failure) {
					t.Errorf("remaining=%d: error = %v, want %v", remaining, err, failure)
				}
			}
		})
	}
}
