package findings

import (
	"strings"
	"testing"

	"github.com/brumbelow/layerleak/internal/detectors"
	"github.com/brumbelow/layerleak/internal/manifest"
)

func TestRedact(t *testing.T) {
	got := Redact("ghp_123456789012345678901234567890123456")
	if got == "ghp_123456789012345678901234567890123456" {
		t.Fatal("Redact() returned raw value")
	}

	if !strings.HasPrefix(got, "ghp") {
		t.Fatalf("Redact() = %q", got)
	}
}

func TestFingerprintStable(t *testing.T) {
	left := Fingerprint("same-value")
	right := Fingerprint("same-value")
	if left != right {
		t.Fatalf("Fingerprint() mismatch: %q != %q", left, right)
	}
}

func TestNormalize(t *testing.T) {
	content := "token=ghp_123456789012345678901234567890123456"
	match := detectors.Match{
		Detector:   "github_token",
		Value:      "ghp_123456789012345678901234567890123456",
		Start:      6,
		End:        len(content),
		Confidence: detectors.ConfidenceHigh,
	}

	finding, err := Normalize(Input{
		ManifestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Platform: manifest.Platform{
			OS:           "linux",
			Architecture: "amd64",
		},
		SourceType:          SourceTypeEnv,
		Key:                 "TOKEN",
		Content:             content,
		PresentInFinalImage: true,
	}, match)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	if finding.DetectorName != "github_token" {
		t.Fatalf("finding.DetectorName = %q", finding.DetectorName)
	}

	if finding.RedactedValue == match.Value {
		t.Fatal("finding.RedactedValue leaked raw value")
	}

	if strings.Contains(finding.ContextSnippet, match.Value) {
		t.Fatal("finding.ContextSnippet leaked raw value")
	}
}

func TestNormalizeDetailed(t *testing.T) {
	content := "token=ghp_123456789012345678901234567890123456"
	match := detectors.Match{
		Detector:   "github_token",
		Value:      "ghp_123456789012345678901234567890123456",
		Start:      6,
		End:        len(content),
		Confidence: detectors.ConfidenceHigh,
	}

	finding, err := NormalizeDetailed(Input{
		ManifestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Platform: manifest.Platform{
			OS:           "linux",
			Architecture: "amd64",
		},
		SourceType:          SourceTypeEnv,
		Key:                 "TOKEN",
		Content:             content,
		PresentInFinalImage: true,
	}, match)
	if err != nil {
		t.Fatalf("NormalizeDetailed() error = %v", err)
	}

	if finding.Value != match.Value {
		t.Fatalf("finding.Value = %q", finding.Value)
	}

	if !strings.Contains(finding.RawSnippet, match.Value) {
		t.Fatalf("finding.RawSnippet = %q", finding.RawSnippet)
	}

	if finding.SourceLocation != "env:TOKEN" {
		t.Fatalf("finding.SourceLocation = %q", finding.SourceLocation)
	}
}

func TestShouldSuppressFilePath(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{name: "test directory", filePath: "app/test/.env", want: true},
		{name: "tests directory", filePath: "app/tests/.env", want: true},
		{name: "case insensitive directory", filePath: "app/Test/.env", want: true},
		{name: "windows separator", filePath: `app\tests\.env`, want: true},
		{name: "filename only", filePath: "app_test.go", want: false},
		{name: "substring only", filePath: "app/latest/.env", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ShouldSuppressFilePath(tt.filePath); got != tt.want {
				t.Fatalf("ShouldSuppressFilePath(%q) = %t, want %t", tt.filePath, got, tt.want)
			}
		})
	}
}

func TestDeduplicateDetailedUsesRawSnippetAcrossFilePaths(t *testing.T) {
	items := []DetailedFinding{
		testDetailedFinding("z.env", "github_token", "TOKEN=ghp_123456789012345678901234567890123456", "TOKEN=ghp********************************56"),
		testDetailedFinding("a.env", "github_token", "TOKEN=ghp_123456789012345678901234567890123456", "TOKEN=ghp********************************56"),
	}

	deduped := DeduplicateDetailed(items)
	if len(deduped) != 1 {
		t.Fatalf("len(deduped) = %d", len(deduped))
	}
	if deduped[0].FilePath != "a.env" {
		t.Fatalf("deduped[0].FilePath = %q", deduped[0].FilePath)
	}
}

func TestDeduplicateDetailedUsesRawSnippetAcrossDetectors(t *testing.T) {
	items := []DetailedFinding{
		testDetailedFinding("app.env", "z_detector", "TOKEN=ghp_123456789012345678901234567890123456", "TOKEN=ghp********************************56"),
		testDetailedFinding("app.env", "a_detector", "TOKEN=ghp_123456789012345678901234567890123456", "TOKEN=ghp********************************56"),
	}

	deduped := DeduplicateDetailed(items)
	if len(deduped) != 1 {
		t.Fatalf("len(deduped) = %d", len(deduped))
	}
	if deduped[0].DetectorName != "a_detector" {
		t.Fatalf("deduped[0].DetectorName = %q", deduped[0].DetectorName)
	}
}

func TestDeduplicateDetailedPreservesDistinctRawSnippetsForSameFingerprint(t *testing.T) {
	items := []DetailedFinding{
		testDetailedFinding("app.env", "github_token", "TOKEN=ghp_123456789012345678901234567890123456", "TOKEN=ghp********************************56"),
		testDetailedFinding("app.env", "github_token", "GH_TOKEN=ghp_123456789012345678901234567890123456", "GH_TOKEN=ghp********************************56"),
	}

	deduped := DeduplicateDetailed(items)
	if len(deduped) != 2 {
		t.Fatalf("len(deduped) = %d", len(deduped))
	}
}

func TestDeduplicateUsesContextSnippetAcrossPublicFindings(t *testing.T) {
	items := []Finding{
		{
			DetectorName:   "github_token",
			SourceType:     SourceTypeFileFinal,
			ManifestDigest: "sha256:a",
			FilePath:       "z.env",
			Fingerprint:    "one",
			ContextSnippet: "TOKEN=ghp********************************56",
		},
		{
			DetectorName:   "github_token",
			SourceType:     SourceTypeFileFinal,
			ManifestDigest: "sha256:a",
			FilePath:       "a.env",
			Fingerprint:    "one",
			ContextSnippet: "TOKEN=ghp********************************56",
		},
	}

	deduped := Deduplicate(items)
	if len(deduped) != 1 {
		t.Fatalf("len(deduped) = %d", len(deduped))
	}
	if deduped[0].FilePath != "a.env" {
		t.Fatalf("deduped[0].FilePath = %q", deduped[0].FilePath)
	}
}

func TestDeduplicatePreservesDistinctContextSnippets(t *testing.T) {
	items := []Finding{
		{
			DetectorName:   "github_token",
			SourceType:     SourceTypeEnv,
			ManifestDigest: "sha256:a",
			Fingerprint:    "one",
			ContextSnippet: "TOKEN=ghp********************************56",
		},
		{
			DetectorName:   "github_token",
			SourceType:     SourceTypeLabel,
			ManifestDigest: "sha256:a",
			Fingerprint:    "one",
			ContextSnippet: "token=ghp********************************56",
		},
	}

	deduped := Deduplicate(items)
	if len(deduped) != 2 {
		t.Fatalf("len(deduped) = %d", len(deduped))
	}
}

func testDetailedFinding(filePath, detectorName, rawSnippet, contextSnippet string) DetailedFinding {
	return DetailedFinding{
		Finding: Finding{
			DetectorName:   detectorName,
			Confidence:     "high",
			SourceType:     SourceTypeFileFinal,
			ManifestDigest: "sha256:a",
			Platform: manifest.Platform{
				OS:           "linux",
				Architecture: "amd64",
			},
			FilePath:       filePath,
			Fingerprint:    Fingerprint("ghp_123456789012345678901234567890123456"),
			ContextSnippet: contextSnippet,
		},
		Value:          "ghp_123456789012345678901234567890123456",
		RawSnippet:     rawSnippet,
		SourceLocation: "file:" + filePath,
		MatchStart:     6,
		MatchEnd:       46,
	}
}
