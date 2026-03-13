package findings

import (
	"strings"
	"testing"

	"git.tools.cloudfor.ge/andrew/layerleak/internal/detectors"
	"git.tools.cloudfor.ge/andrew/layerleak/internal/manifest"
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

func TestDeduplicatePreservesUniqueProvenance(t *testing.T) {
	items := []Finding{
		{
			DetectorName:   "github_token",
			SourceType:     SourceTypeEnv,
			ManifestDigest: "sha256:a",
			Fingerprint:    "one",
			Key:            "TOKEN",
		},
		{
			DetectorName:   "github_token",
			SourceType:     SourceTypeEnv,
			ManifestDigest: "sha256:a",
			Fingerprint:    "one",
			Key:            "TOKEN",
		},
		{
			DetectorName:   "github_token",
			SourceType:     SourceTypeLabel,
			ManifestDigest: "sha256:a",
			Fingerprint:    "one",
			Key:            "token",
		},
	}

	deduped := Deduplicate(items)
	if len(deduped) != 2 {
		t.Fatalf("len(deduped) = %d", len(deduped))
	}
}
