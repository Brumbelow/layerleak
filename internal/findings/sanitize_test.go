package findings

import (
	"strings"
	"testing"

	"github.com/brumbelow/layerleak/v3/internal/detectors"
)

func TestSanitizeControlCharacters(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "clean value is unchanged", in: "config.env.TOKEN", want: "config.env.TOKEN"},
		{name: "nul is replaced", in: "A\x00B", want: "A�B"},
		{name: "other c0 controls and del are replaced", in: "a\x01b\x1fc\x7fd", want: "a�b�c�d"},
		{name: "tab newline and carriage return are kept", in: "a\tb\nc\rd", want: "a\tb\nc\rd"},
		{name: "multibyte text is preserved", in: "clé\x00ñ", want: "clé�ñ"},
		{name: "empty", in: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SanitizeControlCharacters(tt.in); got != tt.want {
				t.Fatalf("SanitizeControlCharacters(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestNormalizeDetailedSanitizesControlCharactersInMetadataProvenance(t *testing.T) {
	secret := "ghp_" + strings.Repeat("1", 36)
	content := "A\x00B=" + secret + "\x01tail"
	match := detectors.Match{
		Detector:   "github_token",
		Value:      secret,
		Start:      4,
		End:        4 + len(secret),
		Confidence: detectors.ConfidenceHigh,
	}

	finding, err := NormalizeDetailed(Input{
		ManifestDigest: "sha256:" + strings.Repeat("a", 64),
		SourceType:     SourceTypeEnv,
		Key:            "config.env.A\x00B",
		Content:        content,
	}, match)
	if err != nil {
		t.Fatalf("NormalizeDetailed() error = %v", err)
	}

	if finding.Key != "config.env.A�B" {
		t.Fatalf("finding.Key = %q, want NUL replaced", finding.Key)
	}
	if finding.SourceLocation != "env:config.env.A�B" {
		t.Fatalf("finding.SourceLocation = %q, want NUL replaced", finding.SourceLocation)
	}
	if strings.ContainsAny(finding.ContextSnippet, "\x00\x01") {
		t.Fatalf("finding.ContextSnippet = %q still carries control characters", finding.ContextSnippet)
	}
	if !strings.Contains(finding.ContextSnippet, "[REDACTED]") || !strings.Contains(finding.ContextSnippet, "A�B=") {
		t.Fatalf("finding.ContextSnippet = %q", finding.ContextSnippet)
	}
	if finding.Fingerprint != Fingerprint(secret) {
		t.Fatalf("finding.Fingerprint = %q, want sha256 of the raw value", finding.Fingerprint)
	}
	if finding.Value != secret {
		t.Fatalf("finding.Value = %q, raw material must stay verbatim", finding.Value)
	}
}

func TestNormalizeDetailedSanitizesControlCharactersInFilePathProvenance(t *testing.T) {
	secret := "ghp_" + strings.Repeat("2", 36)
	content := "token=" + secret
	match := detectors.Match{
		Detector:   "github_token",
		Value:      secret,
		Start:      6,
		End:        len(content),
		Confidence: detectors.ConfidenceHigh,
	}

	finding, err := NormalizeDetailed(Input{
		ManifestDigest: "sha256:" + strings.Repeat("a", 64),
		SourceType:     SourceTypeFileFinal,
		FilePath:       "/app/\x00config\x1f.env",
		LayerDigest:    "sha256:" + strings.Repeat("b", 64),
		Content:        content,
	}, match)
	if err != nil {
		t.Fatalf("NormalizeDetailed() error = %v", err)
	}

	if finding.FilePath != "/app/�config�.env" {
		t.Fatalf("finding.FilePath = %q, want control characters replaced", finding.FilePath)
	}
	if !strings.HasSuffix(finding.SourceLocation, ":"+finding.FilePath) || strings.ContainsAny(finding.SourceLocation, "\x00\x1f") {
		t.Fatalf("finding.SourceLocation = %q", finding.SourceLocation)
	}
}

func TestRedactSanitizesControlCharactersInRedactedValue(t *testing.T) {
	redacted := Redact("ab\x00cdefghijk\x01l")
	if strings.ContainsAny(redacted, "\x00\x01") {
		t.Fatalf("Redact() = %q still carries control characters", redacted)
	}
	if redacted != "ab�********" {
		t.Fatalf("Redact() = %q", redacted)
	}
}
