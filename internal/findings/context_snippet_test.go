package findings

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/brumbelow/layerleak/v3/internal/detectors"
)

// DET-04: context_snippet must redact every copy of a matched value inside
// the public window, including copies no detector matched (a second
// occurrence after a comment marker, a CSV column, the next line).

func snippetTestInput(content string) Input {
	return Input{
		ManifestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SourceType:     SourceTypeFileFinal,
		FilePath:       "app/config.yaml",
		Content:        content,
	}
}

func TestContextSnippetRedactsUndetectedRepeatsOfMatchedValue(t *testing.T) {
	secret := "Xk9fL2mQ8vR4tY7wZ1aB3cD5"
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{
			name:    "repeat after a space",
			content: "token: " + secret + " " + secret,
			want:    "token: [REDACTED] [REDACTED]",
		},
		{
			name:    "repeat in a trailing comment",
			content: "DB_PASSWORD=\"" + secret + "\" # was " + secret,
			want:    "DB_PASSWORD=\"[REDACTED]\" # was [REDACTED]",
		},
		{
			name:    "repeat on the next line",
			content: "password: " + secret + "\nbackup: " + secret + "\n",
			want:    "password: [REDACTED]\nbackup: [REDACTED]",
		},
		{
			name:    "repeat that starts before the window",
			content: secret + "=" + secret,
			want:    "[REDACTED]=[REDACTED]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start := strings.Index(tt.content, secret)
			match := detectors.Match{Detector: "keyword_entropy", Value: secret, Start: start, End: start + len(secret), Confidence: detectors.ConfidenceLow}
			if tt.name == "repeat that starts before the window" {
				start = strings.LastIndex(tt.content, secret)
				match.Start, match.End = start, start+len(secret)
			}
			finding, err := NormalizeDetailedWithMatches(snippetTestInput(tt.content), match, []detectors.Match{match})
			if err != nil {
				t.Fatalf("NormalizeDetailedWithMatches() error = %v", err)
			}
			if strings.Contains(finding.ContextSnippet, secret[:8]) {
				t.Fatalf("context snippet leaked the secret: %q", finding.ContextSnippet)
			}
			if finding.ContextSnippet != tt.want {
				t.Fatalf("ContextSnippet = %q, want %q", finding.ContextSnippet, tt.want)
			}
		})
	}
}

func TestContextSnippetDoesNotOverRedactShortValues(t *testing.T) {
	// Values shorter than eight bytes are redacted only where a detector
	// matched them: "pass" must not blank the inside of "password".
	content := "machine x login y password pass # pass rotation"
	start := strings.Index(content, " pass ") + 1
	match := detectors.Match{Detector: "netrc_password", Value: "pass", Start: start, End: start + 4, Confidence: detectors.ConfidenceMedium}
	finding, err := NormalizeDetailedWithMatches(snippetTestInput(content), match, []detectors.Match{match})
	if err != nil {
		t.Fatalf("NormalizeDetailedWithMatches() error = %v", err)
	}
	if finding.ContextSnippet != "hine x login y password [REDACTED] # pass rotation" {
		t.Fatalf("ContextSnippet = %q", finding.ContextSnippet)
	}
}

func TestContextSnippetRedactsRepeatsProperty(t *testing.T) {
	rng := rand.New(rand.NewSource(0xC0FFEE)) //nolint:gosec // deterministic test data, not security material
	alphabet := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	randomText := func(length int) string {
		buffer := make([]byte, length)
		for index := range buffer {
			buffer[index] = alphabet[rng.Intn(len(alphabet))]
		}
		return string(buffer)
	}
	separators := []string{" ", "  ", ",", " # ", "\n", "\nbackup=", "\" \"", " -> "}

	for trial := 0; trial < 1000; trial++ {
		secret := randomText(12 + rng.Intn(29))
		prefix := randomText(rng.Intn(40)) + " token=" + strings.Repeat("\"", rng.Intn(2))
		separator := separators[rng.Intn(len(separators))]
		suffix := randomText(rng.Intn(40))
		content := prefix + secret + separator + secret + suffix
		if rng.Intn(2) == 0 {
			// A third copy far away, so repeats beyond the window are harmless.
			content += "\n" + strings.Repeat("x", 100) + secret
		}

		first := strings.Index(content, secret)
		match := detectors.Match{Detector: "keyword_entropy", Value: secret, Start: first, End: first + len(secret), Confidence: detectors.ConfidenceLow}
		finding, err := NormalizeDetailedWithMatches(snippetTestInput(content), match, []detectors.Match{match})
		if err != nil {
			t.Fatalf("trial %d: NormalizeDetailedWithMatches() error = %v", trial, err)
		}
		for offset := 0; offset+8 <= len(secret); offset++ {
			if strings.Contains(finding.ContextSnippet, secret[offset:offset+8]) {
				t.Fatalf("trial %d: snippet %q leaks part of the repeated secret", trial, finding.ContextSnippet)
			}
		}
	}
}
