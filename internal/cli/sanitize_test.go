package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/brumbelow/layerleak/v3/internal/jobs"
)

// TestSanitizeProgressValueStripsFormatCharacters covers the terminal
// sanitiser with the format characters an untrusted registry error or image
// string can use to reorder or hide text: bidi overrides and isolates,
// zero-width joiners and spaces, soft hyphens and the byte order mark. They
// are dropped; whitespace and controls still collapse to one space.
func TestSanitizeProgressValueStripsFormatCharacters(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"right-to-left override", "ghcr.io/x/app:\u202e1.0", "ghcr.io/x/app:1.0"},
		{"override then pop", "tag \u202dlatest\u202c failed", "tag latest failed"},
		{"first strong isolate", "\u2068denied\u2069", "denied"},
		{"zero-width joiner", "aws\u200d_access_key_id", "aws_access_key_id"},
		{"zero-width non-joiner and space", "a\u200cb\u200bc", "abc"},
		{"soft hyphen", "pass\u00adword", "password"},
		{"byte order mark", "\ufeffunauthorized", "unauthorized"},
		{"format character inside a whitespace run", "a \u200d\t b", "a b"},
		{"escape and newline", "x\x1b]0;title\x07\ny", "x ]0;title y"},
		{"printable non-ASCII kept", "naïve ✓ 日本", "naïve ✓ 日本"},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			if got := sanitizeProgressValue(item.input); got != item.want {
				t.Fatalf("sanitizeProgressValue(%q) = %q, want %q", item.input, got, item.want)
			}
		})
	}
}

// TestProgressRendererDropsBidiOverridesFromRegistryText checks the plain
// renderer end to end: a tag name carrying a right-to-left override cannot
// reverse the rest of the progress line.
func TestProgressRendererDropsBidiOverridesFromRegistryText(t *testing.T) {
	var out bytes.Buffer
	renderer := newProgressRendererWithMode(&out, progressModePlain)
	if err := renderer.UpdateFromJob(jobs.ProgressUpdate{
		Phase:      jobs.ProgressPhaseResolvingTags,
		Repository: "library/app",
		CurrentTag: "v1\u202egnp.exe",
		Message:    "Resolving\u200d tag digest",
	}); err != nil {
		t.Fatalf("UpdateFromJob() error = %v", err)
	}
	if err := renderer.Finish(); err != nil {
		t.Fatalf("Finish() error = %v", err)
	}
	text := out.String()
	for _, forbidden := range []string{"\u202e", "\u200d"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("progress output kept %q: %q", forbidden, text)
		}
	}
	if !strings.Contains(text, "v1gnp.exe") {
		t.Fatalf("progress output lost the tag text: %q", text)
	}
}
