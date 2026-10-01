package scanservice

import (
	"testing"

	"github.com/brumbelow/layerleak/v3/internal/jobs"
	"github.com/brumbelow/layerleak/v3/internal/scanner"
)

// sanitizeCases are untrusted registry and image strings with terminal
// control sequences, Unicode format characters (bidi overrides and isolates,
// zero-width characters, soft hyphens, the byte order mark) and other
// non-printable runes. Format characters are dropped without a separator so
// a word they split stays whole; whitespace and C0/C1 controls still
// collapse to one space.
var sanitizeCases = []struct {
	name  string
	input string
	want  string
}{
	{"plain text", "registry request failed: status=404", "registry request failed: status=404"},
	{"whitespace runs collapse", "  a \t\n b  ", "a b"},
	{"escape sequence", "bad\x1b[2Jtext", "bad [2Jtext"},
	{"right-to-left override", "file\u202egnp.exe", "filegnp.exe"},
	{"left-to-right override and pop", "a\u202dtag\u202c b", "atag b"},
	{"bidi isolates", "\u2066tag\u2069 failed", "tag failed"},
	{"right-to-left mark", "x\u200fy", "xy"},
	{"zero-width joiner", "to\u200dken", "token"},
	{"zero-width space", "tag\u200b name", "tag name"},
	{"soft hyphen", "secret\u00advalue", "secretvalue"},
	{"byte order mark", "\ufeffstatus=401", "status=401"},
	{"format character between spaces", "a \u200b b", "a b"},
	{"only format characters", "\u202e\u200d\u00ad", ""},
	{"private use", "x\ue000y", "xy"},
	{"unassigned code point", "x\U000e0080y", "xy"},
	{"line separator is whitespace", "a\u2028b", "a b"},
	{"printable non-ASCII kept", "café — 日本 ✓", "café — 日本 ✓"},
	{"no-break space is whitespace", "a\u00a0b", "a b"},
}

func TestSanitizeMessageTextStripsFormatAndNonPrintableRunes(t *testing.T) {
	for _, item := range sanitizeCases {
		t.Run(item.name, func(t *testing.T) {
			if got := SanitizeMessageText(item.input); got != item.want {
				t.Fatalf("SanitizeMessageText(%q) = %q, want %q", item.input, got, item.want)
			}
		})
	}
}

// TestPublicResultStripsFormatCharactersFromMessages covers the PublicResult
// message path end to end: a registry error that tries to reorder itself on
// a terminal reaches stdout JSON and the scan record without the override.
func TestPublicResultStripsFormatCharactersFromMessages(t *testing.T) {
	result := jobs.Result{
		TagResults: []jobs.TagResult{{Tag: "1.0", Status: jobs.TagStatusFailed, Error: "denied\u202e lanretxe"}},
		Targets: []jobs.TargetResult{{
			Error:           "target\u200d failed",
			PlatformResults: []scanner.PlatformResult{{Error: "soft\u00adhyphen", Diagnostics: []scanner.Diagnostic{{Message: "m\u2066sg", Subject: "s\ufeffub"}}}},
		}},
		Diagnostics: []scanner.Diagnostic{{Message: "\u202ascan", Subject: "x\u200by"}},
	}
	public := PublicResult(result)
	checks := []struct{ field, got, want string }{
		{"tag_results[0].error", public.TagResults[0].Error, "denied lanretxe"},
		{"targets[0].error", public.Targets[0].Error, "target failed"},
		{"platform_results[0].error", public.Targets[0].PlatformResults[0].Error, "softhyphen"},
		{"platform diagnostic message", public.Targets[0].PlatformResults[0].Diagnostics[0].Message, "msg"},
		{"platform diagnostic subject", public.Targets[0].PlatformResults[0].Diagnostics[0].Subject, "sub"},
		{"diagnostics[0].message", public.Diagnostics[0].Message, "scan"},
		{"diagnostics[0].subject", public.Diagnostics[0].Subject, "xy"},
	}
	for _, check := range checks {
		if check.got != check.want {
			t.Errorf("%s = %q, want %q", check.field, check.got, check.want)
		}
	}
}
