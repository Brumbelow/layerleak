package findings

import (
	"math/rand"
	"strings"
	"testing"
)

// DET-08: a redacted value must not disclose most of a short password, its
// suffix, or its length. Short values are fully masked; longer values reveal
// only a short prefix; the asterisk run is always the same length.

func TestRedactMasksShortValuesCompletely(t *testing.T) {
	for _, value := range []string{"a", "hunter2", "abcdefgh", "Passw0rd12", "elevenchars", "Pässwörd-11"} {
		if got := Redact(value); got != "********" {
			t.Fatalf("Redact(%q) = %q, want a fixed full mask", value, got)
		}
	}
}

func TestRedactRevealsOnlyAShortPrefixOfLongValues(t *testing.T) {
	tests := []struct {
		value string
		want  string
	}{
		{value: "Passw0rd1234", want: "Pas********"},
		{value: "ghp_123456789012345678901234567890123456", want: "ghp********"},
		{value: "AKIA" + strings.Repeat("A", 16), want: "AKI********"},
		{value: "日本語のとても長い秘密の値です", want: "日本語********"},
		{value: strings.Repeat("x", 500), want: "xxx********"},
	}
	for _, tt := range tests {
		if got := Redact(tt.value); got != tt.want {
			t.Fatalf("Redact(%q) = %q, want %q", tt.value, got, tt.want)
		}
	}
}

func TestRedactNeverDisclosesLengthOrSuffix(t *testing.T) {
	rng := rand.New(rand.NewSource(0x5eed)) //nolint:gosec // deterministic test data, not security material
	alphabet := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=_-.:@éü語")
	for trial := 0; trial < 2000; trial++ {
		length := 1 + rng.Intn(120)
		runes := make([]rune, length)
		for index := range runes {
			runes[index] = alphabet[rng.Intn(len(alphabet))]
		}
		value := string(runes)
		got := []rune(Redact(value))
		wantLength := 8
		if length >= 12 {
			wantLength = 11
			if string(got[:3]) != string(runes[:3]) {
				t.Fatalf("Redact(%q) = %q: prefix changed", value, string(got))
			}
		}
		if len(got) != wantLength {
			t.Fatalf("Redact(%q) = %q: length %d discloses the input length", value, string(got), len(got))
		}
		if strings.TrimLeft(string(got[len(got)-8:]), "*") != "" {
			t.Fatalf("Redact(%q) = %q: suffix leaks characters", value, string(got))
		}
	}
}

func TestRedactKeepsMultilineMarkerAndSanitizesControlCharacters(t *testing.T) {
	if got := Redact("line one\nline two"); got != "[REDACTED MULTILINE]" {
		t.Fatalf("Redact(multiline) = %q", got)
	}
	if got := Redact("\x00\x01\x02" + strings.Repeat("a", 20)); got != "���********" {
		t.Fatalf("Redact(control prefix) = %q", got)
	}
}
