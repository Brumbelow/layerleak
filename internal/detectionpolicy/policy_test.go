package detectionpolicy

import (
	"encoding/base64"
	"testing"
)

func TestDiscardReason(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{
			name:  "empty",
			value: "",
			want:  ReasonDiscardEmpty,
		},
		{
			name:  "whitespace only",
			value: "   \t  ",
			want:  ReasonDiscardEmpty,
		},
		{
			name:  "real-looking value",
			value: "AKIAIOSFODNN7EXAMPLE-real-looking",
			want:  ReasonNone,
		},
		{
			name:  "foobar literal",
			value: "foobar",
			want:  ReasonDiscardPlaceholder,
		},
		{
			name:  "foo:bar literal",
			value: "user=foo:bar",
			want:  ReasonDiscardPlaceholder,
		},
		{
			name:  "user@example.com literal",
			value: "user@example.com",
			want:  ReasonDiscardPlaceholder,
		},
		{
			name:  "test email literal",
			value: "test@example.com",
			want:  ReasonDiscardPlaceholder,
		},
		{
			name:  "base64 encoded foobar",
			value: base64.StdEncoding.EncodeToString([]byte("foobar")),
			want:  ReasonDiscardPlaceholder,
		},
		{
			name:  "base64 raw url encoded foobar",
			value: base64.RawURLEncoding.EncodeToString([]byte("admin@example.com")),
			want:  ReasonDiscardPlaceholder,
		},
		{
			name:  "url with foobar credentials",
			value: "https://foobar:secret@host.example/path",
			want:  ReasonDiscardPlaceholder,
		},
		{
			name:  "url with foo:bar password",
			value: "https://user:foo:bar@example.com/x",
			want:  ReasonDiscardPlaceholder,
		},
		{
			name:  "admin:admin credentials in url",
			value: "https://admin:admin@db.internal/",
			want:  ReasonDiscardPlaceholder,
		},
		{
			name:  "admin:password credentials in url",
			value: "https://admin:password@db.internal/",
			want:  ReasonDiscardPlaceholder,
		},
		{
			name:  "root:password credentials in url",
			value: "https://root:password@db.internal/",
			want:  ReasonDiscardPlaceholder,
		},
		{
			name:  "placeholder prefix in real credential",
			value: "https://admin:passwordREALSECRET@db.internal/",
			want:  ReasonNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DiscardReason(tt.value)
			if got != tt.want {
				t.Fatalf("DiscardReason(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestExampleReason(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		key      string
		line     string
		value    string
		want     string
	}{
		{
			name:     "real-looking actionable finding",
			filePath: "etc/app/config.yaml",
			key:      "API_KEY",
			line:     "API_KEY=sk_live_abcdefghijklmnop",
			value:    "sk_live_abcdefghijklmnop",
			want:     ReasonNone,
		},
		{
			name:     "test path wins immediately",
			filePath: "internal/foo/tests/fixtures/config.yaml",
			key:      "API_KEY",
			line:     "API_KEY=sk_live_realvalue",
			value:    "sk_live_realvalue",
			want:     ReasonTestPath,
		},
		{
			name:     "example filename wins after test path",
			filePath: "etc/.env.example",
			key:      "API_KEY",
			line:     "API_KEY=sk_live_realvalue",
			value:    "sk_live_realvalue",
			want:     ReasonExamplePath,
		},
		{
			name:     "known dummy value is suppressed",
			filePath: "etc/config.yaml",
			key:      "API_KEY",
			line:     "API_KEY=changeme",
			value:    "changeme",
			want:     ReasonKnownDummyValue,
		},
		{
			name:     "EXAMPLE substring in value",
			filePath: "etc/config.yaml",
			key:      "API_KEY",
			line:     "API_KEY=AKIAIOSFODNN7EXAMPLE",
			value:    "AKIAIOSFODNN7EXAMPLE",
			want:     ReasonKnownDummyValue,
		},
		{
			name:     "placeholder marker in line",
			filePath: "etc/config.yaml",
			key:      "API_KEY",
			line:     "API_KEY=YOUR_TOKEN_HERE",
			value:    "YOUR_TOKEN_HERE",
			want:     ReasonKnownDummyValue,
		},
		{
			name:     "placeholder marker in key only",
			filePath: "etc/config.yaml",
			key:      "FAKE_API_KEY",
			line:     "FAKE_API_KEY=sk_live_real",
			value:    "sk_live_real",
			want:     ReasonPlaceholderMarker,
		},
		{
			name:     "weak example path alone is not enough",
			filePath: "docs/usage.md",
			key:      "API_KEY",
			line:     "API_KEY=sk_live_real",
			value:    "sk_live_real",
			want:     ReasonNone,
		},
		{
			name:     "weak example path plus reserved host = suppressed",
			filePath: "docs/usage.md",
			key:      "API_KEY",
			line:     "url=https://example.com/api API_KEY=sk_live_real",
			value:    "sk_live_real",
			want:     ReasonExamplePath,
		},
		{
			name:     "reserved host plus example key = suppressed",
			filePath: "etc/config.yaml",
			key:      "EXAMPLE_API_KEY",
			line:     "EXAMPLE_API_KEY=token-on-localhost",
			value:    "token-on-localhost",
			want:     ReasonReservedHost,
		},
		{
			name:     "reserved host alone is not enough",
			filePath: "etc/config.yaml",
			key:      "API_KEY",
			line:     "API_KEY=real on localhost",
			value:    "real",
			want:     ReasonNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExampleReason(tt.filePath, tt.key, tt.line, tt.value)
			if got != tt.want {
				t.Fatalf("ExampleReason(%q, %q, %q, %q) = %q, want %q", tt.filePath, tt.key, tt.line, tt.value, got, tt.want)
			}
		})
	}
}

func TestTestPathReason(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     string
	}{
		{name: "empty", filePath: "", want: ReasonNone},
		{name: "single dot", filePath: ".", want: ReasonNone},
		{name: "production path", filePath: "etc/config.yaml", want: ReasonNone},
		{name: "test segment", filePath: "src/test/config.yaml", want: ReasonTestPath},
		{name: "tests segment", filePath: "src/tests/config.yaml", want: ReasonTestPath},
		{name: "__tests__ segment", filePath: "src/__tests__/snap", want: ReasonTestPath},
		{name: "fixture segment", filePath: "internal/fixture/data", want: ReasonTestPath},
		{name: "fixtures segment", filePath: "internal/fixtures/data", want: ReasonTestPath},
		{name: "mock segment", filePath: "internal/mock/server.go", want: ReasonTestPath},
		{name: "mocks segment", filePath: "internal/mocks/server.go", want: ReasonTestPath},
		{name: "__mocks__ segment", filePath: "src/__mocks__/module.js", want: ReasonTestPath},
		{name: "spec segment", filePath: "src/spec/fixtures.rb", want: ReasonTestPath},
		{name: "specs segment", filePath: "src/specs/fixtures.rb", want: ReasonTestPath},
		{name: "testdata segment", filePath: "internal/scanner/testdata/config.yaml", want: ReasonTestPath},
		{name: "windows-style backslash path", filePath: "src\\tests\\config.yaml", want: ReasonTestPath},
		{name: "case-insensitive", filePath: "src/TESTS/config.yaml", want: ReasonTestPath},
		{name: "test substring not whole segment", filePath: "src/contest/config.yaml", want: ReasonNone},
		{name: "test segment with trailing space", filePath: "src/tests /config.yaml", want: ReasonNone},
		{name: "e2e segment", filePath: "src/e2e/config.yaml", want: ReasonTestPath},
		{name: "acceptance segment", filePath: "src/acceptance/config.yaml", want: ReasonTestPath},
		{name: "stubs segment", filePath: "src/stubs/server.go", want: ReasonTestPath},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TestPathReason(tt.filePath)
			if got != tt.want {
				t.Fatalf("TestPathReason(%q) = %q, want %q", tt.filePath, got, tt.want)
			}
		})
	}
}

func TestExampleFilenameReason(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     string
	}{
		{name: "empty", filePath: "", want: ReasonNone},
		{name: "production filename", filePath: ".env", want: ReasonNone},
		{name: ".env.example", filePath: ".env.example", want: ReasonExamplePath},
		{name: ".env.sample", filePath: "config/.env.sample", want: ReasonExamplePath},
		{name: ".env.template", filePath: "config/.env.template", want: ReasonExamplePath},
		{name: "config.example.yaml", filePath: "etc/config.example.yaml", want: ReasonExamplePath},
		{name: "case insensitive", filePath: "etc/CONFIG.EXAMPLE.YAML", want: ReasonExamplePath},
		{name: "windows path", filePath: "etc\\config.example.yaml", want: ReasonExamplePath},
		{name: "example suffix with trailing space", filePath: "etc/.env.example ", want: ReasonNone},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExampleFilenameReason(tt.filePath)
			if got != tt.want {
				t.Fatalf("ExampleFilenameReason(%q) = %q, want %q", tt.filePath, got, tt.want)
			}
		})
	}
}

func TestFirstReason(t *testing.T) {
	if got := firstReason(ReasonNone, ReasonTestPath); got != ReasonTestPath {
		t.Fatalf("firstReason(none, test) = %q, want %q", got, ReasonTestPath)
	}
	if got := firstReason(ReasonExamplePath, ReasonTestPath); got != ReasonExamplePath {
		t.Fatalf("firstReason(example, test) = %q, want %q", got, ReasonExamplePath)
	}
	if got := firstReason(ReasonNone, ReasonNone); got != ReasonNone {
		t.Fatalf("firstReason(none, none) = %q, want %q", got, ReasonNone)
	}
}

func TestDiscardValueCandidatesIncludesBase64Decoded(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("foobar"))
	candidates := discardValueCandidates(encoded)

	wantOriginal := false
	wantDecoded := false
	for _, candidate := range candidates {
		if candidate == encoded || candidate == "" {
			wantOriginal = wantOriginal || candidate != ""
			continue
		}
		if candidate == "foobar" {
			wantDecoded = true
		}
	}

	// At minimum, the trimmed lowercase original is always present.
	if len(candidates) < 1 {
		t.Fatalf("discardValueCandidates(%q) returned no candidates", encoded)
	}
	if !wantDecoded {
		t.Fatalf("discardValueCandidates(%q) = %v, expected to include decoded %q", encoded, candidates, "foobar")
	}
	_ = wantOriginal
}

func TestDiscardValueCandidatesSkipsNonPrintableDecoded(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte{0x00, 0x01, 0x02})
	candidates := discardValueCandidates(encoded)

	for _, candidate := range candidates {
		for _, r := range candidate {
			if r < 0x20 && r != '\t' && r != '\n' && r != '\r' && r != ' ' {
				t.Fatalf("discardValueCandidates(%q) leaked non-printable candidate %q", encoded, candidate)
			}
		}
	}
}

func TestIsPrintableText(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "ascii text", value: "hello world", want: true},
		{name: "with tabs", value: "a\tb", want: true},
		{name: "with newline", value: "a\nb", want: true},
		{name: "control char", value: "a\x01b", want: false},
		{name: "null byte", value: "a\x00b", want: false},
		{name: "empty", value: "", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPrintableText(tt.value); got != tt.want {
				t.Fatalf("isPrintableText(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestHasReservedHostSignal(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "example.com", value: "https://example.com/api", want: true},
		{name: "example.org", value: "https://example.org/", want: true},
		{name: "example.net", value: "https://example.net/", want: true},
		{name: "localhost", value: "http://LOCALHOST:8080", want: true},
		{name: "loopback ipv4", value: "http://127.0.0.1:5432", want: true},
		{name: "wildcard bind", value: "0.0.0.0:8080", want: true},
		{name: "real domain", value: "https://api.acme.com/", want: false},
		{name: "empty", value: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasReservedHostSignal(tt.value); got != tt.want {
				t.Fatalf("hasReservedHostSignal(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestHasKnownDummyValueSignal(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "empty", value: "", want: false},
		{name: "whitespace only", value: "   ", want: false},
		{name: "EXAMPLE substring upper", value: "AKIAIOSFODNN7EXAMPLE", want: true},
		{name: "example substring lower triggers via upper", value: "myexamplekey", want: true},
		{name: "changeme literal", value: "changeme", want: true},
		{name: "quoted changeme", value: `"changeme"`, want: true},
		{name: "real-looking", value: "sk_live_abcdef", want: false},
		{name: "your_token_here", value: "your_token_here", want: true},
		{name: "your_secret_here", value: "your_secret_here", want: true},
		{name: "PLACEHOLDER substring", value: "sk-ant-api03-PLACEHOLDERPLACEHOLDER1234", want: true},
		{name: "placeholder mixed case", value: "ghp_PlaceholderValueForDocumentation", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasKnownDummyValueSignal(tt.value); got != tt.want {
				t.Fatalf("hasKnownDummyValueSignal(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestHasPlaceholderMarkerSignal(t *testing.T) {
	if !hasPlaceholderMarkerSignal("placeholder for token") {
		t.Fatal("expected 'placeholder' to trigger marker signal")
	}
	if !hasPlaceholderMarkerSignal("", "", "PLEASE CHANGEME", "") {
		t.Fatal("expected 'changeme' anywhere in args to trigger")
	}
	if !hasPlaceholderMarkerSignal("REPLACE_ME") {
		t.Fatal("expected 'replace_me' to trigger")
	}
	if !hasPlaceholderMarkerSignal("your_api_key_here") {
		t.Fatal("expected 'your_api_key_here' to trigger")
	}
	if !hasPlaceholderMarkerSignal("insert_token") {
		t.Fatal("expected 'insert_token' to trigger")
	}
	if !hasPlaceholderMarkerSignal("token_goes_here") {
		t.Fatal("expected 'token_goes_here' to trigger")
	}
	if hasPlaceholderMarkerSignal("ordinary text") {
		t.Fatal("did not expect ordinary text to trigger")
	}
}

func TestHasWeakExamplePathSignal(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{name: "examples segment", filePath: "examples/foo.yaml", want: true},
		{name: "sample segment", filePath: "sample/foo.yaml", want: true},
		{name: "demo segment", filePath: "demo/foo.yaml", want: true},
		{name: "demos segment", filePath: "demos/foo.yaml", want: true},
		{name: "doc segment", filePath: "doc/foo.md", want: true},
		{name: "docs segment", filePath: "docs/foo.md", want: true},
		{name: "production path", filePath: "etc/foo.yaml", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasWeakExamplePathSignal(tt.filePath); got != tt.want {
				t.Fatalf("hasWeakExamplePathSignal(%q) = %v, want %v", tt.filePath, got, tt.want)
			}
		})
	}
}

func TestHasWeakExampleKeySignal(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want bool
	}{
		{name: "EXAMPLE_KEY", key: "EXAMPLE_KEY", want: true},
		{name: "sample_key", key: "sample_key", want: true},
		{name: "demo-token", key: "demo-token", want: true},
		{name: "API_KEY", key: "API_KEY", want: false},
		{name: "empty", key: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasWeakExampleKeySignal(tt.key); got != tt.want {
				t.Fatalf("hasWeakExampleKeySignal(%q) = %v, want %v", tt.key, got, tt.want)
			}
		})
	}
}

func TestNormalizedPathParts(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     []string
	}{
		{name: "empty", filePath: "", want: nil},
		{name: "dot", filePath: ".", want: nil},
		{name: "root", filePath: "/", want: nil},
		{name: "simple", filePath: "etc/config.yaml", want: []string{"etc", "config.yaml"}},
		{name: "windows backslash", filePath: "etc\\config.yaml", want: []string{"etc", "config.yaml"}},
		{name: "uppercase normalized", filePath: "ETC/Config.YAML", want: []string{"etc", "config.yaml"}},
		{name: "redundant separators", filePath: "etc//config.yaml", want: []string{"etc", "config.yaml"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizedPathParts(tt.filePath)
			if !equalStringSlices(got, tt.want) {
				t.Fatalf("normalizedPathParts(%q) = %v, want %v", tt.filePath, got, tt.want)
			}
		})
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
