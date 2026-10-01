package detectionpolicy

import "testing"

// DET-15: suppression heuristics must not hide real secrets.

func TestExampleReasonIgnoresMarkersInTrailingComments(t *testing.T) {
	token := "ghp_" + "123456789012345678901234567890123456"
	tests := []struct {
		name     string
		filePath string
		key      string
		line     string
		want     string
	}{
		{name: "todo replace this in a comment", filePath: "/app/.env", key: "", line: "GH_TOKEN=" + token + " # TODO replace this with vault lookup", want: ReasonNone},
		{name: "dummy in a comment", filePath: "/app/.env", key: "", line: "GH_TOKEN=" + token + " # dummy account for CI", want: ReasonNone},
		{name: "js comment", filePath: "/app/config.js", key: "", line: "  token: \"" + token + "\", // placeholder until vault", want: ReasonNone},
		{name: "marker in the key still counts", filePath: "/app/.env", key: "", line: "FAKE_GH_TOKEN=" + token, want: ReasonPlaceholderMarker},
		{name: "marker in the value still counts", filePath: "/app/.env", key: "", line: "GH_TOKEN=ghp_PlaceholderPlaceholderPlaceholder12", want: ReasonKnownDummyValue},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value := token
			if tt.want == ReasonKnownDummyValue {
				value = "ghp_PlaceholderPlaceholderPlaceholder12"
			}
			if got := ExampleReason(tt.filePath, tt.key, tt.line, value); got != tt.want {
				t.Fatalf("ExampleReason() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExampleReasonTreatsPathMarkersAsWeak(t *testing.T) {
	token := "ghp_" + "123456789012345678901234567890123456"
	if got := ExampleReason("/app/node_modules/@faker-js/faker/.npmrc", "", "//registry.npmjs.org/:_authToken="+token, token); got != ReasonNone {
		t.Fatalf("path marker alone suppressed a real token: %q", got)
	}
	if got := ExampleReason("/app/node_modules/@faker-js/faker/docs/.npmrc", "", "//registry.npmjs.org/:_authToken="+token, token); got != ReasonExamplePath {
		t.Fatalf("path marker plus docs segment = %q, want example_path", got)
	}
}

func TestTestPathReasonKeepsProductionDirectoriesActionable(t *testing.T) {
	for _, filePath := range []string{
		"/app/config/spec/production.yaml",
		"/usr/src/packages/SPECS/app.env",
		"/app/e2e/prod.env",
		"/app/acceptance/config.yaml",
		"/app/stubs/server.go",
		"/app/mock/handlers.js",
		"/app/mocks/handlers.js",
		"/app/fixture/data.json",
	} {
		if got := TestPathReason(filePath); got != ReasonNone {
			t.Fatalf("TestPathReason(%q) = %q, want none", filePath, got)
		}
	}
	for _, filePath := range []string{"app/tests/.env", "app/test/.env", "src/__tests__/snap", "internal/testdata/x", "internal/fixtures/x", "src/__mocks__/m.js"} {
		if got := TestPathReason(filePath); got != ReasonTestPath {
			t.Fatalf("TestPathReason(%q) = %q, want test_path", filePath, got)
		}
	}
	// A demoted segment still counts as a weak signal.
	if got := ExampleReason("/app/spec/config.yaml", "EXAMPLE_API_KEY", "EXAMPLE_API_KEY=sk_live_real", "sk_live_real"); got != ReasonExamplePath {
		t.Fatalf("spec segment plus example key = %q, want example_path", got)
	}
}

func TestKnownDummyValueJudgesURLsByTheirCredentials(t *testing.T) {
	if hasKnownDummyValueSignal("https://deploy:RealPassw0rd@git.examplecorp.internal/repo.git") {
		t.Fatal("example in the host name suppressed a real credential")
	}
	if !hasKnownDummyValueSignal("https://deploy:EXAMPLEpassword@git.internal/repo.git") {
		t.Fatal("EXAMPLE in the password was not recognised")
	}
	if got := ExampleReason("/app/.git-credentials", "", "https://deploy:RealPassw0rd@git.examplecorp.internal/repo.git", "https://deploy:RealPassw0rd@git.examplecorp.internal/repo.git"); got != ReasonNone {
		t.Fatalf("ExampleReason() = %q, want none", got)
	}
}

func TestTemplateFilenameIsAWeakSignal(t *testing.T) {
	if got := ExampleFilenameReason("/etc/nginx/nginx.conf.template"); got != ReasonNone {
		t.Fatalf("ExampleFilenameReason(template) = %q, want none", got)
	}
	token := "ghp_" + "123456789012345678901234567890123456"
	if got := ExampleReason("/etc/nginx/nginx.conf.template", "", "proxy_set_header Authorization "+token+";", token); got != ReasonNone {
		t.Fatalf("template alone suppressed a real token: %q", got)
	}
	if got := ExampleReason("/app/docs/.env.template", "", "GH_TOKEN="+token, token); got != ReasonExamplePath {
		t.Fatalf("template plus docs segment = %q, want example_path", got)
	}
	for _, filePath := range []string{"etc/.env.example", "config/.env.sample", "etc/config.example.yaml"} {
		if got := ExampleFilenameReason(filePath); got != ReasonExamplePath {
			t.Fatalf("ExampleFilenameReason(%q) = %q", filePath, got)
		}
	}
}

// DET-16: default-credential pairs are findings, suppressed with a reason,
// not silently discarded, unless they sit on a reserved/example host.
func TestDefaultCredentialPairsAreSuppressedNotDiscarded(t *testing.T) {
	tests := []struct {
		value       string
		wantDiscard string
		wantExample string
	}{
		{value: "https://admin:admin@prod-db.internal/", wantDiscard: ReasonNone, wantExample: ReasonDefaultCredentials},
		{value: "postgres://postgres:postgres@db.internal:5432/app", wantDiscard: ReasonNone, wantExample: ReasonDefaultCredentials},
		{value: "amqp://guest:guest@rabbit.internal:5672/", wantDiscard: ReasonNone, wantExample: ReasonDefaultCredentials},
		{value: "https://root:password@db.internal/", wantDiscard: ReasonNone, wantExample: ReasonDefaultCredentials},
		{value: "https://foobar:secret@host.example/path", wantDiscard: ReasonNone, wantExample: ReasonKnownDummyValue},
		{value: "https://admin:admin@example.com/", wantDiscard: ReasonDiscardPlaceholder, wantExample: ReasonNone},
		{value: "https://foo:bar@example.com/config", wantDiscard: ReasonDiscardPlaceholder, wantExample: ReasonNone},
		{value: "https://user:user@localhost:8080/", wantDiscard: ReasonDiscardPlaceholder, wantExample: ReasonNone},
		{value: "https://admin:Sup3rS3cretPw@prod-db.internal/", wantDiscard: ReasonNone, wantExample: ReasonNone},
		{value: "foobar", wantDiscard: ReasonDiscardPlaceholder, wantExample: ReasonNone},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			if got := DiscardReason(tt.value); got != tt.wantDiscard {
				t.Fatalf("DiscardReason() = %q, want %q", got, tt.wantDiscard)
			}
			if tt.wantDiscard != ReasonNone {
				return
			}
			if got := ExampleReason("/app/config.yaml", "DATABASE_URL", "DATABASE_URL="+tt.value, tt.value); got != tt.wantExample {
				t.Fatalf("ExampleReason() = %q, want %q", got, tt.wantExample)
			}
		})
	}
}
