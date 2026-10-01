package detectors

import (
	"strings"
	"testing"

	"github.com/brumbelow/layerleak/v3/internal/detectionpolicy"
)

// DET-22: path weighting must match whole words of the path, not substrings.
func TestSensitivePathMatchesWholeWords(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{path: "/opt/keycloak/conf/x.txt", want: false},
		{path: "/usr/share/keyrings/ubuntu.gpg", want: false},
		{path: "/app/tokenizer/vocab.txt", want: false},
		{path: "/usr/lib/python3/monkey.py", want: false},
		{path: "/usr/bin/docker", want: false},
		{path: "/etc/secrets/db.yaml", want: true},
		{path: "/etc/ssl/private/server.key", want: true},
		{path: "/app/credentials.json", want: true},
		{path: "/app/api-token.txt", want: true},
		{path: "/root/.docker/config.json", want: true},
		{path: "/opt/app/.docker/auth", want: true},
		{path: "/app/.env", want: true},
		{path: "/home/user/.ssh/id_ed25519", want: true},
	}
	for _, tt := range tests {
		if got := sensitivePath(tt.path); got != tt.want {
			t.Fatalf("sensitivePath(%q) = %t, want %t", tt.path, got, tt.want)
		}
	}

	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.signaturetoken"
	under := func(path string) Confidence {
		match, ok := findDetectorMatch(Default().Scan(ScanInput{Path: path, Content: jwt}), "json_web_token")
		if !ok {
			t.Fatalf("expected jwt under %s", path)
		}
		return match.Confidence
	}
	if got := under("/opt/keycloak/conf/x.txt"); got != ConfidenceMedium {
		t.Fatalf("jwt under keycloak path = %q, want medium", got)
	}
	if got := under("/opt/app/secrets/x.txt"); got != ConfidenceHigh {
		t.Fatalf("jwt under secrets path = %q, want high", got)
	}
}

// DET-24: a lower-priority match nested inside a higher-priority one is the
// same credential twice; only the intentional structured nesting stays.
func TestNestedLowerPriorityMatchesAreDropped(t *testing.T) {
	set := Default()
	url := "https://deploy:Xk9fL2mQ8vR4tY7wZ1aB3cD5@db.internal"
	matches := set.Scan(ScanInput{Path: "/app/config.yaml", Content: "database_password_url: " + url + "/app\n"})
	if len(matches) != 1 || matches[0].Detector != "basic_auth_url" {
		t.Fatalf("matches = %#v, want only basic_auth_url", matches)
	}

	connection := "postgres://app:Xk9fL2mQ8vR4tY7wZ1aB3cD5@db.internal:5432"
	matches = set.Scan(ScanInput{Key: "DATABASE_PASSWORD_URL", Content: "DATABASE_PASSWORD_URL=" + connection + "/app"})
	if len(matches) != 1 || matches[0].Detector != "connection_url_credentials" {
		t.Fatalf("matches = %#v, want only connection_url_credentials", matches)
	}

	// Intentional nesting: the structured password inside the whole-URL match
	// has the higher priority and is kept alongside it.
	matches = set.Scan(ScanInput{Path: "/root/.git-credentials", Content: "https://deploy:Xk9fL2mQ8vR4tY7wZ1aB3cD5@github.com/org/repo.git\n"})
	names := make([]string, 0, len(matches))
	for _, match := range matches {
		names = append(names, match.Detector)
	}
	if strings.Join(names, ",") != "basic_auth_url,git_credentials_password" {
		t.Fatalf("detectors = %v", names)
	}
}

// DET-16: placeholder pairs on real hosts reach the policy layer as matches so
// they can be reported as suppressed default credentials.
func TestDefaultCredentialPairsReachThePolicyLayer(t *testing.T) {
	content := "DATABASE_URL=postgres://admin:admin@db.internal/app"
	match, ok := findDetectorMatch(Default().Scan(ScanInput{Content: content}), "connection_url_credentials")
	if !ok {
		t.Fatal("expected connection_url_credentials for a default pair on a real host")
	}
	if got := detectionpolicy.ExampleReason("/app/.env", "", content, match.Value); got != detectionpolicy.ReasonDefaultCredentials {
		t.Fatalf("ExampleReason() = %q, want default_credentials", got)
	}
	for _, match := range Default().Scan(ScanInput{Content: "https://admin:admin@example.com/"}) {
		if match.Detector == "basic_auth_url" {
			t.Fatalf("default pair on a reserved host was not discarded: %#v", match)
		}
	}
}
