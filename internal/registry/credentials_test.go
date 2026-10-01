package registry

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
)

const (
	testUsername = "scanner-bot"
	testPassword = "synthetic-password-not-real-0001"
)

func assertNoSecret(t *testing.T, label, text string) {
	t.Helper()
	encoded := base64.StdEncoding.EncodeToString([]byte(testUsername + ":" + testPassword))
	for _, secret := range []string{testPassword, encoded} {
		if strings.Contains(text, secret) {
			t.Fatalf("%s leaks a secret: %q", label, text)
		}
	}
}

func TestNormalizeCredentialHost(t *testing.T) {
	tests := map[string]string{
		"ghcr.io":                         "ghcr.io",
		"GHCR.IO":                         "ghcr.io",
		"https://ghcr.io":                 "ghcr.io",
		"https://ghcr.io/":                "ghcr.io",
		"https://ghcr.io/v2/":             "ghcr.io",
		"localhost:5000":                  "localhost:5000",
		"http://localhost:5000/":          "localhost:5000",
		"registry.internal.":              "registry.internal",
		"[::1]:5000":                      "[::1]:5000",
		"user@registry.example":           "registry.example",
		"docker.io":                       dockerHubLookupHost,
		"index.docker.io":                 dockerHubLookupHost,
		"registry-1.docker.io":            dockerHubLookupHost,
		"https://index.docker.io/v1/":     dockerHubLookupHost,
		"https://registry-1.docker.io/v2": dockerHubLookupHost,
		"":                                "",
		"   ":                             "",
		"https://":                        "",
		"bad host":                        "",
	}
	for input, want := range tests {
		if got := normalizeCredentialHost(input); got != want {
			t.Errorf("normalizeCredentialHost(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestStaticCredentialsMatchOnlyTheBoundHost(t *testing.T) {
	source := StaticCredentials("ghcr.io", testUsername, testPassword)
	ctx := context.Background()

	credential, ok, err := source.Lookup(ctx, "ghcr.io")
	if err != nil || !ok {
		t.Fatalf("Lookup(ghcr.io) = (%v, %v, %v)", credential, ok, err)
	}
	if credential.Username != testUsername || credential.Password != testPassword {
		t.Fatalf("Lookup(ghcr.io) returned a different credential")
	}
	for _, host := range []string{"ghcr.io:5000", "registry.example", "cdn.ghcr.io", "", "index.docker.io"} {
		if _, ok, err := source.Lookup(ctx, host); ok || err != nil {
			t.Fatalf("Lookup(%q) = (ok=%v, err=%v), want no match", host, ok, err)
		}
	}
}

func TestStaticCredentialsResolveDockerHubAliases(t *testing.T) {
	source := StaticCredentials("docker.io", testUsername, testPassword)
	for _, host := range []string{"registry-1.docker.io", "index.docker.io", "docker.io", "https://index.docker.io/v1/"} {
		if _, ok, err := source.Lookup(context.Background(), host); !ok || err != nil {
			t.Fatalf("Lookup(%q) = (ok=%v, err=%v), want match", host, ok, err)
		}
	}
}

func TestStaticCredentialsWithoutValuesNeverMatch(t *testing.T) {
	for name, source := range map[string]CredentialSource{
		"empty credential": StaticCredentials("ghcr.io", "", ""),
		"empty host":       StaticCredentials("", testUsername, testPassword),
		"invalid host":     StaticCredentials("https://", testUsername, testPassword),
	} {
		if _, ok, err := source.Lookup(context.Background(), "ghcr.io"); ok || err != nil {
			t.Fatalf("%s: Lookup() = (ok=%v, err=%v)", name, ok, err)
		}
	}
	var nilStatic *staticCredentials
	if _, ok, err := nilStatic.Lookup(context.Background(), "ghcr.io"); ok || err != nil {
		t.Fatalf("nil static Lookup() = (ok=%v, err=%v)", ok, err)
	}
}

type stubCredentialSource struct {
	credential Credential
	ok         bool
	err        error
	calls      int
}

func (s *stubCredentialSource) Lookup(context.Context, string) (Credential, bool, error) {
	s.calls++
	return s.credential, s.ok, s.err
}

func TestChainCredentialsFirstMatchWins(t *testing.T) {
	first := &stubCredentialSource{}
	second := &stubCredentialSource{credential: Credential{Username: "second", Password: "p2"}, ok: true}
	third := &stubCredentialSource{credential: Credential{Username: "third", Password: "p3"}, ok: true}
	chain := ChainCredentials(first, nil, second, third)

	credential, ok, err := chain.Lookup(context.Background(), "registry.example")
	if err != nil || !ok || credential.Username != "second" {
		t.Fatalf("Lookup() = (%v, %v, %v)", credential, ok, err)
	}
	if first.calls != 1 || second.calls != 1 || third.calls != 0 {
		t.Fatalf("calls = (%d, %d, %d)", first.calls, second.calls, third.calls)
	}
}

func TestChainCredentialsStopsOnError(t *testing.T) {
	failure := errors.New("helper unsupported")
	first := &stubCredentialSource{err: failure}
	second := &stubCredentialSource{credential: Credential{Username: "second", Password: "p2"}, ok: true}
	chain := ChainCredentials(first, second)

	_, ok, err := chain.Lookup(context.Background(), "registry.example")
	if !errors.Is(err, failure) || ok {
		t.Fatalf("Lookup() = (ok=%v, err=%v)", ok, err)
	}
	if second.calls != 0 {
		t.Fatalf("second source consulted after an error")
	}
}

func TestChainCredentialsEmptyReportsNoMatch(t *testing.T) {
	if _, ok, err := ChainCredentials(nil, nil).Lookup(context.Background(), "registry.example"); ok || err != nil {
		t.Fatalf("Lookup() = (ok=%v, err=%v)", ok, err)
	}
}

func TestCredentialIdentityScopesByUserAndPassword(t *testing.T) {
	anonymous := Credential{}
	first := Credential{Username: testUsername, Password: testPassword}
	samePassword := Credential{Username: "other-user", Password: testPassword}
	otherPassword := Credential{Username: testUsername, Password: "synthetic-password-not-real-0002"}

	if anonymous.identity() != "anonymous" {
		t.Fatalf("anonymous identity = %q", anonymous.identity())
	}
	identities := map[string]bool{first.identity(): true, samePassword.identity(): true, otherPassword.identity(): true}
	if len(identities) != 3 {
		t.Fatalf("identities collide: %v", identities)
	}
	if first.identity() != (Credential{Username: testUsername, Password: testPassword}).identity() {
		t.Fatal("identity is not stable")
	}
	for identity := range identities {
		assertNoSecret(t, "identity", identity)
		if strings.Contains(identity, testUsername) {
			t.Fatalf("identity %q contains the username", identity)
		}
	}
}

func TestCredentialFormattingRedactsSecrets(t *testing.T) {
	credential := Credential{Username: testUsername, Password: testPassword}
	for verb, text := range map[string]string{
		"%v":  fmt.Sprintf("%v", credential),
		"%+v": fmt.Sprintf("%+v", credential),
		"%#v": fmt.Sprintf("%#v", credential),
		"%q":  fmt.Sprintf("%q", credential),
	} {
		assertNoSecret(t, verb, text)
		if strings.Contains(text, testUsername) {
			t.Fatalf("%s reveals the username: %q", verb, text)
		}
		if !strings.Contains(text, "redacted") {
			t.Fatalf("%s = %q, want a redaction marker", verb, text)
		}
	}
}

func TestOptionsFormattingRedactsCredentialSources(t *testing.T) {
	options := Options{
		BaseURL: "https://ghcr.io",
		Credentials: ChainCredentials(
			StaticCredentials("ghcr.io", testUsername, testPassword),
			DockerConfigCredentials("/nonexistent/config.json"),
		),
	}
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		text := fmt.Sprintf(verb, options)
		assertNoSecret(t, "Options "+verb, text)
		if strings.Contains(text, testUsername) {
			t.Fatalf("Options %s reveals the username: %q", verb, text)
		}
	}
	text := fmt.Sprintf("%+v", options.Credentials)
	if !strings.Contains(text, "ghcr.io") || !strings.Contains(text, "/nonexistent/config.json") {
		t.Fatalf("credential source description = %q, want host and path", text)
	}

	client := MustNewClient(Options{BaseURL: "https://ghcr.io", AllowPrivateHosts: true, Credentials: options.Credentials})
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		assertNoSecret(t, "Client "+verb, fmt.Sprintf(verb, client))
	}
	var nilStatic *staticCredentials
	var nilDocker *dockerConfigSource
	if fmt.Sprint(nilStatic) == "" || fmt.Sprint(nilDocker) == "" || fmt.Sprintf("%#v", nilStatic) == "" {
		t.Fatal("nil sources must still format")
	}
}

func TestCredentialBasicAuthorization(t *testing.T) {
	credential := Credential{Username: "user", Password: "pass:word"}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass:word"))
	if got := credential.basicAuthorization(); got != want {
		t.Fatalf("basicAuthorization() = %q, want %q", got, want)
	}
	if !(Credential{}).IsZero() || (Credential{Password: "x"}).IsZero() {
		t.Fatal("IsZero() mismatch")
	}
}
