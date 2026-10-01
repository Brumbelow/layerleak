package registry

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brumbelow/layerleak/v3/internal/limits"
)

func writeDockerConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write docker config: %v", err)
	}
	return path
}

func TestDockerConfigCredentialsReadsBothFieldShapes(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte(testUsername + ":" + testPassword))
	path := writeDockerConfig(t, `{
  "auths": {
    "ghcr.io": {"auth": "`+encoded+`"},
    "https://registry.example:5000/v2/": {"username": "plain-user", "password": "plain-synthetic-0003"},
    "localhost:5000": {}
  }
}`)
	source := DockerConfigCredentials(path)
	ctx := context.Background()

	credential, ok, err := source.Lookup(ctx, "ghcr.io")
	if err != nil || !ok || credential.Username != testUsername || credential.Password != testPassword {
		t.Fatalf("Lookup(ghcr.io) = (%v, %v, %v)", credential, ok, err)
	}
	credential, ok, err = source.Lookup(ctx, "registry.example:5000")
	if err != nil || !ok || credential.Username != "plain-user" || credential.Password != "plain-synthetic-0003" {
		t.Fatalf("Lookup(registry.example:5000) = (%v, %v, %v)", credential, ok, err)
	}
	for _, host := range []string{"localhost:5000", "registry.example", "other.example", ""} {
		if _, ok, err := source.Lookup(ctx, host); ok || err != nil {
			t.Fatalf("Lookup(%q) = (ok=%v, err=%v), want no match", host, ok, err)
		}
	}
}

func TestDockerConfigCredentialsAcceptsPasswordWithColonAndUnpaddedBase64(t *testing.T) {
	raw := base64.RawStdEncoding.EncodeToString([]byte("user:pa:ss:word"))
	source := DockerConfigCredentials(writeDockerConfig(t, `{"auths": {"ghcr.io": {"auth": "`+raw+`"}}}`))
	credential, ok, err := source.Lookup(context.Background(), "ghcr.io")
	if err != nil || !ok || credential.Username != "user" || credential.Password != "pa:ss:word" {
		t.Fatalf("Lookup() = (%v, %v, %v)", credential, ok, err)
	}
}

func TestDockerConfigCredentialsResolveDockerHubAliases(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte(testUsername + ":" + testPassword))
	for _, key := range []string{"https://index.docker.io/v1/", "index.docker.io", "docker.io"} {
		source := DockerConfigCredentials(writeDockerConfig(t, `{"auths": {"`+key+`": {"auth": "`+encoded+`"}}}`))
		for _, host := range []string{"registry-1.docker.io", "index.docker.io", "docker.io"} {
			credential, ok, err := source.Lookup(context.Background(), host)
			if err != nil || !ok || credential.Password != testPassword {
				t.Fatalf("key %q: Lookup(%q) = (ok=%v, err=%v)", key, host, ok, err)
			}
		}
		if _, ok, _ := source.Lookup(context.Background(), "ghcr.io"); ok {
			t.Fatalf("key %q matched ghcr.io", key)
		}
	}
}

func TestDockerConfigCredentialsPreferAuthFieldAndFirstEntryForAlias(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("from-auth:synthetic-0004"))
	source := DockerConfigCredentials(writeDockerConfig(t, `{"auths": {
  "ghcr.io": {"auth": "`+encoded+`", "username": "from-plain", "password": "synthetic-0005"},
  "docker.io": {},
  "https://index.docker.io/v1/": {"username": "hub-user", "password": "synthetic-0006"}
}}`))
	credential, ok, err := source.Lookup(context.Background(), "ghcr.io")
	if err != nil || !ok || credential.Username != "from-auth" {
		t.Fatalf("Lookup(ghcr.io) = (%v, %v, %v)", credential, ok, err)
	}
	credential, ok, err = source.Lookup(context.Background(), "registry-1.docker.io")
	if err != nil || !ok || credential.Username != "hub-user" {
		t.Fatalf("Lookup(registry-1.docker.io) = (%v, %v, %v), want the entry that carries a credential", credential, ok, err)
	}
}

func TestDockerConfigCredentialsReportUnsupportedHelpers(t *testing.T) {
	source := DockerConfigCredentials(writeDockerConfig(t, `{
  "auths": {"ghcr.io": {}, "https://index.docker.io/v1/": {}},
  "credsStore": "desktop",
  "credHelpers": {"123456789012.dkr.ecr.us-east-1.amazonaws.com": "ecr-login", "ghcr.io": "gh"}
}`))
	ctx := context.Background()
	tests := map[string]string{
		"123456789012.dkr.ecr.us-east-1.amazonaws.com": "credential helper ecr-login",
		"ghcr.io":              "credential helper gh",
		"registry-1.docker.io": "credential store desktop",
	}
	for host, mechanism := range tests {
		_, ok, err := source.Lookup(ctx, host)
		var unsupported *UnsupportedCredentialError
		if ok || !errors.As(err, &unsupported) {
			t.Fatalf("Lookup(%q) = (ok=%v, err=%v), want UnsupportedCredentialError", host, ok, err)
		}
		if unsupported.Mechanism != mechanism {
			t.Fatalf("Lookup(%q) mechanism = %q, want %q", host, unsupported.Mechanism, mechanism)
		}
		if !strings.Contains(err.Error(), "not support") || !strings.Contains(err.Error(), mechanism) {
			t.Fatalf("Lookup(%q) error = %v", host, err)
		}
	}
	// A host without an auths placeholder is not claimed by the store.
	if _, ok, err := source.Lookup(ctx, "quay.io"); ok || err != nil {
		t.Fatalf("Lookup(quay.io) = (ok=%v, err=%v)", ok, err)
	}
}

func TestDockerConfigCredentialsPlaceholderWithoutStoreIsAnonymous(t *testing.T) {
	source := DockerConfigCredentials(writeDockerConfig(t, `{"auths": {"ghcr.io": {}}}`))
	if _, ok, err := source.Lookup(context.Background(), "ghcr.io"); ok || err != nil {
		t.Fatalf("Lookup() = (ok=%v, err=%v)", ok, err)
	}
}

func TestDockerConfigCredentialsRejectMalformedEntries(t *testing.T) {
	tests := map[string]struct {
		body string
		want string
	}{
		"malformed base64":  {body: `{"auths": {"ghcr.io": {"auth": "!!not-base64!!"}}}`, want: "not valid base64"},
		"missing separator": {body: `{"auths": {"ghcr.io": {"auth": "` + base64.StdEncoding.EncodeToString([]byte("nocolon")) + `"}}}`, want: "username:password"},
		"empty username":    {body: `{"auths": {"ghcr.io": {"auth": "` + base64.StdEncoding.EncodeToString([]byte(":"+testPassword)) + `"}}}`, want: "username:password"},
		"half plain fields": {body: `{"auths": {"ghcr.io": {"username": "only-user"}}}`, want: "both be set"},
		"identity token":    {body: `{"auths": {"ghcr.io": {"identitytoken": "synthetic-identity-0007"}}}`, want: "identity token"},
		"invalid host key":  {body: `{"auths": {"https://": {"username": "u", "password": "p"}}}`, want: "invalid host"},
		"not json":          {body: `{"auths": `, want: "not valid json"},
		"wrong shape":       {body: `{"auths": []}`, want: "not valid json"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			source := DockerConfigCredentials(writeDockerConfig(t, test.body))
			_, ok, err := source.Lookup(context.Background(), "ghcr.io")
			if ok || err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Lookup() = (ok=%v, err=%v), want %q", ok, err, test.want)
			}
			assertNoSecret(t, "error", err.Error())
			for _, marker := range []string{"!!not-base64!!", "synthetic-identity-0007", "nocolon"} {
				if strings.Contains(err.Error(), marker) {
					t.Fatalf("error echoes the field value: %v", err)
				}
			}
		})
	}
}

func TestDockerConfigCredentialsReportMissingAndOversizedFiles(t *testing.T) {
	missing := DockerConfigCredentials(filepath.Join(t.TempDir(), "absent.json"))
	_, ok, err := missing.Lookup(context.Background(), "ghcr.io")
	if ok || err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing Lookup() = (ok=%v, err=%v)", ok, err)
	}
	// The read error is cached: the file is not re-read on every request.
	if _, _, again := missing.Lookup(context.Background(), "ghcr.io"); again == nil || again.Error() != err.Error() {
		t.Fatalf("second Lookup() error = %v, want the cached %v", again, err)
	}

	oversized := DockerConfigCredentials(writeDockerConfig(t, `{"auths": {"ghcr.io": {"username": "`+strings.Repeat("a", maxDockerConfigBytes)+`", "password": "p"}}}`))
	_, ok, err = oversized.Lookup(context.Background(), "ghcr.io")
	var exceeded *limits.ExceededError
	if ok || !errors.As(err, &exceeded) {
		t.Fatalf("oversized Lookup() = (ok=%v, err=%v), want limits.ExceededError", ok, err)
	}

	if _, ok, err := DockerConfigCredentials("").Lookup(context.Background(), "ghcr.io"); ok || err != nil {
		t.Fatalf("empty path Lookup() = (ok=%v, err=%v)", ok, err)
	}
	var nilSource *dockerConfigSource
	if _, ok, err := nilSource.Lookup(context.Background(), "ghcr.io"); ok || err != nil {
		t.Fatalf("nil source Lookup() = (ok=%v, err=%v)", ok, err)
	}
}

func TestDockerConfigCredentialsIgnoreUnknownFields(t *testing.T) {
	source := DockerConfigCredentials(writeDockerConfig(t, `{
  "auths": {"ghcr.io": {"username": "u", "password": "p", "email": "ignored@example.invalid"}},
  "HttpHeaders": {"User-Agent": "Docker-Client"},
  "currentContext": "default",
  "credHelpers": {"": "ignored", "quay.io": " "}
}`))
	credential, ok, err := source.Lookup(context.Background(), "ghcr.io")
	if err != nil || !ok || credential.Username != "u" {
		t.Fatalf("Lookup() = (%v, %v, %v)", credential, ok, err)
	}
	if _, ok, err := source.Lookup(context.Background(), "quay.io"); ok || err != nil {
		t.Fatalf("Lookup(quay.io) = (ok=%v, err=%v), want blank helper ignored", ok, err)
	}
}
