package cli

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brumbelow/layerleak/v3/internal/config"
	"github.com/brumbelow/layerleak/v3/internal/jobs"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
	"github.com/brumbelow/layerleak/v3/internal/registry"
)

func TestCredentialFromFlagsRequiresBothOrNeither(t *testing.T) {
	if credential, err := credentialFromFlags("", false, strings.NewReader("ignored\n")); err != nil || !credential.IsZero() {
		t.Fatalf("no flags: %+v %v", credential, err)
	}
	if _, err := credentialFromFlags("", true, strings.NewReader("secret\n")); err == nil || !strings.Contains(err.Error(), "--username") {
		t.Fatalf("--password-stdin alone accepted: %v", err)
	}
	if _, err := credentialFromFlags("robot", false, nil); err == nil || !strings.Contains(err.Error(), "--password-stdin") {
		t.Fatalf("--username alone accepted: %v", err)
	}
	if _, err := credentialFromFlags("robot", true, strings.NewReader("\n")); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty password accepted: %v", err)
	}
	if _, err := credentialFromFlags("robot", true, strings.NewReader(strings.Repeat("x", maxPasswordBytes+1))); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized password accepted: %v", err)
	}
}

func TestReadPasswordStdinTrimsExactlyOneTrailingNewline(t *testing.T) {
	cases := map[string]string{
		"synthetic-pass\n":    "synthetic-pass",
		"synthetic-pass\r\n":  "synthetic-pass",
		"synthetic-pass":      "synthetic-pass",
		"synthetic-pass\n\n":  "synthetic-pass\n",
		" spaced pass \n":     " spaced pass ",
		"multi\nline-token\n": "multi\nline-token",
		"ends-with-cr\r":      "ends-with-cr\r",
		"\nleading-newline":   "\nleading-newline",
	}
	for input, want := range cases {
		got, err := readPasswordStdin(strings.NewReader(input))
		if err != nil || got != want {
			t.Errorf("readPasswordStdin(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
}

func TestExitForOutcomeNamesTheRegistryOnAuthenticationFailure(t *testing.T) {
	unauthorized := &registry.StatusError{StatusCode: http.StatusUnauthorized, Method: http.MethodGet, URL: "https://registry.example/v2/library/app/manifests/latest", Auth: true}
	result := jobs.Result{ResultSchemaVersion: jobs.ResultSchemaVersion, Status: jobs.ResultStatusFailed}
	_, err := exitForOutcome(result, unauthorized, false, false, failOnLow, "registry.example")
	var coded interface{ ExitCode() int }
	if !errors.As(err, &coded) || coded.ExitCode() != exitCodeFailure || err.Error() != "authentication to registry.example failed" {
		t.Fatalf("exit = %v", err)
	}
	if !registry.IsUnauthorized(err) {
		t.Fatal("underlying unauthorized error no longer reachable through the exit error")
	}
	forbidden := &registry.StatusError{StatusCode: http.StatusForbidden}
	if _, err := exitForOutcome(result, forbidden, false, false, failOnLow, "ghcr.io"); err == nil || err.Error() != "authentication to ghcr.io failed" {
		t.Fatalf("403 message = %v", err)
	}
	other := errors.New("synthetic failure")
	if _, err := exitForOutcome(result, other, false, false, failOnLow, "ghcr.io"); err == nil || err.Error() != "synthetic failure" {
		t.Fatalf("non-auth message = %v", err)
	}
}

func TestRegistryHostForPrefersTheBaseURLOverride(t *testing.T) {
	ref, err := manifest.ParseReference("ghcr.io/org/app:1")
	if err != nil {
		t.Fatal(err)
	}
	if got := registryHostFor(config.Config{}, ref); got != "ghcr.io" {
		t.Fatalf("host = %q", got)
	}
	if got := registryHostFor(config.Config{RegistryBaseURL: "https://mirror.internal:5000"}, ref); got != "mirror.internal:5000" {
		t.Fatalf("override host = %q", got)
	}
}

// TestScanCommandNeverLeaksTheCredential pipes a password to --password-stdin
// against a registry that only answers 401 Basic challenges. Over the plain
// http test server the client refuses to send the credential at all, so the
// scan fails; nothing the command printed, logged, returned or recorded may
// contain the username or the password.
func TestScanCommandNeverLeaksTheCredential(t *testing.T) {
	const username = "robot-user"
	password := "synthetic-" + "stdin-password-7f3a"
	var authorizations []string
	installCommandRegistry(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		authorizations = append(authorizations, request.Header.Get("Authorization"))
		return commandResponse(http.StatusUnauthorized, "", nil, map[string]string{"Www-Authenticate": `Basic realm="private"`}), nil
	}))
	dir := t.TempDir()
	t.Setenv("LAYERLEAK_FINDINGS_DIR", dir)
	t.Setenv("LAYERLEAK_LOG_LEVEL", "debug")

	command := newRootCmd()
	var stdout, stderr bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	command.SetIn(strings.NewReader(password + "\n"))
	command.SetContext(context.Background())
	command.SetArgs([]string{"scan", "library/app:latest", "--format", "json", "--progress", "plain", "--username", username, "--password-stdin"})
	err := command.Execute()
	var coded interface{ ExitCode() int }
	if !errors.As(err, &coded) || coded.ExitCode() != exitCodeFailure {
		t.Fatalf("exit = %v", err)
	}
	if !errors.Is(err, registry.ErrCredentialsRequireHTTPS) {
		t.Fatalf("plain-http registry did not refuse the credential: %v", err)
	}
	for _, header := range authorizations {
		if header != "" {
			t.Fatalf("credential sent over plain http: %q", header)
		}
	}
	surfaces := map[string]string{"stdout": stdout.String(), "stderr": stderr.String(), "error": err.Error()}
	records, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	for _, record := range records {
		body, readErr := os.ReadFile(record)
		if readErr != nil {
			t.Fatal(readErr)
		}
		surfaces["record "+filepath.Base(record)] = string(body)
	}
	for name, text := range surfaces {
		if strings.Contains(text, password) || strings.Contains(text, "robot-user") {
			t.Fatalf("%s leaked the credential: %q", name, text)
		}
	}
}

func TestScanCommandRejectsHalfSpecifiedCredentialFlags(t *testing.T) {
	for _, args := range [][]string{{"--username", "robot"}, {"--password-stdin"}} {
		command := newRootCmd()
		command.SetOut(new(bytes.Buffer))
		command.SetErr(new(bytes.Buffer))
		command.SetIn(strings.NewReader("secret\n"))
		command.SetArgs(append([]string{"scan", "library/app:latest"}, args...))
		err := command.Execute()
		if err == nil || !strings.Contains(err.Error(), "--username") && !strings.Contains(err.Error(), "--password-stdin") {
			t.Fatalf("%v accepted: %v", args, err)
		}
	}
}
