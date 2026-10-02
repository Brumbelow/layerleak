package scanservice

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brumbelow/layerleak/v3/internal/config"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
	"github.com/brumbelow/layerleak/v3/internal/registry"
)

const (
	testCredentialUsername = "scanner-bot"
	testCredentialPassword = "synthetic-password-not-real-0001"
)

// captureRegistryOptions runs registryClient for the reference, as the API
// does (no per-request credential), and returns the registry.Options the
// service built.
func captureRegistryOptions(t *testing.T, cfg config.Config, reference string) registry.Options {
	t.Helper()
	return captureRegistryOptionsForRequest(t, cfg, reference, registry.Credential{})
}

// captureRegistryOptionsForRequest runs registryClient for the reference with
// a caller-supplied credential, as the CLI does, and returns the
// registry.Options the service built.
func captureRegistryOptionsForRequest(t *testing.T, cfg config.Config, reference string, credential registry.Credential) registry.Options {
	t.Helper()
	service := New(cfg, nil)
	var captured registry.Options
	service.newRegistryClient = func(options registry.Options) (*registry.Client, error) {
		captured = options
		options.AllowPrivateHosts = true
		return registry.NewClient(options)
	}
	ref, err := manifest.ParseReference(reference)
	if err != nil {
		t.Fatalf("ParseReference(%q) error = %v", reference, err)
	}
	if _, err := service.registryClient(ref, Request{Reference: ref, Credential: credential}); err != nil {
		t.Fatalf("registryClient() error = %v", err)
	}
	return captured
}

func testRequestCredential() registry.Credential {
	return registry.Credential{Username: testCredentialUsername, Password: testCredentialPassword}
}

func assertNoCredentialFor(t *testing.T, source registry.CredentialSource, hosts ...string) {
	t.Helper()
	if source == nil {
		return
	}
	for _, host := range hosts {
		if _, ok := lookup(t, source, host); ok {
			t.Fatalf("credential leaked to %s", host)
		}
	}
}

func lookup(t *testing.T, source registry.CredentialSource, host string) (registry.Credential, bool) {
	t.Helper()
	credential, ok, err := source.Lookup(context.Background(), host)
	if err != nil {
		t.Fatalf("Lookup(%q) error = %v", host, err)
	}
	return credential, ok
}

func TestRegistryClientStaysAnonymousWithoutCredentials(t *testing.T) {
	options := captureRegistryOptions(t, config.Config{}, "ghcr.io/org/app:latest")
	if options.Credentials != nil {
		t.Fatalf("Credentials = %v, want nil", options.Credentials)
	}
}

// TestRegistryClientIgnoresConfiguredCredentialsForCallerNamedRegistries is
// the API case: the process carries LAYERLEAK_REGISTRY_USERNAME/PASSWORD but
// no endpoint pin, and the registry host comes from whatever reference the
// caller submitted. The pair must not be bound to that host, or one POST to
// the unauthenticated API would deliver it to an attacker-chosen realm.
func TestRegistryClientIgnoresConfiguredCredentialsForCallerNamedRegistries(t *testing.T) {
	cfg := config.Config{RegistryUsername: testCredentialUsername, RegistryPassword: config.Secret(testCredentialPassword)}
	for _, reference := range []string{"ghcr.io/org/app:latest", "attacker.example/x/y:latest", "library/alpine:3.20"} {
		options := captureRegistryOptions(t, cfg, reference)
		if options.Credentials != nil {
			t.Fatalf("%s: Credentials = %v, want nil without an endpoint pin or a request credential", reference, options.Credentials)
		}
	}
}

func TestRegistryClientBindsRequestCredentialToTheReferenceHost(t *testing.T) {
	options := captureRegistryOptionsForRequest(t, config.Config{}, "ghcr.io/org/app:latest", testRequestCredential())
	if options.BaseURL != "https://ghcr.io" {
		t.Fatalf("BaseURL = %q", options.BaseURL)
	}
	credential, ok := lookup(t, options.Credentials, "ghcr.io")
	if !ok || credential.Username != testCredentialUsername || credential.Password != testCredentialPassword {
		t.Fatalf("Lookup(ghcr.io) = (%v, %v)", credential, ok)
	}
	assertNoCredentialFor(t, options.Credentials, "registry-1.docker.io", "quay.io", "ghcr.io:5000", "cdn.ghcr.io")
}

func TestRegistryClientBindsRequestCredentialToDockerHubAliases(t *testing.T) {
	options := captureRegistryOptionsForRequest(t, config.Config{}, "library/alpine:3.20", testRequestCredential())
	if options.BaseURL != "https://registry-1.docker.io" {
		t.Fatalf("BaseURL = %q", options.BaseURL)
	}
	if _, ok := lookup(t, options.Credentials, "registry-1.docker.io"); !ok {
		t.Fatal("Docker Hub credential does not match the host the client contacts")
	}
	assertNoCredentialFor(t, options.Credentials, "ghcr.io")
}

func TestRegistryClientBindsRequestCredentialToTheEndpointOverride(t *testing.T) {
	cfg := config.Config{RegistryBaseURL: "https://mirror.internal:5000"}
	options := captureRegistryOptionsForRequest(t, cfg, "ghcr.io/org/app:latest", testRequestCredential())
	if _, ok := lookup(t, options.Credentials, "mirror.internal:5000"); !ok {
		t.Fatal("request credential does not match the configured endpoint host")
	}
	assertNoCredentialFor(t, options.Credentials, "ghcr.io")
}

func TestRegistryClientPrefersRequestCredentialOverConfiguredPair(t *testing.T) {
	cfg := config.Config{
		RegistryBaseURL:  "https://mirror.internal:5000",
		RegistryUsername: "configured-user",
		RegistryPassword: config.Secret("synthetic-configured-0004"),
	}
	options := captureRegistryOptionsForRequest(t, cfg, "ghcr.io/org/app:latest", testRequestCredential())
	credential, ok := lookup(t, options.Credentials, "mirror.internal:5000")
	if !ok || credential.Username != testCredentialUsername {
		t.Fatalf("Lookup(mirror.internal:5000) = (%v, %v), want the request credential", credential, ok)
	}
}

func TestConfiguredCredential(t *testing.T) {
	if credential := ConfiguredCredential(config.Config{}); !credential.IsZero() {
		t.Fatalf("ConfiguredCredential(empty) = %v, want zero", credential)
	}
	cfg := config.Config{RegistryUsername: testCredentialUsername, RegistryPassword: config.Secret(testCredentialPassword)}
	if credential := ConfiguredCredential(cfg); credential != testRequestCredential() {
		t.Fatalf("ConfiguredCredential() = %v", credential)
	}
	// The CLI path: the configured pair, vouched for by the caller, binds to
	// the scanned reference's registry even without an endpoint pin.
	options := captureRegistryOptionsForRequest(t, cfg, "ghcr.io/org/app:latest", ConfiguredCredential(cfg))
	if _, ok := lookup(t, options.Credentials, "ghcr.io"); !ok {
		t.Fatal("configured credential handed over per request does not reach the reference host")
	}
}

func TestRegistryClientBindsStaticCredentialsToTheEndpointOverride(t *testing.T) {
	cfg := config.Config{
		RegistryBaseURL:  "https://mirror.internal:5000",
		RegistryUsername: testCredentialUsername,
		RegistryPassword: config.Secret(testCredentialPassword),
	}
	options := captureRegistryOptions(t, cfg, "ghcr.io/org/app:latest")
	if _, ok := lookup(t, options.Credentials, "mirror.internal:5000"); !ok {
		t.Fatal("credential does not match the configured endpoint host")
	}
	if _, ok := lookup(t, options.Credentials, "ghcr.io"); ok {
		t.Fatal("credential matched the reference host instead of the endpoint actually contacted")
	}
}

func TestRegistryClientChainsDockerConfigAfterStaticCredentials(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("hub-user:synthetic-hub-0002"))
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"auths":{"https://index.docker.io/v1/":{"auth":"`+encoded+`"},"ghcr.io":{"username":"docker-user","password":"synthetic-docker-0003"}}}`), 0o600); err != nil {
		t.Fatalf("write docker config: %v", err)
	}
	cfg := config.Config{DockerConfigPath: path}
	options := captureRegistryOptionsForRequest(t, cfg, "ghcr.io/org/app:latest", testRequestCredential())
	credential, ok := lookup(t, options.Credentials, "ghcr.io")
	if !ok || credential.Username != testCredentialUsername {
		t.Fatalf("Lookup(ghcr.io) = (%v, %v), want the static credential first", credential, ok)
	}
	credential, ok = lookup(t, options.Credentials, "registry-1.docker.io")
	if !ok || credential.Username != "hub-user" {
		t.Fatalf("Lookup(registry-1.docker.io) = (%v, %v), want the Docker config entry", credential, ok)
	}

	dockerOnly := captureRegistryOptions(t, config.Config{DockerConfigPath: path}, "ghcr.io/org/app:latest")
	credential, ok = lookup(t, dockerOnly.Credentials, "ghcr.io")
	if !ok || credential.Username != "docker-user" {
		t.Fatalf("docker-only Lookup(ghcr.io) = (%v, %v)", credential, ok)
	}
}

func TestRegistryOptionsFormattingDoesNotRevealCredentials(t *testing.T) {
	cfg := config.Config{
		RegistryBaseURL:  "https://mirror.internal:5000",
		RegistryUsername: testCredentialUsername,
		RegistryPassword: config.Secret(testCredentialPassword),
		DockerConfigPath: "/nonexistent/config.json",
	}
	options := captureRegistryOptions(t, cfg, "ghcr.io/org/app:latest")
	request := Request{Credential: testRequestCredential()}
	encoded := base64.StdEncoding.EncodeToString([]byte(testCredentialUsername + ":" + testCredentialPassword))
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		for label, value := range map[string]any{"options": options, "config": cfg, "request": request} {
			text := fmt.Sprintf(verb, value)
			if strings.Contains(text, testCredentialPassword) || strings.Contains(text, encoded) {
				t.Fatalf("%s %s reveals the password: %q", label, verb, text)
			}
		}
	}
}

// TestScanAndSaveAuthenticatesToPrivateRegistry drives a whole scan against a
// registry whose token service rejects anonymous requests: the credential
// reaches the realm as Basic authentication, the scan completes, and a wrong
// password surfaces as an unauthorized scan error that never echoes the
// credential. Both legitimate credential paths are covered: the configured
// pair with LAYERLEAK_REGISTRY_BASE_URL pinning the host (server mode) and a
// per-request credential bound to the reference host (the CLI).
func TestScanAndSaveAuthenticatesToPrivateRegistry(t *testing.T) {
	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte(testCredentialUsername+":"+testCredentialPassword))

	modes := map[string]func(password string) (config.Config, Request){
		"pinned endpoint": func(password string) (config.Config, Request) {
			return config.Config{
				RegistryBaseURL:  "https://registry.test",
				RegistryUsername: testCredentialUsername,
				RegistryPassword: config.Secret(password),
			}, Request{}
		},
		"request credential": func(password string) (config.Config, Request) {
			return config.Config{}, Request{Credential: registry.Credential{Username: testCredentialUsername, Password: password}}
		},
	}
	for name, mode := range modes {
		t.Run(name, func(t *testing.T) {
			t.Run("correct password", func(t *testing.T) {
				cfg, request := mode(testCredentialPassword)
				outcome, realmAuthorization, err := runPrivateRegistryScan(t, cfg, request, "registry.test/org/private:latest", expected)
				if err != nil {
					t.Fatalf("ScanAndSave() error = %v", err)
				}
				if outcome.Result.TotalFindings == 0 {
					t.Fatal("private image scan produced no findings")
				}
				if len(realmAuthorization) != 1 || realmAuthorization[0] != expected {
					t.Fatalf("realm authorization = %q", realmAuthorization)
				}
				text := fmt.Sprintf("%+v", outcome.Result)
				if strings.Contains(text, testCredentialPassword) || strings.Contains(text, "synthetic-scan-token-0001") {
					t.Fatal("scan result carries the credential or token")
				}
			})
			t.Run("wrong password", func(t *testing.T) {
				cfg, request := mode("synthetic-wrong-password-0009")
				_, _, err := runPrivateRegistryScan(t, cfg, request, "registry.test/org/private:latest", expected)
				if !registry.IsUnauthorized(err) {
					t.Fatalf("ScanAndSave() error = %v, want unauthorized", err)
				}
				text := fmt.Sprintf("%v %+v", err, err)
				wrong := "Basic " + base64.StdEncoding.EncodeToString([]byte(testCredentialUsername+":synthetic-wrong-password-0009"))
				if strings.Contains(text, "synthetic-wrong-password-0009") || strings.Contains(text, wrong) {
					t.Fatalf("error reveals the credential: %q", text)
				}
			})
		})
	}
}

// TestScanAndSaveNeverSendsConfiguredCredentialsToCallerNamedRegistries is
// the exfiltration scenario: a server process configured with
// LAYERLEAK_REGISTRY_USERNAME/PASSWORD and no endpoint pin scans a reference
// an API caller chose. That registry answers with a Bearer challenge whose
// realm is a third host under the caller's control. No request of the scan,
// to the registry or to the realm, may carry the configured pair.
func TestScanAndSaveNeverSendsConfiguredCredentialsToCallerNamedRegistries(t *testing.T) {
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte(testCredentialUsername+":"+testCredentialPassword))
	var (
		realmAuthorization []string
		basicSeen          []string
	)
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if authorization := request.Header.Get("Authorization"); strings.HasPrefix(authorization, "Basic ") {
			basicSeen = append(basicSeen, request.URL.Host)
		}
		if request.URL.Host == "third-party.example" {
			realmAuthorization = append(realmAuthorization, request.Header.Get("Authorization"))
			return testResponse(http.StatusUnauthorized, "application/json", []byte(`{"errors":[{"code":"UNAUTHORIZED"}]}`), nil), nil
		}
		return testResponse(http.StatusUnauthorized, "", nil, map[string]string{
			"Www-Authenticate": `Bearer realm="https://third-party.example/token",service="attacker.example",scope="repository:x/y:pull"`,
		}), nil
	})
	service := New(config.Config{
		RegistryUsername:        testCredentialUsername,
		RegistryPassword:        config.Secret(testCredentialPassword),
		MaxFileBytes:            1 << 20,
		MaxConfigBytes:          1 << 20,
		TagPageSize:             100,
		RegistryRequestAttempts: 2,
	}, &recordingStore{})
	service.newRegistryClient = func(options registry.Options) (*registry.Client, error) {
		options.AllowPrivateHosts = true
		options.HTTPClient = &http.Client{Transport: transport}
		return registry.NewClient(options)
	}
	reference, err := manifest.ParseReference("attacker.example/x/y:latest")
	if err != nil {
		t.Fatalf("ParseReference() error = %v", err)
	}
	_, err = service.ScanAndSave(context.Background(), Request{Reference: reference})
	if !registry.IsUnauthorized(err) {
		t.Fatalf("ScanAndSave() error = %v, want the anonymous unauthorized outcome", err)
	}
	if len(basicSeen) != 0 {
		t.Fatalf("configured credential was sent to %v", basicSeen)
	}
	if len(realmAuthorization) == 0 {
		t.Fatal("the realm was never contacted; the scenario did not run")
	}
	for _, authorization := range realmAuthorization {
		if authorization != "" {
			t.Fatalf("realm received Authorization %q, want anonymous", authorization)
		}
	}
	if strings.Contains(fmt.Sprintf("%v %+v", err, err), basic) {
		t.Fatal("error reveals the configured credential")
	}
}

// runPrivateRegistryScan scans reference through a stub registry whose token
// realm (auth.test) only issues a token to the expected Basic credential and
// returns the Authorization values the realm saw.
func runPrivateRegistryScan(t *testing.T, cfg config.Config, request Request, reference, expected string) (Outcome, []string, error) {
	t.Helper()
	configBody := []byte(`{"architecture":"amd64","os":"linux","config":{"Env":["GH_TOKEN=ghp_123456789012345678901234567890123456"]}}`)
	configDescriptor := scanTestDescriptor(t, manifest.MediaTypeOCIImageConfig, configBody)
	manifestBody := scanTestManifestBody(t, configDescriptor)
	manifestDescriptor := scanTestDescriptor(t, manifest.MediaTypeOCIImageManifest, manifestBody)

	var realmAuthorization []string
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "auth.test" {
			realmAuthorization = append(realmAuthorization, request.Header.Get("Authorization"))
			if request.Header.Get("Authorization") != expected {
				return testResponse(http.StatusUnauthorized, "application/json", []byte(`{"errors":[{"code":"UNAUTHORIZED"}]}`), nil), nil
			}
			return testResponse(http.StatusOK, "application/json", []byte(`{"token":"synthetic-scan-token-0001","expires_in":300}`), nil), nil
		}
		if request.Header.Get("Authorization") != "Bearer synthetic-scan-token-0001" {
			return testResponse(http.StatusUnauthorized, "", nil, map[string]string{
				"Www-Authenticate": `Bearer realm="https://auth.test/token",service="registry.test",scope="repository:org/private:pull"`,
			}), nil
		}
		switch request.URL.Path {
		case "/v2/org/private/manifests/latest", "/v2/org/private/manifests/" + manifestDescriptor.Digest:
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, manifestBody, map[string]string{"Docker-Content-Digest": manifestDescriptor.Digest}), nil
		case "/v2/org/private/blobs/" + configDescriptor.Digest:
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, configBody, nil), nil
		default:
			return testResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
		}
	})
	cfg.MaxFileBytes = 1 << 20
	cfg.MaxConfigBytes = 1 << 20
	cfg.TagPageSize = 100
	cfg.RegistryRequestAttempts = 2
	service := New(cfg, &recordingStore{})
	service.newRegistryClient = func(options registry.Options) (*registry.Client, error) {
		options.AllowPrivateHosts = true
		options.HTTPClient = &http.Client{Transport: transport}
		return registry.NewClient(options)
	}
	ref, err := manifest.ParseReference(reference)
	if err != nil {
		t.Fatalf("ParseReference() error = %v", err)
	}
	request.Reference = ref
	outcome, err := service.ScanAndSave(context.Background(), request)
	return outcome, realmAuthorization, err
}
