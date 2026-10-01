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

// captureRegistryOptions runs registryClient for the reference and returns the
// registry.Options the service built.
func captureRegistryOptions(t *testing.T, cfg config.Config, reference string) registry.Options {
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
	if _, err := service.registryClient(ref); err != nil {
		t.Fatalf("registryClient() error = %v", err)
	}
	return captured
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

func TestRegistryClientBindsStaticCredentialsToTheReferenceHost(t *testing.T) {
	cfg := config.Config{RegistryUsername: testCredentialUsername, RegistryPassword: config.Secret(testCredentialPassword)}
	options := captureRegistryOptions(t, cfg, "ghcr.io/org/app:latest")
	if options.BaseURL != "https://ghcr.io" {
		t.Fatalf("BaseURL = %q", options.BaseURL)
	}
	credential, ok := lookup(t, options.Credentials, "ghcr.io")
	if !ok || credential.Username != testCredentialUsername || credential.Password != testCredentialPassword {
		t.Fatalf("Lookup(ghcr.io) = (%v, %v)", credential, ok)
	}
	for _, host := range []string{"registry-1.docker.io", "quay.io", "ghcr.io:5000", "cdn.ghcr.io"} {
		if _, ok := lookup(t, options.Credentials, host); ok {
			t.Fatalf("credential leaked to %s", host)
		}
	}
}

func TestRegistryClientBindsStaticCredentialsToDockerHubAliases(t *testing.T) {
	cfg := config.Config{RegistryUsername: testCredentialUsername, RegistryPassword: config.Secret(testCredentialPassword)}
	options := captureRegistryOptions(t, cfg, "library/alpine:3.20")
	if options.BaseURL != "https://registry-1.docker.io" {
		t.Fatalf("BaseURL = %q", options.BaseURL)
	}
	if _, ok := lookup(t, options.Credentials, "registry-1.docker.io"); !ok {
		t.Fatal("Docker Hub credential does not match the host the client contacts")
	}
	if _, ok := lookup(t, options.Credentials, "ghcr.io"); ok {
		t.Fatal("Docker Hub credential matched ghcr.io")
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
	cfg := config.Config{
		RegistryUsername: testCredentialUsername,
		RegistryPassword: config.Secret(testCredentialPassword),
		DockerConfigPath: path,
	}
	options := captureRegistryOptions(t, cfg, "ghcr.io/org/app:latest")
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
	cfg := config.Config{RegistryUsername: testCredentialUsername, RegistryPassword: config.Secret(testCredentialPassword), DockerConfigPath: "/nonexistent/config.json"}
	options := captureRegistryOptions(t, cfg, "ghcr.io/org/app:latest")
	encoded := base64.StdEncoding.EncodeToString([]byte(testCredentialUsername + ":" + testCredentialPassword))
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		for label, value := range map[string]any{"options": options, "config": cfg} {
			text := fmt.Sprintf(verb, value)
			if strings.Contains(text, testCredentialPassword) || strings.Contains(text, encoded) {
				t.Fatalf("%s %s reveals the password: %q", label, verb, text)
			}
		}
	}
}

// TestScanAndSaveAuthenticatesToPrivateRegistry drives a whole scan against a
// registry whose token service rejects anonymous requests: the configured
// credential reaches the realm as Basic authentication, the scan completes,
// and a wrong password surfaces as an unauthorized scan error that never
// echoes the credential.
func TestScanAndSaveAuthenticatesToPrivateRegistry(t *testing.T) {
	configBody := []byte(`{"architecture":"amd64","os":"linux","config":{"Env":["GH_TOKEN=ghp_123456789012345678901234567890123456"]}}`)
	configDescriptor := scanTestDescriptor(t, manifest.MediaTypeOCIImageConfig, configBody)
	manifestBody := scanTestManifestBody(t, configDescriptor)
	manifestDescriptor := scanTestDescriptor(t, manifest.MediaTypeOCIImageManifest, manifestBody)
	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte(testCredentialUsername+":"+testCredentialPassword))

	run := func(t *testing.T, password string) (Outcome, []string, error) {
		t.Helper()
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
		store := &recordingStore{}
		service := New(config.Config{
			RegistryBaseURL:         "https://registry.test",
			RegistryUsername:        testCredentialUsername,
			RegistryPassword:        config.Secret(password),
			MaxFileBytes:            1 << 20,
			MaxConfigBytes:          1 << 20,
			TagPageSize:             100,
			RegistryRequestAttempts: 2,
		}, store)
		service.newRegistryClient = func(options registry.Options) (*registry.Client, error) {
			options.AllowPrivateHosts = true
			options.HTTPClient = &http.Client{Transport: transport}
			return registry.NewClient(options)
		}
		reference, err := manifest.ParseReference("registry.test/org/private:latest")
		if err != nil {
			t.Fatalf("ParseReference() error = %v", err)
		}
		outcome, err := service.ScanAndSave(context.Background(), Request{Reference: reference})
		return outcome, realmAuthorization, err
	}

	t.Run("correct password", func(t *testing.T) {
		outcome, realmAuthorization, err := run(t, testCredentialPassword)
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
		_, _, err := run(t, "synthetic-wrong-password-0009")
		if !registry.IsUnauthorized(err) {
			t.Fatalf("ScanAndSave() error = %v, want unauthorized", err)
		}
		text := fmt.Sprintf("%v %+v", err, err)
		wrong := "Basic " + base64.StdEncoding.EncodeToString([]byte(testCredentialUsername+":synthetic-wrong-password-0009"))
		if strings.Contains(text, "synthetic-wrong-password-0009") || strings.Contains(text, wrong) {
			t.Fatalf("error reveals the credential: %q", text)
		}
	})
}
