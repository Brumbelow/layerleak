package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"git.tools.cloudfor.ge/andrew/layerleak/internal/manifest"
)

func TestScanCommandJSONOutputAndExitCode(t *testing.T) {
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "auth.test" {
			body, _ := json.Marshal(map[string]string{"token": "test-token"})
			return commandResponse(http.StatusOK, "application/json", body, nil), nil
		}

		if request.Header.Get("Authorization") != "Bearer test-token" {
			return commandResponse(http.StatusUnauthorized, "", nil, map[string]string{
				"Www-Authenticate": `Bearer realm="https://auth.test/token",service="registry.test",scope="repository:library/app:pull"`,
			}), nil
		}

		switch request.URL.Path {
		case "/v2/library/app/manifests/latest":
			return commandResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, []byte(`{"schemaVersion":2,"mediaType":"`+manifest.MediaTypeOCIImageManifest+`","config":{"mediaType":"`+manifest.MediaTypeOCIImageConfig+`","digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":1},"layers":[]}`), map[string]string{
				"Docker-Content-Digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			}), nil
		case "/v2/library/app/blobs/sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb":
			return commandResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, []byte(`{"architecture":"amd64","os":"linux","config":{"Env":["GH_TOKEN=ghp_123456789012345678901234567890123456"]}}`), nil), nil
		default:
			return commandResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
		}
	})

	oldTransport := http.DefaultTransport
	http.DefaultTransport = transport
	defer func() {
		http.DefaultTransport = oldTransport
	}()

	findingsDir := t.TempDir()
	t.Setenv("LAYERLEAK_REGISTRY_BASE_URL", "https://registry.test")
	t.Setenv("LAYERLEAK_MAX_FILE_BYTES", "1048576")
	t.Setenv("LAYERLEAK_FINDINGS_DIR", findingsDir)

	command := newRootCmd()
	var stdout bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&stdout)
	command.SetContext(context.Background())
	command.SetArgs([]string{"scan", "library/app:latest", "--format", "json"})

	err := command.Execute()
	exit, ok := err.(interface{ ExitCode() int })
	if !ok {
		t.Fatalf("Execute() error = %v", err)
	}
	if exit.ExitCode() != 2 {
		t.Fatalf("exit.ExitCode() = %d", exit.ExitCode())
	}

	if !strings.Contains(stdout.String(), `"requested_digest"`) {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "://LAYERLEAK") {
		t.Fatalf("stdout missing progress logo: %q", stdout.String())
	}
	if strings.Contains(stdout.String(), "ghp_123456789012345678901234567890123456") {
		t.Fatalf("stdout leaked raw secret: %q", stdout.String())
	}

	entries, readErr := os.ReadDir(findingsDir)
	if readErr != nil {
		t.Fatalf("ReadDir() error = %v", readErr)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d", len(entries))
	}

	body, readErr := os.ReadFile(findingsDir + string(os.PathSeparator) + entries[0].Name())
	if readErr != nil {
		t.Fatalf("ReadFile() error = %v", readErr)
	}
	if !strings.Contains(string(body), "ghp_123456789012345678901234567890123456") {
		t.Fatalf("findings file did not include raw secret: %q", string(body))
	}
}

type roundTripFunc func(request *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func commandResponse(statusCode int, contentType string, body []byte, headers map[string]string) *http.Response {
	header := make(http.Header)
	for key, value := range headers {
		header.Set(key, value)
	}
	if contentType != "" {
		header.Set("Content-Type", contentType)
	}

	return &http.Response{
		StatusCode: statusCode,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader(body)),
	}
}
