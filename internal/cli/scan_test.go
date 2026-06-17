package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/brumbelow/layerleak/internal/manifest"
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
	if !strings.Contains(stdout.String(), layerLeakLogo) {
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
	if strings.Contains(string(body), "ghp_123456789012345678901234567890123456") {
		t.Fatalf("findings file leaked raw secret: %q", string(body))
	}
	if !strings.Contains(string(body), `"redacted_value"`) {
		t.Fatalf("findings file missing redacted value field: %q", string(body))
	}
}

func TestScanCommandFailsWhenDatabaseIsConfiguredButUnavailable(t *testing.T) {
	t.Setenv("LAYERLEAK_DATABASE_URL", "postgres://postgres:postgres@127.0.0.1:1/layerleak?sslmode=disable&connect_timeout=1")
	t.Setenv("LAYERLEAK_FINDINGS_DIR", t.TempDir())

	command := newRootCmd()
	command.SetOut(io.Discard)
	command.SetErr(io.Discard)
	command.SetContext(context.Background())
	command.SetArgs([]string{"scan", "library/app:latest", "--format", "json"})

	if err := command.Execute(); err == nil {
		t.Fatal("Execute() error = nil")
	}
}

func TestScanCommandSanitizesProgressErrors(t *testing.T) {
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
			return commandResponse(http.StatusNotFound, "text/plain", []byte("missing line one\nmissing\tline two"), nil), nil
		default:
			return commandResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
		}
	})

	oldTransport := http.DefaultTransport
	http.DefaultTransport = transport
	defer func() {
		http.DefaultTransport = oldTransport
	}()

	t.Setenv("LAYERLEAK_REGISTRY_BASE_URL", "https://registry.test")
	t.Setenv("LAYERLEAK_FINDINGS_DIR", t.TempDir())

	command := newRootCmd()
	var stderr bytes.Buffer
	command.SetOut(io.Discard)
	command.SetErr(&stderr)
	command.SetContext(context.Background())
	command.SetArgs([]string{"scan", "library/app:latest", "--format", "json"})

	if err := command.Execute(); err == nil {
		t.Fatal("Execute() error = nil")
	}

	output := stderr.String()
	if strings.Contains(output, "missing line one\nmissing\tline two") {
		t.Fatalf("stderr contained unsanitized multiline error: %q", output)
	}
	if !strings.Contains(output, "body=missing line one missing line two") {
		t.Fatalf("stderr missing sanitized error body: %q", output)
	}
}

func TestScanCommandWritesPartialResultsOnConfiguredLimitError(t *testing.T) {
	firstManifestDigest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	secondManifestDigest := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	firstConfigDigest := "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	secondConfigDigest := "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	indexDigest := "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

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
			return commandResponse(http.StatusOK, manifest.MediaTypeOCIImageIndex, []byte(`{
  "schemaVersion":2,
  "mediaType":"`+manifest.MediaTypeOCIImageIndex+`",
  "manifests":[
    {"mediaType":"`+manifest.MediaTypeOCIImageManifest+`","digest":"`+firstManifestDigest+`","size":1,"platform":{"os":"linux","architecture":"amd64"}},
    {"mediaType":"`+manifest.MediaTypeOCIImageManifest+`","digest":"`+secondManifestDigest+`","size":1,"platform":{"os":"linux","architecture":"arm64"}}
  ]
}`), map[string]string{
				"Docker-Content-Digest": indexDigest,
			}), nil
		case "/v2/library/app/manifests/" + firstManifestDigest:
			return commandResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, []byte(`{"schemaVersion":2,"mediaType":"`+manifest.MediaTypeOCIImageManifest+`","config":{"mediaType":"`+manifest.MediaTypeOCIImageConfig+`","digest":"`+firstConfigDigest+`","size":1},"layers":[]}`), map[string]string{
				"Docker-Content-Digest": firstManifestDigest,
			}), nil
		case "/v2/library/app/manifests/" + secondManifestDigest:
			return commandResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, []byte(`{"schemaVersion":2,"mediaType":"`+manifest.MediaTypeOCIImageManifest+`","config":{"mediaType":"`+manifest.MediaTypeOCIImageConfig+`","digest":"`+secondConfigDigest+`","size":1},"layers":[]}`), map[string]string{
				"Docker-Content-Digest": secondManifestDigest,
			}), nil
		case "/v2/library/app/blobs/" + firstConfigDigest:
			return commandResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, []byte(`{"architecture":"amd64","os":"linux","config":{"Env":["GH_TOKEN=ghp_123456789012345678901234567890123456"]}}`), nil), nil
		case "/v2/library/app/blobs/" + secondConfigDigest:
			return commandResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, []byte(`{"architecture":"arm64","os":"linux","config":{"Env":["GH_TOKEN=ghp_123456789012345678901234567890123456"],"User":"builder","WorkingDir":"https://builder:supersecretvalue@registry.internal/app"}}`), nil), nil
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
	t.Setenv("LAYERLEAK_FINDINGS_DIR", findingsDir)
	t.Setenv("LAYERLEAK_MAX_CONFIG_BYTES", "128")

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
	if exit.ExitCode() != 1 {
		t.Fatalf("exit.ExitCode() = %d", exit.ExitCode())
	}
	if !strings.Contains(err.Error(), "max config bytes limit") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(stdout.String(), `"total_findings"`) {
		t.Fatalf("stdout = %q", stdout.String())
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
	if strings.Contains(string(body), "ghp_123456789012345678901234567890123456") {
		t.Fatalf("partial findings file leaked raw secret: %q", string(body))
	}
	if !strings.Contains(string(body), `"redacted_value"`) {
		t.Fatalf("partial findings file missing redacted value field: %q", string(body))
	}
}

func TestScanCommandRejectsInvalidScopeFlags(t *testing.T) {
	cases := []struct {
		name string
		flag string
	}{
		{"tag page size must be positive", "--tag-page-size=0"},
		{"tag page size must be parsable", "--tag-page-size=-1"},
		{"max repository tags must be non-negative", "--max-repository-tags=-1"},
		{"max repository targets must be non-negative", "--max-repository-targets=-1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("LAYERLEAK_REGISTRY_BASE_URL", "https://registry.test")
			t.Setenv("LAYERLEAK_FINDINGS_DIR", t.TempDir())

			command := newRootCmd()
			command.SetOut(io.Discard)
			command.SetErr(io.Discard)
			command.SetContext(context.Background())
			command.SetArgs([]string{"scan", "library/app:latest", "--format", "json", tc.flag})

			err := command.Execute()
			if err == nil {
				t.Fatalf("Execute() error = nil for %s", tc.flag)
			}
			if !strings.Contains(err.Error(), "must be") {
				t.Fatalf("Execute() err = %q, want validation message", err.Error())
			}
		})
	}
}

func TestScanCommandRepositorySweepUsesTagPageSizeFlag(t *testing.T) {
	var (
		mu              sync.Mutex
		observedQueries []string
	)
	configDigest := "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	manifestDigest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

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
		case "/v2/library/app/tags/list":
			mu.Lock()
			observedQueries = append(observedQueries, request.URL.RawQuery)
			mu.Unlock()
			body, _ := json.Marshal(map[string]any{"name": "library/app", "tags": []string{"latest"}})
			return commandResponse(http.StatusOK, "application/json", body, nil), nil
		case "/v2/library/app/manifests/latest":
			return commandResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, []byte(`{"schemaVersion":2,"mediaType":"`+manifest.MediaTypeOCIImageManifest+`","config":{"mediaType":"`+manifest.MediaTypeOCIImageConfig+`","digest":"`+configDigest+`","size":1},"layers":[]}`), map[string]string{
				"Docker-Content-Digest": manifestDigest,
			}), nil
		case "/v2/library/app/manifests/" + manifestDigest:
			return commandResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, []byte(`{"schemaVersion":2,"mediaType":"`+manifest.MediaTypeOCIImageManifest+`","config":{"mediaType":"`+manifest.MediaTypeOCIImageConfig+`","digest":"`+configDigest+`","size":1},"layers":[]}`), map[string]string{
				"Docker-Content-Digest": manifestDigest,
			}), nil
		case "/v2/library/app/blobs/" + configDigest:
			return commandResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, []byte(`{"architecture":"amd64","os":"linux","config":{}}`), nil), nil
		default:
			return commandResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
		}
	})

	oldTransport := http.DefaultTransport
	http.DefaultTransport = transport
	defer func() {
		http.DefaultTransport = oldTransport
	}()

	t.Setenv("LAYERLEAK_REGISTRY_BASE_URL", "https://registry.test")
	t.Setenv("LAYERLEAK_FINDINGS_DIR", t.TempDir())

	command := newRootCmd()
	var stdout bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&stdout)
	command.SetContext(context.Background())
	command.SetArgs([]string{"scan", "library/app", "--format", "json", "--tag-page-size", "37"})

	if err := command.Execute(); err != nil {
		if _, ok := err.(interface{ ExitCode() int }); !ok {
			t.Fatalf("Execute() error = %v", err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(observedQueries) == 0 {
		t.Fatalf("no tag list query observed")
	}
	for _, query := range observedQueries {
		if !strings.Contains(query, "n=37") {
			t.Fatalf("tag list query = %q, want n=37", query)
		}
	}
}

func TestScanCommandRepositorySweepHonorsMaxRepositoryTagsFlag(t *testing.T) {
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
		if request.URL.Path == "/v2/library/app/tags/list" {
			body, _ := json.Marshal(map[string]any{"name": "library/app", "tags": []string{"latest", "v1", "v2"}})
			return commandResponse(http.StatusOK, "application/json", body, nil), nil
		}
		return commandResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
	})

	oldTransport := http.DefaultTransport
	http.DefaultTransport = transport
	defer func() {
		http.DefaultTransport = oldTransport
	}()

	t.Setenv("LAYERLEAK_REGISTRY_BASE_URL", "https://registry.test")
	t.Setenv("LAYERLEAK_FINDINGS_DIR", t.TempDir())

	command := newRootCmd()
	var stdout bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&stdout)
	command.SetContext(context.Background())
	command.SetArgs([]string{"scan", "library/app", "--format", "json", "--max-repository-tags", "1"})

	err := command.Execute()
	if err == nil {
		t.Fatalf("Execute() error = nil, want limit exceeded")
	}
	if !strings.Contains(err.Error(), "max repository tags") {
		t.Fatalf("Execute() err = %q, want repository tag limit error", err.Error())
	}
}

func TestScanCommandRepositorySweepHonorsMaxRepositoryTargetsFlag(t *testing.T) {
	firstDigest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	secondDigest := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

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
		case "/v2/library/app/tags/list":
			body, _ := json.Marshal(map[string]any{"name": "library/app", "tags": []string{"v1", "v2"}})
			return commandResponse(http.StatusOK, "application/json", body, nil), nil
		case "/v2/library/app/manifests/v1":
			return commandResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, []byte(`{"schemaVersion":2,"mediaType":"`+manifest.MediaTypeOCIImageManifest+`","config":{"mediaType":"`+manifest.MediaTypeOCIImageConfig+`","digest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","size":1},"layers":[]}`), map[string]string{
				"Docker-Content-Digest": firstDigest,
			}), nil
		case "/v2/library/app/manifests/v2":
			return commandResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, []byte(`{"schemaVersion":2,"mediaType":"`+manifest.MediaTypeOCIImageManifest+`","config":{"mediaType":"`+manifest.MediaTypeOCIImageConfig+`","digest":"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","size":1},"layers":[]}`), map[string]string{
				"Docker-Content-Digest": secondDigest,
			}), nil
		}
		return commandResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
	})

	oldTransport := http.DefaultTransport
	http.DefaultTransport = transport
	defer func() {
		http.DefaultTransport = oldTransport
	}()

	t.Setenv("LAYERLEAK_REGISTRY_BASE_URL", "https://registry.test")
	t.Setenv("LAYERLEAK_FINDINGS_DIR", t.TempDir())

	command := newRootCmd()
	var stdout bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&stdout)
	command.SetContext(context.Background())
	command.SetArgs([]string{"scan", "library/app", "--format", "json", "--max-repository-targets", "1"})

	err := command.Execute()
	if err == nil {
		t.Fatalf("Execute() error = nil, want repository target limit error")
	}
	if !strings.Contains(err.Error(), "max repository targets") {
		t.Fatalf("Execute() err = %q, want repository target limit error", err.Error())
	}
}

func TestScanCommandWarnsOnBareRepositorySweep(t *testing.T) {
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
		// Make the tag list fail so the run terminates quickly; the warning must
		// be emitted before tag enumeration begins.
		return commandResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
	})

	oldTransport := http.DefaultTransport
	http.DefaultTransport = transport
	defer func() {
		http.DefaultTransport = oldTransport
	}()

	t.Setenv("LAYERLEAK_REGISTRY_BASE_URL", "https://registry.test")
	t.Setenv("LAYERLEAK_FINDINGS_DIR", t.TempDir())

	command := newRootCmd()
	var stdout bytes.Buffer
	command.SetOut(io.Discard)
	command.SetErr(&stdout)
	command.SetContext(context.Background())
	command.SetArgs([]string{"scan", "library/app", "--format", "json"})

	_ = command.Execute()

	output := stdout.String()
	if !strings.Contains(output, "enumerates every public tag") {
		t.Fatalf("stderr missing bare repository sweep warning: %q", output)
	}
}

func TestScanCommandDoesNotWarnOnPinnedReference(t *testing.T) {
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
		return commandResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
	})

	oldTransport := http.DefaultTransport
	http.DefaultTransport = transport
	defer func() {
		http.DefaultTransport = oldTransport
	}()

	t.Setenv("LAYERLEAK_REGISTRY_BASE_URL", "https://registry.test")
	t.Setenv("LAYERLEAK_FINDINGS_DIR", t.TempDir())

	command := newRootCmd()
	var stdout bytes.Buffer
	command.SetOut(io.Discard)
	command.SetErr(&stdout)
	command.SetContext(context.Background())
	command.SetArgs([]string{"scan", "library/app:latest", "--format", "json"})

	_ = command.Execute()

	if strings.Contains(stdout.String(), "enumerates every public tag") {
		t.Fatalf("pinned reference run should not warn about bare repository sweep: %q", stdout.String())
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
