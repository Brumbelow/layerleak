package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/brumbelow/layerleak/internal/jobs"
	"github.com/brumbelow/layerleak/internal/manifest"
	"github.com/brumbelow/layerleak/internal/scanner"
)

func TestRenderSummarySanitizesUntrustedCells(t *testing.T) {
	result := jobs.Result{
		Status:             jobs.ResultStatusPartial,
		RequestedReference: "library/app:latest",
		Repository:         "library/app",
		Mode:               "reference",
		Targets: []jobs.TargetResult{{
			PlatformResults: []scanner.PlatformResult{{
				ManifestDigest: "sha256:safe",
				Error:          "bad\nrow\x1b[2J\tcell",
			}},
		}},
	}
	var output bytes.Buffer
	if err := renderSummary(&output, result); err != nil {
		t.Fatalf("renderSummary() error = %v", err)
	}
	if strings.ContainsAny(output.String(), "\r\x1b") || strings.Contains(output.String(), "bad\nrow") {
		t.Fatalf("renderSummary() emitted terminal controls: %q", output.String())
	}
	if !strings.Contains(output.String(), "bad row [2J cell") {
		t.Fatalf("renderSummary() missing sanitized status: %q", output.String())
	}
}

func TestScanCommandJSONOutputAndExitCode(t *testing.T) {
	configBody := []byte(`{"architecture":"amd64","os":"linux","config":{"Env":["GH_TOKEN=ghp_123456789012345678901234567890123456"]}}`)
	configDescriptor := commandDescriptor(t, manifest.MediaTypeOCIImageConfig, configBody)
	manifestBody := commandManifestBody(t, configDescriptor)
	manifestDigest := commandDescriptor(t, manifest.MediaTypeOCIImageManifest, manifestBody).Digest
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
			return commandResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, manifestBody, map[string]string{
				"Docker-Content-Digest": manifestDigest,
			}), nil
		case "/v2/library/app/blobs/" + configDescriptor.Digest:
			return commandResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, configBody, nil), nil
		default:
			return commandResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
		}
	})

	installCommandRegistry(t, transport)

	findingsDir := t.TempDir()
	t.Setenv("LAYERLEAK_MAX_FILE_BYTES", "1048576")
	t.Setenv("LAYERLEAK_FINDINGS_DIR", findingsDir)

	command := newRootCmd()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&stderr)
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
	var publicResult map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &publicResult); err != nil {
		t.Fatalf("stdout is not pure JSON: %v; output=%q", err, stdout.String())
	}
	if strings.Contains(stdout.String(), "layerleak:") || strings.Contains(stdout.String(), "██") {
		t.Fatalf("stdout contains progress output: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "layerleak:") {
		t.Fatalf("stderr missing plain progress output: %q", stderr.String())
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

	installCommandRegistry(t, transport)

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
	if strings.Contains(output, "missing line one") || strings.Contains(output, "missing line two") {
		t.Fatalf("stderr contained registry response body: %q", output)
	}
	if !strings.Contains(output, "status=404 Not Found") {
		t.Fatalf("stderr missing safe registry status: %q", output)
	}
}

func TestScanCommandWritesPartialResultsOnConfiguredLimitError(t *testing.T) {
	firstConfigBody := []byte(`{"architecture":"amd64","os":"linux","config":{"Env":["GH_TOKEN=ghp_123456789012345678901234567890123456"]}}`)
	secondConfigBody := []byte(`{"architecture":"arm64","os":"linux","config":{"Env":["GH_TOKEN=ghp_123456789012345678901234567890123456"],"User":"builder","WorkingDir":"https://builder:supersecretvalue@registry.internal/app"}}`)
	firstConfig := commandDescriptor(t, manifest.MediaTypeOCIImageConfig, firstConfigBody)
	secondConfig := commandDescriptor(t, manifest.MediaTypeOCIImageConfig, secondConfigBody)
	firstManifestBody := commandManifestBody(t, firstConfig)
	secondManifestBody := commandManifestBody(t, secondConfig)
	firstManifest := commandDescriptor(t, manifest.MediaTypeOCIImageManifest, firstManifestBody)
	firstManifest.Platform = manifest.Platform{OS: "linux", Architecture: "amd64"}
	secondManifest := commandDescriptor(t, manifest.MediaTypeOCIImageManifest, secondManifestBody)
	secondManifest.Platform = manifest.Platform{OS: "linux", Architecture: "arm64"}
	indexBody := commandIndexBody(t, firstManifest, secondManifest)
	indexDigest := commandDescriptor(t, manifest.MediaTypeOCIImageIndex, indexBody).Digest

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
			return commandResponse(http.StatusOK, manifest.MediaTypeOCIImageIndex, indexBody, map[string]string{
				"Docker-Content-Digest": indexDigest,
			}), nil
		case "/v2/library/app/manifests/" + firstManifest.Digest:
			return commandResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, firstManifestBody, map[string]string{
				"Docker-Content-Digest": firstManifest.Digest,
			}), nil
		case "/v2/library/app/manifests/" + secondManifest.Digest:
			return commandResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, secondManifestBody, map[string]string{
				"Docker-Content-Digest": secondManifest.Digest,
			}), nil
		case "/v2/library/app/blobs/" + firstConfig.Digest:
			return commandResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, firstConfigBody, nil), nil
		case "/v2/library/app/blobs/" + secondConfig.Digest:
			return commandResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, secondConfigBody, nil), nil
		default:
			return commandResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
		}
	})

	installCommandRegistry(t, transport)

	findingsDir := t.TempDir()
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

	allowedDir := t.TempDir()
	t.Setenv("LAYERLEAK_FINDINGS_DIR", allowedDir)
	allowedCommand := newRootCmd()
	allowedCommand.SetOut(io.Discard)
	allowedCommand.SetErr(io.Discard)
	allowedCommand.SetContext(context.Background())
	allowedCommand.SetArgs([]string{"scan", "library/app:latest", "--format", "json", "--allow-partial"})

	allowedErr := allowedCommand.Execute()
	allowedExit, ok := allowedErr.(interface{ ExitCode() int })
	if !ok {
		t.Fatalf("allow-partial Execute() error = %v", allowedErr)
	}
	if allowedExit.ExitCode() != 2 {
		t.Fatalf("allow-partial exit code = %d, want 2", allowedExit.ExitCode())
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
			command.SetArgs([]string{"scan", "library/app", "--all-tags", "--format", "json", tc.flag})

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

func TestScanCommandValidatesOutputAndScopeBeforeScanning(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{name: "invalid format", args: []string{"scan", "library/app", "--format", "xml"}, want: "unsupported output format"},
		{name: "invalid progress", args: []string{"scan", "library/app", "--progress", "sometimes"}, want: "unsupported progress mode"},
		{name: "invalid platform", args: []string{"scan", "library/app", "--platform", "linux"}, want: "invalid --platform"},
		{name: "all tags pinned", args: []string{"scan", "library/app:latest", "--all-tags"}, want: "requires a bare repository"},
		{name: "scope limit without all tags", args: []string{"scan", "library/app", "--tag-page-size", "50"}, want: "requires --all-tags"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			command := newRootCmd()
			command.SetOut(io.Discard)
			command.SetErr(io.Discard)
			command.SetArgs(tc.args)
			err := command.Execute()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Execute() error = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestScanCommandRepositorySweepUsesTagPageSizeFlag(t *testing.T) {
	var (
		mu              sync.Mutex
		observedQueries []string
	)
	configBody := []byte(`{"architecture":"amd64","os":"linux","config":{}}`)
	configDescriptor := commandDescriptor(t, manifest.MediaTypeOCIImageConfig, configBody)
	manifestBody := commandManifestBody(t, configDescriptor)
	manifestDigest := commandDescriptor(t, manifest.MediaTypeOCIImageManifest, manifestBody).Digest

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
			return commandResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, manifestBody, map[string]string{
				"Docker-Content-Digest": manifestDigest,
			}), nil
		case "/v2/library/app/manifests/" + manifestDigest:
			return commandResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, manifestBody, map[string]string{
				"Docker-Content-Digest": manifestDigest,
			}), nil
		case "/v2/library/app/blobs/" + configDescriptor.Digest:
			return commandResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, configBody, nil), nil
		default:
			return commandResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
		}
	})

	installCommandRegistry(t, transport)

	t.Setenv("LAYERLEAK_FINDINGS_DIR", t.TempDir())

	command := newRootCmd()
	var stdout bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&stdout)
	command.SetContext(context.Background())
	command.SetArgs([]string{"scan", "library/app", "--all-tags", "--format", "json", "--tag-page-size", "37"})

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

	installCommandRegistry(t, transport)

	t.Setenv("LAYERLEAK_FINDINGS_DIR", t.TempDir())

	command := newRootCmd()
	var stdout bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&stdout)
	command.SetContext(context.Background())
	command.SetArgs([]string{"scan", "library/app", "--all-tags", "--format", "json", "--max-repository-tags", "1"})

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

	installCommandRegistry(t, transport)

	t.Setenv("LAYERLEAK_FINDINGS_DIR", t.TempDir())

	command := newRootCmd()
	var stdout bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&stdout)
	command.SetContext(context.Background())
	command.SetArgs([]string{"scan", "library/app", "--all-tags", "--format", "json", "--max-repository-targets", "1"})

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

	installCommandRegistry(t, transport)

	t.Setenv("LAYERLEAK_FINDINGS_DIR", t.TempDir())

	command := newRootCmd()
	var stdout bytes.Buffer
	command.SetOut(io.Discard)
	command.SetErr(&stdout)
	command.SetContext(context.Background())
	command.SetArgs([]string{"scan", "library/app", "--all-tags", "--format", "json"})

	_ = command.Execute()

	output := stdout.String()
	if !strings.Contains(output, "enumerates every public tag") {
		t.Fatalf("stderr missing bare repository sweep warning: %q", output)
	}
}

func TestScanCommandBareReferenceDefaultsToLatestWithoutTagEnumeration(t *testing.T) {
	var manifestRequested bool
	var tagsRequested bool
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
			tagsRequested = true
		}
		if request.URL.Path == "/v2/library/app/manifests/latest" {
			manifestRequested = true
		}
		return commandResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
	})

	installCommandRegistry(t, transport)

	t.Setenv("LAYERLEAK_FINDINGS_DIR", t.TempDir())

	command := newRootCmd()
	var stdout bytes.Buffer
	command.SetOut(io.Discard)
	command.SetErr(&stdout)
	command.SetContext(context.Background())
	command.SetArgs([]string{"scan", "library/app", "--format", "json"})

	_ = command.Execute()

	if strings.Contains(stdout.String(), "enumerates every public tag") {
		t.Fatalf("default latest scan should not warn about repository sweep: %q", stdout.String())
	}
	if tagsRequested {
		t.Fatal("bare reference unexpectedly enumerated tags")
	}
	if !manifestRequested {
		t.Fatal("bare reference did not request the latest manifest")
	}
}

type roundTripFunc func(request *http.Request) (*http.Response, error)

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

func installCommandRegistry(t *testing.T, transport roundTripFunc) {
	t.Helper()
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		forwarded := request.Clone(request.Context())
		forwarded.URL.Host = "registry.test"
		if request.URL.Path == "/token" {
			forwarded.URL.Host = "auth.test"
		}
		response, err := transport(forwarded)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		defer response.Body.Close()
		for key, values := range response.Header {
			for _, value := range values {
				if strings.EqualFold(key, "Www-Authenticate") {
					value = strings.ReplaceAll(value, "https://auth.test/token", server.URL+"/token")
				}
				writer.Header().Add(key, value)
			}
		}
		writer.WriteHeader(response.StatusCode)
		_, _ = io.Copy(writer, response.Body)
	}))
	t.Cleanup(server.Close)

	host := strings.TrimPrefix(server.URL, "http://")
	t.Setenv("LAYERLEAK_REGISTRY_BASE_URL", server.URL)
	t.Setenv("LAYERLEAK_REGISTRY_AUTH_URL", server.URL+"/token")
	t.Setenv("LAYERLEAK_ALLOWED_PRIVATE_REGISTRY_HOSTS", host)
	t.Setenv("LAYERLEAK_ALLOWED_PRIVATE_AUTH_HOSTS", host)
}

func commandDescriptor(t *testing.T, mediaType string, body []byte) manifest.Descriptor {
	t.Helper()
	digest, err := manifest.DigestBytes("sha256", body)
	if err != nil {
		t.Fatalf("DigestBytes() error = %v", err)
	}
	return manifest.Descriptor{MediaType: mediaType, Digest: digest, Size: int64(len(body))}
}

func commandManifestBody(t *testing.T, configDescriptor manifest.Descriptor) []byte {
	t.Helper()
	body, err := json.Marshal(manifest.ImageManifest{
		SchemaVersion: 2,
		MediaType:     manifest.MediaTypeOCIImageManifest,
		Config:        configDescriptor,
		Layers:        []manifest.Descriptor{},
	})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	return body
}

func commandIndexBody(t *testing.T, descriptors ...manifest.Descriptor) []byte {
	t.Helper()
	body, err := json.Marshal(manifest.ImageIndex{
		SchemaVersion: 2,
		MediaType:     manifest.MediaTypeOCIImageIndex,
		Manifests:     descriptors,
	})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	return body
}
