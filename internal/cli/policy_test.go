package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/findings"
	"github.com/brumbelow/layerleak/v3/internal/jobs"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
)

func TestCountBlockingFindingsHonoursEveryFailOnLevel(t *testing.T) {
	items := []findings.Finding{
		{Confidence: "high"}, {Confidence: "medium"}, {Confidence: "low"}, {Confidence: "low"}, {Confidence: ""},
	}
	cases := map[string]int{"low": 5, "medium": 2, "high": 1, "none": 0}
	for value, want := range cases {
		threshold, err := parseFailOn(value)
		if err != nil {
			t.Fatal(err)
		}
		if got := countBlockingFindings(items, threshold); got != want {
			t.Errorf("--fail-on %s counted %d, want %d", value, got, want)
		}
	}
	if _, err := parseFailOn("critical"); err == nil {
		t.Fatal("unknown --fail-on value accepted")
	}
}

// exitFixtureKind selects what the fake registry serves for library/app:latest.
type exitFixtureKind string

const (
	exitFixtureClean          exitFixtureKind = "clean"
	exitFixtureFinding        exitFixtureKind = "finding"
	exitFixtureFailed         exitFixtureKind = "failed"
	exitFixturePartial        exitFixtureKind = "partial"
	exitFixturePartialFinding exitFixtureKind = "partial-finding"
	exitFixtureUnsupported    exitFixtureKind = "unsupported"
)

// installExitFixture serves a single manifest (clean, finding or failed) or an
// index whose first manifest completes and whose second is missing (partial)
// or carries a foreign layer (unsupported manifest, acceptable partial).
func installExitFixture(t *testing.T, kind exitFixtureKind) {
	t.Helper()
	cleanBody := []byte(`{"architecture":"amd64","os":"linux","config":{}}`)
	findingBody := []byte(`{"architecture":"amd64","os":"linux","config":{"Env":["GH_TOKEN=ghp_123456789012345678901234567890123456"]}}`)
	body := cleanBody
	if kind == exitFixtureFinding || kind == exitFixturePartialFinding {
		body = findingBody
	}
	config := commandDescriptor(t, manifest.MediaTypeOCIImageConfig, body)
	manifestBody := commandManifestBody(t, config)
	good := commandDescriptor(t, manifest.MediaTypeOCIImageManifest, manifestBody)
	good.Platform = manifest.Platform{OS: "linux", Architecture: "amd64"}

	arm64Body := []byte(`{"architecture":"arm64","os":"linux","config":{}}`)
	arm64Config := commandDescriptor(t, manifest.MediaTypeOCIImageConfig, arm64Body)
	foreignLayer := manifest.Descriptor{MediaType: manifest.MediaTypeDockerSchema2ForeignLayerGzip, Digest: "sha256:" + strings.Repeat("c", 64), Size: 10}
	unsupportedBody, err := json.Marshal(manifest.ImageManifest{SchemaVersion: 2, MediaType: manifest.MediaTypeOCIImageManifest, Config: arm64Config, Layers: []manifest.Descriptor{foreignLayer}})
	if err != nil {
		t.Fatal(err)
	}
	unsupported := commandDescriptor(t, manifest.MediaTypeOCIImageManifest, unsupportedBody)
	unsupported.Platform = manifest.Platform{OS: "linux", Architecture: "arm64"}
	missing := good
	missing.Digest = "sha256:" + strings.Repeat("b", 64)
	missing.Platform = manifest.Platform{OS: "linux", Architecture: "arm64"}

	second := missing
	if kind == exitFixtureUnsupported {
		second = unsupported
	}
	indexBody := commandIndexBody(t, good, second)
	installCommandRegistry(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if kind == exitFixtureFailed {
			return commandResponse(http.StatusNotFound, "text/plain", nil, nil), nil
		}
		switch request.URL.Path {
		case "/v2/library/app/manifests/latest":
			if kind == exitFixturePartial || kind == exitFixturePartialFinding || kind == exitFixtureUnsupported {
				return commandResponse(http.StatusOK, manifest.MediaTypeOCIImageIndex, indexBody, nil), nil
			}
			return commandResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, manifestBody, map[string]string{"Docker-Content-Digest": good.Digest}), nil
		case "/v2/library/app/manifests/" + good.Digest:
			return commandResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, manifestBody, nil), nil
		case "/v2/library/app/manifests/" + unsupported.Digest:
			return commandResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, unsupportedBody, nil), nil
		case "/v2/library/app/blobs/" + config.Digest:
			return commandResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, body, nil), nil
		case "/v2/library/app/blobs/" + arm64Config.Digest:
			return commandResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, arm64Body, nil), nil
		default:
			return commandResponse(http.StatusNotFound, "text/plain", nil, nil), nil
		}
	}))
}

func runExitFixture(t *testing.T, kind exitFixtureKind, args ...string) (int, string, error) {
	t.Helper()
	installExitFixture(t, kind)
	t.Setenv("LAYERLEAK_FINDINGS_DIR", t.TempDir())
	t.Setenv("LAYERLEAK_MAX_FILE_BYTES", "1048576")
	command := newRootCmd()
	var stdout, stderr bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	command.SetContext(context.Background())
	command.SetArgs(append([]string{"scan", "library/app:latest", "--format", "json", "--progress", "off"}, args...))
	err := command.Execute()
	code := 0
	if err != nil {
		code = 1
		var coded interface{ ExitCode() int }
		if errors.As(err, &coded) {
			code = coded.ExitCode()
		}
	}
	// Operational failures (exit 1) may end before any result exists.
	if code != exitCodeFailure && !json.Valid(stdout.Bytes()) {
		t.Fatalf("stdout is not JSON: %q", stdout.String())
	}
	return code, stderr.String(), err
}

func TestScanCommandExitCodeTable(t *testing.T) {
	cases := []struct {
		name        string
		kind        exitFixtureKind
		args        []string
		want        int
		wantMessage string
	}{
		{"clean", exitFixtureClean, nil, 0, ""},
		{"finding fail-on low (default)", exitFixtureFinding, nil, 2, ""},
		{"finding fail-on medium", exitFixtureFinding, []string{"--fail-on", "medium"}, 2, ""},
		{"finding fail-on high", exitFixtureFinding, []string{"--fail-on", "high"}, 2, ""},
		{"finding fail-on none", exitFixtureFinding, []string{"--fail-on", "none"}, 0, ""},
		{"failed scan", exitFixtureFailed, nil, 1, "404"},
		{"partial unaccepted", exitFixturePartial, nil, 3, "--allow-partial"},
		{"partial accepted", exitFixturePartial, []string{"--allow-partial"}, 0, ""},
		{"partial unaccepted with findings takes 2", exitFixturePartialFinding, nil, 2, "--allow-partial"},
		{"partial accepted with findings", exitFixturePartialFinding, []string{"--allow-partial"}, 2, ""},
		{"partial unaccepted with findings below threshold", exitFixturePartialFinding, []string{"--fail-on", "none"}, 3, "--allow-partial"},
		{"unsupported manifest unaccepted", exitFixtureUnsupported, nil, 3, "--allow-partial"},
		{"unsupported manifest accepted", exitFixtureUnsupported, []string{"--allow-partial"}, 0, ""},
		{"invalid fail-on", exitFixtureClean, []string{"--fail-on", "critical"}, 1, "--fail-on"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			code, stderr, err := runExitFixture(t, tt.kind, tt.args...)
			if code != tt.want {
				t.Fatalf("exit code = %d, want %d (err=%v stderr=%q)", code, tt.want, err, stderr)
			}
			if tt.wantMessage != "" && (err == nil || !strings.Contains(err.Error(), tt.wantMessage)) {
				t.Fatalf("error = %v, want it to mention %q", err, tt.wantMessage)
			}
			if tt.want == 0 && len(tt.args) > 0 && tt.args[0] == "--allow-partial" && !strings.Contains(stderr, "accepted by --allow-partial") {
				t.Fatalf("accepted partial scan did not warn: %q", stderr)
			}
		})
	}
}

func TestScanCommandReportsTimeoutOnceAndNamesTheSetting(t *testing.T) {
	installReliableCommandFixture(t)
	t.Setenv("LAYERLEAK_FINDINGS_DIR", t.TempDir())
	t.Setenv("LAYERLEAK_SCAN_TIMEOUT", "1ns")
	command := newScanCmd()
	command.SilenceUsage = true
	command.SilenceErrors = true
	var stdout, stderr bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	command.SetArgs([]string{"library/app:latest", "--format", "json", "--progress", "plain"})
	err := command.Execute()
	var coded interface{ ExitCode() int }
	if !errors.As(err, &coded) || coded.ExitCode() != 1 || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout exit = %v", err)
	}
	message := err.Error()
	if strings.Count(message, "LAYERLEAK_SCAN_TIMEOUT") != 1 || strings.Contains(message, "context deadline exceeded context deadline exceeded") {
		t.Fatalf("timeout message = %q", message)
	}
	if strings.Contains(stderr.String(), "Scan record:") || stdout.Len() != 0 {
		t.Fatalf("timed-out scan published output: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestScanCommandNamesTheSignalThatCanceledIt(t *testing.T) {
	installReliableCommandFixture(t)
	t.Setenv("LAYERLEAK_FINDINGS_DIR", t.TempDir())
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(&signalCancellation{signal: syscall.SIGINT})
	command := newScanCmd()
	command.SetOut(io.Discard)
	command.SetErr(io.Discard)
	command.SetContext(ctx)
	command.SetArgs([]string{"library/app:latest", "--format", "json", "--progress", "off"})
	err := command.Execute()
	if err == nil || !errors.Is(err, context.Canceled) || err.Error() != "scan canceled by interrupt signal" {
		t.Fatalf("signal cancellation = %v", err)
	}
}

func TestWatchSignalsCancelsOnceThenRestoresDefaultHandling(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	var stderr bytes.Buffer
	var captured chan<- os.Signal
	stopped := make(chan struct{}, 1)
	stop := watchSignals(cancel, &stderr, func(ch chan<- os.Signal) { captured = ch }, func(chan<- os.Signal) { stopped <- struct{}{} })
	defer stop()

	captured <- syscall.SIGINT
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("first signal did not cancel the run")
	}
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("signal handling was not restored after the first signal")
	}
	var bySignal *signalCancellation
	if !errors.As(context.Cause(ctx), &bySignal) || bySignal.signal != syscall.SIGINT {
		t.Fatalf("cause = %v", context.Cause(ctx))
	}
	if !strings.Contains(stderr.String(), "interrupt received (interrupt), finishing...") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	stop()
	stop() // idempotent
}

func TestEffectiveProgressModeFallsBackToPlain(t *testing.T) {
	env := map[string]string{}
	lookup := func(key string) string { return env[key] }
	if got := effectiveProgressMode(progressModeAuto, "info", lookup); got != progressModeAuto {
		t.Fatalf("plain terminal defaults changed: %s", got)
	}
	if got := effectiveProgressMode(progressModeAuto, "debug", lookup); got != progressModePlain {
		t.Fatalf("debug logging did not force plain progress: %s", got)
	}
	env["TERM"] = "dumb"
	if got := effectiveProgressMode(progressModeAuto, "info", lookup); got != progressModePlain {
		t.Fatalf("TERM=dumb did not force plain progress: %s", got)
	}
	delete(env, "TERM")
	env["CI"] = "true"
	if got := effectiveProgressMode(progressModeAuto, "info", lookup); got != progressModePlain {
		t.Fatalf("CI=true did not force plain progress: %s", got)
	}
	if got := effectiveProgressMode(progressModeTTY, "debug", lookup); got != progressModeTTY {
		t.Fatalf("explicit --progress tty overridden: %s", got)
	}
}

func TestDebugLoggingUsesTheCommandStderr(t *testing.T) {
	installReliableCommandFixture(t)
	t.Setenv("LAYERLEAK_FINDINGS_DIR", t.TempDir())
	t.Setenv("LAYERLEAK_LOG_LEVEL", "debug")
	command := newScanCmd()
	var stdout, stderr bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	command.SetArgs([]string{"library/app:latest", "--format", "json"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), `"level":"DEBUG"`) {
		t.Fatalf("debug log lines did not reach the command stderr: %q", stderr.String())
	}
	if strings.Contains(stderr.String(), "\x1b[") || !strings.Contains(stderr.String(), "layerleak: ") {
		t.Fatalf("debug run did not fall back to plain progress: %q", stderr.String())
	}
	var result jobs.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("stdout polluted by logging: %v", err)
	}
}
