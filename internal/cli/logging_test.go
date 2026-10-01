package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

// TestNewLoggerSelectsHandlerByFormat pins the CLI to the shared
// internal/logging constructor: json and text select the matching slog
// handler and anything else is rejected before a scan starts.
func TestNewLoggerSelectsHandlerByFormat(t *testing.T) {
	var output bytes.Buffer
	jsonLogger, err := newLogger("debug", "json", &output)
	if err != nil {
		t.Fatalf("newLogger(json) error = %v", err)
	}
	if _, ok := jsonLogger.Handler().(*slog.JSONHandler); !ok {
		t.Fatalf("json handler = %T", jsonLogger.Handler())
	}
	jsonLogger.Debug("progress update failed", "error", "boom")
	var record map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &record); err != nil {
		t.Fatalf("json record = %q: %v", output.String(), err)
	}
	if record["msg"] != "progress update failed" || record["level"] != "DEBUG" {
		t.Fatalf("record = %v", record)
	}

	output.Reset()
	textLogger, err := newLogger("info", "text", &output)
	if err != nil {
		t.Fatalf("newLogger(text) error = %v", err)
	}
	if _, ok := textLogger.Handler().(*slog.TextHandler); !ok {
		t.Fatalf("text handler = %T", textLogger.Handler())
	}
	if textLogger.Enabled(context.Background(), slog.LevelDebug) {
		t.Fatal("debug enabled at info level")
	}
	textLogger.Info("scan started", "repository", "library/app")
	if line := output.String(); strings.HasPrefix(line, "{") || !strings.Contains(line, `msg="scan started"`) || !strings.Contains(line, "repository=library/app") {
		t.Fatalf("text record = %q", line)
	}

	if _, err := newLogger("info", "yaml", &output); err == nil || !strings.Contains(err.Error(), "unsupported log format") {
		t.Fatalf("newLogger(yaml) error = %v", err)
	}
	if _, err := newLogger("verbose", "json", &output); err == nil || !strings.Contains(err.Error(), "parse log level") {
		t.Fatalf("newLogger(verbose) error = %v", err)
	}
}

// TestScanCommandLogFormatFlag checks that --log-format text switches the
// stderr log records to key=value form, that LAYERLEAK_LOG_FORMAT is
// honoured when the flag is absent, and that an invalid flag value is
// rejected before the registry is contacted.
func TestScanCommandLogFormatFlag(t *testing.T) {
	run := func(t *testing.T, env string, args ...string) (string, error) {
		t.Helper()
		installExitFixture(t, exitFixtureClean)
		t.Setenv("LAYERLEAK_FINDINGS_DIR", t.TempDir())
		t.Setenv("LAYERLEAK_LOG_LEVEL", "debug")
		t.Setenv("LAYERLEAK_LOG_FORMAT", env)
		command := newRootCmd()
		var stdout, stderr bytes.Buffer
		command.SetOut(&stdout)
		command.SetErr(&stderr)
		command.SetContext(context.Background())
		command.SetArgs(append([]string{"scan", "library/app:latest", "--format", "json", "--progress", "off", "--no-artifacts"}, args...))
		err := command.Execute()
		return stderr.String(), err
	}

	stderr, err := run(t, "", "--log-format", "text")
	if err != nil {
		t.Fatalf("text scan error = %v (stderr=%q)", err, stderr)
	}
	if !strings.Contains(stderr, "level=DEBUG") || strings.Contains(stderr, `"level":"DEBUG"`) {
		t.Fatalf("--log-format text did not switch the log records: %q", stderr)
	}

	stderr, err = run(t, "text")
	if err != nil {
		t.Fatalf("env text scan error = %v (stderr=%q)", err, stderr)
	}
	if !strings.Contains(stderr, "level=DEBUG") {
		t.Fatalf("LAYERLEAK_LOG_FORMAT=text was ignored: %q", stderr)
	}

	stderr, err = run(t, "", "--log-format", "json")
	if err != nil {
		t.Fatalf("json scan error = %v (stderr=%q)", err, stderr)
	}
	if !strings.Contains(stderr, `"level":"DEBUG"`) {
		t.Fatalf("--log-format json did not produce JSON records: %q", stderr)
	}

	stderr, err = run(t, "", "--log-format", "yaml")
	if err == nil || !strings.Contains(err.Error(), "invalid --log-format") {
		t.Fatalf("invalid --log-format error = %v", err)
	}
	if strings.Contains(stderr, "layerleak:") {
		t.Fatalf("scan started despite an invalid --log-format: %q", stderr)
	}
}
