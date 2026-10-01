package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestRunLogsFatalErrorAsJSON(t *testing.T) {
	stderr := &bytes.Buffer{}

	code := run(stderr, func() error { return errors.New("synthetic startup failure") })

	if code != 1 {
		t.Fatalf("exit code = %d", code)
	}
	line := strings.TrimSpace(stderr.String())
	if strings.Count(line, "\n") != 0 {
		t.Fatalf("expected one log line, got %q", line)
	}
	var record map[string]any
	if err := json.Unmarshal([]byte(line), &record); err != nil {
		t.Fatalf("stderr is not JSON: %v: %q", err, line)
	}
	if record["level"] != "ERROR" || record["error"] != "synthetic startup failure" || record["msg"] != "api server exited with an error" {
		t.Fatalf("record = %v", record)
	}
}

func TestRunExitsZeroQuietlyOnCleanShutdown(t *testing.T) {
	stderr := &bytes.Buffer{}

	if code := run(stderr, func() error { return nil }); code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected stderr: %q", stderr.String())
	}
}
