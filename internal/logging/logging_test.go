package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestParseFormatAcceptsDocumentedNamesOnly(t *testing.T) {
	for input, want := range map[string]Format{"": FormatJSON, "json": FormatJSON, " JSON ": FormatJSON, "text": FormatText, "Text": FormatText} {
		got, err := ParseFormat(input)
		if err != nil || got != want {
			t.Fatalf("ParseFormat(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	for _, input := range []string{"yaml", "logfmt", "json,text", "texts"} {
		if _, err := ParseFormat(input); err == nil || !strings.Contains(err.Error(), "use json or text") {
			t.Fatalf("ParseFormat(%q) error = %v, want a rejection naming the accepted values", input, err)
		}
	}
}

func TestNewLoggerWritesJSONRecords(t *testing.T) {
	var output bytes.Buffer
	logger, err := NewLogger(&output, "info", "json")
	if err != nil {
		t.Fatal(err)
	}
	logger.Debug("hidden")
	logger.Info("scan started", "repository", "library/app")
	if logger.Enabled(context.Background(), slog.LevelDebug) {
		t.Fatal("debug enabled at info level")
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("records = %q, want exactly one", output.String())
	}
	var record map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &record); err != nil {
		t.Fatalf("record is not JSON: %v (%q)", err, lines[0])
	}
	if record["msg"] != "scan started" || record["repository"] != "library/app" || record["level"] != "INFO" {
		t.Fatalf("record = %v", record)
	}
}

func TestNewLoggerWritesTextRecords(t *testing.T) {
	var output bytes.Buffer
	logger, err := NewLogger(&output, "warn", "text")
	if err != nil {
		t.Fatal(err)
	}
	logger.Info("hidden")
	logger.Warn("tag list truncated", "limit", 500)
	line := strings.TrimSpace(output.String())
	if strings.Count(line, "\n") != 0 || strings.HasPrefix(line, "{") {
		t.Fatalf("text handler output = %q", output.String())
	}
	for _, want := range []string{"level=WARN", `msg="tag list truncated"`, "limit=500"} {
		if !strings.Contains(line, want) {
			t.Fatalf("text record %q lacks %q", line, want)
		}
	}
}

func TestNewLoggerRejectsInvalidLevelAndFormat(t *testing.T) {
	if _, err := NewLogger(&bytes.Buffer{}, "verbose", "json"); err == nil || !strings.Contains(err.Error(), "parse log level") {
		t.Fatalf("invalid level error = %v", err)
	}
	if _, err := NewLogger(&bytes.Buffer{}, "info", "xml"); err == nil || !strings.Contains(err.Error(), `unsupported log format "xml"`) {
		t.Fatalf("invalid format error = %v", err)
	}
	if _, err := NewHandler(&bytes.Buffer{}, Format("yaml"), slog.LevelInfo); err == nil {
		t.Fatal("NewHandler accepted an unknown format")
	}
}
