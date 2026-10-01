package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/brumbelow/layerleak/v3/internal/version"
)

func runVersionCommand(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(append([]string{"version"}, args...))
	err := cmd.Execute()
	return out.String(), err
}

func TestVersionCommandTextMatchesVersionFlag(t *testing.T) {
	text, err := runVersionCommand(t)
	if err != nil {
		t.Fatalf("version error = %v", err)
	}
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if len(lines) != 5 {
		t.Fatalf("expected 5 lines, got %d: %q", len(lines), text)
	}
	if want := "layerleak version " + effectiveVersion(); lines[0] != want {
		t.Fatalf("first line = %q, want %q", lines[0], want)
	}
	for i, prefix := range []string{"commit: ", "built: ", "go: ", "platform: "} {
		if !strings.HasPrefix(lines[i+1], prefix) || strings.TrimPrefix(lines[i+1], prefix) == "" {
			t.Fatalf("line %d = %q, want prefix %q with a value", i+1, lines[i+1], prefix)
		}
	}

	flag := newRootCmd()
	var out bytes.Buffer
	flag.SetOut(&out)
	flag.SetArgs([]string{"--version"})
	if err := flag.Execute(); err != nil {
		t.Fatalf("--version error = %v", err)
	}
	if strings.TrimSpace(out.String()) != lines[0] {
		t.Fatalf("--version printed %q, version subcommand printed %q", strings.TrimSpace(out.String()), lines[0])
	}
}

func TestVersionCommandJSON(t *testing.T) {
	text, err := runVersionCommand(t, "--format", "json")
	if err != nil {
		t.Fatalf("version --format json error = %v", err)
	}
	var info version.Info
	if err := json.Unmarshal([]byte(text), &info); err != nil {
		t.Fatalf("json.Unmarshal() error = %v for %q", err, text)
	}
	if info.Version != effectiveVersion() || info.GoVersion == "" || info.OS == "" || info.Arch == "" || info.Commit == "" || info.BuildTime == "" {
		t.Fatalf("unexpected info %+v", info)
	}
	for _, key := range []string{`"version"`, `"commit"`, `"modified"`, `"build_time"`, `"go_version"`, `"os"`, `"arch"`} {
		if !strings.Contains(text, key) {
			t.Fatalf("JSON output lacks %s: %s", key, text)
		}
	}
}

func TestVersionCommandRejectsUnknownFormatAndArguments(t *testing.T) {
	if _, err := runVersionCommand(t, "--format", "yaml"); err == nil || !strings.Contains(err.Error(), "unsupported output format") {
		t.Fatalf("expected format rejection, got %v", err)
	}
	if _, err := runVersionCommand(t, "extra"); err == nil {
		t.Fatal("expected argument rejection")
	}
}
