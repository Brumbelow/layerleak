package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/brumbelow/layerleak/v3/internal/detectors"
)

var updateDocs = flag.Bool("update-docs", false, "rewrite docs/detectors.md from the detector catalog")

func runDetectorsList(t *testing.T, args ...string) (string, error) {
	t.Helper()
	command := newRootCmd()
	var stdout, stderr bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	command.SetContext(context.Background())
	command.SetArgs(append([]string{"detectors", "list"}, args...))
	err := command.Execute()
	if stderr.Len() != 0 {
		t.Fatalf("detectors list wrote to stderr: %q", stderr.String())
	}
	return stdout.String(), err
}

func TestDetectorsListTablePrintsEveryCatalogID(t *testing.T) {
	output, err := runDetectorsList(t)
	if err != nil {
		t.Fatalf("detectors list error = %v", err)
	}
	lines := strings.Split(strings.TrimRight(output, "\n"), "\n")
	catalog := detectors.Default().Catalog()
	if len(lines) != len(catalog)+1 {
		t.Fatalf("table has %d lines, want header plus %d rows:\n%s", len(lines), len(catalog), output)
	}
	if fields := strings.Fields(lines[0]); strings.Join(fields, " ") != "ID CONFIDENCE STRATEGY DESCRIPTION" {
		t.Fatalf("header = %q", lines[0])
	}
	for index, id := range catalog {
		row := lines[index+1]
		if !strings.HasPrefix(row, id+" ") {
			t.Fatalf("row %d = %q, want it to start with %q", index+1, row, id)
		}
	}
	if !strings.Contains(output, "github_token") || !strings.Contains(output, "GitHub personal access") {
		t.Fatalf("table lacks the github_token row: %s", output)
	}
}

func TestDetectorsListJSONMatchesDescribe(t *testing.T) {
	output, err := runDetectorsList(t, "--format", "json")
	if err != nil {
		t.Fatalf("detectors list --format json error = %v", err)
	}
	var document detectorCatalog
	if err := json.Unmarshal([]byte(output), &document); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, output)
	}
	want := detectors.Default().Describe()
	if document.Count != len(want) || len(document.Detectors) != len(want) {
		t.Fatalf("count = %d, detectors = %d, want %d", document.Count, len(document.Detectors), len(want))
	}
	for index, info := range want {
		got := document.Detectors[index]
		if got.ID != info.ID || got.Confidence != info.Confidence || got.Description != info.Description || strings.Join(got.Strategies, ",") != strings.Join(info.Strategies, ",") {
			t.Fatalf("detectors[%d] = %+v, want %+v", index, got, info)
		}
	}
}

func TestDetectorsListRejectsUnknownFormat(t *testing.T) {
	output, err := runDetectorsList(t, "--format", "yaml")
	var coded interface{ ExitCode() int }
	if err == nil || !errors.As(err, &coded) || coded.ExitCode() != exitCodeFailure || !strings.Contains(err.Error(), "use table or json") {
		t.Fatalf("detectors list --format yaml = %q, %v", output, err)
	}
	if output != "" {
		t.Fatalf("unexpected output for a rejected format: %q", output)
	}
}

// TestDetectorsDocMatchesCatalog is the golden test behind docs/detectors.md:
// the committed file must equal what the current catalog renders. Regenerate
// with `go test ./internal/cli -run TestDetectorsDocMatchesCatalog -update-docs`
// whenever a detector is added, renamed, re-tiered or re-described.
func TestDetectorsDocMatchesCatalog(t *testing.T) {
	var rendered bytes.Buffer
	if err := renderDetectorsMarkdown(&rendered, detectors.Default().Describe()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("..", "..", "docs", "detectors.md")
	if *updateDocs {
		if err := os.WriteFile(path, rendered.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	committed, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s is missing; run `go test ./internal/cli -run TestDetectorsDocMatchesCatalog -update-docs`", path)
	}
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(committed, rendered.Bytes()) {
		t.Fatalf("%s is out of date with the detector catalog; review the change, then run `go test ./internal/cli -run TestDetectorsDocMatchesCatalog -update-docs`", path)
	}
}

// TestDetectorsDocMentionsOnlyDocumentedAPIPaths guards the prose around the
// catalog: every /api/v1 path docs/detectors.md refers to must be a path the
// OpenAPI document declares, so the generated file cannot advertise an
// endpoint the API does not serve.
func TestDetectorsDocMentionsOnlyDocumentedAPIPaths(t *testing.T) {
	var rendered bytes.Buffer
	if err := renderDetectorsMarkdown(&rendered, detectors.Default().Describe()); err != nil {
		t.Fatal(err)
	}
	spec, err := os.ReadFile(filepath.Join("..", "..", "web", "docs", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	declared := map[string]bool{}
	for _, match := range regexp.MustCompile(`(?m)^  (/\S+):`).FindAllStringSubmatch(string(spec), -1) {
		declared[match[1]] = true
	}
	if len(declared) == 0 {
		t.Fatal("no paths parsed from web/docs/openapi.yaml")
	}
	for _, path := range regexp.MustCompile(`/api/v1/[A-Za-z0-9_{}/-]*`).FindAllString(rendered.String(), -1) {
		if !declared[path] {
			t.Errorf("docs/detectors.md mentions %s, which web/docs/openapi.yaml does not declare", path)
		}
	}
}

func TestRenderDetectorsMarkdownEscapesTableCells(t *testing.T) {
	var output bytes.Buffer
	infos := []detectors.Info{{ID: "sample_rule", Confidence: "low/medium", Strategies: []string{"regex", "key_value"}, Description: "Matches a | b."}}
	if err := renderDetectorsMarkdown(&output, infos); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, want := range []string{"## Detectors (1)", "| `sample_rule` | low/medium | `regex`, `key_value` | Matches a \\| b. |", "| `path_only` |"} {
		if !strings.Contains(text, want) {
			t.Fatalf("markdown lacks %q:\n%s", want, text)
		}
	}
}
