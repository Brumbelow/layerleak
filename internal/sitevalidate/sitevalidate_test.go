package sitevalidate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type demoFixture struct {
	Version   int    `json:"version"`
	Command   string `json:"command"`
	RunResult struct {
		TotalFindings             int `json:"total_findings"`
		SuppressedExampleFindings int `json:"suppressed_example_findings"`
	} `json:"run_result"`
	Frames []struct {
		DelayMS  int    `json:"delay_ms"`
		Status   string `json:"status"`
		Terminal string `json:"terminal"`
	} `json:"frames"`
	Tables map[string]struct {
		Columns []string         `json:"columns"`
		Rows    []map[string]any `json:"rows"`
	} `json:"tables"`
}

func TestPagesSiteFilesExist(t *testing.T) {
	root := repoRoot(t)
	required := []string{
		"web/index.html",
		"web/docs/index.html",
		"web/demo/index.html",
		"web/assets/styles.css",
		"web/assets/site.js",
		"web/assets/demo.js",
		"web/assets/demo-data.json",
		"web/.nojekyll",
	}

	for _, relativePath := range required {
		if _, err := os.Stat(filepath.Join(root, relativePath)); err != nil {
			t.Fatalf("missing required site file %s: %v", relativePath, err)
		}
	}
}

func TestDemoFixtureIsIntentional(t *testing.T) {
	root := repoRoot(t)
	body, err := os.ReadFile(filepath.Join(root, "web/assets/demo-data.json"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	var fixture demoFixture
	if err := json.Unmarshal(body, &fixture); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if fixture.Version != 1 {
		t.Fatalf("fixture.Version = %d", fixture.Version)
	}
	if fixture.Command != "layerleak scan vulnerableHost:latest --platform linux/amd64" {
		t.Fatalf("fixture.Command = %q", fixture.Command)
	}
	if fixture.RunResult.TotalFindings < 5 || fixture.RunResult.TotalFindings > 7 {
		t.Fatalf("fixture.RunResult.TotalFindings = %d", fixture.RunResult.TotalFindings)
	}
	if fixture.RunResult.SuppressedExampleFindings != 1 {
		t.Fatalf("fixture.RunResult.SuppressedExampleFindings = %d", fixture.RunResult.SuppressedExampleFindings)
	}
	if len(fixture.Frames) < 5 {
		t.Fatalf("len(fixture.Frames) = %d", len(fixture.Frames))
	}

	for index, frame := range fixture.Frames {
		if frame.DelayMS <= 0 {
			t.Fatalf("frame %d delay = %d", index, frame.DelayMS)
		}
		if strings.TrimSpace(frame.Status) == "" {
			t.Fatalf("frame %d status is empty", index)
		}
		if !strings.Contains(frame.Terminal, "layerleak scan vulnerableHost:latest --platform linux/amd64") {
			t.Fatalf("frame %d terminal is missing the demo command", index)
		}
	}

	requiredTables := []string{
		"repositories",
		"tags",
		"manifests",
		"findings",
		"finding_occurrences",
	}

	for _, tableName := range requiredTables {
		table, ok := fixture.Tables[tableName]
		if !ok {
			t.Fatalf("missing table %q", tableName)
		}
		if len(table.Columns) == 0 {
			t.Fatalf("table %q has no columns", tableName)
		}
		if len(table.Rows) == 0 {
			t.Fatalf("table %q has no rows", tableName)
		}
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()

	current, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}

	for {
		if _, err := os.Stat(filepath.Join(current, "go.mod")); err == nil {
			return current
		}

		parent := filepath.Dir(current)
		if parent == current {
			t.Fatal("repo root not found")
		}
		current = parent
	}
}
