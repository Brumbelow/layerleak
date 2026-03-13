package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"git.tools.cloudfor.ge/andrew/layerleak/internal/scanner"
)

func TestWriteResultFileUsesConfiguredDirectory(t *testing.T) {
	tempDir := t.TempDir()

	filePath, err := writeResultFile(tempDir, scanner.Result{
		RequestedDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		TotalFindings:   3,
	})
	if err != nil {
		t.Fatalf("writeResultFile() error = %v", err)
	}

	if filepath.Dir(filePath) != tempDir {
		t.Fatalf("filepath.Dir(filePath) = %q", filepath.Dir(filePath))
	}

	body, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	var result scanner.Result
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if result.TotalFindings != 3 {
		t.Fatalf("result.TotalFindings = %d", result.TotalFindings)
	}
}

func TestResolveFindingsDirDefaultsToRepoRootFindings(t *testing.T) {
	dir, err := resolveFindingsDir("")
	if err != nil {
		t.Fatalf("resolveFindingsDir() error = %v", err)
	}

	if !strings.HasSuffix(dir, string(filepath.Separator)+"findings") {
		t.Fatalf("dir = %q", dir)
	}
}
