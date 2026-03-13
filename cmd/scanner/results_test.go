package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"git.tools.cloudfor.ge/andrew/layerleak/internal/findings"
	"git.tools.cloudfor.ge/andrew/layerleak/internal/manifest"
	"git.tools.cloudfor.ge/andrew/layerleak/internal/scanner"
)

func TestWriteResultFileUsesConfiguredDirectory(t *testing.T) {
	tempDir := t.TempDir()

	filePath, err := writeResultFile(tempDir, scanner.Result{
		RequestedDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		TotalFindings:   3,
		DetailedFindings: []findings.DetailedFinding{
			{
				Finding: findings.Finding{
					DetectorName:        "github_token",
					Confidence:          "high",
					SourceType:          findings.SourceTypeEnv,
					ManifestDigest:      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					Platform:            manifest.Platform{OS: "linux", Architecture: "amd64"},
					Key:                 "TOKEN",
					Fingerprint:         "fingerprint",
					PresentInFinalImage: true,
				},
				Value:          "ghp_123456789012345678901234567890123456",
				RawSnippet:     "TOKEN=ghp_123456789012345678901234567890123456",
				SourceLocation: "env:TOKEN",
				MatchStart:     6,
				MatchEnd:       46,
			},
		},
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

	var result persistedResult
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if result.TotalFindings != 3 {
		t.Fatalf("result.TotalFindings = %d", result.TotalFindings)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("len(result.Findings) = %d", len(result.Findings))
	}
	if result.Findings[0].Value != "ghp_123456789012345678901234567890123456" {
		t.Fatalf("result.Findings[0].Value = %q", result.Findings[0].Value)
	}
	if result.Findings[0].SourceLocation != "env:TOKEN" {
		t.Fatalf("result.Findings[0].SourceLocation = %q", result.Findings[0].SourceLocation)
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

func TestBuildPersistedResultCapsRepeatedLowConfidenceFileFindings(t *testing.T) {
	result := buildPersistedResult(scanner.Result{
		TotalFindings: 5,
		DetailedFindings: []findings.DetailedFinding{
			testDetailedFinding("line one", "file:1"),
			testDetailedFinding("line two", "file:2"),
			testDetailedFinding("line three", "file:3"),
			testDetailedFinding("line four", "file:4"),
			testDetailedFinding("line five", "file:5"),
		},
	})

	if result.TotalFindings != 5 {
		t.Fatalf("result.TotalFindings = %d", result.TotalFindings)
	}
	if len(result.Findings) != persistedLowConfidenceGroupCap {
		t.Fatalf("len(result.Findings) = %d", len(result.Findings))
	}
	if result.Findings[0].OccurrenceCount != 5 {
		t.Fatalf("result.Findings[0].OccurrenceCount = %d", result.Findings[0].OccurrenceCount)
	}
	if result.Findings[0].SuppressedCount != 2 {
		t.Fatalf("result.Findings[0].SuppressedCount = %d", result.Findings[0].SuppressedCount)
	}
	if result.Findings[2].SourceLocation != "file:3" {
		t.Fatalf("result.Findings[2].SourceLocation = %q", result.Findings[2].SourceLocation)
	}
}

func testDetailedFinding(snippet, location string) findings.DetailedFinding {
	return findings.DetailedFinding{
		Finding: findings.Finding{
			DetectorName:        "keyword_entropy",
			Confidence:          "low",
			SourceType:          findings.SourceTypeFileFinal,
			ManifestDigest:      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Platform:            manifest.Platform{OS: "linux", Architecture: "amd64"},
			FilePath:            "usr/share/doc/base-passwd/README",
			LayerDigest:         "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			Fingerprint:         "fingerprint",
			PresentInFinalImage: true,
		},
		Value:          "base-passwd/user-change-gecos",
		RawSnippet:     snippet,
		SourceLocation: location,
		MatchStart:     1,
		MatchEnd:       10,
	}
}
