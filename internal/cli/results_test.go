package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brumbelow/layerleak/internal/findings"
	"github.com/brumbelow/layerleak/internal/jobs"
	"github.com/brumbelow/layerleak/internal/manifest"
)

func TestWriteResultFileUsesConfiguredDirectory(t *testing.T) {
	tempDir := filepath.Join(t.TempDir(), "nested", "findings")

	filePath, err := writeResultFile(tempDir, false, jobs.Result{
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
					RedactedValue:       "ghp********************************56",
					Fingerprint:         "fingerprint",
					ContextSnippet:      "TOKEN=ghp********************************56",
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

	var result []persistedFinding
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("len(result) = %d", len(result))
	}
	if result[0].Value != "" {
		t.Fatalf("result[0].Value = %q", result[0].Value)
	}
	if result[0].RawContextSnippet != "" {
		t.Fatalf("result[0].RawContextSnippet = %q", result[0].RawContextSnippet)
	}
	if result[0].RedactedValue != "ghp********************************56" {
		t.Fatalf("result[0].RedactedValue = %q", result[0].RedactedValue)
	}
	if result[0].ContextSnippet != "TOKEN=ghp********************************56" {
		t.Fatalf("result[0].ContextSnippet = %q", result[0].ContextSnippet)
	}
	if result[0].SourceLocation != "env:TOKEN" {
		t.Fatalf("result[0].SourceLocation = %q", result[0].SourceLocation)
	}

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("Stat(filePath) error = %v", err)
	}
	if fileInfo.Mode().Perm()&0o077 != 0 {
		t.Fatalf("file permissions = %o", fileInfo.Mode().Perm())
	}

	dirInfo, err := os.Stat(tempDir)
	if err != nil {
		t.Fatalf("Stat(tempDir) error = %v", err)
	}
	if dirInfo.Mode().Perm()&0o077 != 0 {
		t.Fatalf("directory permissions = %o", dirInfo.Mode().Perm())
	}
}

func TestBuildPersistedFindingsIncludesSuppressedExampleFindings(t *testing.T) {
	result := buildPersistedFindings(jobs.Result{
		DetailedFindings: []findings.DetailedFinding{
			testDetailedFinding("line one", "file:1"),
		},
		SuppressedDetailedFindings: []findings.DetailedFinding{
			func() findings.DetailedFinding {
				item := testDetailedFinding("line two", "file:2")
				item.Disposition = findings.DispositionExample
				item.DispositionReason = findings.DispositionReasonTestPath
				return item
			}(),
		},
	}, false)

	if len(result) != 2 {
		t.Fatalf("len(result) = %d", len(result))
	}
	if result[1].Disposition != findings.DispositionExample {
		t.Fatalf("result[1].Disposition = %q", result[1].Disposition)
	}
	if result[1].DispositionReason != findings.DispositionReasonTestPath {
		t.Fatalf("result[1].DispositionReason = %q", result[1].DispositionReason)
	}
}

func TestBuildPersistedFindingsIncludesRawFieldsWhenEnabled(t *testing.T) {
	result := buildPersistedFindings(jobs.Result{
		DetailedFindings: []findings.DetailedFinding{
			testDetailedFinding("line one", "file:1"),
		},
	}, true)

	if len(result) != 1 {
		t.Fatalf("len(result) = %d", len(result))
	}
	if result[0].Value != "base-passwd/user-change-gecos" {
		t.Fatalf("result[0].Value = %q", result[0].Value)
	}
	if result[0].RawContextSnippet != "line one" {
		t.Fatalf("result[0].RawContextSnippet = %q", result[0].RawContextSnippet)
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

func TestBuildPersistedFindingsCapsRepeatedLowConfidenceFileFindings(t *testing.T) {
	result := buildPersistedFindings(jobs.Result{
		TotalFindings: 5,
		DetailedFindings: []findings.DetailedFinding{
			testDetailedFinding("line one", "file:1"),
			testDetailedFinding("line two", "file:2"),
			testDetailedFinding("line three", "file:3"),
			testDetailedFinding("line four", "file:4"),
			testDetailedFinding("line five", "file:5"),
		},
	}, false)

	if len(result) != persistedLowConfidenceGroupCap {
		t.Fatalf("len(result) = %d", len(result))
	}
	if result[0].OccurrenceCount != 5 {
		t.Fatalf("result[0].OccurrenceCount = %d", result[0].OccurrenceCount)
	}
	if result[0].SuppressedCount != 2 {
		t.Fatalf("result[0].SuppressedCount = %d", result[0].SuppressedCount)
	}
	if result[2].SourceLocation != "file:3" {
		t.Fatalf("result[2].SourceLocation = %q", result[2].SourceLocation)
	}
}

func testDetailedFinding(snippet, location string) findings.DetailedFinding {
	return findings.DetailedFinding{
		Finding: findings.Finding{
			DetectorName:        "keyword_entropy",
			Confidence:          "low",
			Disposition:         findings.DispositionActionable,
			SourceType:          findings.SourceTypeFileFinal,
			ManifestDigest:      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Platform:            manifest.Platform{OS: "linux", Architecture: "amd64"},
			FilePath:            "usr/share/doc/base-passwd/README",
			LayerDigest:         "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			RedactedValue:       "bas***********************os",
			Fingerprint:         "fingerprint",
			ContextSnippet:      "base-passwd/user-change-gecos",
			PresentInFinalImage: true,
		},
		Value:          "base-passwd/user-change-gecos",
		RawSnippet:     snippet,
		SourceLocation: location,
		MatchStart:     1,
		MatchEnd:       10,
	}
}
