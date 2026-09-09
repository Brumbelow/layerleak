package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/brumbelow/layerleak/internal/scanner"
	"github.com/brumbelow/layerleak/internal/scanservice"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

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

func TestWriteResultFilePublishesConcurrentResultsWithoutCollisions(t *testing.T) {
	const writers = 16
	findingsDir := t.TempDir()
	result := jobs.Result{
		RequestedDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}

	paths := make(chan string, writers)
	errors := make(chan error, writers)
	var group sync.WaitGroup
	for range writers {
		group.Add(1)
		go func() {
			defer group.Done()
			path, err := writeResultFile(findingsDir, false, result)
			if err != nil {
				errors <- err
				return
			}
			paths <- path
		}()
	}
	group.Wait()
	close(errors)
	close(paths)

	for err := range errors {
		t.Fatalf("writeResultFile() error = %v", err)
	}
	unique := make(map[string]struct{})
	for path := range paths {
		unique[path] = struct{}{}
	}
	if len(unique) != writers {
		t.Fatalf("unique result paths = %d, want %d", len(unique), writers)
	}
	entries, err := os.ReadDir(findingsDir)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	if len(entries) != writers {
		t.Fatalf("result files = %d, want %d", len(entries), writers)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".layerleak-result-") {
			t.Fatalf("temporary result file was left behind: %s", entry.Name())
		}
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

func TestWriteResultArtifactsPreservesCoverageAndRedactsRecord(t *testing.T) {
	for _, status := range []jobs.ResultStatus{jobs.ResultStatusCompleted, jobs.ResultStatusPartial} {
		for _, raw := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/raw=%v", status, raw), func(t *testing.T) {
				dir := t.TempDir()
				result := jobs.Result{ResultSchemaVersion: 1, Status: status, RequestedReference: "library/app:latest", ResolvedReference: "library/app@sha256:abc", Repository: "library/app", Mode: "reference", ManifestCount: 2, CompletedManifestCount: 1, Coverage: scanner.Coverage{Complete: status == jobs.ResultStatusCompleted}, Diagnostics: []scanner.Diagnostic{{Code: "test_failure", Message: "synthetic-private-error"}}}
				paths, err := writeResultArtifacts(dir, raw, scanservice.Outcome{Result: result, SaveError: errors.New("synthetic-database-detail")}, "postgres")
				if err != nil {
					t.Fatal(err)
				}
				if filepath.Base(paths.Findings) != filepath.Base(paths.Scan) || filepath.Dir(paths.Scan) != filepath.Join(dir, "scans") {
					t.Fatalf("paths = %+v", paths)
				}
				body, err := os.ReadFile(paths.Scan)
				if err != nil {
					t.Fatal(err)
				}
				var record struct {
					Version     int         `json:"record_schema_version"`
					CreatedAt   time.Time   `json:"created_at"`
					Result      jobs.Result `json:"result"`
					Persistence struct {
						Status    string `json:"status"`
						ScanRunID int64  `json:"scan_run_id"`
						ErrorCode string `json:"error_code"`
					} `json:"persistence"`
				}
				if err := json.Unmarshal(body, &record); err != nil {
					t.Fatal(err)
				}
				if record.Version != 1 || record.CreatedAt.IsZero() || record.Result.Status != status || record.Result.RequestedReference != "library/app:latest" || record.Result.ResolvedReference != "library/app@sha256:abc" || record.Result.CompletedManifestCount != 1 || record.Result.Coverage.Complete != (status == jobs.ResultStatusCompleted) {
					t.Fatalf("incomplete record: %s", body)
				}
				if record.Persistence.Status != "failed" || record.Persistence.ScanRunID != 0 || record.Persistence.ErrorCode != "storage_unavailable" {
					t.Fatalf("persistence = %s", body)
				}
				if strings.Contains(string(body), "synthetic-private-error") || strings.Contains(string(body), "synthetic-database-detail") {
					t.Fatalf("unsafe record: %s", body)
				}
				legacy, _ := os.ReadFile(paths.Findings)
				if strings.TrimSpace(string(legacy)) != "[]" {
					t.Fatalf("legacy zero findings = %s", legacy)
				}
				for _, path := range []string{dir, filepath.Join(dir, "scans"), paths.Findings, paths.Scan} {
					info, err := os.Stat(path)
					if err != nil || info.Mode().Perm()&0o077 != 0 {
						t.Fatalf("insecure artifact %s: %v", path, err)
					}
				}
			})
		}
	}
}

func TestWriteResultArtifactsRawOptInDoesNotAffectCompanion(t *testing.T) {
	item := testDetailedFinding("synthetic-raw-context", "file:1")
	item.Value = "synthetic-raw-value"
	result := jobs.Result{ResultSchemaVersion: 1, Status: jobs.ResultStatusCompleted, DetailedFindings: []findings.DetailedFinding{item}, Findings: []findings.Finding{item.Finding}}
	paths, err := writeResultArtifacts(t.TempDir(), true, scanservice.Outcome{Result: result, ScanRunID: 42}, "postgres")
	if err != nil {
		t.Fatal(err)
	}
	legacy, _ := os.ReadFile(paths.Findings)
	companion, _ := os.ReadFile(paths.Scan)
	if !strings.Contains(string(legacy), "synthetic-raw-value") || !strings.Contains(string(legacy), "synthetic-raw-context") {
		t.Fatal("legacy raw opt-in lost")
	}
	if strings.Contains(string(companion), "synthetic-raw-value") || strings.Contains(string(companion), "synthetic-raw-context") || !strings.Contains(string(companion), `"scan_run_id": 42`) {
		t.Fatalf("companion = %s", companion)
	}
}

func TestWriteResultArtifactsKeepsFindingsWhenCompanionFails(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "scans"), []byte("obstruction"), 0o600); err != nil {
		t.Fatal(err)
	}
	paths, err := writeResultArtifacts(dir, false, scanservice.Outcome{Result: jobs.Result{ResultSchemaVersion: 1}}, "noop")
	if err == nil || paths.Findings == "" || paths.Scan != "" {
		t.Fatalf("paths=%+v err=%v", paths, err)
	}
	body, readErr := os.ReadFile(paths.Findings)
	if readErr != nil || !json.Valid(body) {
		t.Fatalf("successful artifact removed: %v", readErr)
	}
}

func TestPublishResultArtifactsKeepsRecordWhenFindingsCannotBePublished(t *testing.T) {
	dir := t.TempDir()
	collision := filepath.Join(dir, "scan.json")
	if err := os.WriteFile(collision, []byte("existing findings"), 0o600); err != nil {
		t.Fatal(err)
	}
	paths, err := publishResultArtifacts(dir, "scan.json", []persistedFinding{}, localScanRecord{RecordSchemaVersion: 1})
	if err == nil || paths.Findings != "" || paths.Scan != filepath.Join(dir, "scans", "scan.json") {
		t.Fatalf("paths=%+v err=%v", paths, err)
	}
	body, _ := os.ReadFile(collision)
	if string(body) != "existing findings" {
		t.Fatalf("existing artifact overwritten: %s", body)
	}
	body, readErr := os.ReadFile(paths.Scan)
	if readErr != nil || !json.Valid(body) {
		t.Fatalf("record not preserved: %v", readErr)
	}
}

func TestWriteResultArtifactsConcurrentBasenames(t *testing.T) {
	dir := t.TempDir()
	const writers = 16
	var group sync.WaitGroup
	results := make(chan resultArtifactPaths, writers)
	failures := make(chan error, writers)
	for range writers {
		group.Add(1)
		go func() {
			defer group.Done()
			paths, err := writeResultArtifacts(dir, false, scanservice.Outcome{Result: jobs.Result{ResultSchemaVersion: 1, Status: jobs.ResultStatusCompleted}}, "noop")
			if err != nil {
				failures <- err
			} else {
				results <- paths
			}
		}()
	}
	group.Wait()
	close(results)
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for paths := range results {
		name := filepath.Base(paths.Findings)
		if seen[name] || name != filepath.Base(paths.Scan) {
			t.Fatalf("colliding or unmatched pair: %+v", paths)
		}
		seen[name] = true
		body, err := os.ReadFile(paths.Scan)
		if err != nil {
			t.Fatal(err)
		}
		var record localScanRecord
		if err := json.Unmarshal(body, &record); err != nil {
			t.Fatal(err)
		}
		if record.Persistence.Status != "disabled" || record.Persistence.ScanRunID != 0 {
			t.Fatalf("persistence=%+v", record.Persistence)
		}
	}
	if len(seen) != writers {
		t.Fatalf("published pairs=%d", len(seen))
	}
	for _, path := range []string{dir, filepath.Join(dir, "scans")} {
		entries, err := os.ReadDir(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".layerleak-result-") {
				t.Fatalf("temporary file left: %s", entry.Name())
			}
		}
	}
}
