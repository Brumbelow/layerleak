package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/findings"
	"github.com/brumbelow/layerleak/v3/internal/jobs"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
	"github.com/brumbelow/layerleak/v3/internal/scanner"
	"github.com/brumbelow/layerleak/v3/internal/scanservice"
)

var recordFileNamePattern = regexp.MustCompile(`^\d{8}T\d{6}Z-library-app-latest-[A-Z0-9]+\.json$`)

func TestWriteResultArtifactsWritesOneRedactedRecordPerScan(t *testing.T) {
	for _, raw := range []bool{false, true} {
		t.Run(fmt.Sprintf("raw=%v", raw), func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "nested", "findings")
			t.Setenv("LAYERLEAK_PERSIST_RAW_SECRETS", map[bool]string{false: "0", true: "1"}[raw])
			artifact, err := writeResultArtifacts(artifactOptions{outputDir: dir}, scanservice.Outcome{Result: configuredDirectoryResult()}, "noop")
			if err != nil {
				t.Fatalf("writeResultArtifacts() error = %v", err)
			}
			if filepath.Dir(artifact.Path) != dir || !recordFileNamePattern.MatchString(filepath.Base(artifact.Path)) {
				t.Fatalf("artifact path = %q", artifact.Path)
			}
			assertResultDirectory(t, dir, 1)
			if _, err := os.Stat(filepath.Join(dir, "scans")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("legacy scans/ directory created: %v", err)
			}
			body, err := os.ReadFile(artifact.Path)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(body), "ghp_1234567890123456789") || strings.Contains(string(body), "raw_context_snippet") || strings.Contains(string(body), `"value"`) {
				t.Fatalf("record carries raw material: %s", body)
			}
			record := readLocalScanRecord(t, artifact.Path)
			if record.RecordSchemaVersion != 2 || record.CreatedAt.IsZero() {
				t.Fatalf("record header = %+v", record)
			}
			if len(record.Findings) != 1 || record.Findings[0].RedactedValue != "ghp********" || record.Findings[0].SourceLocation != "env:TOKEN" || record.Findings[0].ContextSnippet != "TOKEN=ghp********" {
				t.Fatalf("record findings = %+v", record.Findings)
			}
			if record.Result.ResultSchemaVersion != jobs.ResultSchemaVersion || record.Result.DetailedFindings != nil {
				t.Fatalf("record result = %+v", record.Result)
			}
			assertPrivateArtifacts(t, artifact.Path, dir, filepath.Dir(dir))
		})
	}
}

func configuredDirectoryResult() jobs.Result {
	return jobs.Result{
		ResultSchemaVersion: jobs.ResultSchemaVersion,
		RequestedReference:  "library/app:latest",
		Repository:          "library/app",
		RequestedDigest:     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		TotalFindings:       3,
		DetailedFindings: []findings.DetailedFinding{{
			Finding: findings.Finding{
				DetectorName:        "github_token",
				Confidence:          "high",
				SourceType:          findings.SourceTypeEnv,
				ManifestDigest:      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				Platform:            manifest.Platform{OS: "linux", Architecture: "amd64"},
				Key:                 "TOKEN",
				RedactedValue:       "ghp********",
				Fingerprint:         "fingerprint",
				ContextSnippet:      "TOKEN=ghp********",
				PresentInFinalImage: true,
			},
			Value:          "ghp_1234567890123456789" + "01234567890123456",
			RawSnippet:     "TOKEN=ghp_1234567890123456789" + "01234567890123456",
			SourceLocation: "env:TOKEN",
			MatchStart:     6,
			MatchEnd:       46,
		}},
	}
}

// assertPrivateArtifacts checks files are 0600 and directories the CLI
// created are 0700. Pre-existing directories are checked by their own tests.
func assertPrivateArtifacts(t *testing.T, paths ...string) {
	t.Helper()
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Stat(%s) error = %v", path, err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("insecure artifact %s: permissions = %o", path, info.Mode().Perm())
		}
	}
}

func TestResolveFindingsDirUsesWorkingDirectoryNotGoModule(t *testing.T) {
	workdir := t.TempDir()
	// A go.mod above the working directory must not re-root the output.
	if err := os.WriteFile(filepath.Join(workdir, "go.mod"), []byte("module example.test/other\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cwd := filepath.Join(workdir, "deeper")
	if err := os.Mkdir(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(cwd)
	resolved, err := filepath.EvalSymlinks(cwd)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, flag, env, want string
	}{
		{"default", "", "", filepath.Join(resolved, "findings")},
		{"relative env", "", "out/records", filepath.Join(resolved, "out", "records")},
		{"absolute env", "", filepath.Join(workdir, "abs"), filepath.Join(workdir, "abs")},
		{"flag wins", "flagged", filepath.Join(workdir, "abs"), filepath.Join(resolved, "flagged")},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			dir, err := resolveFindingsDir(tt.flag, tt.env)
			if err != nil {
				t.Fatal(err)
			}
			got, _ := filepath.EvalSymlinks(filepath.Dir(dir))
			if filepath.Join(got, filepath.Base(dir)) != tt.want && dir != tt.want {
				t.Fatalf("resolveFindingsDir(%q, %q) = %q, want %q", tt.flag, tt.env, dir, tt.want)
			}
		})
	}
}

func TestEnsurePrivateDirectoryNeverChangesExistingModeOrFollowsSymlinks(t *testing.T) {
	base := t.TempDir()

	shared := filepath.Join(base, "shared")
	if err := os.Mkdir(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o755); err != nil { //nolint:gosec // the test needs a group-readable directory
		t.Fatal(err)
	}
	warning, err := ensurePrivateDirectory(shared)
	if err != nil || !strings.Contains(warning, "accessible to other users") {
		t.Fatalf("shared dir: warning=%q err=%v", warning, err)
	}
	info, _ := os.Stat(shared)
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("pre-existing directory mode changed to %o", info.Mode().Perm())
	}

	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := ensurePrivateDirectory(link); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("symlinked dir accepted: %v", err)
	}
	info, _ = os.Stat(target)
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("symlink target mode changed to %o", info.Mode().Perm())
	}

	fresh := filepath.Join(base, "fresh", "nested")
	warning, err = ensurePrivateDirectory(fresh)
	if err != nil || warning != "" {
		t.Fatalf("fresh dir: warning=%q err=%v", warning, err)
	}
	assertPrivateArtifacts(t, fresh, filepath.Dir(fresh))

	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ensurePrivateDirectory(file); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("regular file accepted: %v", err)
	}
}

func TestPublishTemporaryFallsBackWithoutHardLinks(t *testing.T) {
	original := linkFile
	t.Cleanup(func() { linkFile = original })
	linkFile = func(string, string) error { return syscall.EPERM }

	dir := t.TempDir()
	path, err := publishResultJSON(dir, "record.json", map[string]string{"ok": "yes"})
	if err != nil {
		t.Fatalf("publishResultJSON() without hard links error = %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(body), `"ok": "yes"`) {
		t.Fatalf("copied record = %q, %v", body, err)
	}
	assertPrivateArtifacts(t, path)
	assertResultDirectory(t, dir, 1)

	// The no-overwrite guarantee survives the fallback.
	if _, err := publishResultJSON(dir, "record.json", map[string]string{"ok": "no"}); err == nil {
		t.Fatal("existing record overwritten through the copy fallback")
	}
	body, _ = os.ReadFile(path)
	if !strings.Contains(string(body), `"ok": "yes"`) {
		t.Fatalf("existing record changed: %s", body)
	}
	assertResultDirectory(t, dir, 1)
}

func TestPublishResultJSONNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	collision := filepath.Join(dir, "scan.json")
	if err := os.WriteFile(collision, []byte("existing record"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := publishResultJSON(dir, "scan.json", localScanRecord{RecordSchemaVersion: recordSchemaVersion}); err == nil {
		t.Fatal("existing artifact overwritten")
	}
	body, _ := os.ReadFile(collision)
	if string(body) != "existing record" {
		t.Fatalf("existing artifact changed: %s", body)
	}
	assertResultDirectory(t, dir, 1)
}

func TestWriteResultArtifactsPublishesConcurrentResultsWithoutCollisions(t *testing.T) {
	const writers = 16
	findingsDir := t.TempDir()
	result := jobs.Result{ResultSchemaVersion: jobs.ResultSchemaVersion, Status: jobs.ResultStatusCompleted, RequestedReference: "library/app:latest"}

	paths := make(chan string, writers)
	failures := make(chan error, writers)
	var group sync.WaitGroup
	for range writers {
		group.Add(1)
		go func() {
			defer group.Done()
			artifact, err := writeResultArtifacts(artifactOptions{outputDir: findingsDir}, scanservice.Outcome{Result: result}, "noop")
			if err != nil {
				failures <- err
				return
			}
			paths <- artifact.Path
		}()
	}
	group.Wait()
	close(failures)
	close(paths)

	for err := range failures {
		t.Fatalf("writeResultArtifacts() error = %v", err)
	}
	unique := make(map[string]struct{})
	for path := range paths {
		unique[path] = struct{}{}
		record := readLocalScanRecord(t, path)
		if record.Persistence.Status != "disabled" || record.Persistence.ScanRunID != 0 {
			t.Fatalf("persistence=%+v", record.Persistence)
		}
	}
	if len(unique) != writers {
		t.Fatalf("unique result paths = %d, want %d", len(unique), writers)
	}
	assertResultDirectory(t, findingsDir, writers)
}

func TestWriteResultArtifactsRecordsPersistenceAndKeepsDiagnostics(t *testing.T) {
	for _, status := range []jobs.ResultStatus{jobs.ResultStatusCompleted, jobs.ResultStatusPartial, jobs.ResultStatusFailed} {
		t.Run(string(status), func(t *testing.T) {
			dir := t.TempDir()
			result := jobs.Result{ResultSchemaVersion: jobs.ResultSchemaVersion, Status: status, RequestedReference: "library/app:latest", ResolvedReference: "library/app@sha256:abc", Repository: "library/app", Mode: "reference", ManifestCount: 2, CompletedManifestCount: 1, Coverage: scanner.Coverage{Complete: status == jobs.ResultStatusCompleted}, Diagnostics: []scanner.Diagnostic{{Code: "test_failure", Message: "synthetic-diagnostic\x1b[2Jtext"}}}
			artifact, err := writeResultArtifacts(artifactOptions{outputDir: dir, now: func() time.Time { return time.Date(2026, time.October, 1, 8, 30, 0, 0, time.UTC) }}, scanservice.Outcome{Result: result, SaveError: errors.New("synthetic-database-detail")}, "postgres")
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(filepath.Base(artifact.Path), "20261001T083000Z-library-app-latest-") {
				t.Fatalf("file name = %q", filepath.Base(artifact.Path))
			}
			body, err := os.ReadFile(artifact.Path)
			if err != nil {
				t.Fatal(err)
			}
			record := readLocalScanRecord(t, artifact.Path)
			if record.RecordSchemaVersion != 2 || record.CreatedAt.IsZero() || record.Result.Status != status {
				t.Fatalf("incomplete record: %+v", record)
			}
			if record.Persistence.Status != "failed" || record.Persistence.ScanRunID != 0 || record.Persistence.ErrorCode != "storage_unavailable" {
				t.Fatalf("persistence = %+v", record.Persistence)
			}
			// Real diagnostic text, control characters removed, storage detail neutral.
			if !strings.Contains(string(body), "synthetic-diagnostic [2Jtext") || strings.Contains(string(body), "synthetic-database-detail") || strings.ContainsRune(string(body), 0x1b) {
				t.Fatalf("unexpected record messages: %s", body)
			}
			if record.Findings == nil {
				t.Fatalf("findings array omitted: %s", body)
			}
		})
	}
}

func TestWriteResultArtifactsRecordsSavedScanRunID(t *testing.T) {
	item := findings.DetailedFinding{
		Finding:    findings.Finding{DetectorName: "keyword_entropy", Confidence: "low", Disposition: findings.DispositionActionable, SourceType: findings.SourceTypeFileFinal, FilePath: "app/.env", RedactedValue: "syn********", Fingerprint: "fingerprint", ContextSnippet: "SECRET=syn********"},
		Value:      "synthetic-raw-value",
		RawSnippet: "SECRET=synthetic-raw-value",
	}
	result := jobs.Result{ResultSchemaVersion: jobs.ResultSchemaVersion, Status: jobs.ResultStatusCompleted, DetailedFindings: []findings.DetailedFinding{item}, Findings: []findings.Finding{item.Finding}}
	artifact, err := writeResultArtifacts(artifactOptions{outputDir: t.TempDir()}, scanservice.Outcome{Result: result, ScanRunID: 42}, "postgres")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(artifact.Path)
	if strings.Contains(string(body), "synthetic-raw-value") || !strings.Contains(string(body), `"scan_run_id": 42`) || !strings.Contains(string(body), `"status": "saved"`) {
		t.Fatalf("record = %s", body)
	}
}

func TestWriteResultArtifactsWarnsOnceForSharedDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // the test needs a group-readable directory
		t.Fatal(err)
	}
	artifact, err := writeResultArtifacts(artifactOptions{outputDir: dir}, scanservice.Outcome{Result: jobs.Result{ResultSchemaVersion: jobs.ResultSchemaVersion}}, "noop")
	if err != nil {
		t.Fatal(err)
	}
	if len(artifact.Warnings) != 1 || !strings.Contains(artifact.Warnings[0], "accessible to other users") {
		t.Fatalf("warnings = %q", artifact.Warnings)
	}
	info, _ := os.Stat(dir)
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("shared directory mode changed to %o", info.Mode().Perm())
	}
	assertPrivateArtifacts(t, artifact.Path)
}

func TestSanitizePathTokenBoundsAndCleansReferences(t *testing.T) {
	cases := map[string]string{
		"library/app:latest":         "library-app-latest",
		"ghcr.io/Org/App@sha256:abc": "ghcr-io-Org-App-sha256-abc",
		"../../etc/passwd":           "etc-passwd",
		"weird\x00chars\n":           "weirdchars",
		strings.Repeat("a", 200):     strings.Repeat("a", 96),
	}
	for input, want := range cases {
		if got := sanitizePathToken(input); got != want {
			t.Errorf("sanitizePathToken(%q) = %q, want %q", input, got, want)
		}
	}
}

func readLocalScanRecord(t *testing.T, path string) localScanRecord {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record localScanRecord
	if err := json.Unmarshal(body, &record); err != nil {
		t.Fatal(err)
	}
	return record
}

func assertResultDirectory(t *testing.T, path string, wantEntries int) {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatalf("ReadDir(%s) error = %v", path, err)
	}
	if len(entries) != wantEntries {
		t.Fatalf("result entries in %s = %d, want %d", path, len(entries), wantEntries)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".layerleak-result-") {
			t.Fatalf("temporary result file was left behind: %s", entry.Name())
		}
	}
}
