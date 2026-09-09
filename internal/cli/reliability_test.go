package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brumbelow/layerleak/internal/config"
	"github.com/brumbelow/layerleak/internal/jobs"
	"github.com/brumbelow/layerleak/internal/manifest"
	"github.com/brumbelow/layerleak/internal/storage"
)

func TestScanCommandPreservesOutputAfterProgressFailure(t *testing.T) {
	installReliableCommandFixture(t)
	dir := t.TempDir()
	t.Setenv("LAYERLEAK_FINDINGS_DIR", dir)
	command := newScanCmd()
	command.SilenceUsage = true
	var stdout bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(brokenWriter{})
	command.SetArgs([]string{"library/app:latest", "--format", "json", "--progress", "plain"})
	if err := command.Execute(); err != nil {
		t.Fatalf("progress prevented result publication: %v", err)
	}
	if !json.Valid(stdout.Bytes()) {
		t.Fatalf("no JSON output: %q", stdout.String())
	}
	paths, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	if len(paths) != 1 {
		t.Fatalf("saved findings = %v", paths)
	}
}

func installReliableCommandFixture(t *testing.T, statuses ...jobs.ResultStatus) {
	t.Helper()
	body := []byte(`{"architecture":"amd64","os":"linux","config":{}}`)
	descriptor := commandDescriptor(t, manifest.MediaTypeOCIImageConfig, body)
	manifestBody := commandManifestBody(t, descriptor)
	digest := commandDescriptor(t, manifest.MediaTypeOCIImageManifest, manifestBody).Digest

	status := jobs.ResultStatusCompleted
	if len(statuses) > 0 {
		status = statuses[0]
	}
	first := commandDescriptor(t, manifest.MediaTypeOCIImageManifest, manifestBody)
	first.Platform = manifest.Platform{OS: "linux", Architecture: "amd64"}
	missing := first
	missing.Digest = "sha256:" + strings.Repeat("b", 64)
	missing.Platform.Architecture = "arm64"
	indexBody := commandIndexBody(t, first, missing)
	installCommandRegistry(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if status == jobs.ResultStatusFailed {
			return commandResponse(http.StatusNotFound, "text/plain", nil, nil), nil
		}
		switch request.URL.Path {
		case "/v2/library/app/manifests/latest":
			if status == jobs.ResultStatusPartial {
				return commandResponse(http.StatusOK, manifest.MediaTypeOCIImageIndex, indexBody, nil), nil
			}
			return commandResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, manifestBody, map[string]string{"Docker-Content-Digest": digest}), nil
		case "/v2/library/app/manifests/" + first.Digest:
			return commandResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, manifestBody, nil), nil
		case "/v2/library/app/blobs/" + descriptor.Digest:
			return commandResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, body, nil), nil
		default:
			return commandResponse(http.StatusNotFound, "text/plain", nil, nil), nil
		}
	}))
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestScanCommandPreservesOutputAfterSaveFailure(t *testing.T) {
	installReliableCommandFixture(t)
	dir := t.TempDir()
	t.Setenv("LAYERLEAK_FINDINGS_DIR", dir)
	store := &commandFailingStore{}
	command := newScanCmdWithStore(func(config.Config) (storage.Store, error) { return store, nil })
	command.SilenceUsage = true
	var stdout bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(io.Discard)
	command.SetArgs([]string{"library/app:latest", "--format", "json"})
	err := command.Execute()
	if err == nil {
		t.Fatal("save failure was hidden")
	}
	var result jobs.Result
	if decodeErr := json.Unmarshal(stdout.Bytes(), &result); decodeErr != nil {
		t.Fatalf("result lost after save failure: %v; err=%v", decodeErr, err)
	}
	if result.Status != jobs.ResultStatusCompleted {
		t.Fatalf("status=%s", result.Status)
	}
	paths, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	if len(paths) != 1 {
		t.Fatalf("local result lost: %v", paths)
	}
	records, _ := filepath.Glob(filepath.Join(dir, "scans", "*.json"))
	if len(records) != 1 {
		t.Fatalf("scan record lost: %v", records)
	}
	body, _ := os.ReadFile(paths[0])
	if !json.Valid(body) {
		t.Fatal("invalid local result")
	}
}

type commandFailingStore struct{}

func (*commandFailingStore) Name() string { return "failing" }
func (*commandFailingStore) SaveScan(context.Context, storage.ScanRecord) (int64, error) {
	return 0, errors.New("synthetic database failure")
}

func TestScanCommandPublishesJSONWhenCompanionPublicationFails(t *testing.T) {
	installReliableCommandFixture(t)
	dir := t.TempDir()
	t.Setenv("LAYERLEAK_FINDINGS_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "scans"), []byte("obstruction"), 0o600); err != nil {
		t.Fatal(err)
	}
	command := newScanCmd()
	command.SilenceUsage = true
	var stdout, stderr bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	command.SetArgs([]string{"library/app:latest", "--format", "json", "--progress", "plain"})
	if err := command.Execute(); err == nil {
		t.Fatal("publication error hidden")
	}
	if !json.Valid(stdout.Bytes()) {
		t.Fatalf("usable stdout lost: %s", stdout.String())
	}
	paths, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	if len(paths) != 1 {
		t.Fatalf("successful legacy artifact lost: %v", paths)
	}
	if !strings.Contains(stderr.String(), paths[0]) || strings.Contains(stderr.String(), "Scan record:") {
		t.Fatalf("incorrect artifact reporting: %s", stderr.String())
	}
}

func TestScanCommandOutputFailureRemainsVisibleAfterSave(t *testing.T) {
	installReliableCommandFixture(t)
	dir := t.TempDir()
	t.Setenv("LAYERLEAK_FINDINGS_DIR", dir)
	command := newScanCmd()
	command.SilenceUsage = true
	command.SetOut(brokenWriter{})
	command.SetErr(io.Discard)
	command.SetArgs([]string{"library/app:latest", "--format", "json"})
	if err := command.Execute(); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("output error hidden: %v", err)
	}
	paths, _ := filepath.Glob(filepath.Join(dir, "scans", "*.json"))
	if len(paths) != 1 {
		t.Fatalf("saved record lost: %v", paths)
	}
}

func TestScanCommandCoverageAndSaveFailureExitCodes(t *testing.T) {
	tests := []struct {
		status          jobs.ResultStatus
		saveFails       bool
		wantCode        int
		wantPersistence string
		wantScanRunID   int64
	}{
		{jobs.ResultStatusCompleted, false, 0, "saved", 17},
		{jobs.ResultStatusCompleted, true, 1, "failed", 0},
		{jobs.ResultStatusPartial, false, 0, "saved", 17},
		{jobs.ResultStatusPartial, true, 1, "failed", 0},
		{jobs.ResultStatusFailed, false, 1, "", 0},
		{jobs.ResultStatusFailed, true, 1, "", 0},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s/save_fails=%v", tt.status, tt.saveFails), func(t *testing.T) {
			installReliableCommandFixture(t, tt.status)
			dir := t.TempDir()
			t.Setenv("LAYERLEAK_FINDINGS_DIR", dir)
			store := &commandOutcomeStore{fail: tt.saveFails}
			command := newScanCmdWithStore(func(config.Config) (storage.Store, error) { return store, nil })
			command.SilenceUsage = true
			var stdout bytes.Buffer
			command.SetOut(&stdout)
			command.SetErr(brokenWriter{})
			command.SetArgs([]string{"library/app:latest", "--format", "json", "--allow-partial", "--progress", "plain"})
			err := command.Execute()
			assertCommandExitAndSave(t, err, tt.wantCode, store.calls)
			assertCommandCoveragePublication(t, dir, stdout.Bytes(), tt.status, tt.wantPersistence, tt.wantScanRunID)
		})
	}
}

func assertCommandExitAndSave(t *testing.T, err error, wantCode, saves int) {
	t.Helper()
	code := 0
	if err != nil {
		code = 1
		var coded interface{ ExitCode() int }
		if errors.As(err, &coded) {
			code = coded.ExitCode()
		}
	}
	if code != wantCode || saves != 1 {
		t.Fatalf("exit=%d want=%d saves=%d err=%v", code, wantCode, saves, err)
	}
}

func assertCommandCoveragePublication(t *testing.T, dir string, stdout []byte, status jobs.ResultStatus, persistence string, scanRunID int64) {
	t.Helper()
	paths, _ := filepath.Glob(filepath.Join(dir, "scans", "*.json"))
	if status == jobs.ResultStatusFailed {
		if len(paths) != 0 || len(stdout) != 0 {
			t.Fatalf("failed scan publication behavior changed: files=%v stdout=%s", paths, stdout)
		}
		return
	}
	if len(paths) != 1 {
		t.Fatalf("record lost: %v", paths)
	}
	var result jobs.Result
	if err := json.Unmarshal(stdout, &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != status {
		t.Fatalf("status=%s want=%s", result.Status, status)
	}
	record := readLocalScanRecord(t, paths[0])
	if record.Persistence.Status != persistence || record.Persistence.ScanRunID != scanRunID {
		t.Fatalf("persistence=%+v", record.Persistence)
	}
}

type commandOutcomeStore struct {
	fail  bool
	calls int
}

func (s *commandOutcomeStore) Name() string { return "recording" }
func (s *commandOutcomeStore) SaveScan(context.Context, storage.ScanRecord) (int64, error) {
	s.calls++
	if s.fail {
		return 99, errors.New("synthetic storage detail")
	}
	return 17, nil
}

func TestScanCommandPreservesResultsAfterStorageDeadline(t *testing.T) {
	for _, status := range []jobs.ResultStatus{jobs.ResultStatusCompleted, jobs.ResultStatusPartial} {
		t.Run(string(status), func(t *testing.T) {
			installReliableCommandFixture(t, status)
			dir := t.TempDir()
			t.Setenv("LAYERLEAK_FINDINGS_DIR", dir)
			ctx := context.Background()
			command := newScanCmdWithStore(func(config.Config) (storage.Store, error) { return &deadlineStore{}, nil })
			command.SilenceUsage = true
			command.SetContext(ctx)
			var stdout bytes.Buffer
			command.SetOut(&stdout)
			command.SetErr(io.Discard)
			command.SetArgs([]string{"library/app:latest", "--format", "json", "--allow-partial"})
			err := command.Execute()
			if !errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
				t.Fatalf("storage deadline/context = %v/%v", err, ctx.Err())
			}
			var result jobs.Result
			if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
				t.Fatalf("storage deadline discarded stdout: %v", err)
			}
			if result.Status != status {
				t.Fatalf("status=%s want=%s", result.Status, status)
			}
			legacy, _ := filepath.Glob(filepath.Join(dir, "*.json"))
			records, _ := filepath.Glob(filepath.Join(dir, "scans", "*.json"))
			if len(legacy) != 1 || len(records) != 1 {
				t.Fatalf("storage deadline discarded artifacts: %v %v", legacy, records)
			}
			body, _ := os.ReadFile(records[0])
			var record localScanRecord
			if err := json.Unmarshal(body, &record); err != nil {
				t.Fatal(err)
			}
			if record.Persistence.Status != "failed" || record.Persistence.ScanRunID != 0 {
				t.Fatalf("persistence=%+v", record.Persistence)
			}
		})
	}
}

type deadlineStore struct{}

func (*deadlineStore) Name() string { return "deadline" }
func (*deadlineStore) SaveScan(context.Context, storage.ScanRecord) (int64, error) {
	return 0, context.DeadlineExceeded
}

func TestScanCommandReportsDurableArtifactPaths(t *testing.T) {
	for _, mode := range []string{"off", "tty", "plain"} {
		t.Run(mode, func(t *testing.T) {
			installReliableCommandFixture(t)
			dir := filepath.Join(t.TempDir(), strings.Repeat("long-directory-", 8))
			t.Setenv("LAYERLEAK_FINDINGS_DIR", dir)
			t.Setenv("COLUMNS", "80")
			command := newScanCmd()
			command.SilenceUsage = true
			var stdout, stderr bytes.Buffer
			command.SetOut(&stdout)
			command.SetErr(&stderr)
			command.SetArgs([]string{"library/app:latest", "--format", "json", "--progress", mode})
			if err := command.Execute(); err != nil {
				t.Fatal(err)
			}
			if !json.Valid(stdout.Bytes()) {
				t.Fatalf("stdout polluted: %s", stdout.String())
			}
			paths, _ := filepath.Glob(filepath.Join(dir, "*.json"))
			records, _ := filepath.Glob(filepath.Join(dir, "scans", "*.json"))
			if len(paths) != 1 || len(records) != 1 {
				t.Fatalf("missing artifacts: %v %v", paths, records)
			}
			want := "Findings: " + paths[0] + "\nScan record: " + records[0] + "\n"
			if !strings.HasSuffix(stderr.String(), want) {
				t.Fatalf("missing durable full paths at end of stderr: %q", stderr.String())
			}
			if strings.Count(stderr.String(), paths[0]) != 1 || strings.Count(stderr.String(), records[0]) != 1 {
				t.Fatalf("duplicate artifact paths: %q", stderr.String())
			}
		})
	}
}

func TestScanCommandCancellationDuringSaveStillSkipsPublication(t *testing.T) {
	installReliableCommandFixture(t)
	dir := t.TempDir()
	t.Setenv("LAYERLEAK_FINDINGS_DIR", dir)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := &cancelingStore{cancel: cancel}
	command := newScanCmdWithStore(func(config.Config) (storage.Store, error) { return store, nil })
	command.SilenceUsage = true
	command.SetContext(ctx)
	var stdout, stderr bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	command.SetArgs([]string{"library/app:latest", "--format", "json", "--progress", "off"})
	if err := command.Execute(); !errors.Is(err, context.Canceled) {
		t.Fatalf("actual cancellation not retained: %v", err)
	}
	paths, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	records, _ := filepath.Glob(filepath.Join(dir, "scans", "*.json"))
	if stdout.Len() != 0 || len(paths) != 0 || len(records) != 0 {
		t.Fatalf("canceled command published results: stdout=%q paths=%v records=%v", stdout.String(), paths, records)
	}
	if strings.Contains(stderr.String(), "Findings: ") || strings.Contains(stderr.String(), "Scan record: ") {
		t.Fatalf("canceled command claimed artifacts: %q", stderr.String())
	}
}

type cancelingStore struct{ cancel context.CancelFunc }

func (*cancelingStore) Name() string { return "canceling" }
func (s *cancelingStore) SaveScan(context.Context, storage.ScanRecord) (int64, error) {
	s.cancel()
	return 17, nil
}
