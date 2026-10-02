package cli

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/findings"
	"github.com/brumbelow/layerleak/v3/internal/jobs"
	"github.com/brumbelow/layerleak/v3/internal/scanservice"
)

// recordSchemaVersion is the record_schema_version of the local scan record.
// Version 2 (3.0.0) made the record the only local artifact: it embeds the
// public result and a findings array, and never carries raw values.
const recordSchemaVersion = 2

// defaultFindingsDirName is the directory under the working directory that
// receives scan records when neither --output-dir nor LAYERLEAK_FINDINGS_DIR
// is set.
const defaultFindingsDirName = "findings"

// linkFile publishes a fully written temporary file under its final name. It
// is a variable so tests can simulate filesystems without hard links.
var linkFile = os.Link

// localScanRecord is the one file written per scan.
type localScanRecord struct {
	RecordSchemaVersion int                `json:"record_schema_version"`
	CreatedAt           time.Time          `json:"created_at"`
	Result              jobs.Result        `json:"result"`
	Findings            []recordFinding    `json:"findings"`
	Persistence         persistenceOutcome `json:"persistence"`
}

// recordFinding is a public finding plus its source location. Raw values and
// raw snippets are never written locally; raw persistence is database-only.
type recordFinding struct {
	findings.Finding
	SourceLocation string `json:"source_location,omitempty"`
}

type persistenceOutcome struct {
	Status       string `json:"status"`
	ScanRunID    int64  `json:"scan_run_id,omitempty"`
	ErrorCode    string `json:"error_code,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
}

// artifactOptions selects where the scan record is written.
type artifactOptions struct {
	// outputDir is the --output-dir flag; it wins over configuredDir.
	outputDir string
	// configuredDir is LAYERLEAK_FINDINGS_DIR; a relative value resolves
	// against the working directory.
	configuredDir string
	// now stamps created_at and the file name; nil means time.Now.
	now func() time.Time
}

// scanArtifact describes a published record.
type scanArtifact struct {
	Path string
	// Warnings are non-fatal observations about the destination, printed once.
	Warnings []string
}

// resolveFindingsDir picks the record directory: --output-dir, then
// LAYERLEAK_FINDINGS_DIR, then ./findings under the working directory.
// Relative values resolve against the working directory, never against a
// surrounding Go module.
func resolveFindingsDir(outputDir, configuredDir string) (string, error) {
	value := strings.TrimSpace(outputDir)
	if value == "" {
		value = strings.TrimSpace(configuredDir)
	}
	if value == "" {
		value = defaultFindingsDirName
	}
	if filepath.IsAbs(value) {
		return filepath.Clean(value), nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("resolve current working directory: %w", err)
	}
	return filepath.Clean(filepath.Join(cwd, value)), nil
}

// ensurePrivateDirectory creates dir with mode 0700 when it is absent and
// otherwise leaves it exactly as found: it never changes the mode of a
// pre-existing directory and never follows a symbolic link in its place. It
// returns a warning when an existing directory is readable by other users.
func ensurePrivateDirectory(dir string) (string, error) {
	info, err := os.Lstat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", fmt.Errorf("create result directory: %w", err)
		}
		return "", nil
	case err != nil:
		return "", fmt.Errorf("inspect result directory: %w", err)
	case info.Mode()&fs.ModeSymlink != 0:
		return "", fmt.Errorf("result directory %q is a symbolic link; point --output-dir or LAYERLEAK_FINDINGS_DIR at the directory itself", dir)
	case !info.IsDir():
		return "", fmt.Errorf("result directory %q is not a directory", dir)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Sprintf("warning: result directory %q is accessible to other users (mode %04o); scan records are written 0600 but the directory is left unchanged", dir, perm), nil
	}
	return "", nil
}

// buildLocalScanRecord assembles the local record for an outcome.
func buildLocalScanRecord(outcome scanservice.Outcome, storeName string, now time.Time) localScanRecord {
	persistence := persistenceOutcome{Status: "disabled"}
	if outcome.SaveError != nil {
		persistence = persistenceOutcome{Status: "failed", ErrorCode: "storage_unavailable", ErrorMessage: "the scan result could not be stored"}
	} else if storeName != "noop" {
		persistence = persistenceOutcome{Status: "saved", ScanRunID: outcome.ScanRunID}
	}
	return localScanRecord{
		RecordSchemaVersion: recordSchemaVersion,
		CreatedAt:           now.UTC().Truncate(time.Second),
		Result:              scanservice.PublicResult(outcome.Result),
		Findings:            buildRecordFindings(outcome.Result),
		Persistence:         persistence,
	}
}

// buildRecordFindings lists every finding (actionable first, then suppressed)
// in its public form with the source location the detector reported.
func buildRecordFindings(result jobs.Result) []recordFinding {
	items := make([]recordFinding, 0, len(result.DetailedFindings)+len(result.SuppressedDetailedFindings))
	for _, item := range result.DetailedFindings {
		items = append(items, recordFinding{Finding: item.PublicFinding(), SourceLocation: item.SourceLocation})
	}
	for _, item := range result.SuppressedDetailedFindings {
		items = append(items, recordFinding{Finding: item.PublicFinding(), SourceLocation: item.SourceLocation})
	}
	return items
}

// writeResultArtifacts writes the one scan record for this run and returns
// its path. Raw values never reach the record regardless of
// LAYERLEAK_PERSIST_RAW_SECRETS.
func writeResultArtifacts(options artifactOptions, outcome scanservice.Outcome, storeName string) (scanArtifact, error) {
	now := time.Now
	if options.now != nil {
		now = options.now
	}
	dir, err := resolveFindingsDir(options.outputDir, options.configuredDir)
	if err != nil {
		return scanArtifact{}, err
	}
	warning, err := ensurePrivateDirectory(dir)
	if err != nil {
		return scanArtifact{}, err
	}
	artifact := scanArtifact{}
	if warning != "" {
		artifact.Warnings = append(artifact.Warnings, warning)
	}
	stamp := now()
	record := buildLocalScanRecord(outcome, storeName, stamp)
	path, err := publishResultJSON(dir, uniqueResultFileName(outcome.Result, stamp), record)
	if err != nil {
		return artifact, err
	}
	artifact.Path = path
	return artifact, nil
}

// publishResultJSON writes value to a private temporary file inside dir and
// publishes it under name without ever overwriting an existing file. The
// directory must already exist (see ensurePrivateDirectory).
func publishResultJSON(dir, name string, value any) (string, error) {
	file, err := os.CreateTemp(dir, ".layerleak-result-*")
	if err != nil {
		return "", fmt.Errorf("create result file: %w", err)
	}
	temporary := file.Name()
	// Best-effort cleanup; the explicit removal after publication reports errors.
	defer func() { _ = os.Remove(temporary) }()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		_ = file.Close()
		return "", fmt.Errorf("write result file: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return "", fmt.Errorf("sync result file: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close result file: %w", err)
	}
	path := filepath.Join(dir, name)
	if err := publishTemporary(temporary, path); err != nil {
		return "", err
	}
	if err := os.Remove(temporary); err != nil {
		return path, fmt.Errorf("remove temporary result file: %w", err)
	}
	return path, nil
}

// publishTemporary links the written temporary file to its final name. On
// filesystems without hard links it falls back to an exclusive create plus
// copy, which keeps the no-overwrite guarantee. An existing destination is
// always an error.
func publishTemporary(temporary, path string) error {
	err := linkFile(temporary, path)
	if err == nil {
		return nil
	}
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("publish result file: %w", err)
	}
	if copyErr := copyExclusive(temporary, path); copyErr != nil {
		return fmt.Errorf("publish result file: %w (hard link failed: %v)", copyErr, err)
	}
	return nil
}

func copyExclusive(source, destination string) error {
	input, err := os.Open(source) //nolint:gosec // the CLI created this temporary file moments ago inside the result directory
	if err != nil {
		return err
	}
	defer func() { _ = input.Close() }()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // destination is inside the result directory the operator chose
	if err != nil {
		return err
	}
	if _, err := io.Copy(output, input); err != nil {
		_ = output.Close()
		_ = os.Remove(destination)
		return err
	}
	if err := output.Sync(); err != nil {
		_ = output.Close()
		return err
	}
	return output.Close()
}

// writeOutputFile writes formatted output to path, creating or truncating it
// with mode 0600. "-" or an empty path means stdout and is handled by the
// caller.
func writeOutputFile(path string, write func(io.Writer) error) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) //nolint:gosec // path is the operator-chosen --output destination
	if err != nil {
		return fmt.Errorf("open output file: %w", err)
	}
	if err := write(file); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close output file: %w", err)
	}
	return nil
}

// uniqueResultFileName returns <utc-timestamp>-<reference-token>-<random>.json.
func uniqueResultFileName(result jobs.Result, now time.Time) string {
	token := sanitizePathToken(result.RequestedReference)
	if token == "" {
		token = sanitizePathToken(result.Repository)
	}
	if token == "" {
		token = "scan-result"
	}
	return fmt.Sprintf("%s-%s-%s.json", now.UTC().Format("20060102T150405Z"), token, rand.Text())
}

func sanitizePathToken(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	var builder strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			builder.WriteRune(r)
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
		case r == '-', r == '_':
			builder.WriteRune(r)
		case r == ':', r == '/', r == '.', r == ' ', r == '@':
			builder.WriteRune('-')
		}
	}
	token := strings.Trim(builder.String(), "-")
	const maxTokenLength = 96
	if len(token) > maxTokenLength {
		token = strings.Trim(token[:maxTokenLength], "-")
	}
	return token
}
