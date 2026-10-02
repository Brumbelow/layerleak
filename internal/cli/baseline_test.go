package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/findings"
	"github.com/brumbelow/layerleak/v3/internal/jobs"
)

const (
	testFingerprintA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testFingerprintB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testFingerprintC = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

func writeBaselineFixture(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadBaselineRejectsMalformedFiles(t *testing.T) {
	now := time.Date(2026, time.October, 1, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name, body, want string
	}{
		{"not json", `baseline: []`, "not a JSON object"},
		{"array", `[]`, "not a JSON object"},
		{"missing version", `{"entries": []}`, "baseline_schema_version is missing"},
		{"unknown version", `{"baseline_schema_version": 2, "entries": []}`, "unsupported baseline_schema_version 2"},
		{"missing entries", `{"baseline_schema_version": 1}`, "entries is missing"},
		{"unknown field", `{"baseline_schema_version": 1, "entries": [], "ignore": true}`, `unknown field "ignore"`},
		{"unknown entry field", `{"baseline_schema_version": 1, "entries": [{"fingerprint": "` + testFingerprintA + `", "path": "/x"}]}`, `unknown field "path"`},
		{"trailing content", `{"baseline_schema_version": 1, "entries": []} {}`, "trailing content"},
		{"trailing object close", `{"baseline_schema_version": 1, "entries": []}}`, "trailing content"},
		{"trailing array close", `{"baseline_schema_version": 1, "entries": []}]]]`, "trailing content"},
		{"trailing garbage", `{"baseline_schema_version": 1, "entries": []} garbage`, "trailing content"},
		{"trailing non-JSON whitespace", "{\"baseline_schema_version\": 1, \"entries\": []}\u00a0", "trailing content"},
		{"short fingerprint", `{"baseline_schema_version": 1, "entries": [{"fingerprint": "abc"}]}`, "entry 0: fingerprint must be"},
		{"empty fingerprint", `{"baseline_schema_version": 1, "entries": [{"fingerprint": "", "detector": "github_token"}]}`, "entry 0: fingerprint must be"},
		{"bad detector", `{"baseline_schema_version": 1, "entries": [{"fingerprint": "` + testFingerprintA + `", "detector": "GitHub Token"}]}`, "entry 0: detector"},
		{"bad expires", `{"baseline_schema_version": 1, "entries": [{"fingerprint": "` + testFingerprintA + `", "expires": "tomorrow"}]}`, "entry 0: expires must be an RFC 3339 timestamp"},
		{"long reason", `{"baseline_schema_version": 1, "entries": [{"fingerprint": "` + testFingerprintA + `", "reason": "` + strings.Repeat("r", maxBaselineReasonBytes+1) + `"}]}`, "entry 0: reason exceeds"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			path := writeBaselineFixture(t, tt.body)
			_, err := loadBaseline(path, now)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("loadBaseline() error = %v, want it to mention %q", err, tt.want)
			}
			if !strings.Contains(err.Error(), path) {
				t.Fatalf("error does not name the file: %v", err)
			}
		})
	}
	if _, err := loadBaseline(filepath.Join(t.TempDir(), "missing.json"), now); err == nil || !strings.Contains(err.Error(), "open baseline file") {
		t.Fatalf("missing file error = %v", err)
	}
}

func TestLoadBaselineAcceptsValidFileAndIgnoresExpiredEntriesWithPrefixWarning(t *testing.T) {
	now := time.Date(2026, time.October, 1, 12, 0, 0, 0, time.UTC)
	path := writeBaselineFixture(t, `{
  "baseline_schema_version": 1,
  "entries": [
    {"fingerprint": "`+strings.ToUpper(testFingerprintA)+`", "detector": "github_token", "reason": "rotated 2026-09-01"},
    {"fingerprint": "`+testFingerprintB+`", "expires": "2026-09-30T00:00:00Z", "reason": "temporary"},
    {"fingerprint": "`+testFingerprintC+`", "expires": "2026-12-31T00:00:00Z"}
  ]
}`)
	loaded, err := loadBaseline(path, now)
	if err != nil {
		t.Fatalf("loadBaseline() error = %v", err)
	}
	if loaded.Len() != 2 {
		t.Fatalf("Len() = %d, want 2 live entries", loaded.Len())
	}
	if len(loaded.Warnings) != 1 {
		t.Fatalf("warnings = %v", loaded.Warnings)
	}
	warning := loaded.Warnings[0]
	if !strings.HasPrefix(warning, "warning: baseline entry "+testFingerprintB[:fingerprintPrefixLength]+"...") || !strings.Contains(warning, "expired at 2026-09-30T00:00:00Z") {
		t.Fatalf("warning = %q", warning)
	}
	if strings.Contains(warning, testFingerprintB) {
		t.Fatalf("warning leaks the full fingerprint: %q", warning)
	}
	if _, ok := loaded.match(findings.Finding{DetectorName: "github_token", Fingerprint: testFingerprintA}); !ok {
		t.Fatal("uppercase fingerprint was not normalised")
	}
	if _, ok := loaded.match(findings.Finding{DetectorName: "github_token", Fingerprint: testFingerprintB}); ok {
		t.Fatal("expired entry still matches")
	}
	if _, ok := loaded.match(findings.Finding{DetectorName: "anything", Fingerprint: testFingerprintC}); !ok {
		t.Fatal("future-dated entry does not match")
	}
}

func TestBaselineMatchesFingerprintsAcrossDetectorsOnlyWhenUnscoped(t *testing.T) {
	now := time.Date(2026, time.October, 1, 12, 0, 0, 0, time.UTC)
	path := writeBaselineFixture(t, `{"baseline_schema_version": 1, "entries": [
  {"fingerprint": "`+testFingerprintA+`", "detector": "github_token"},
  {"fingerprint": "`+testFingerprintB+`"}
]}`)
	loaded, err := loadBaseline(path, now)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		detector, fingerprint string
		want                  bool
	}{
		{"github_token", testFingerprintA, true},
		{"keyword_entropy", testFingerprintA, false},
		{"github_token", testFingerprintB, true},
		{"keyword_entropy", testFingerprintB, true},
		{"github_token", testFingerprintC, false},
		{"sensitive_file_private_key", "", false},
	}
	for _, tt := range cases {
		if _, got := loaded.match(findings.Finding{DetectorName: tt.detector, Fingerprint: tt.fingerprint}); got != tt.want {
			t.Errorf("match(%s, %.8s) = %t, want %t", tt.detector, tt.fingerprint, got, tt.want)
		}
	}
	var none *baseline
	if _, ok := none.match(findings.Finding{Fingerprint: testFingerprintA}); ok || none.Len() != 0 {
		t.Fatal("nil baseline matched")
	}
}

func TestApplyBaselineMovesMatchesToSuppressedAndRecounts(t *testing.T) {
	loaded := &baseline{entries: map[string][]baselineEntry{testFingerprintA: {{Fingerprint: testFingerprintA, Reason: "accepted"}}}}
	token := findings.DetailedFinding{Finding: findings.Finding{DetectorName: "github_token", Confidence: "high", Disposition: findings.DispositionActionable, Fingerprint: testFingerprintA}, Value: "synthetic-raw"}
	aws := findings.DetailedFinding{Finding: findings.Finding{DetectorName: "aws_access_key_id", Confidence: "high", Disposition: findings.DispositionActionable, Fingerprint: testFingerprintB}}
	example := findings.DetailedFinding{Finding: findings.Finding{DetectorName: "basic_auth_url", Confidence: "low", Disposition: findings.DispositionExample, DispositionReason: findings.DispositionReasonTestPath, Fingerprint: testFingerprintA}}
	original := jobs.Result{
		Findings:                   []findings.Finding{token.Finding, aws.Finding},
		DetailedFindings:           []findings.DetailedFinding{token, aws},
		SuppressedFindings:         []findings.Finding{example.Finding},
		SuppressedDetailedFindings: []findings.DetailedFinding{example},
		TotalFindings:              2, UniqueFingerprints: 2, SuppressedFindingsCount: 1, SuppressedUniqueFingerprints: 1,
	}

	result, baselined := applyBaseline(original, loaded)
	if baselined != 1 {
		t.Fatalf("baselined = %d", baselined)
	}
	if len(result.Findings) != 1 || result.Findings[0].DetectorName != "aws_access_key_id" || len(result.DetailedFindings) != 1 {
		t.Fatalf("actionable findings = %+v", result.Findings)
	}
	if result.TotalFindings != 1 || result.UniqueFingerprints != 1 || result.SuppressedFindingsCount != 2 || result.SuppressedUniqueFingerprints != 1 {
		t.Fatalf("counters = total %d unique %d suppressed %d suppressed unique %d", result.TotalFindings, result.UniqueFingerprints, result.SuppressedFindingsCount, result.SuppressedUniqueFingerprints)
	}
	if len(result.SuppressedFindings) != 2 || result.SuppressedFindings[0].Disposition != findings.DispositionExample || result.SuppressedFindings[1].Disposition != findings.DispositionBaselined || result.SuppressedFindings[1].DispositionReason != "" {
		t.Fatalf("suppressed findings = %+v", result.SuppressedFindings)
	}
	if len(result.SuppressedDetailedFindings) != 2 || result.SuppressedDetailedFindings[1].Disposition != findings.DispositionBaselined || result.SuppressedDetailedFindings[1].Value != "synthetic-raw" {
		t.Fatalf("suppressed detailed findings = %+v", result.SuppressedDetailedFindings)
	}
	if countBaselined(result.SuppressedFindings) != 1 || countBaselined(result.Findings) != 0 {
		t.Fatal("countBaselined disagrees with the applied view")
	}
	// The scanner's result that was persisted is untouched.
	if len(original.Findings) != 2 || original.Findings[0].Disposition != findings.DispositionActionable || original.TotalFindings != 2 || len(original.SuppressedFindings) != 1 {
		t.Fatalf("applyBaseline modified its input: %+v", original)
	}
	if unchanged, count := applyBaseline(original, nil); count != 0 || len(unchanged.Findings) != 2 {
		t.Fatal("nil baseline changed the result")
	}
	if got := loaded.justification(result.SuppressedFindings[1]); got != "accepted by the caller's baseline file: accepted" {
		t.Fatalf("justification = %q", got)
	}
	if got := loaded.justification(result.SuppressedFindings[0]); got != "" {
		t.Fatalf("example finding got a baseline justification: %q", got)
	}
}

func TestBaselineFromSourceReadsResultsAndRecords(t *testing.T) {
	result := `{"result_schema_version": 2, "findings": [
  {"detector_name": "github_token", "disposition": "actionable", "fingerprint": "` + testFingerprintB + `", "redacted_value": "ghp********"},
  {"detector_name": "aws_access_key_id", "disposition": "actionable", "fingerprint": "` + testFingerprintA + `", "redacted_value": "AKI********"},
  {"detector_name": "aws_access_key_id", "disposition": "actionable", "fingerprint": "` + testFingerprintA + `", "redacted_value": "AKI********"},
  {"detector_name": "keyword_entropy", "disposition": "actionable", "fingerprint": "", "redacted_value": "***"}
 ], "suppressed_findings": [
  {"detector_name": "basic_auth_url", "disposition": "example", "fingerprint": "` + testFingerprintC + `"}
 ]}`
	document, err := baselineFromSource(strings.NewReader(result), "accepted after review")
	if err != nil {
		t.Fatalf("baselineFromSource(result) error = %v", err)
	}
	want := []baselineEntry{
		{Fingerprint: testFingerprintA, Detector: "aws_access_key_id", Reason: "accepted after review"},
		{Fingerprint: testFingerprintB, Detector: "github_token", Reason: "accepted after review"},
	}
	if document.BaselineSchemaVersion != baselineSchemaVersion || len(document.Entries) != len(want) {
		t.Fatalf("document = %+v", document)
	}
	for index := range want {
		if document.Entries[index] != want[index] {
			t.Fatalf("entries[%d] = %+v, want %+v", index, document.Entries[index], want[index])
		}
	}
	var encoded bytes.Buffer
	if err := encodeBaseline(&encoded, document); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"redacted_value", "ghp", "AKI", "context_snippet"} {
		if strings.Contains(encoded.String(), forbidden) {
			t.Fatalf("baseline carries %q: %s", forbidden, encoded.String())
		}
	}

	record := `{"record_schema_version": 2, "created_at": "2026-10-01T12:00:07Z", "result": {"result_schema_version": 2, "findings": [
  {"detector_name": "github_token", "disposition": "actionable", "fingerprint": "` + testFingerprintB + `"}]}, "findings": [], "persistence": {"status": "disabled"}}`
	document, err = baselineFromSource(strings.NewReader(record), "r")
	if err != nil || len(document.Entries) != 1 || document.Entries[0].Detector != "github_token" {
		t.Fatalf("baselineFromSource(record) = %+v, %v", document, err)
	}

	for name, body := range map[string]string{
		"old result":  `{"result_schema_version": 1, "findings": []}`,
		"old record":  `{"record_schema_version": 1, "result": {"result_schema_version": 2, "findings": []}}`,
		"old nested":  `{"record_schema_version": 2, "result": {"result_schema_version": 1, "findings": []}}`,
		"no versions": `{"findings": []}`,
		"not json":    `findings`,
	} {
		if _, err := baselineFromSource(strings.NewReader(body), "r"); err == nil {
			t.Errorf("%s: baselineFromSource accepted %s", name, body)
		}
	}
}

func runBaselineCreate(t *testing.T, now func() time.Time, args ...string) (string, string, error) {
	t.Helper()
	command := newBaselineCreateCmd(now)
	command.SilenceUsage = true
	command.SilenceErrors = true
	var stdout, stderr bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	command.SetContext(context.Background())
	command.SetArgs(args)
	err := command.Execute()
	return stdout.String(), stderr.String(), err
}

func TestBaselineCreateCommandWritesAndRefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "result.json")
	body := `{"result_schema_version": 2, "findings": [{"detector_name": "github_token", "disposition": "actionable", "fingerprint": "` + testFingerprintA + `"}]}`
	if err := os.WriteFile(source, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	now := func() time.Time { return time.Date(2026, time.October, 1, 23, 59, 0, 0, time.UTC) }
	target := filepath.Join(dir, "baseline.json")

	stdout, stderr, err := runBaselineCreate(t, now, "--from", source, "--output", target)
	if err != nil || stdout != "" || !strings.Contains(stderr, "Baseline: 1 entries written to") {
		t.Fatalf("create: stdout=%q stderr=%q err=%v", stdout, stderr, err)
	}
	info, err := os.Stat(target)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("baseline file mode = %v (err %v)", info, err)
	}
	loaded, err := loadBaseline(target, now())
	if err != nil || loaded.Len() != 1 {
		t.Fatalf("written baseline does not load: %v", err)
	}
	entry, ok := loaded.match(findings.Finding{DetectorName: "github_token", Fingerprint: testFingerprintA})
	if !ok || entry.Reason != "baselined on 2026-10-01" {
		t.Fatalf("entry = %+v, %t", entry, ok)
	}

	_, _, err = runBaselineCreate(t, now, "--from", source, "--output", target)
	var coded interface{ ExitCode() int }
	if err == nil || !errors.As(err, &coded) || coded.ExitCode() != exitCodeFailure || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("second create without --force = %v", err)
	}
	if _, _, err := runBaselineCreate(t, now, "--from", source, "--output", target, "--force", "--reason", "accepted"); err != nil {
		t.Fatalf("create --force error = %v", err)
	}
	loaded, err = loadBaseline(target, now())
	if err != nil {
		t.Fatal(err)
	}
	if entry, _ := loaded.match(findings.Finding{DetectorName: "github_token", Fingerprint: testFingerprintA}); entry.Reason != "accepted" {
		t.Fatalf("--force did not replace the file: %+v", entry)
	}

	stdout, _, err = runBaselineCreate(t, now, "--from", source, "--output", "-")
	if err != nil {
		t.Fatal(err)
	}
	var printed baselineDocument
	if err := json.Unmarshal([]byte(stdout), &printed); err != nil || len(printed.Entries) != 1 {
		t.Fatalf("stdout baseline = %q: %v", stdout, err)
	}

	if _, _, err := runBaselineCreate(t, now); err == nil || !strings.Contains(err.Error(), "--from is required") {
		t.Fatalf("missing --from error = %v", err)
	}
	if _, _, err := runBaselineCreate(t, now, "--from", filepath.Join(dir, "missing.json")); err == nil || !strings.Contains(err.Error(), "open --from file") {
		t.Fatalf("missing source error = %v", err)
	}
	if err := os.WriteFile(source, []byte(`{"result_schema_version": 1, "findings": []}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runBaselineCreate(t, now, "--from", source, "--output", "-"); err == nil || !strings.Contains(err.Error(), "unsupported result_schema_version 1") {
		t.Fatalf("old schema error = %v", err)
	}
}

// runBaselineScan runs `scan library/app:latest` against the installed
// fixture with the given extra arguments and returns stdout, stderr and the
// exit code (0 for a nil error).
func runBaselineScan(t *testing.T, args ...string) (string, string, int, error) {
	t.Helper()
	command := newRootCmd()
	var stdout, stderr bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	command.SetContext(context.Background())
	command.SetArgs(append([]string{"scan", "library/app:latest", "--progress", "off"}, args...))
	err := command.Execute()
	code := 0
	var coded interface{ ExitCode() int }
	if errors.As(err, &coded) {
		code = coded.ExitCode()
	} else if err != nil {
		code = -1
	}
	return stdout.String(), stderr.String(), code, err
}

func TestScanCommandBaselineIsAPerCallerView(t *testing.T) {
	installExitFixture(t, exitFixtureFinding)
	recordDir := t.TempDir()
	t.Setenv("LAYERLEAK_FINDINGS_DIR", recordDir)
	t.Setenv("LAYERLEAK_MAX_FILE_BYTES", "1048576")
	work := t.TempDir()

	// 1. An unbaselined scan fails with exit 2 and yields the result to baseline.
	stdout, _, code, _ := runBaselineScan(t, "--format", "json", "--no-artifacts")
	if code != exitCodeFindings {
		t.Fatalf("unbaselined exit = %d", code)
	}
	var published jobs.Result
	if err := json.Unmarshal([]byte(stdout), &published); err != nil || len(published.Findings) != 1 || published.Findings[0].DetectorName != "github_token" {
		t.Fatalf("unbaselined result = %v (%s)", err, stdout)
	}
	fingerprint := published.Findings[0].Fingerprint
	resultPath := filepath.Join(work, "result.json")
	if err := os.WriteFile(resultPath, []byte(stdout), 0o600); err != nil {
		t.Fatal(err)
	}

	// 2. baseline create turns it into a baseline file.
	baselinePath := filepath.Join(work, "baseline.json")
	if _, _, err := runBaselineCreate(t, time.Now, "--from", resultPath, "--output", baselinePath, "--reason", "rotated; old layer only"); err != nil {
		t.Fatalf("baseline create error = %v", err)
	}

	// 3. The baselined scan exits 0 with the finding reported as baselined on
	// stdout and in the scan record.
	stdout, stderr, code, err := runBaselineScan(t, "--format", "json", "--baseline", baselinePath)
	if code != 0 {
		t.Fatalf("baselined exit = %d (%v, stderr %q)", code, err, stderr)
	}
	var baselined jobs.Result
	if err := json.Unmarshal([]byte(stdout), &baselined); err != nil {
		t.Fatalf("baselined result: %v", err)
	}
	if len(baselined.Findings) != 0 || baselined.TotalFindings != 0 || baselined.UniqueFingerprints != 0 {
		t.Fatalf("baselined result still has actionable findings: %+v", baselined.Findings)
	}
	if len(baselined.SuppressedFindings) != 1 || baselined.SuppressedFindings[0].Disposition != findings.DispositionBaselined || baselined.SuppressedFindings[0].Fingerprint != fingerprint || baselined.SuppressedFindingsCount != 1 || baselined.SuppressedUniqueFingerprints != 1 {
		t.Fatalf("baselined result suppressed findings = %+v (count %d)", baselined.SuppressedFindings, baselined.SuppressedFindingsCount)
	}
	if baselined.Targets[0].FindingsCount != 1 {
		t.Fatalf("per-target count should keep the scanner's value, got %d", baselined.Targets[0].FindingsCount)
	}
	if strings.Contains(stdout, "ghp_123456789012345678901234567890123456") {
		t.Fatal("baselined output leaked the raw secret")
	}
	entries, err := os.ReadDir(recordDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("scan records = %v, %v", entries, err)
	}
	record := readLocalScanRecord(t, filepath.Join(recordDir, entries[0].Name()))
	if record.Result.TotalFindings != 0 || len(record.Findings) != 1 || record.Findings[0].Disposition != findings.DispositionBaselined {
		t.Fatalf("scan record does not carry the baselined view: %+v", record.Findings)
	}

	// 4. The summary names the baselined count and lists no actionable rows.
	stdout, _, code, _ = runBaselineScan(t, "--format", "summary", "--baseline", baselinePath, "--no-artifacts")
	if code != 0 || !strings.Contains(stdout, "Baselined Findings:           1") || !strings.Contains(stdout, "Suppressed Example Findings:  0") || strings.Contains(stdout, "Redacted Value") {
		t.Fatalf("summary exit %d:\n%s", code, stdout)
	}

	// 5. SARIF carries the baseline reason as the suppression justification.
	stdout, _, code, _ = runBaselineScan(t, "--format", "sarif", "--baseline", baselinePath, "--no-artifacts")
	if code != 0 {
		t.Fatalf("sarif exit = %d", code)
	}
	var log struct {
		Runs []struct {
			Results []struct {
				Suppressions []struct {
					Kind, Status, Justification string
				} `json:"suppressions"`
				Properties map[string]any `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(stdout), &log); err != nil || len(log.Runs) != 1 || len(log.Runs[0].Results) != 1 {
		t.Fatalf("sarif = %v\n%s", err, stdout)
	}
	suppressions := log.Runs[0].Results[0].Suppressions
	if len(suppressions) != 1 || suppressions[0].Kind != "external" || suppressions[0].Status != "accepted" || suppressions[0].Justification != "accepted by the caller's baseline file: rotated; old layer only" || log.Runs[0].Results[0].Properties["disposition"] != "baselined" {
		t.Fatalf("sarif suppressions = %+v properties = %v", suppressions, log.Runs[0].Results[0].Properties)
	}

	// 6. --fail-on still applies to findings the baseline does not cover: an
	// entry scoped to another detector leaves the finding actionable.
	scoped := writeBaselineFixture(t, `{"baseline_schema_version": 1, "entries": [{"fingerprint": "`+fingerprint+`", "detector": "keyword_entropy"}]}`)
	if _, _, code, _ := runBaselineScan(t, "--format", "json", "--baseline", scoped, "--no-artifacts"); code != exitCodeFindings {
		t.Fatalf("detector-scoped entry for another detector changed the exit code to %d", code)
	}

	// 7. An expired entry is ignored with a prefix-only warning and exit 2.
	expired := writeBaselineFixture(t, `{"baseline_schema_version": 1, "entries": [{"fingerprint": "`+fingerprint+`", "expires": "2020-01-01T00:00:00Z"}]}`)
	_, stderr, code, _ = runBaselineScan(t, "--format", "json", "--baseline", expired, "--no-artifacts")
	if code != exitCodeFindings || !strings.Contains(stderr, "warning: baseline entry "+fingerprint[:fingerprintPrefixLength]+"... expired") || strings.Contains(stderr, fingerprint) {
		t.Fatalf("expired entry: exit %d stderr %q", code, stderr)
	}

	// 8. A malformed baseline fails before the scan starts.
	malformed := writeBaselineFixture(t, `{"baseline_schema_version": 7, "entries": []}`)
	_, stderr, code, err = runBaselineScan(t, "--format", "json", "--baseline", malformed, "--no-artifacts")
	if code != exitCodeFailure || err == nil || !strings.Contains(err.Error(), "unsupported baseline_schema_version 7") || strings.Contains(stderr, "layerleak:") {
		t.Fatalf("malformed baseline: exit %d err %v stderr %q", code, err, stderr)
	}
}

// TestScanCommandNeverReadsLayerleakignoreImplicitly pins the explicit-flag
// contract: a .layerleakignore file in the working directory is not a baseline.
func TestScanCommandNeverReadsLayerleakignoreImplicitly(t *testing.T) {
	installExitFixture(t, exitFixtureFinding)
	t.Setenv("LAYERLEAK_FINDINGS_DIR", t.TempDir())
	t.Setenv("LAYERLEAK_MAX_FILE_BYTES", "1048576")
	stdout, _, code, _ := runBaselineScan(t, "--format", "json", "--no-artifacts")
	if code != exitCodeFindings {
		t.Fatalf("exit = %d", code)
	}
	var published jobs.Result
	if err := json.Unmarshal([]byte(stdout), &published); err != nil || len(published.Findings) != 1 {
		t.Fatal("expected one finding to baseline")
	}
	work := t.TempDir()
	body := `{"baseline_schema_version": 1, "entries": [{"fingerprint": "` + published.Findings[0].Fingerprint + `"}]}`
	if err := os.WriteFile(filepath.Join(work, ".layerleakignore"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(work)
	if _, _, code, _ := runBaselineScan(t, "--format", "json", "--no-artifacts"); code != exitCodeFindings {
		t.Fatalf("a .layerleakignore in the working directory changed the exit code to %d", code)
	}
	if _, _, code, _ := runBaselineScan(t, "--format", "json", "--no-artifacts", "--baseline", ".layerleakignore"); code != 0 {
		t.Fatalf("the same file passed explicitly should baseline the finding, exit %d", code)
	}
}
