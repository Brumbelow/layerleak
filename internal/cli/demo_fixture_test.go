package cli

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/findings"
	"github.com/brumbelow/layerleak/v3/internal/jobs"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
	"github.com/brumbelow/layerleak/v3/internal/scanservice"
)

var updateDemo = flag.Bool("update-demo", false, "rewrite web/assets/demo-data.json from a real scan of a synthetic OCI image layout")

// The browser demo on the documentation site (web/docs/demo/) replays
// web/assets/demo-data.json. TestDemoFixtureMatchesRealScan rebuilds that
// fixture from a real `layerleak scan` of a synthetic OCI image layout, so the
// transcript, the result fields and the Postgres-style tables cannot drift
// from what the CLI prints. Regenerate with
// `go test ./internal/cli -run TestDemoFixtureMatchesRealScan -update-demo`.
//
// Only clock-, build- and host-dependent values are pinned: scanned_at,
// created_at, the record file name's timestamp and random suffix,
// scanner.version and the temporary working directory. Everything else is the
// CLI's own output.
const (
	demoLayoutDir   = "payments-api"
	demoTag         = "1.4.2"
	demoReference   = "oci:" + demoLayoutDir + ":" + demoTag
	demoVersion     = "v3.0.0"
	demoRecordNonce = "DEMODEMODEMODEMODEMODEMODE"
	// demoWorkdir stands in for the temporary working directory in the
	// transcript: the CLI prints the scan record's absolute path.
	demoWorkdir = "/work"
)

var (
	demoScannedAt = time.Date(2026, time.October, 1, 12, 0, 0, 0, time.UTC)
	demoCreatedAt = time.Date(2026, time.October, 1, 12, 0, 1, 0, time.UTC)
	demoArgs      = []string{demoReference, "--progress", "plain", "--no-db"}
)

const (
	demoAlphanumeric = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	demoUpperDigits  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	demoBase64       = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)

// demoValue returns n characters drawn from alphabet by hashing label. The
// demo image's secrets are assembled from these at run time, so the source
// holds no secret-shaped literal, the values are obviously synthetic, and the
// fingerprints in the committed fixture are reproducible.
func demoValue(label, alphabet string, n int) string {
	var builder strings.Builder
	for counter := 0; builder.Len() < n; counter++ {
		sum := sha256.Sum256([]byte("layerleak-demo/" + label + "/" + strconv.Itoa(counter)))
		for _, b := range sum {
			if builder.Len() == n {
				break
			}
			builder.WriteByte(alphabet[int(b)%len(alphabet)])
		}
	}
	return builder.String()
}

type demoTarEntry struct {
	name string
	body []byte
}

func demoLayer(t *testing.T, entries []demoTarEntry) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	modTime := time.Date(2026, time.September, 30, 9, 0, 0, 0, time.UTC)
	for _, entry := range entries {
		if err := writer.WriteHeader(&tar.Header{Name: entry.name, Mode: 0o644, Typeflag: tar.TypeReg, Size: int64(len(entry.body)), ModTime: modTime}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(entry.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return localGzip(t, buffer.Bytes())
}

func demoJar(t *testing.T, name string, body []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	file, err := writer.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: time.Date(2026, time.September, 30, 9, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func demoMarshal(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// writeDemoLayout writes the synthetic payments-api image: an OCI image
// layout whose index.json names one multi-platform index tagged 1.4.2 with a
// linux/amd64 image, a windows/amd64 image and a BuildKit attestation
// manifest. The linux image carries one synthetic secret in each place
// Layerleak looks: the config environment, a label and the build history, a
// file in the final filesystem, a file deleted by a later layer, a file inside
// a nested archive, an unreadable SSH key reported by path, and a test fixture
// that is reported as suppressed.
func writeDemoLayout(t *testing.T, dir string) {
	t.Helper()
	githubToken := "gh" + "p_" + demoValue("github", demoAlphanumeric, 36)
	awsKeyID := "AK" + "IA" + demoValue("aws-key-id", demoUpperDigits, 16)
	awsSecret := demoValue("aws-secret", demoBase64, 40)
	stripeKey := "sk" + "_live_" + demoValue("stripe", demoAlphanumeric, 24)
	slackWebhook := "https://hooks.slack.com/services/T" + demoValue("slack-team", demoUpperDigits, 8) + "/B" + demoValue("slack-bot", demoUpperDigits, 10) + "/" + demoValue("slack-secret", demoAlphanumeric, 24)
	gitPassword := demoValue("git-password", demoAlphanumeric, 20)
	databasePassword := demoValue("database-password", demoAlphanumeric, 22)
	npmToken := "np" + "m_" + demoValue("npm", demoAlphanumeric, 36)

	config := demoMarshal(t, map[string]any{
		"architecture": "amd64",
		"os":           "linux",
		"created":      "2026-09-30T09:00:00Z",
		"config": map[string]any{
			"Env":        []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "GH_TOKEN=" + githubToken},
			"Labels":     map[string]string{"org.opencontainers.image.title": "payments-api", "com.acme.alerts.webhook": slackWebhook},
			"WorkingDir": "/srv/app",
		},
		"history": []map[string]any{
			{"created": "2026-09-30T09:00:00Z", "created_by": "/bin/sh -c #(nop) ADD file:base in /"},
			{"created": "2026-09-30T09:00:00Z", "created_by": "/bin/sh -c git clone https://ci-bot:" + gitPassword + "@git.acme-payments.io/platform/payments-api.git /srv/app"},
			{"created": "2026-09-30T09:00:00Z", "created_by": "/bin/sh -c rm /srv/app/.env.production"},
		},
	})
	baseLayer := demoLayer(t, []demoTarEntry{
		{name: "srv/app/.env.production", body: []byte("NODE_ENV=production\nSTRIPE_API_KEY=" + stripeKey + "\n")},
		{name: "srv/app/tests/fixtures/.env", body: []byte("NPM_TOKEN=" + npmToken + "\n")},
		{name: "opt/app/lib/payments.jar", body: demoJar(t, "BOOT-INF/classes/application.properties", []byte("spring.datasource.url=postgres://payments:"+databasePassword+"@ledger-db.acme-payments.io:5432/ledger\n"))},
	})
	finalLayer := demoLayer(t, []demoTarEntry{
		{name: "srv/app/.wh..env.production", body: nil},
		{name: "root/.aws/credentials", body: []byte("[default]\naws_access_key_id = " + awsKeyID + "\naws_secret_access_key = " + awsSecret + "\n")},
		{name: "root/.ssh/id_ed25519", body: append([]byte{0, 0, 0, 11}, []byte(demoValue("ssh-key", demoBase64, 48))...)},
	})

	blobs := map[string][]byte{}
	put := func(mediaType string, body []byte) manifest.Descriptor {
		descriptor := commandDescriptor(t, mediaType, body)
		blobs[descriptor.Digest] = body
		return descriptor
	}
	configDescriptor := put(manifest.MediaTypeOCIImageConfig, config)
	linuxManifest := put(manifest.MediaTypeOCIImageManifest, demoMarshal(t, manifest.ImageManifest{
		SchemaVersion: 2, MediaType: manifest.MediaTypeOCIImageManifest, Config: configDescriptor,
		Layers: []manifest.Descriptor{put(manifest.MediaTypeOCIImageLayerGzip, baseLayer), put(manifest.MediaTypeOCIImageLayerGzip, finalLayer)},
	}))
	linuxManifest.Platform = manifest.Platform{OS: "linux", Architecture: "amd64"}

	windowsConfig := put(manifest.MediaTypeOCIImageConfig, demoMarshal(t, map[string]any{"architecture": "amd64", "os": "windows", "config": map[string]any{}}))
	windowsManifest := put(manifest.MediaTypeOCIImageManifest, demoMarshal(t, manifest.ImageManifest{SchemaVersion: 2, MediaType: manifest.MediaTypeOCIImageManifest, Config: windowsConfig, Layers: []manifest.Descriptor{}}))
	windowsManifest.Platform = manifest.Platform{OS: "windows", Architecture: "amd64"}

	attestationConfig := put(manifest.MediaTypeOCIImageConfig, []byte(`{}`))
	attestation := put(manifest.MediaTypeOCIImageManifest, demoMarshal(t, manifest.ImageManifest{SchemaVersion: 2, MediaType: manifest.MediaTypeOCIImageManifest, Config: attestationConfig, Layers: []manifest.Descriptor{}}))
	attestation.Platform = manifest.Platform{OS: "unknown", Architecture: "unknown"}
	attestation.Annotations = map[string]string{"vnd.docker.reference.type": "attestation-manifest", "vnd.docker.reference.digest": linuxManifest.Digest}

	index := put(manifest.MediaTypeOCIImageIndex, commandIndexBody(t, linuxManifest, windowsManifest, attestation))
	index.Annotations = map[string]string{"org.opencontainers.image.ref.name": demoTag}

	for digest, body := range blobs {
		algorithm, encoded, _ := strings.Cut(digest, ":")
		localWrite(t, filepath.Join(dir, "blobs", algorithm, encoded), body)
	}
	localWrite(t, filepath.Join(dir, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`))
	localWrite(t, filepath.Join(dir, "index.json"), commandIndexBody(t, index))
}

// demoScan is what one real scan of the synthetic layout produced.
type demoScan struct {
	exitCode int
	stdout   string
	stderr   string
	record   localScanRecord
	path     string
	workdirs []string
}

var demoRecordName = regexp.MustCompile(`findings/\d{8}T\d{6}Z-([A-Za-z0-9_-]+)-[A-Z2-7]{26}\.json`)

func runDemoScan(t *testing.T) demoScan {
	t.Helper()
	workdir := t.TempDir()
	writeDemoLayout(t, filepath.Join(workdir, demoLayoutDir))
	for _, name := range []string{"LAYERLEAK_DATABASE_URL", "LAYERLEAK_FINDINGS_DIR", "LAYERLEAK_PERSIST_RAW_SECRETS", "LAYERLEAK_REGISTRY_USERNAME", "LAYERLEAK_REGISTRY_PASSWORD", "LAYERLEAK_DOCKER_CONFIG", "LAYERLEAK_LOG_FORMAT", "CI", "TERM"} {
		t.Setenv(name, "")
	}
	t.Setenv("LAYERLEAK_LOG_LEVEL", "warn")
	t.Chdir(workdir)

	stdout, stderr, err := runScan(t, "", demoArgs...)
	scan := demoScan{exitCode: exitCodeOf(t, err), stdout: stdout, stderr: stderr, workdirs: []string{workdir}}
	if resolved, resolveErr := filepath.EvalSymlinks(workdir); resolveErr == nil && resolved != workdir {
		scan.workdirs = append([]string{resolved}, scan.workdirs...)
	}
	paths, globErr := filepath.Glob(filepath.Join("findings", "*.json"))
	if globErr != nil || len(paths) != 1 {
		t.Fatalf("scan records = %v, %v (stderr %s)", paths, globErr, stderr)
	}
	scan.path = filepath.ToSlash(paths[0])
	body, readErr := os.ReadFile(paths[0])
	if readErr != nil {
		t.Fatal(readErr)
	}
	if decodeErr := json.Unmarshal(body, &scan.record); decodeErr != nil {
		t.Fatalf("scan record: %v", decodeErr)
	}
	return scan
}

// pinDemoOutput replaces the values that depend on the wall clock, the random
// record suffix and the temporary working directory in one piece of CLI
// output. The transcript never prints the scanner version.
func pinDemoOutput(text string, workdirs ...string) string {
	for _, workdir := range workdirs {
		text = strings.ReplaceAll(text, workdir, demoWorkdir)
	}
	return demoRecordName.ReplaceAllString(text, "findings/"+demoCreatedAt.Format("20060102T150405Z")+"-${1}-"+demoRecordNonce+".json")
}

type demoStat struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

type demoFrame struct {
	DelayMS  int    `json:"delay_ms"`
	Status   string `json:"status"`
	Terminal string `json:"terminal"`
}

type demoTable struct {
	Description string           `json:"description"`
	Columns     []string         `json:"columns"`
	Rows        []map[string]any `json:"rows"`
}

type demoRunResult struct {
	Status             string            `json:"status"`
	ExitCode           int               `json:"exit_code"`
	RequestedReference string            `json:"requested_reference"`
	Repository         string            `json:"repository"`
	ResolvedReference  string            `json:"resolved_reference"`
	RequestedDigest    string            `json:"requested_digest"`
	ScannedAt          string            `json:"scanned_at"`
	Scanner            jobs.ScannerInfo  `json:"scanner"`
	TotalFindings      int               `json:"total_findings"`
	UniqueFingerprints int               `json:"unique_fingerprints"`
	SuppressedFindings int               `json:"suppressed_findings_count"`
	Coverage           any               `json:"coverage"`
	Diagnostics        any               `json:"diagnostics"`
	RecordSchema       int               `json:"record_schema_version"`
	ResultSchema       int               `json:"result_schema_version"`
	Persistence        string            `json:"persistence"`
	RawStorageEnabled  bool              `json:"raw_storage_enabled"`
	Artifacts          map[string]string `json:"artifacts"`
}

type demoFixture struct {
	Version    int                  `json:"version"`
	Synthetic  bool                 `json:"synthetic"`
	Generator  string               `json:"generator"`
	Command    string               `json:"command"`
	RunResult  demoRunResult        `json:"run_result"`
	Stats      []demoStat           `json:"stats"`
	Frames     []demoFrame          `json:"frames"`
	TableOrder []string             `json:"table_order"`
	Tables     map[string]demoTable `json:"tables"`
}

func buildDemoFixture(t *testing.T, scan demoScan) demoFixture {
	t.Helper()
	record := scan.record
	record.Result.ScannedAt = demoScannedAt
	record.Result.Scanner.Version = demoVersion
	record.CreatedAt = demoCreatedAt
	result := record.Result
	recordPath := pinDemoOutput(scan.path)
	command := "layerleak scan " + strings.Join(demoArgs, " ")

	coverage := "complete"
	if !result.Coverage.Complete {
		coverage = "partial"
	}
	diagnostics := make([]string, 0, len(result.Diagnostics))
	for _, diagnostic := range result.Diagnostics {
		diagnostics = append(diagnostics, diagnostic.Code)
	}
	if len(diagnostics) == 0 {
		diagnostics = append(diagnostics, "none")
	}
	fixture := demoFixture{
		Version:   2,
		Synthetic: true,
		Generator: "go test ./internal/cli -run TestDemoFixtureMatchesRealScan -update-demo",
		Command:   command,
		RunResult: demoRunResult{
			Status:             string(result.Status),
			ExitCode:           scan.exitCode,
			RequestedReference: result.RequestedReference,
			Repository:         result.Repository,
			ResolvedReference:  result.ResolvedReference,
			RequestedDigest:    result.RequestedDigest,
			ScannedAt:          demoScannedAt.Format(time.RFC3339),
			Scanner:            result.Scanner,
			TotalFindings:      result.TotalFindings,
			UniqueFingerprints: result.UniqueFingerprints,
			SuppressedFindings: result.SuppressedFindingsCount,
			Coverage:           result.Coverage,
			Diagnostics:        result.Diagnostics,
			RecordSchema:       record.RecordSchemaVersion,
			ResultSchema:       result.ResultSchemaVersion,
			Persistence:        record.Persistence.Status,
			RawStorageEnabled:  false,
			Artifacts:          map[string]string{"scan_record": recordPath},
		},
		Stats: []demoStat{
			{Label: "Status", Value: string(result.Status) + " (exit " + strconv.Itoa(scan.exitCode) + ")"},
			{Label: "Coverage", Value: coverage + ", " + strconv.Itoa(result.Coverage.FilesScanned) + " files scanned"},
			{Label: "Actionable findings", Value: strconv.Itoa(result.TotalFindings) + " (+" + strconv.Itoa(result.SuppressedFindingsCount) + " suppressed)"},
			{Label: "Diagnostics", Value: strings.Join(diagnostics, ", ")},
			{Label: "Scan record", Value: recordPath},
		},
		TableOrder: []string{"repositories", "tags", "manifests", "findings", "finding_occurrences"},
	}
	fixture.Frames = demoFrames(command, pinDemoOutput(scan.stderr, scan.workdirs...), pinDemoOutput(scan.stdout, scan.workdirs...))
	fixture.Tables = demoTables(t, record)
	return fixture
}

// demoFrames replays the plain progress lines the scan wrote to stderr one at
// a time, then the whole terminal as the scan left it: the progress, the
// scan record path (stderr) and the summary (stdout).
func demoFrames(command, stderr, stdout string) []demoFrame {
	prompt := "$ " + command + "\n"
	lines := strings.Split(strings.TrimRight(stderr, "\n"), "\n")
	frames := make([]demoFrame, 0, len(lines)+1)
	for index, line := range lines {
		if !strings.HasPrefix(line, "layerleak: ") {
			continue
		}
		frames = append(frames, demoFrame{
			DelayMS:  500,
			Status:   demoFrameStatus(line),
			Terminal: prompt + strings.Join(lines[:index+1], "\n"),
		})
	}
	frames = append(frames, demoFrame{
		DelayMS:  1200,
		Status:   "showing final summary",
		Terminal: prompt + strings.Join(lines, "\n") + "\n\n" + strings.TrimRight(stdout, "\n"),
	})
	return frames
}

// demoFrameStatus turns "layerleak: Scanning: Selected manifests (0/1, 0
// findings) [...]" into "selected manifests".
func demoFrameStatus(line string) string {
	status := strings.TrimPrefix(line, "layerleak: ")
	if _, message, ok := strings.Cut(status, ": "); ok {
		status = message
	}
	if before, _, ok := strings.Cut(status, " ("); ok {
		status = before
	}
	return strings.ToLower(strings.TrimSpace(status))
}

// demoTables derives the Postgres rows a persistent run would write from the
// scan record, through the same storage record builder the CLI and the API
// use. Raw-value columns are empty because raw persistence is off by default.
func demoTables(t *testing.T, record localScanRecord) map[string]demoTable {
	t.Helper()
	reference, err := manifest.ParseImageReference(record.Result.RequestedReference)
	if err != nil {
		t.Fatal(err)
	}
	result := record.Result
	result.DetailedFindings = nil
	result.SuppressedDetailedFindings = nil
	for _, item := range record.Findings {
		detailed := findings.DetailedFinding{Finding: item.Finding, SourceLocation: item.SourceLocation, MatchStart: item.MatchStart, MatchEnd: item.MatchEnd}
		if item.Disposition == findings.DispositionActionable {
			result.DetailedFindings = append(result.DetailedFindings, detailed)
		} else {
			result.SuppressedDetailedFindings = append(result.SuppressedDetailedFindings, detailed)
		}
	}
	stored, err := scanservice.BuildScanRecord(reference, result, demoScannedAt, nil)
	if err != nil {
		t.Fatal(err)
	}
	seen := demoScannedAt.Format(time.RFC3339)

	tables := map[string]demoTable{
		"repositories": {
			Description: "repositories: one row per registry and repository; a local source is stored under the registry local",
			Columns:     []string{"id", "registry", "repository", "first_seen_at", "last_seen_at"},
			Rows:        []map[string]any{{"id": 1, "registry": stored.Registry, "repository": stored.Repository, "first_seen_at": seen, "last_seen_at": seen}},
		},
	}

	tagRows := make([]map[string]any, 0, len(stored.Tags))
	for _, tag := range stored.Tags {
		tagRows = append(tagRows, map[string]any{
			"repository_id": 1, "tag": tag.Name, "manifest_digest": tag.ManifestDigest, "root_digest": tag.RootDigest,
			"platform_os": tag.Platform.OS, "platform_architecture": tag.Platform.Architecture, "platform_variant": tag.Platform.Variant,
			"status": tag.Status, "error": tag.Error, "first_seen_at": seen, "last_seen_at": seen,
		})
	}
	tables["tags"] = demoTable{
		Description: "tags: the tag mapped to the manifest the scan selected",
		Columns:     []string{"repository_id", "tag", "manifest_digest", "root_digest", "platform_os", "platform_architecture", "platform_variant", "status", "error", "first_seen_at", "last_seen_at"},
		Rows:        tagRows,
	}

	manifestRows := make([]map[string]any, 0)
	for _, target := range stored.Targets {
		for _, item := range target.Manifests {
			manifestRows = append(manifestRows, map[string]any{
				"digest": item.Digest, "platform_os": item.Platform.OS, "platform_architecture": item.Platform.Architecture, "platform_variant": item.Platform.Variant,
				"first_seen_at": seen, "last_seen_at": seen, "last_scan_status": item.Status, "last_scan_error": item.Error,
			})
		}
	}
	tables["manifests"] = demoTable{
		Description: "manifests: each scanned platform manifest and its last scan status",
		Columns:     []string{"digest", "platform_os", "platform_architecture", "platform_variant", "first_seen_at", "last_seen_at", "last_scan_status", "last_scan_error"},
		Rows:        manifestRows,
	}

	// findings holds one row per (manifest_digest, fingerprint);
	// finding_occurrences one row per place the value was seen. Both are in
	// the deduplicated order storage writes them.
	findingIDs := map[string]int{}
	findingRows := make([]map[string]any, 0)
	occurrenceRows := make([]map[string]any, 0)
	for _, item := range stored.DetailedFindings {
		key := item.ManifestDigest + "|" + item.Fingerprint
		id, ok := findingIDs[key]
		if !ok {
			id = len(findingIDs) + 1
			findingIDs[key] = id
			findingRows = append(findingRows, map[string]any{
				"id": id, "manifest_digest": item.ManifestDigest, "fingerprint": item.Fingerprint,
				"redacted_value": item.RedactedValue, "value": "", "first_seen_at": seen, "last_seen_at": seen,
			})
		}
		occurrenceRows = append(occurrenceRows, map[string]any{
			"id": len(occurrenceRows) + 1, "finding_id": id, "detector_name": item.DetectorName, "confidence": item.Confidence,
			"disposition": string(item.Disposition), "disposition_reason": string(item.DispositionReason), "source_type": string(item.SourceType),
			"platform_os": item.Platform.OS, "platform_architecture": item.Platform.Architecture, "platform_variant": item.Platform.Variant,
			"file_path": item.FilePath, "layer_digest": item.LayerDigest, "source_key": item.Key, "line_number": item.LineNumber,
			"context_snippet": item.ContextSnippet, "raw_snippet": "", "source_location": item.SourceLocation,
			"match_start": item.MatchStart, "match_end": item.MatchEnd, "present_in_final_image": item.PresentInFinalImage,
			"first_seen_at": seen, "last_seen_at": seen,
		})
	}
	tables["findings"] = demoTable{
		Description: "findings: one row per manifest and fingerprint; value stays empty without LAYERLEAK_PERSIST_RAW_SECRETS",
		Columns:     []string{"id", "manifest_digest", "fingerprint", "redacted_value", "value", "first_seen_at", "last_seen_at"},
		Rows:        findingRows,
	}
	tables["finding_occurrences"] = demoTable{
		Description: "finding_occurrences: where each value was seen, including the suppressed test fixture",
		Columns:     []string{"id", "finding_id", "detector_name", "confidence", "disposition", "disposition_reason", "source_type", "platform_os", "platform_architecture", "platform_variant", "file_path", "layer_digest", "source_key", "line_number", "context_snippet", "raw_snippet", "source_location", "match_start", "match_end", "present_in_final_image", "first_seen_at", "last_seen_at"},
		Rows:        occurrenceRows,
	}
	if len(findingRows) == 0 || len(occurrenceRows) != len(stored.DetailedFindings) || !slices.ContainsFunc(occurrenceRows, func(row map[string]any) bool { return row["disposition"] != string(findings.DispositionActionable) }) {
		t.Fatalf("demo tables are missing rows: %d findings, %d occurrences", len(findingRows), len(occurrenceRows))
	}
	return tables
}

func TestDemoFixtureMatchesRealScan(t *testing.T) {
	// Resolve the fixture before runDemoScan moves into its temporary
	// working directory.
	path, err := filepath.Abs(filepath.Join("..", "..", "web", "assets", "demo-data.json"))
	if err != nil {
		t.Fatal(err)
	}
	scan := runDemoScan(t)
	if scan.exitCode != exitCodeFindings {
		t.Fatalf("demo scan exit = %d, want %d; stderr:\n%s", scan.exitCode, exitCodeFindings, scan.stderr)
	}
	fixture := buildDemoFixture(t, scan)
	body, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	body = append(body, '\n')

	// The demo must never carry a raw value: every synthetic secret is
	// rebuilt here and searched for in the fixture.
	for _, label := range []string{"github", "aws-key-id", "aws-secret", "stripe", "slack-secret", "git-password", "database-password", "npm", "ssh-key"} {
		for _, alphabet := range []string{demoAlphanumeric, demoUpperDigits, demoBase64} {
			if value := demoValue(label, alphabet, 16); bytes.Contains(body, []byte(value)) {
				t.Fatalf("demo fixture carries raw material for %s", label)
			}
		}
	}

	if *updateDemo {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	expected, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s is missing; run `go test ./internal/cli -run TestDemoFixtureMatchesRealScan -update-demo`", path)
	}
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(expected, body) {
		t.Fatalf("%s differs from a real scan of the demo layout; review the change, then run `go test ./internal/cli -run TestDemoFixtureMatchesRealScan -update-demo`.\n--- got ---\n%s", path, body)
	}
}
