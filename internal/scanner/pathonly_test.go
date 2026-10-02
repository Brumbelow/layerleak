package scanner

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/brumbelow/layerleak/v3/internal/detectors"
	"github.com/brumbelow/layerleak/v3/internal/findings"
	"github.com/brumbelow/layerleak/v3/internal/layers"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
)

const (
	pathOnlyManifestDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	pathOnlyLayerDigest    = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

var pathOnlyPlatform = manifest.Platform{OS: "linux", Architecture: "amd64"}

func binaryArtifact(path string, class layers.ContentClass) layers.Artifact {
	return layers.Artifact{
		Path:         path,
		LayerDigest:  pathOnlyLayerDigest,
		Type:         layers.ArtifactTypeRegularFile,
		ContentClass: class,
		Scannable:    false,
		Size:         4096,
	}
}

func textArtifact(path, content string) layers.Artifact {
	return layers.Artifact{
		Path:         path,
		LayerDigest:  pathOnlyLayerDigest,
		Type:         layers.ArtifactTypeRegularFile,
		ContentClass: layers.ContentClassText,
		Scannable:    true,
		Content:      []byte(content),
	}
}

// LAY-12: a binary or oversize sensitive artifact is reported by its path,
// without any value-derived field, fingerprinted on the layer digest and path.
func TestScanArtifactsReportsUnscannableSensitiveFilesByPath(t *testing.T) {
	items := scanArtifacts(detectors.Default(), pathOnlyManifestDigest, pathOnlyPlatform, findings.SourceTypeFileFinal, true, []layers.Artifact{
		binaryArtifact("etc/ssl/private/server.p12", layers.ContentClassBinaryNUL),
		binaryArtifact("root/.ssh/id_rsa", layers.ContentClassOversize),
		binaryArtifact("usr/bin/tool", layers.ContentClassBinaryELF),
		binaryArtifact("opt/app/truststore.jks", layers.ContentClassBinaryNUL),
	})
	if len(items) != 2 {
		t.Fatalf("len(items) = %d: %#v", len(items), items)
	}

	keystore := items[0]
	if keystore.DetectorName != "sensitive_file_keystore" || keystore.FilePath != "etc/ssl/private/server.p12" {
		t.Fatalf("items[0] = %#v", keystore)
	}
	if keystore.Confidence != string(detectors.ConfidenceMedium) {
		t.Fatalf("keystore.Confidence = %q", keystore.Confidence)
	}
	if keystore.RedactedValue != "" || keystore.ContextSnippet != "" || keystore.Value != "" || keystore.RawSnippet != "" {
		t.Fatalf("path-only finding carries value-derived fields: %#v", keystore)
	}
	if keystore.LineNumber != 0 || keystore.MatchStart != 0 || keystore.MatchEnd != 0 || keystore.Finding.MatchStart != 0 || keystore.Finding.MatchEnd != 0 {
		t.Fatalf("path-only finding carries a span: %#v", keystore)
	}
	if want := findings.Fingerprint(pathOnlyLayerDigest + "\n" + "etc/ssl/private/server.p12"); keystore.Fingerprint != want {
		t.Fatalf("keystore.Fingerprint = %q, want %q", keystore.Fingerprint, want)
	}
	if keystore.SourceType != findings.SourceTypeFileFinal || !keystore.PresentInFinalImage || keystore.LayerDigest != pathOnlyLayerDigest {
		t.Fatalf("provenance = %#v", keystore.Finding)
	}
	if keystore.Disposition != findings.DispositionActionable || keystore.SourceLocation != "file_final:etc/ssl/private/server.p12" {
		t.Fatalf("disposition/location = %q/%q", keystore.Disposition, keystore.SourceLocation)
	}

	key := items[1]
	if key.DetectorName != "sensitive_file_private_key" || key.FilePath != "root/.ssh/id_rsa" || key.Confidence != string(detectors.ConfidenceMedium) {
		t.Fatalf("items[1] = %#v", key)
	}
	if key.Fingerprint == keystore.Fingerprint {
		t.Fatal("two paths share a fingerprint")
	}
}

// A readable file is judged by its content alone: the PEM rule reports the
// key, and a .netrc without a password yields nothing rather than a
// path-only finding.
func TestScanArtifactsNeverAddsPathOnlyFindingToReadableFiles(t *testing.T) {
	pem := "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n-----END OPENSSH PRIVATE KEY-----\n"
	items := scanArtifacts(detectors.Default(), pathOnlyManifestDigest, pathOnlyPlatform, findings.SourceTypeFileFinal, true, []layers.Artifact{
		textArtifact("root/.ssh/id_rsa", pem),
		textArtifact("root/.netrc", "machine example.internal login deploy\n"),
		textArtifact("root/.ssh/id_ed25519", ""),
	})
	if len(items) != 1 || items[0].DetectorName != "pem_private_key" {
		t.Fatalf("items = %#v", items)
	}
	if items[0].RedactedValue == "" || items[0].Fingerprint != findings.Fingerprint(strings.TrimSuffix(pem, "\n")) {
		t.Fatalf("content finding lost its value: %#v", items[0])
	}
}

// Path-only findings go through the same classification and provenance
// redaction as content findings: a test directory suppresses, a secret inside
// the path is redacted, and the fingerprint still identifies the artifact.
func TestPathOnlyFindingsAreClassifiedAndRedacted(t *testing.T) {
	pathSecret := "ghp_" + "123456789012345678901234567890123456"
	items := scanArtifacts(detectors.Default(), pathOnlyManifestDigest, pathOnlyPlatform, findings.SourceTypeFileDeletedLayer, false, []layers.Artifact{
		binaryArtifact("app/tests/fixtures/id_rsa", layers.ContentClassBinaryLowPrintable),
		binaryArtifact("secrets/"+pathSecret+"/vault.kdbx", layers.ContentClassBinaryNUL),
	})
	if len(items) != 2 {
		t.Fatalf("len(items) = %d: %#v", len(items), items)
	}
	suppressed := items[0]
	if suppressed.Disposition != findings.DispositionExample || suppressed.DispositionReason != findings.DispositionReasonTestPath {
		t.Fatalf("test-path finding = %#v", suppressed.Finding)
	}
	if suppressed.SourceType != findings.SourceTypeFileDeletedLayer || suppressed.PresentInFinalImage {
		t.Fatalf("deleted-layer provenance = %#v", suppressed.Finding)
	}
	redacted := items[1]
	if redacted.DetectorName != "sensitive_file_password_database" {
		t.Fatalf("items[1] = %#v", redacted)
	}
	for field, value := range map[string]string{
		"file path":       redacted.FilePath,
		"source location": redacted.SourceLocation,
		"context snippet": redacted.ContextSnippet,
		"redacted value":  redacted.RedactedValue,
	} {
		if strings.Contains(value, pathSecret) {
			t.Fatalf("%s leaked the path secret: %q", field, value)
		}
	}
	if !strings.Contains(redacted.FilePath, "[REDACTED]") {
		t.Fatalf("redacted.FilePath = %q", redacted.FilePath)
	}
	if redacted.Fingerprint != findings.Fingerprint(pathOnlyLayerDigest+"\n"+"secrets/"+pathSecret+"/vault.kdbx") {
		t.Fatalf("redacted.Fingerprint = %q", redacted.Fingerprint)
	}
}

// Path-only findings count against the findings budget like any other.
func TestPathOnlyFindingsHonourTheFindingsBudget(t *testing.T) {
	budget := newDetectionBudget(context.Background(), Request{MaxFindings: 1})
	items := scanArtifactsWithBudget(budget, detectors.Default(), pathOnlyManifestDigest, pathOnlyPlatform, findings.SourceTypeFileFinal, true, []layers.Artifact{
		binaryArtifact("a/client.pfx", layers.ContentClassBinaryNUL),
		binaryArtifact("b/client.pfx", layers.ContentClassBinaryNUL),
	})
	if len(items) != 1 || !budget.stopped() || budget.retained != 1 {
		t.Fatalf("items = %d, stopped = %t, retained = %d", len(items), budget.stopped(), budget.retained)
	}
}

// Symlinks and other non-file entries among deleted artifacts are not files
// and never produce a path-only finding; two identical path-only findings
// deduplicate to one.
func TestPathOnlyFindingsSkipNonFilesAndDeduplicate(t *testing.T) {
	link := binaryArtifact("root/.ssh/id_rsa", "")
	link.Type = layers.ArtifactTypeSymlink
	link.Linkname = "/run/secrets/key"
	items := scanArtifacts(detectors.Default(), pathOnlyManifestDigest, pathOnlyPlatform, findings.SourceTypeFileDeletedLayer, false, []layers.Artifact{
		link,
		binaryArtifact("root/.gnupg/secring.gpg", layers.ContentClassBinaryNUL),
		binaryArtifact("root/.gnupg/secring.gpg", layers.ContentClassBinaryNUL),
	})
	if len(items) != 2 {
		t.Fatalf("items = %#v", items)
	}
	deduped := findings.DeduplicateDetailed(items)
	if len(deduped) != 1 || deduped[0].DetectorName != "sensitive_file_gpg_keyring" {
		t.Fatalf("deduped = %#v", deduped)
	}
	public := deduped[0].PublicFinding()
	if public.RedactedValue != "" || public.ContextSnippet != "" || public.FilePath != "root/.gnupg/secring.gpg" {
		t.Fatalf("public finding = %#v", public)
	}
}

// End to end through layer replay: real content classification marks a
// PKCS#12 bundle binary and an oversize key file unscannable, and both reach
// the result as path-only findings while the readable .env is scanned.
func TestReplayedBinaryAndOversizeSensitiveFilesAreReported(t *testing.T) {
	ctx := context.Background()
	pkcs12 := "\x30\x82\x0a\x00\x02\x01\x03\x30\x82\x09\x00\x06\x09\x2a\x86\x48\x00\x00\x00" + strings.Repeat("\x00\xff", 64)
	layer := gzipLayer(t, []tarEntry{
		{name: "etc/app/client.p12", body: pkcs12},
		{name: "root/.ssh/id_ed25519", body: strings.Repeat("A", 600)},
		{name: "app/.env", body: "GH_TOKEN=ghp_123456789012345678901234567890123456\n"},
	})
	descriptor := descriptorFor(t, manifest.MediaTypeDockerSchema2LayerGzip, layer)
	replay, err := layers.Replay(ctx, []manifest.Descriptor{descriptor}, layers.ReplayOptions{MaxFileBytes: 512}, layers.OpenFunc(func(context.Context, manifest.Descriptor) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(layer)), nil
	}))
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if replay.Coverage.FilesExcludedBinary != 1 || replay.Coverage.FilesSkippedOversize != 1 {
		t.Fatalf("coverage = %#v", replay.Coverage)
	}

	items := scanArtifacts(detectors.Default(), pathOnlyManifestDigest, pathOnlyPlatform, findings.SourceTypeFileFinal, true, replay.FinalFiles)
	names := make(map[string]string, len(items))
	for _, item := range items {
		names[item.DetectorName] = item.FilePath
	}
	if len(items) != 3 || names["github_token"] != "app/.env" || names["sensitive_file_keystore"] != "etc/app/client.p12" || names["sensitive_file_private_key"] != "root/.ssh/id_ed25519" {
		t.Fatalf("items = %#v", names)
	}
	for _, item := range items {
		if item.LayerDigest != descriptor.Digest {
			t.Fatalf("layer digest = %q, want %q", item.LayerDigest, descriptor.Digest)
		}
		if strings.HasPrefix(item.DetectorName, "sensitive_file_") && (item.RedactedValue != "" || item.Value != "") {
			t.Fatalf("path-only finding carries a value: %#v", item)
		}
	}
}

// scanPath runs only while the detection budget admits it: a stopped, failed,
// exhausted or cancelled budget yields nothing and records why, and the
// finding limit is enforced between the matches of one path.
func TestScanPathHonoursTheDetectionBudget(t *testing.T) {
	input := findings.Input{
		ManifestDigest:      pathOnlyManifestDigest,
		Platform:            pathOnlyPlatform,
		SourceType:          findings.SourceTypeFileFinal,
		FilePath:            "etc/ssl/private/server.p12",
		LayerDigest:         pathOnlyLayerDigest,
		PresentInFinalImage: true,
	}
	set := detectors.Default()

	unbounded := (*detectionBudget)(nil).scanPath(set, input)
	if len(unbounded) == 0 {
		t.Fatal("scanPath() with no budget found nothing")
	}
	for _, finding := range unbounded {
		if finding.RedactedValue != "" || finding.ContextSnippet != "" || finding.LineNumber != 0 || finding.Value != "" || finding.RawSnippet != "" ||
			finding.MatchStart != 0 || finding.MatchEnd != 0 || finding.Finding.MatchStart != 0 || finding.Finding.MatchEnd != 0 ||
			finding.Fingerprint != findings.Fingerprint(pathOnlyLayerDigest+"\n"+input.FilePath) {
			t.Fatalf("path-only finding keeps value-derived fields: %#v", finding)
		}
	}

	stopped := newDetectionBudget(context.Background(), Request{})
	stopped.exceeded = true
	if got := stopped.scanPath(set, input); got != nil {
		t.Fatalf("stopped budget: scanPath() = %#v", got)
	}

	failed := newDetectionBudget(context.Background(), Request{})
	failed.err = context.DeadlineExceeded
	if got := failed.scanPath(set, input); got != nil {
		t.Fatalf("failed budget: scanPath() = %#v", got)
	}

	exhausted := newDetectionBudget(context.Background(), Request{MaxFindings: 1, ExistingFindings: 1})
	if got := exhausted.scanPath(set, input); got != nil || !exhausted.exceeded || exhausted.observed != 1 || exhausted.diagnosticManifest != pathOnlyManifestDigest {
		t.Fatalf("exhausted budget: scanPath() = %#v, budget = %+v", got, exhausted)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cancelled := newDetectionBudget(ctx, Request{})
	if got := cancelled.scanPath(set, input); got != nil || cancelled.err != context.Canceled || cancelled.exceeded {
		t.Fatalf("cancelled budget: scanPath() = %#v, budget = %+v", got, cancelled)
	}

	admitted := newDetectionBudget(context.Background(), Request{MaxFindings: 10})
	if got := admitted.scanPath(set, input); len(got) != len(unbounded) || admitted.retained != len(got) {
		t.Fatalf("admitted budget: %d findings, retained = %d, want %d", len(got), admitted.retained, len(unbounded))
	}
}

// The finding limit between the matches of one path records the overflow
// as the next finding that did not fit.
func TestPathFindingsFullRecordsTheOverflow(t *testing.T) {
	var none *detectionBudget
	if none.pathFindingsFull(pathOnlyManifestDigest) {
		t.Fatal("a nil budget has no finding limit")
	}
	unlimited := newDetectionBudget(context.Background(), Request{ExistingFindings: 5})
	if unlimited.pathFindingsFull(pathOnlyManifestDigest) || unlimited.exceeded {
		t.Fatal("a budget without MaxFindings has no finding limit")
	}
	full := newDetectionBudget(context.Background(), Request{MaxFindings: 2, ExistingFindings: 2})
	if !full.pathFindingsFull(pathOnlyManifestDigest) || !full.exceeded || full.observed != 3 || full.diagnosticManifest != pathOnlyManifestDigest {
		t.Fatalf("full budget = %+v", full)
	}
}

// Every nested skip reason has its own wording; an unknown reason is named.
func TestNestedSkipMessageWordsEveryReason(t *testing.T) {
	tests := []struct {
		reason layers.NestedSkipReason
		want   string
	}{
		{layers.NestedSkipOversize, "not expanded, its 3 bytes exceed the 1024 byte nested archive limit"},
		{layers.NestedSkipBytesLimit, "expansion stopped at the 1024 byte nested archive limit after 3 entries"},
		{layers.NestedSkipEntriesLimit, "expansion stopped at the 1024 entry nested archive limit"},
		{layers.NestedSkipLayerBudget, "expansion stopped after 3 entries when the remaining layer or image budget (1024) was spent"},
		{layers.NestedSkipRetainedBytes, "3 expanded entries were dropped to stay within the 1024 retained bytes limit"},
		{layers.NestedSkipMalformed, "3 entries (or the archive structure) could not be decoded"},
		{layers.NestedSkipEncrypted, "3 encrypted entries were skipped"},
		{layers.NestedSkipUnsupportedMethod, "3 entries use an unsupported compression method"},
		{layers.NestedSkipUnsafeEntries, "3 entries with unsafe paths were skipped"},
		{layers.NestedSkipOversizeEntries, "3 entries exceeded the 1024 byte per-file limit"},
		{layers.NestedSkipDepth, "3 archives inside it were not opened (one nesting level)"},
		{layers.NestedSkipReason("future_reason"), "future_reason"},
	}
	for _, test := range tests {
		t.Run(string(test.reason), func(t *testing.T) {
			skip := layers.NestedSkip{Path: "lib/app.jar", LayerDigest: " " + pathOnlyLayerDigest + " ", Reason: test.reason, Observed: 3, Limit: 1024}
			want := "nested archive lib/app.jar in layer " + pathOnlyLayerDigest + ": " + test.want
			if got := nestedSkipMessage(detectors.Default(), skip); got != want {
				t.Fatalf("nestedSkipMessage() = %q, want %q", got, want)
			}
		})
	}
}
