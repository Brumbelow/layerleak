package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brumbelow/layerleak/v3/internal/manifest"
)

// TestScanDetectsSecretsInUTF16Files scans the committed UTF-16LE and UTF-16BE
// fixtures (with and without a byte-order mark) and checks that findings refer
// to the transcoded text: the line number and match span index the UTF-8 form,
// the files count as scanned and transcoded, and none is excluded as binary.
func TestScanDetectsSecretsInUTF16Files(t *testing.T) {
	entries := make([]tarEntry, 0, 3)
	for _, name := range []string{"secret-utf16le-bom.env", "secret-utf16be-bom.env", "secret-utf16le-nobom.ps1"} {
		body, err := os.ReadFile(filepath.Join("testdata", "utf16", name))
		if err != nil {
			t.Fatalf("read fixture: %v", err)
		}
		if !strings.Contains(string(body), "\x00") {
			t.Fatalf("fixture %s is not UTF-16", name)
		}
		entries = append(entries, tarEntry{name: "app/" + name, body: string(body)})
	}
	f := newRegistryFixture()
	layer := f.blob(t, manifest.MediaTypeDockerSchema2LayerGzip, gzipLayer(t, entries))
	f.setRootManifest(t, configBlob(t, f, "linux", "amd64"), []manifest.Descriptor{layer})

	result, err := Scan(context.Background(), f.request(t, ""))
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if result.Status != ResultStatusCompleted || !result.Coverage.Complete {
		t.Fatalf("result = %+v", result)
	}
	if result.Coverage.FilesSeen != 3 || result.Coverage.FilesScanned != 3 || result.Coverage.FilesExcludedBinary != 0 || result.Coverage.FilesTranscodedUTF16 != 3 {
		t.Fatalf("Coverage = %+v", result.Coverage)
	}

	found := make(map[string]bool)
	for _, finding := range result.Findings {
		if finding.DetectorName != "github_token" {
			continue
		}
		found[finding.FilePath] = true
		if finding.LineNumber != 2 {
			t.Fatalf("%s: line_number = %d, want 2 (in the transcoded text)", finding.FilePath, finding.LineNumber)
		}
		if finding.MatchEnd-finding.MatchStart != len("ghp_000000000000000000000000000000000000") {
			t.Fatalf("%s: span %d-%d does not cover the UTF-8 token", finding.FilePath, finding.MatchStart, finding.MatchEnd)
		}
		if strings.Contains(finding.ContextSnippet, "\x00") || strings.Contains(finding.RedactedValue, "\x00") {
			t.Fatalf("%s: finding carries NUL bytes: %+v", finding.FilePath, finding)
		}
	}
	for _, entry := range entries {
		if !found[entry.name] {
			t.Fatalf("no github_token finding for %s; findings = %+v", entry.name, result.Findings)
		}
	}
}
