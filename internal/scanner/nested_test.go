package scanner

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/brumbelow/layerleak/v3/internal/manifest"
)

func zipBytes(t *testing.T, entries map[string]string, encrypted ...string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	// Deterministic archive order.
	for i := range names {
		for j := i + 1; j < len(names); j++ {
			if names[j] < names[i] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	for _, name := range names {
		header := &zip.FileHeader{Name: name, Method: zip.Deflate}
		header.SetMode(0o644)
		for _, locked := range encrypted {
			if locked == name {
				header.Flags |= 0x1
			}
		}
		entryWriter, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatalf("CreateHeader() error = %v", err)
		}
		if _, err := entryWriter.Write([]byte(entries[name])); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	return buffer.Bytes()
}

// TestScanFindsSecretsInsideNestedArchives scans a jar stored in a layer: the
// secret inside it is reported under the `outer!inner` provenance path, a
// keystore inside it is reported by path, an encrypted archive is a bounded
// skip with a nested_archive_skipped diagnostic, coverage stays complete and
// the nested counters are reported.
func TestScanFindsSecretsInsideNestedArchives(t *testing.T) {
	jar := zipBytes(t, map[string]string{
		"META-INF/MANIFEST.MF":   "Manifest-Version: 1.0\n",
		"config/application.yml": "github:\n  token: " + syntheticGitHubToken + "\n",
		"com/example/App.class":  "\xca\xfe\xba\xbe\x00\x00\x00\x34",
		"keys/server.p12":        "\x30\x82\x01\x00binary",
	})
	locked := zipBytes(t, map[string]string{"secret.txt": "x"}, "secret.txt")
	f := newRegistryFixture()
	layer := f.blob(t, manifest.MediaTypeDockerSchema2LayerGzip, gzipLayer(t, []tarEntry{
		{name: "app/lib/app.jar", body: string(jar)},
		{name: "app/locked.zip", body: string(locked)},
	}))
	f.setRootManifest(t, configBlob(t, f, "linux", "amd64"), []manifest.Descriptor{layer})

	request := f.request(t, "")
	request.MaxNestedArchiveBytes = 64 << 20
	request.MaxNestedArchiveEntries = 10000
	result, err := Scan(context.Background(), request)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if result.Status != ResultStatusCompleted || !result.Coverage.Complete {
		t.Fatalf("result = %+v", result)
	}
	if result.Coverage.NestedArchivesExpanded != 2 || result.Coverage.NestedEntriesScanned != 4 || result.Coverage.FilesSeen != 2 || result.Coverage.FilesExcludedBinary != 2 {
		t.Fatalf("Coverage = %+v", result.Coverage)
	}

	byPath := make(map[string]string)
	for _, finding := range result.Findings {
		byPath[finding.FilePath+"|"+finding.DetectorName] = finding.RedactedValue
		if strings.Contains(finding.FilePath, "!") && finding.LayerDigest != layer.Digest {
			t.Fatalf("nested finding lost its layer digest: %+v", finding)
		}
	}
	if _, ok := byPath["app/lib/app.jar!config/application.yml|github_token"]; !ok {
		t.Fatalf("no github_token finding inside the jar: %v", byPath)
	}
	if _, ok := byPath["app/lib/app.jar!keys/server.p12|sensitive_file_keystore"]; !ok {
		t.Fatalf("no path-only keystore finding inside the jar: %v", byPath)
	}
	if _, ok := byPath["app/lib/app.jar!com/example/App.class|sensitive_file_keystore"]; ok {
		t.Fatalf("class file was reported: %v", byPath)
	}

	diagnostic, ok := findDiagnostic(result.Diagnostics, "nested_archive_skipped", "")
	if !ok {
		t.Fatalf("no nested_archive_skipped diagnostic: %v", result.Diagnostics)
	}
	if diagnostic.Scope != "platform" || diagnostic.Observed != 1 || !strings.Contains(diagnostic.Message, "app/locked.zip") || !strings.Contains(diagnostic.Message, "1 encrypted entries") {
		t.Fatalf("diagnostic = %+v", diagnostic)
	}
	if len(result.PlatformResults) != 1 || result.PlatformResults[0].Status != ResultStatusCompleted {
		t.Fatalf("platform results = %+v", result.PlatformResults)
	}
}

// TestScanReportsNestedEntriesBehindHardlinkChains stores a jar once and
// links to it twice, the second hardlink pointing at the first: the entries
// inside the jar are reported under the jar's path and under both hardlinks,
// so path-sensitive detectors see every name the content is reachable by.
func TestScanReportsNestedEntriesBehindHardlinkChains(t *testing.T) {
	jar := zipBytes(t, map[string]string{
		"config/app.yml": "github:\n  token: " + syntheticGitHubToken + "\n",
	})
	f := newRegistryFixture()
	layer := f.blob(t, manifest.MediaTypeDockerSchema2LayerGzip, gzipLayer(t, []tarEntry{
		{name: "app/a.jar", body: string(jar)},
		{name: "app/h1", typeflag: tar.TypeLink, linkname: "app/a.jar"},
		{name: "app/h2", typeflag: tar.TypeLink, linkname: "app/h1"},
	}))
	f.setRootManifest(t, configBlob(t, f, "linux", "amd64"), []manifest.Descriptor{layer})

	request := f.request(t, "")
	request.MaxNestedArchiveBytes = 64 << 20
	request.MaxNestedArchiveEntries = 10000
	result, err := Scan(context.Background(), request)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if result.Status != ResultStatusCompleted || !result.Coverage.Complete {
		t.Fatalf("result = %+v", result)
	}
	paths := make([]string, 0, len(result.Findings))
	for _, finding := range result.Findings {
		if finding.DetectorName != "github_token" || finding.LayerDigest != layer.Digest {
			t.Fatalf("unexpected finding %+v", finding)
		}
		paths = append(paths, finding.FilePath)
	}
	sort.Strings(paths)
	want := "app/a.jar!config/app.yml,app/h1!config/app.yml,app/h2!config/app.yml"
	if got := strings.Join(paths, ","); got != want {
		t.Fatalf("finding paths = %q, want %q", got, want)
	}
}

func TestScanRedactsSecretsInNestedArchivePathsOfDiagnostics(t *testing.T) {
	locked := zipBytes(t, map[string]string{"secret.txt": "x"}, "secret.txt")
	f := newRegistryFixture()
	layer := f.blob(t, manifest.MediaTypeDockerSchema2LayerGzip, gzipLayer(t, []tarEntry{
		{name: "app/" + syntheticGitHubToken + ".zip", body: string(locked)},
	}))
	f.setRootManifest(t, configBlob(t, f, "linux", "amd64"), []manifest.Descriptor{layer})
	request := f.request(t, "")
	request.MaxNestedArchiveBytes = 64 << 20
	result, err := Scan(context.Background(), request)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	diagnostic, ok := findDiagnostic(result.Diagnostics, "nested_archive_skipped", "")
	if !ok {
		t.Fatalf("no nested_archive_skipped diagnostic: %v", result.Diagnostics)
	}
	if strings.Contains(diagnostic.Message, syntheticGitHubToken) || !strings.Contains(diagnostic.Message, "[REDACTED]") {
		t.Fatalf("diagnostic leaks the token: %q", diagnostic.Message)
	}
}

func TestScanWithoutNestedBoundsDoesNotExpandArchives(t *testing.T) {
	jar := zipBytes(t, map[string]string{"config/application.yml": "token: " + syntheticGitHubToken + "\n"})
	f := newRegistryFixture()
	layer := f.blob(t, manifest.MediaTypeDockerSchema2LayerGzip, gzipLayer(t, []tarEntry{{name: "app.jar", body: string(jar)}}))
	f.setRootManifest(t, configBlob(t, f, "linux", "amd64"), []manifest.Descriptor{layer})
	result, err := Scan(context.Background(), f.request(t, ""))
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if result.TotalFindings != 0 || result.Coverage.NestedArchivesExpanded != 0 || len(result.Diagnostics) != 0 {
		t.Fatalf("result = %+v", result)
	}
}
