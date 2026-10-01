package layers

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"testing"
)

const nestedSecret = "GITHUB_TOKEN=ghp_000000000000000000000000000000000000\n"

type zipEntry struct {
	name      string
	body      string
	mode      os.FileMode
	encrypted bool
	method    uint16
}

func zipArchive(t testing.TB, entries []zipEntry) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.name, Method: zip.Deflate}
		if entry.method != 0 {
			header.Method = entry.method
		}
		if entry.mode != 0 {
			header.SetMode(entry.mode)
		} else if strings.HasSuffix(entry.name, "/") {
			header.SetMode(0o755 | os.ModeDir)
		} else {
			header.SetMode(0o644)
		}
		if entry.encrypted {
			header.Flags |= 0x1
		}
		entryWriter, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatalf("CreateHeader(%q) error = %v", entry.name, err)
		}
		if _, err := entryWriter.Write([]byte(entry.body)); err != nil {
			t.Fatalf("Write(%q) error = %v", entry.name, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("zip Close() error = %v", err)
	}
	return buffer.Bytes()
}

func gzipFile(t testing.TB, name string, body []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	writer.Name = name
	if _, err := writer.Write(body); err != nil {
		t.Fatalf("gzip Write() error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("gzip Close() error = %v", err)
	}
	return buffer.Bytes()
}

func nestedOptions(maxBytes int64, maxEntries int) ReplayOptions {
	return ReplayOptions{
		MaxFileBytes:            1 << 20,
		MaxNestedArchiveBytes:   maxBytes,
		MaxNestedArchiveEntries: maxEntries,
	}
}

func replayOne(t testing.TB, layer []byte, options ReplayOptions) ReplayResult {
	t.Helper()
	result, err := replayTestLayers(t, []testLayer{{digest: "sha256:nested", body: layer}}, options)
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	return result
}

func nestedPaths(artifact Artifact) []string {
	paths := make([]string, 0, len(artifact.Nested))
	for _, nested := range artifact.Nested {
		paths = append(paths, nested.Path)
	}
	return paths
}

func skipReasons(skips []NestedSkip) []string {
	reasons := make([]string, 0, len(skips))
	for _, skip := range skips {
		reasons = append(reasons, fmt.Sprintf("%s:%s:%d", skip.Path, skip.Reason, skip.Observed))
	}
	return reasons
}

func TestNestedArchiveKind(t *testing.T) {
	tarBytes := tarArchive(t, []tarEntry{{name: "a", body: "x"}})
	tests := []struct {
		name    string
		content []byte
		want    string
	}{
		{name: "zip", content: zipArchive(t, []zipEntry{{name: "a", body: "x"}}), want: "zip"},
		{name: "gzip", content: gzipFile(t, "", []byte("x")), want: "gzip"},
		{name: "tar", content: tarBytes, want: "tar"},
		{name: "text", content: []byte("PK is not a zip\n"), want: ""},
		{name: "empty zip marker", content: []byte("PK\x05\x06"), want: ""},
		{name: "short", content: []byte{0x1f}, want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := nestedArchiveKind(tc.content); got != tc.want {
				t.Fatalf("nestedArchiveKind() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestReplayExpandsZipFamilyArchivesOneLevel(t *testing.T) {
	inner := zipArchive(t, []zipEntry{{name: "deep/secret.properties", body: nestedSecret}})
	archive := zipArchive(t, []zipEntry{
		{name: "META-INF/"},
		{name: "META-INF/MANIFEST.MF", body: "Manifest-Version: 1.0\n"},
		{name: "config/app.properties", body: "token=" + strings.TrimPrefix(nestedSecret, "GITHUB_TOKEN=")},
		{name: "com/example/App.class", body: "\xca\xfe\xba\xbe\x00\x00\x00\x34binary"},
		{name: "lib/inner.jar", body: string(inner)},
		{name: "keys/server.p12", body: "\x30\x82\x01\x00binary keystore"},
		{name: "link", body: "config/app.properties", mode: 0o777 | os.ModeSymlink},
		{name: "../escape.txt", body: "escaped"},
		{name: "/abs.txt", body: "absolute"},
		{name: "locked.txt", body: "secret", encrypted: true},
		{name: "empty.txt", body: ""},
	})
	options := nestedOptions(64<<20, 10000)
	options.NestedKeepPath = func(path string) bool { return strings.HasSuffix(path, ".p12") }
	result := replayOne(t, gzipLayer(t, []tarEntry{{name: "app/lib.jar", body: string(archive)}}), options)

	if len(result.FinalFiles) != 1 {
		t.Fatalf("FinalFiles = %+v", result.FinalFiles)
	}
	outer := result.FinalFiles[0]
	if outer.Scannable || outer.ContentClass != ContentClassBinaryNUL || outer.Content != nil {
		t.Fatalf("outer archive = %+v, want binary without content", outer)
	}
	wantPaths := []string{
		"app/lib.jar!META-INF/MANIFEST.MF",
		"app/lib.jar!config/app.properties",
		"app/lib.jar!keys/server.p12",
		"app/lib.jar!empty.txt",
	}
	if got := nestedPaths(outer); strings.Join(got, ",") != strings.Join(wantPaths, ",") {
		t.Fatalf("nested paths = %v, want %v", got, wantPaths)
	}
	for _, nested := range outer.Nested {
		if nested.LayerDigest != "sha256:nested" || nested.Type != ArtifactTypeRegularFile {
			t.Fatalf("nested artifact = %+v", nested)
		}
		switch nested.Path {
		case "app/lib.jar!config/app.properties":
			if !nested.Scannable || !strings.Contains(string(nested.Content), "ghp_") {
				t.Fatalf("properties entry = %+v", nested)
			}
		case "app/lib.jar!keys/server.p12":
			if nested.Scannable || nested.Content != nil {
				t.Fatalf("keystore entry = %+v, want path-only", nested)
			}
		}
	}
	wantSkips := []string{
		"app/lib.jar:encrypted:1",
		"app/lib.jar:unsafe_entries:2",
		"app/lib.jar:depth:1",
	}
	if got := skipReasons(result.NestedSkips); strings.Join(got, ",") != strings.Join(wantSkips, ",") {
		t.Fatalf("skips = %v, want %v", got, wantSkips)
	}
	coverage := result.Coverage
	if coverage.NestedArchivesExpanded != 1 || coverage.NestedEntriesScanned != 5 || coverage.FilesSeen != 1 || coverage.FilesExcludedBinary != 1 || coverage.EntriesSkippedUnsafe != 0 {
		t.Fatalf("Coverage = %+v", coverage)
	}
	if recomputed := recomputedRetainedBytes(stateFromResult(t, result)); recomputed != coverage.RetainedBytes {
		t.Fatalf("RetainedBytes = %d, recomputed %d", coverage.RetainedBytes, recomputed)
	}
}

// stateFromResult rebuilds a State from a result so the retention accounting
// of nested artifacts can be recomputed with the test helper.
func stateFromResult(t testing.TB, result ReplayResult) *State {
	t.Helper()
	state := NewState()
	for _, artifact := range result.FinalFiles {
		state.final[artifact.Path] = artifact
		for directory := parentPath(artifact.Path); directory != ""; directory = parentPath(directory) {
			state.dirs[directory] = struct{}{}
		}
	}
	state.deleted = append(state.deleted, result.DeletedArtifacts...)
	return state
}

func TestReplayExpandsGzipAndTarArchives(t *testing.T) {
	tarball := tarArchive(t, []tarEntry{
		{name: "pkg/", typeflag: tar.TypeDir},
		{name: "pkg/.env", body: nestedSecret},
		{name: "pkg/link", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"},
		{name: "pkg/hard", typeflag: tar.TypeLink, linkname: "pkg/.env"},
		{name: "pkg/../../escape", body: "x"},
	})
	layer := gzipLayer(t, []tarEntry{
		{name: "src/pkg.tgz", body: string(gzipBytes(t, tarball))},
		{name: "src/pkg.tar", body: string(tarball)},
		{name: "src/settings.env.gz", body: string(gzipFile(t, "", []byte(nestedSecret)))},
		{name: "src/named.gz", body: string(gzipFile(t, "renamed.env", []byte(nestedSecret)))},
		{name: "src/badname.gz", body: string(gzipFile(t, "../up.env", []byte(nestedSecret)))},
	})
	result := replayOne(t, layer, nestedOptions(64<<20, 10000))
	got := make(map[string][]string)
	for _, artifact := range result.FinalFiles {
		got[artifact.Path] = nestedPaths(artifact)
	}
	want := map[string]string{
		"src/pkg.tgz":         "src/pkg.tgz!pkg/.env",
		"src/pkg.tar":         "src/pkg.tar!pkg/.env",
		"src/settings.env.gz": "src/settings.env.gz!settings.env",
		"src/named.gz":        "src/named.gz!renamed.env",
		"src/badname.gz":      "src/badname.gz!badname",
	}
	for path, nested := range want {
		if strings.Join(got[path], ",") != nested {
			t.Fatalf("%s nested = %v, want %s", path, got[path], nested)
		}
	}
	if result.Coverage.NestedArchivesExpanded != 5 || result.Coverage.NestedEntriesScanned != 5 {
		t.Fatalf("Coverage = %+v", result.Coverage)
	}
	wantSkips := []string{"src/pkg.tgz:unsafe_entries:1", "src/pkg.tar:unsafe_entries:1"}
	if skips := skipReasons(result.NestedSkips); strings.Join(skips, ",") != strings.Join(wantSkips, ",") {
		t.Fatalf("skips = %v, want %v", skips, wantSkips)
	}
	for _, artifact := range result.FinalFiles {
		for _, nested := range artifact.Nested {
			if !nested.Scannable || string(nested.Content) != nestedSecret {
				t.Fatalf("nested %s = %+v", nested.Path, nested)
			}
		}
	}
}

func TestReplayNestedArchiveBoundsAreBoundedSkips(t *testing.T) {
	entries := make([]zipEntry, 0, 6)
	for index := range 6 {
		entries = append(entries, zipEntry{name: fmt.Sprintf("f%d.txt", index), body: strings.Repeat("a", 1000)})
	}
	archive := zipArchive(t, entries)

	t.Run("entries limit refuses a zip before its directory is parsed", func(t *testing.T) {
		// A zip's central directory is materialised in full by the reader,
		// so an archive with more entries than the allowance is refused as
		// a whole from its end-of-central-directory record.
		result := replayOne(t, gzipLayer(t, []tarEntry{{name: "a.zip", body: string(archive)}}), nestedOptions(64<<20, 4))
		if got := nestedPaths(result.FinalFiles[0]); len(got) != 0 {
			t.Fatalf("nested = %v", got)
		}
		if skips := skipReasons(result.NestedSkips); strings.Join(skips, ",") != "a.zip:entries_limit:6" {
			t.Fatalf("skips = %v", skips)
		}
		if result.NestedSkips[0].Limit != 4 || result.Coverage.NestedArchivesExpanded != 0 || result.Coverage.NestedEntriesScanned != 0 {
			t.Fatalf("skip = %+v coverage = %+v", result.NestedSkips[0], result.Coverage)
		}
	})

	t.Run("entries limit stops a tar stream", func(t *testing.T) {
		tarEntries := make([]tarEntry, 0, 6)
		for index := range 6 {
			tarEntries = append(tarEntries, tarEntry{name: fmt.Sprintf("f%d.txt", index), body: strings.Repeat("a", 1000)})
		}
		inner := tarArchive(t, tarEntries)
		result := replayOne(t, gzipLayer(t, []tarEntry{{name: "a.tar", body: string(inner)}}), nestedOptions(64<<20, 4))
		if got := nestedPaths(result.FinalFiles[0]); len(got) != 4 {
			t.Fatalf("nested = %v", got)
		}
		if skips := skipReasons(result.NestedSkips); strings.Join(skips, ",") != "a.tar:entries_limit:5" {
			t.Fatalf("skips = %v", skips)
		}
		if result.NestedSkips[0].Limit != 4 || result.Coverage.NestedArchivesExpanded != 1 {
			t.Fatalf("skip = %+v coverage = %+v", result.NestedSkips[0], result.Coverage)
		}
	})

	t.Run("bytes limit stops decompression", func(t *testing.T) {
		result := replayOne(t, gzipLayer(t, []tarEntry{{name: "a.zip", body: string(archive)}}), nestedOptions(2500, 0))
		if got := nestedPaths(result.FinalFiles[0]); len(got) != 2 {
			t.Fatalf("nested = %v", got)
		}
		if skips := skipReasons(result.NestedSkips); strings.Join(skips, ",") != "a.zip:bytes_limit:3" {
			t.Fatalf("skips = %v", skips)
		}
		if result.Coverage.NestedBytesExpanded > 2501 {
			t.Fatalf("NestedBytesExpanded = %d", result.Coverage.NestedBytesExpanded)
		}
	})

	t.Run("archive above the limit is not buffered", func(t *testing.T) {
		options := nestedOptions(int64(len(archive))-1, 0)
		options.MaxFileBytes = 64
		result := replayOne(t, gzipLayer(t, []tarEntry{{name: "a.zip", body: string(archive)}}), options)
		outer := result.FinalFiles[0]
		if outer.ContentClass != ContentClassOversize || len(outer.Nested) != 0 {
			t.Fatalf("outer = %+v", outer)
		}
		if skips := skipReasons(result.NestedSkips); strings.Join(skips, ",") != fmt.Sprintf("a.zip:oversize:%d", len(archive)) {
			t.Fatalf("skips = %v", skips)
		}
		if result.Coverage.NestedArchivesExpanded != 0 || result.Coverage.FilesSkippedOversize != 1 {
			t.Fatalf("Coverage = %+v", result.Coverage)
		}
	})

	t.Run("archive above the per-file limit but within the nested limit is expanded", func(t *testing.T) {
		// Three 200-byte entries: the archive's headers alone push it past a
		// 256-byte per-file limit while every entry still fits that limit.
		small := zipArchive(t, []zipEntry{
			{name: "one.txt", body: strings.Repeat("alpha ", 40)[:200]},
			{name: "two.txt", body: strings.Repeat("bravo ", 40)[:200]},
			{name: "three.txt", body: strings.Repeat("delta ", 40)[:200]},
		})
		options := nestedOptions(64<<20, 0)
		options.MaxFileBytes = 256
		if int64(len(small)) <= options.MaxFileBytes {
			t.Fatalf("archive is %d bytes, expected it above the per-file limit", len(small))
		}
		result := replayOne(t, gzipLayer(t, []tarEntry{{name: "a.zip", body: string(small)}}), options)
		outer := result.FinalFiles[0]
		if outer.ContentClass != ContentClassOversize || len(outer.Nested) != 3 {
			t.Fatalf("outer class = %q nested = %v", outer.ContentClass, nestedPaths(outer))
		}
		if len(result.NestedSkips) != 0 || result.Coverage.NestedArchivesExpanded != 1 || result.Coverage.FilesSkippedOversize != 1 {
			t.Fatalf("skips = %v coverage = %+v", result.NestedSkips, result.Coverage)
		}
	})

	t.Run("inner entry above the per-file limit", func(t *testing.T) {
		options := nestedOptions(64<<20, 0)
		options.MaxFileBytes = 999
		result := replayOne(t, gzipLayer(t, []tarEntry{{name: "a.zip", body: string(archive)}}), options)
		if len(result.FinalFiles[0].Nested) != 0 {
			t.Fatalf("nested = %v", nestedPaths(result.FinalFiles[0]))
		}
		if skips := skipReasons(result.NestedSkips); strings.Join(skips, ",") != "a.zip:oversize_entries:6" {
			t.Fatalf("skips = %v", skips)
		}
	})

	t.Run("layer byte budget bounds expansion without failing the layer", func(t *testing.T) {
		// The layer stream (one 712-byte zip in a tar) fits 4096 bytes; the
		// 6000 bytes of nested content do not, so expansion stops after four
		// entries and the layer still completes.
		options := nestedOptions(64<<20, 0)
		options.MaxLayerBytes = 4096
		result, err := replayTestLayers(t, []testLayer{{digest: "sha256:nested", body: gzipLayer(t, []tarEntry{{name: "a.zip", body: string(archive)}})}}, options)
		if err != nil {
			t.Fatalf("Replay() error = %v", err)
		}
		if skips := skipReasons(result.NestedSkips); strings.Join(skips, ",") != "a.zip:layer_budget:5" {
			t.Fatalf("skips = %v", skips)
		}
		if got := nestedPaths(result.FinalFiles[0]); len(got) != 4 || result.Coverage.LayersCompleted != 1 {
			t.Fatalf("nested = %v coverage = %+v", got, result.Coverage)
		}
	})

	t.Run("disabled", func(t *testing.T) {
		result := replayOne(t, gzipLayer(t, []tarEntry{{name: "a.zip", body: string(archive)}}), nestedOptions(0, 0))
		if len(result.FinalFiles[0].Nested) != 0 || len(result.NestedSkips) != 0 || result.Coverage.NestedArchivesExpanded != 0 {
			t.Fatalf("result = %+v", result)
		}
	})
}

// zipDirectoryEnd returns the offset of the end-of-central-directory record of
// a zip written by archive/zip (no comment, no zip64 records).
func zipDirectoryEnd(t testing.TB, archive []byte) int {
	t.Helper()
	offset := bytes.LastIndex(archive, []byte("PK\x05\x06"))
	if offset < 0 || offset+22 != len(archive) {
		t.Fatalf("no end-of-central-directory record at the end of the archive (offset %d, len %d)", offset, len(archive))
	}
	return offset
}

// declareZipEntries rewrites the entry count the end-of-central-directory
// record declares, leaving the directory itself untouched.
func declareZipEntries(t testing.TB, archive []byte, records uint16) []byte {
	t.Helper()
	patched := bytes.Clone(archive)
	binary.LittleEndian.PutUint16(patched[zipDirectoryEnd(t, patched)+10:], records)
	return patched
}

// zip64Archive rewrites a plain zip as a zip64 one: the end record defers to
// a zip64 end-of-central-directory record (and its locator) that declares
// `records` entries while the central directory keeps its real contents.
func zip64Archive(t testing.TB, archive []byte, records uint64) []byte {
	t.Helper()
	end := zipDirectoryEnd(t, archive)
	directorySize := uint64(binary.LittleEndian.Uint32(archive[end+12:]))
	directoryOffset := uint64(binary.LittleEndian.Uint32(archive[end+16:]))

	var out bytes.Buffer
	out.Write(archive[:end])
	zip64End := make([]byte, 56)
	copy(zip64End, "PK\x06\x06")
	binary.LittleEndian.PutUint64(zip64End[4:], 44)
	binary.LittleEndian.PutUint16(zip64End[12:], 45)
	binary.LittleEndian.PutUint16(zip64End[14:], 45)
	binary.LittleEndian.PutUint64(zip64End[24:], records)
	binary.LittleEndian.PutUint64(zip64End[32:], records)
	binary.LittleEndian.PutUint64(zip64End[40:], directorySize)
	binary.LittleEndian.PutUint64(zip64End[48:], directoryOffset)
	out.Write(zip64End)
	locator := make([]byte, 20)
	copy(locator, "PK\x06\x07")
	binary.LittleEndian.PutUint64(locator[8:], uint64(end))
	binary.LittleEndian.PutUint32(locator[16:], 1)
	out.Write(locator)
	plainEnd := bytes.Clone(archive[end:])
	binary.LittleEndian.PutUint16(plainEnd[8:], 0xffff)
	binary.LittleEndian.PutUint16(plainEnd[10:], 0xffff)
	binary.LittleEndian.PutUint32(plainEnd[12:], 0xffffffff)
	binary.LittleEndian.PutUint32(plainEnd[16:], 0xffffffff)
	out.Write(plainEnd)
	return out.Bytes()
}

// storedZipArchive writes a zip of count empty, stored entries.
func storedZipArchive(t testing.TB, count int) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for index := range count {
		if _, err := writer.CreateHeader(&zip.FileHeader{Name: fmt.Sprintf("f%05d", index), Method: zip.Store}); err != nil {
			t.Fatalf("CreateHeader() error = %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("zip Close() error = %v", err)
	}
	return buffer.Bytes()
}

// TestReplayZipDirectoryIsBoundedBeforeParsing feeds zips whose directory
// records lie about or exceed the entry allowance: each is refused from its
// end record, so the reader never materialises the headers, and the skip
// reports the entry count the directory declares or actually holds.
func TestReplayZipDirectoryIsBoundedBeforeParsing(t *testing.T) {
	entries := make([]zipEntry, 0, 6)
	for index := range 6 {
		entries = append(entries, zipEntry{name: fmt.Sprintf("f%d.txt", index), body: "x"})
	}
	archive := zipArchive(t, entries)

	t.Run("declared count above the allowance", func(t *testing.T) {
		// archive/zip would reject the mismatch as malformed only after
		// parsing the directory; the refusal happens first and reports the
		// declared count.
		lying := declareZipEntries(t, archive, 60000)
		result := replayOne(t, gzipLayer(t, []tarEntry{{name: "a.zip", body: string(lying)}}), nestedOptions(64<<20, 10000))
		if skips := skipReasons(result.NestedSkips); strings.Join(skips, ",") != "a.zip:entries_limit:60000" {
			t.Fatalf("skips = %v", skips)
		}
		if result.NestedSkips[0].Limit != 10000 || len(result.FinalFiles[0].Nested) != 0 || result.Coverage.NestedArchivesExpanded != 0 {
			t.Fatalf("skip = %+v nested = %v coverage = %+v", result.NestedSkips[0], nestedPaths(result.FinalFiles[0]), result.Coverage)
		}
	})

	t.Run("directory holds more headers than declared", func(t *testing.T) {
		// The declared count fits the allowance (the reader compares only its
		// low 16 bits) but the directory itself does not.
		lying := declareZipEntries(t, archive, 2)
		result := replayOne(t, gzipLayer(t, []tarEntry{{name: "a.zip", body: string(lying)}}), nestedOptions(64<<20, 4))
		if skips := skipReasons(result.NestedSkips); strings.Join(skips, ",") != "a.zip:entries_limit:6" {
			t.Fatalf("skips = %v", skips)
		}
		if len(result.FinalFiles[0].Nested) != 0 || result.Coverage.NestedArchivesExpanded != 0 {
			t.Fatalf("nested = %v coverage = %+v", nestedPaths(result.FinalFiles[0]), result.Coverage)
		}
	})

	t.Run("zip64 record declares the count", func(t *testing.T) {
		honest := zip64Archive(t, archive, 6)
		if reader, err := zip.NewReader(bytes.NewReader(honest), int64(len(honest))); err != nil || len(reader.File) != 6 {
			t.Fatalf("zip64 fixture is not a valid archive: files = %d, err = %v", len(reader.File), err)
		}
		result := replayOne(t, gzipLayer(t, []tarEntry{{name: "a.zip", body: string(honest)}}), nestedOptions(64<<20, 10000))
		if got := nestedPaths(result.FinalFiles[0]); len(got) != 6 || len(result.NestedSkips) != 0 {
			t.Fatalf("nested = %v skips = %v", got, result.NestedSkips)
		}

		lying := zip64Archive(t, archive, 70000)
		result = replayOne(t, gzipLayer(t, []tarEntry{{name: "a.zip", body: string(lying)}}), nestedOptions(64<<20, 10000))
		if skips := skipReasons(result.NestedSkips); strings.Join(skips, ",") != "a.zip:entries_limit:70000" {
			t.Fatalf("skips = %v", skips)
		}
		if len(result.FinalFiles[0].Nested) != 0 || result.Coverage.NestedArchivesExpanded != 0 {
			t.Fatalf("nested = %v coverage = %+v", nestedPaths(result.FinalFiles[0]), result.Coverage)
		}
	})

	t.Run("layer entry budget refuses the archive as layer_budget", func(t *testing.T) {
		options := nestedOptions(64<<20, 0)
		options.MaxLayerEntries = 5
		result, err := replayTestLayers(t, []testLayer{{digest: "sha256:nested", body: gzipLayer(t, []tarEntry{{name: "a.zip", body: string(archive)}})}}, options)
		if err != nil {
			t.Fatalf("Replay() error = %v", err)
		}
		if skips := skipReasons(result.NestedSkips); strings.Join(skips, ",") != "a.zip:layer_budget:6" {
			t.Fatalf("skips = %v", skips)
		}
		if len(result.FinalFiles[0].Nested) != 0 || result.Coverage.LayersCompleted != 1 || result.Coverage.NestedArchivesExpanded != 0 {
			t.Fatalf("nested = %v coverage = %+v", nestedPaths(result.FinalFiles[0]), result.Coverage)
		}
	})

	// Trailing bytes after the end record and a zip64 directory offset past
	// the end are both accepted by archive/zip, which then parses every
	// header; the pre-check must see the same directory and refuse it.
	large := storedZipArchive(t, 20000)
	padded := append(bytes.Clone(large), make([]byte, 65600)...)
	shifted := zip64Archive(t, large, 20000)
	zip64End := bytes.LastIndex(shifted, []byte(zipDirectory64EndSig))
	binary.LittleEndian.PutUint64(shifted[zip64End+zipDirectory64Offset:], uint64(len(shifted)+1000))
	for _, tc := range []struct {
		name    string
		archive []byte
	}{
		{name: "trailing bytes after the end record", archive: padded},
		{name: "zip64 directory offset past the end", archive: shifted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if reader, err := zip.NewReader(bytes.NewReader(tc.archive), int64(len(tc.archive))); err != nil || len(reader.File) != 20000 {
				t.Fatalf("archive/zip must accept the fixture: err = %v", err)
			}
			result := replayOne(t, gzipLayer(t, []tarEntry{{name: "a.zip", body: string(tc.archive)}}), nestedOptions(64<<20, 10000))
			if skips := skipReasons(result.NestedSkips); strings.Join(skips, ",") != "a.zip:entries_limit:20000" {
				t.Fatalf("skips = %v", skips)
			}
			if len(result.FinalFiles[0].Nested) != 0 || result.Coverage.NestedArchivesExpanded != 0 || result.Coverage.NestedEntriesSeen != 0 {
				t.Fatalf("nested = %d coverage = %+v", len(result.FinalFiles[0].Nested), result.Coverage)
			}
		})
	}

	t.Run("honest archive within the allowance is expanded", func(t *testing.T) {
		result := replayOne(t, gzipLayer(t, []tarEntry{{name: "a.zip", body: string(archive)}}), nestedOptions(64<<20, 6))
		if got := nestedPaths(result.FinalFiles[0]); len(got) != 6 || len(result.NestedSkips) != 0 || result.Coverage.NestedArchivesExpanded != 1 {
			t.Fatalf("nested = %v skips = %v coverage = %+v", got, result.NestedSkips, result.Coverage)
		}
	})
}

func TestReplayNestedArchiveMalformedAndBombsAreBoundedSkips(t *testing.T) {
	t.Run("malformed zip", func(t *testing.T) {
		body := "PK\x03\x04" + strings.Repeat("\x00garbage", 64)
		result := replayOne(t, gzipLayer(t, []tarEntry{{name: "broken.zip", body: body}}), nestedOptions(64<<20, 0))
		if skips := skipReasons(result.NestedSkips); strings.Join(skips, ",") != "broken.zip:malformed:1" {
			t.Fatalf("skips = %v", skips)
		}
		if result.Coverage.NestedArchivesExpanded != 0 || len(result.FinalFiles[0].Nested) != 0 {
			t.Fatalf("result = %+v", result)
		}
	})

	t.Run("truncated gzip", func(t *testing.T) {
		body := gzipFile(t, "", []byte(strings.Repeat("x", 4096)))
		result := replayOne(t, gzipLayer(t, []tarEntry{{name: "cut.gz", body: string(body[:len(body)-10])}}), nestedOptions(64<<20, 0))
		if skips := skipReasons(result.NestedSkips); strings.Join(skips, ",") != "cut.gz:malformed:1" {
			t.Fatalf("skips = %v", skips)
		}
	})

	t.Run("highly compressible entries stop at the byte limit", func(t *testing.T) {
		entries := make([]zipEntry, 0, 8)
		for index := range 8 {
			entries = append(entries, zipEntry{name: fmt.Sprintf("zeros-%d", index), body: strings.Repeat("\x00", 512<<10)})
		}
		bomb := zipArchive(t, entries)
		if len(bomb) > 64<<10 {
			t.Fatalf("bomb is %d bytes, expected it to compress well", len(bomb))
		}
		options := nestedOptions(1<<20, 0)
		result := replayOne(t, gzipLayer(t, []tarEntry{{name: "bomb.zip", body: string(bomb)}}), options)
		if skips := skipReasons(result.NestedSkips); strings.Join(skips, ",") != "bomb.zip:bytes_limit:3" {
			t.Fatalf("skips = %v", skips)
		}
		if result.Coverage.NestedBytesExpanded > (1<<20)+1 {
			t.Fatalf("NestedBytesExpanded = %d", result.Coverage.NestedBytesExpanded)
		}
	})

	t.Run("gzip bomb stops at the byte limit", func(t *testing.T) {
		bomb := gzipFile(t, "", []byte(strings.Repeat("\x00", 8<<20)))
		result := replayOne(t, gzipLayer(t, []tarEntry{{name: "bomb.gz", body: string(bomb)}}), nestedOptions(1<<20, 0))
		if skips := skipReasons(result.NestedSkips); strings.Join(skips, ",") != "bomb.gz:bytes_limit:0" {
			t.Fatalf("skips = %v", skips)
		}
	})

	t.Run("tar in gzip is charged every decompressed byte", func(t *testing.T) {
		// A tar holding only a directory followed by 7 MiB of zeros: the walk
		// reads no regular content, yet all of it was inflated. Twenty copies
		// must exhaust an 8 MiB image budget after the first, not inflate
		// 140 MiB for free.
		inner := append(tarArchive(t, []tarEntry{{name: "d/", typeflag: tar.TypeDir}}), make([]byte, 7<<20)...)
		bomb := gzipFile(t, "", inner)
		entries := make([]tarEntry, 0, 20)
		for index := range 20 {
			entries = append(entries, tarEntry{name: fmt.Sprintf("a%02d.tgz", index), body: string(bomb)})
		}
		options := nestedOptions(64<<20, 10000)
		options.MaxTotalBytes = 8 << 20
		result := replayOne(t, gzipLayer(t, entries), options)
		// Each refused archive is charged the one overflow-probe byte that
		// proved its allowance spent, as for a plain gzip member.
		if got := result.Coverage.NestedBytesExpanded; got < int64(len(inner)) || got > (8<<20)+int64(len(entries)) {
			t.Fatalf("NestedBytesExpanded = %d, want the first archive's %d decompressed bytes charged within the 8 MiB budget", got, len(inner))
		}
		if len(result.NestedSkips) != 19 {
			t.Fatalf("skips = %v, want a layer_budget skip for each later archive", skipReasons(result.NestedSkips))
		}
		for index, skip := range result.NestedSkips {
			if want := fmt.Sprintf("a%02d.tgz", index+1); skip.Path != want || skip.Reason != NestedSkipLayerBudget {
				t.Fatalf("skip %d = %+v, want %s:%s", index, skip, want, NestedSkipLayerBudget)
			}
		}
	})
}

func TestReplayNestedEntriesFollowTheOuterArtifact(t *testing.T) {
	archive := zipArchive(t, []zipEntry{{name: "app.env", body: nestedSecret}})
	lower := gzipLayer(t, []tarEntry{{name: "opt/bundle.zip", body: string(archive)}})
	upper := gzipLayer(t, []tarEntry{{name: "opt/.wh.bundle.zip"}})
	result, err := replayTestLayers(t, []testLayer{
		{digest: "sha256:lower", body: lower},
		{digest: "sha256:upper", body: upper},
	}, nestedOptions(64<<20, 0))
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if len(result.FinalFiles) != 0 || len(result.DeletedArtifacts) != 1 {
		t.Fatalf("result = %+v", result)
	}
	deleted := result.DeletedArtifacts[0]
	if deleted.DeletedByLayerDigest != "sha256:upper" || strings.Join(nestedPaths(deleted), ",") != "opt/bundle.zip!app.env" {
		t.Fatalf("deleted = %+v", deleted)
	}
	// The deleted artifact keeps its nested entries (and their retention
	// charge); the "opt" directory survives the file whiteout.
	if want := retainedDeletedArtifactBytes(deleted) + retainedMapStringBytes("opt"); result.Coverage.RetainedBytes != want {
		t.Fatalf("RetainedBytes = %d, want %d", result.Coverage.RetainedBytes, want)
	}
}

// TestReplayHardlinkChainToArchiveNamesTheArchive links to an archive through
// another hardlink: every hardlink in the chain names the regular file whose
// nested entries it shares, so the entries can be re-rooted under its path.
func TestReplayHardlinkChainToArchiveNamesTheArchive(t *testing.T) {
	archive := zipArchive(t, []zipEntry{{name: "config/app.yml", body: nestedSecret}})
	result := replayOne(t, gzipLayer(t, []tarEntry{
		{name: "app/a.jar", body: string(archive)},
		{name: "app/h1", typeflag: tar.TypeLink, linkname: "app/a.jar"},
		{name: "app/h2", typeflag: tar.TypeLink, linkname: "app/h1"},
	}), nestedOptions(64<<20, 0))
	if len(result.FinalFiles) != 3 {
		t.Fatalf("FinalFiles = %+v", result.FinalFiles)
	}
	for _, artifact := range result.FinalFiles {
		switch artifact.Path {
		case "app/a.jar":
			if artifact.Type != ArtifactTypeRegularFile || artifact.Linkname != "" {
				t.Fatalf("archive = %+v", artifact)
			}
		case "app/h1", "app/h2":
			if artifact.Type != ArtifactTypeHardlink || artifact.Linkname != "app/a.jar" {
				t.Fatalf("hardlink %s = type %q linkname %q, want hardlink to app/a.jar", artifact.Path, artifact.Type, artifact.Linkname)
			}
		default:
			t.Fatalf("unexpected artifact %+v", artifact)
		}
		if got := strings.Join(nestedPaths(artifact), ","); got != "app/a.jar!config/app.yml" {
			t.Fatalf("%s nested = %q", artifact.Path, got)
		}
	}
	if result.Coverage.FilesSeen != 3 || result.Coverage.FilesExcludedBinary != 3 || result.Coverage.NestedArchivesExpanded != 1 {
		t.Fatalf("Coverage = %+v", result.Coverage)
	}
}

func TestReplayDropsNestedEntriesInsteadOfFailingOnRetainedBytes(t *testing.T) {
	archive := zipArchive(t, []zipEntry{{name: "app.env", body: strings.Repeat("x", 4000)}})
	layer := gzipLayer(t, []tarEntry{{name: "bundle.zip", body: string(archive)}})
	options := nestedOptions(64<<20, 0)
	// Enough for the outer artifact and the directory bookkeeping, not for the
	// 4000 bytes of nested text.
	options.MaxRetainedBytes = retainedFinalArtifactBaseBytes("bundle.zip", "") + 2000
	result, err := replayTestLayers(t, []testLayer{{digest: "sha256:nested", body: layer}}, options)
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if len(result.FinalFiles) != 1 || len(result.FinalFiles[0].Nested) != 0 {
		t.Fatalf("result = %+v", result)
	}
	if skips := skipReasons(result.NestedSkips); strings.Join(skips, ",") != "bundle.zip:retained_bytes:1" {
		t.Fatalf("skips = %v", skips)
	}
	if result.Coverage.LayersCompleted != 1 {
		t.Fatalf("Coverage = %+v", result.Coverage)
	}
}

func TestReplayNestedExpansionIsDeterministic(t *testing.T) {
	archive := zipArchive(t, []zipEntry{
		{name: "z.txt", body: "z"}, {name: "a.txt", body: "a"}, {name: "locked", body: "l", encrypted: true},
	})
	layer := gzipLayer(t, []tarEntry{{name: "x.zip", body: string(archive)}, {name: "y.zip", body: string(archive)}})
	first := replayOne(t, layer, nestedOptions(64<<20, 0))
	second := replayOne(t, layer, nestedOptions(64<<20, 0))
	if fmt.Sprintf("%+v", first) != fmt.Sprintf("%+v", second) {
		t.Fatalf("non-deterministic expansion:\n%+v\n%+v", first, second)
	}
	if got := nestedPaths(first.FinalFiles[0]); strings.Join(got, ",") != "x.zip!z.txt,x.zip!a.txt" {
		t.Fatalf("archive order was not kept: %v", got)
	}
	if skips := skipReasons(first.NestedSkips); strings.Join(skips, ",") != "x.zip:encrypted:1,y.zip:encrypted:1" {
		t.Fatalf("skips = %v", skips)
	}
}
