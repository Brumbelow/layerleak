package layers

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
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

	t.Run("entries limit", func(t *testing.T) {
		result := replayOne(t, gzipLayer(t, []tarEntry{{name: "a.zip", body: string(archive)}}), nestedOptions(64<<20, 4))
		if got := nestedPaths(result.FinalFiles[0]); len(got) != 4 {
			t.Fatalf("nested = %v", got)
		}
		if skips := skipReasons(result.NestedSkips); strings.Join(skips, ",") != "a.zip:entries_limit:5" {
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
