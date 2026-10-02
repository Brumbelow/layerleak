package layers

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/brumbelow/layerleak/v3/internal/manifest"
)

// stateSnapshot is a deep copy of everything Replay keeps between layers.
type stateSnapshot struct {
	final             map[string]Artifact
	deleted           []Artifact
	dirs              map[string]struct{}
	directoryChildren map[string]map[string]struct{}
	artifactChildren  map[string]map[string]struct{}
	entries           int
	retainedBytes     int64
}

func snapshotState(state *State) stateSnapshot {
	clonePathIndex := func(source map[string]map[string]struct{}) map[string]map[string]struct{} {
		result := make(map[string]map[string]struct{}, len(source))
		for parent, children := range source {
			cloned := make(map[string]struct{}, len(children))
			for child := range children {
				cloned[child] = struct{}{}
			}
			result[parent] = cloned
		}
		return result
	}
	final := make(map[string]Artifact, len(state.final))
	for key, value := range state.final {
		final[key] = value
	}
	dirs := make(map[string]struct{}, len(state.dirs))
	for key := range state.dirs {
		dirs[key] = struct{}{}
	}
	return stateSnapshot{
		final:             final,
		deleted:           append([]Artifact(nil), state.deleted...),
		dirs:              dirs,
		directoryChildren: clonePathIndex(state.directoryChildren),
		artifactChildren:  clonePathIndex(state.artifactChildren),
		entries:           state.entries,
		retainedBytes:     state.coverage.RetainedBytes,
	}
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// assertSnapshotEqual compares a state with a snapshot field by field so a
// difference names the structure and the paths involved.
func assertSnapshotEqual(t *testing.T, label string, state *State, want stateSnapshot) {
	t.Helper()
	got := snapshotState(state)
	if !reflect.DeepEqual(got.final, want.final) {
		t.Fatalf("%s: final differs\n got: %v\nwant: %v", label, sortedKeys(got.final), sortedKeys(want.final))
	}
	if !reflect.DeepEqual(got.deleted, want.deleted) {
		t.Fatalf("%s: deleted differs\n got: %d entries\nwant: %d entries", label, len(got.deleted), len(want.deleted))
	}
	if !reflect.DeepEqual(got.dirs, want.dirs) {
		t.Fatalf("%s: dirs differ\n got: %v\nwant: %v", label, sortedKeys(got.dirs), sortedKeys(want.dirs))
	}
	if !reflect.DeepEqual(got.directoryChildren, want.directoryChildren) {
		t.Fatalf("%s: directory index differs\n got: %v\nwant: %v", label, got.directoryChildren, want.directoryChildren)
	}
	if !reflect.DeepEqual(got.artifactChildren, want.artifactChildren) {
		t.Fatalf("%s: artifact index differs\n got: %v\nwant: %v", label, got.artifactChildren, want.artifactChildren)
	}
	if got.entries != want.entries || got.retainedBytes != want.retainedBytes {
		t.Fatalf("%s: entries %d/%d retained %d/%d", label, got.entries, want.entries, got.retainedBytes, want.retainedBytes)
	}
}

// randomLayerEntries draws a layer from a small path alphabet so overwrites,
// file/directory transitions, hardlinks, whiteouts and opaque whiteouts hit
// existing state often.
func randomLayerEntries(random *testRand, count int) []tarEntry {
	names := []string{"a", "b", "c", "a/x", "a/y", "b/x", "a/x/deep", "c/d/e", "a/x/deep/f"}
	entries := make([]tarEntry, 0, count)
	for range count {
		name := names[random.IntN(len(names))]
		switch random.IntN(10) {
		case 0, 1:
			entries = append(entries, tarEntry{name: name, typeflag: tar.TypeDir})
		case 2:
			entries = append(entries, tarEntry{name: name, typeflag: tar.TypeSymlink, linkname: names[random.IntN(len(names))]})
		case 3:
			entries = append(entries, tarEntry{name: name, typeflag: tar.TypeLink, linkname: names[random.IntN(len(names))]})
		case 4:
			parent, base := "", name
			if index := strings.LastIndex(name, "/"); index >= 0 {
				parent, base = name[:index+1], name[index+1:]
			}
			entries = append(entries, tarEntry{name: parent + ".wh." + base})
		case 5:
			entries = append(entries, tarEntry{name: name + "/.wh..wh..opq"})
		default:
			entries = append(entries, tarEntry{name: name, body: strings.Repeat("v", random.IntN(64))})
		}
	}
	return entries
}

// TestReplayRollbackRestoresExactPreLayerState is the property test behind the
// undo journal: for random base states and random failing layers (failing at
// a random entry through the entry limit, the retained-bytes limit, a
// truncated stream or a read error), the state after the failure equals the
// state before the layer, structure for structure. A control run of the same
// layer without the failure shows that the layer did mutate the state.
func TestReplayRollbackRestoresExactPreLayerState(t *testing.T) {
	options := ReplayOptions{MaxFileBytes: 1 << 20, MaxLayerEntries: 1000, MaxTotalEntries: 100000, MaxRetainedBytes: 1 << 30}
	descriptor := manifest.Descriptor{Digest: "sha256:failing", MediaType: manifest.MediaTypeOCIImageLayer}
	mutated := 0
	for seed := range 300 {
		random := newTestRand(uint64(seed)<<8 | 7)
		state := NewState()
		for layer := range 1 + random.IntN(3) {
			body := tarArchive(t, randomLayerEntries(random, 1+random.IntN(12)))
			if err := state.applyLayer(context.Background(), manifest.Descriptor{Digest: fmt.Sprintf("sha256:base%d", layer), MediaType: manifest.MediaTypeOCIImageLayer}, bytes.NewReader(body), options); err != nil {
				t.Fatalf("seed %d: base layer error = %v", seed, err)
			}
		}
		before := snapshotState(state)
		entries := randomLayerEntries(random, 2+random.IntN(12))
		body := tarArchive(t, entries)

		failing := options
		var reader io.Reader = bytes.NewReader(body)
		var label string
		switch random.IntN(4) {
		case 0:
			failing.MaxLayerEntries = 1 + random.IntN(len(entries))
			label = fmt.Sprintf("entry limit %d", failing.MaxLayerEntries)
		case 1:
			failing.MaxRetainedBytes = before.retainedBytes + int64(random.IntN(600))
			label = fmt.Sprintf("retained limit %d", failing.MaxRetainedBytes)
		case 2:
			cut := 1 + random.IntN(len(body)-1)
			reader = bytes.NewReader(body[:cut])
			label = fmt.Sprintf("truncated at %d", cut)
		default:
			cut := 1 + random.IntN(len(body)-1)
			reader = io.MultiReader(bytes.NewReader(body[:cut]), &failingReader{err: errors.New("injected read failure")})
			label = fmt.Sprintf("read error at %d", cut)
		}
		err := state.applyLayer(context.Background(), descriptor, reader, failing)
		if err == nil {
			// The random failure did not trigger (for example an entry limit
			// above the entry count); the layer committed and is not a
			// rollback case. Check it is at least internally consistent.
			if recomputed := recomputedRetainedBytes(state); recomputed != state.coverage.RetainedBytes {
				t.Fatalf("seed %d (%s): RetainedBytes = %d, recomputed %d", seed, label, state.coverage.RetainedBytes, recomputed)
			}
			continue
		}
		assertSnapshotEqual(t, fmt.Sprintf("seed %d (%s, %v)", seed, label, err), state, before)
		if state.journal != nil {
			t.Fatalf("seed %d: journal left open after rollback", seed)
		}

		// The same layer applied without the failure must change the state
		// (otherwise the rollback check proves nothing for this seed).
		control := NewState()
		if err := control.applyLayer(context.Background(), descriptor, bytes.NewReader(body), options); err != nil {
			continue
		}
		if len(control.final) > 0 || len(control.dirs) > 0 || len(control.deleted) > 0 {
			mutated++
		}
	}
	if mutated == 0 {
		t.Fatal("no seed produced a mutating layer; the property was not exercised")
	}
}

type failingReader struct{ err error }

func (r *failingReader) Read([]byte) (int, error) { return 0, r.err }

// TestReplayRollbackUndoesWhiteoutsAndDirectoryTransitions pins the cases the
// journal has to reverse exactly: an overwrite, a file replaced by a
// directory, a directory replaced by a file, a whiteout and an opaque
// whiteout, all in one failing layer.
func TestReplayRollbackUndoesWhiteoutsAndDirectoryTransitions(t *testing.T) {
	options := ReplayOptions{MaxFileBytes: 1 << 20, MaxRetainedBytes: 1 << 30}
	base := tarArchive(t, []tarEntry{
		{name: "keep", body: "keep"},
		{name: "file-then-dir", body: "old"},
		{name: "dir-then-file/child", body: "child"},
		{name: "wh/victim", body: "gone"},
		{name: "opq/one", body: "1"},
		{name: "opq/two/three", body: "3"},
	})
	state := NewState()
	if err := state.applyLayer(context.Background(), manifest.Descriptor{Digest: "sha256:base", MediaType: manifest.MediaTypeOCIImageLayer}, bytes.NewReader(base), options); err != nil {
		t.Fatalf("base layer error = %v", err)
	}
	before := snapshotState(state)

	upper := tarArchive(t, []tarEntry{
		{name: "keep", body: "replaced"},
		{name: "file-then-dir/new", body: "new"},
		{name: "dir-then-file", body: "now a file"},
		{name: "wh/.wh.victim"},
		{name: "opq/.wh..wh..opq"},
		{name: "opq/fresh", body: "fresh"},
	})
	// The layer is complete and valid; it fails only on the aggregate entry
	// limit at its last entry, after every mutation above was applied.
	failing := options
	failing.MaxTotalEntries = state.entries + 5
	err := state.applyLayer(context.Background(), manifest.Descriptor{Digest: "sha256:upper", MediaType: manifest.MediaTypeOCIImageLayer}, bytes.NewReader(upper), failing)
	if err == nil {
		t.Fatal("applyLayer() error = nil")
	}
	assertSnapshotEqual(t, "after rollback", state, before)

	// And the same layer commits cleanly without the limit, with the
	// whiteouts applied to lower entries only.
	if err := state.applyLayer(context.Background(), manifest.Descriptor{Digest: "sha256:upper", MediaType: manifest.MediaTypeOCIImageLayer}, bytes.NewReader(upper), options); err != nil {
		t.Fatalf("applyLayer() error = %v", err)
	}
	result := state.Result()
	finalPaths := make([]string, 0, len(result.FinalFiles))
	for _, artifact := range result.FinalFiles {
		finalPaths = append(finalPaths, artifact.Path)
	}
	if want := "dir-then-file,file-then-dir/new,keep,opq/fresh"; strings.Join(finalPaths, ",") != want {
		t.Fatalf("final paths = %v, want %s", finalPaths, want)
	}
	deletedPaths := make([]string, 0, len(result.DeletedArtifacts))
	for _, artifact := range result.DeletedArtifacts {
		deletedPaths = append(deletedPaths, artifact.Path)
	}
	if want := "dir-then-file/child,file-then-dir,keep,opq/one,opq/two/three,wh/victim"; strings.Join(deletedPaths, ",") != want {
		t.Fatalf("deleted paths = %v, want %s", deletedPaths, want)
	}
	if recomputed := recomputedRetainedBytes(state); recomputed != state.coverage.RetainedBytes {
		t.Fatalf("RetainedBytes = %d, recomputed %d", state.coverage.RetainedBytes, recomputed)
	}
}

// BenchmarkReplayManyLayers replays a wide base followed by many small layers,
// the shape LAY-14 is about: per-layer cost must not grow with the size of the
// accumulated state.
func BenchmarkReplayManyLayers(b *testing.B) {
	baseEntries := make([]tarEntry, 0, 20000)
	for index := range 20000 {
		baseEntries = append(baseEntries, tarEntry{name: fmt.Sprintf("base/%03d/file-%05d", index%100, index), body: "x"})
	}
	layers := []testLayer{{digest: "sha256:wide-base", body: gzipLayer(b, baseEntries)}}
	for layer := range 200 {
		entries := make([]tarEntry, 0, 20)
		for file := range 20 {
			entries = append(entries, tarEntry{name: fmt.Sprintf("app/layer-%03d/file-%02d", layer, file), body: "y"})
		}
		layers = append(layers, testLayer{digest: fmt.Sprintf("sha256:layer-%03d", layer), body: gzipLayer(b, entries)})
	}
	options := ReplayOptions{MaxFileBytes: 1 << 20, MaxLayerEntries: 50000, MaxTotalEntries: 250000, MaxRetainedBytes: 1 << 30}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := replayTestLayers(b, layers, options); err != nil {
			b.Fatal(err)
		}
	}
}
