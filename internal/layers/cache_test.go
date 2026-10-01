package layers

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/brumbelow/layerleak/v3/internal/limits"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
)

func TestLayerCacheIsLRUAndBounded(t *testing.T) {
	if NewLayerCache(0) != nil || NewLayerCache(-1) != nil {
		t.Fatal("NewLayerCache(<=0) must return nil (cache off)")
	}
	var off *LayerCache
	if off.lookup(manifest.Descriptor{Digest: "sha256:a"}) != nil || off.Store(&LayerRecord{cacheable: true}) || off.Stats() != (LayerCacheStats{}) {
		t.Fatal("a nil cache must be inert")
	}

	record := func(digest string, size int64) *LayerRecord {
		descriptor := manifest.Descriptor{Digest: digest, MediaType: manifest.MediaTypeOCIImageLayerGzip}
		item := newLayerRecord(descriptor)
		item.size = size
		return item
	}
	cache := NewLayerCache(300)
	for _, item := range []*LayerRecord{record("sha256:a", 100), record("sha256:b", 100), record("sha256:c", 100)} {
		if !cache.Store(item) {
			t.Fatalf("Store(%s) = false", item.Digest)
		}
	}
	if cache.Store(record("sha256:big", 301)) || cache.Stats().Rejected != 1 {
		t.Fatalf("an oversize record must be rejected: %+v", cache.Stats())
	}
	// Touch a so that b is the least recently used.
	if cache.lookup(manifest.Descriptor{Digest: "sha256:a", MediaType: manifest.MediaTypeOCIImageLayerGzip}) == nil {
		t.Fatal("lookup(a) missed")
	}
	if !cache.Store(record("sha256:d", 100)) {
		t.Fatal("Store(d) = false")
	}
	if cache.lookup(manifest.Descriptor{Digest: "sha256:b", MediaType: manifest.MediaTypeOCIImageLayerGzip}) != nil {
		t.Fatal("b should have been evicted as least recently used")
	}
	for _, digest := range []string{"sha256:a", "sha256:c", "sha256:d"} {
		if cache.lookup(manifest.Descriptor{Digest: digest, MediaType: manifest.MediaTypeOCIImageLayerGzip}) == nil {
			t.Fatalf("lookup(%s) missed", digest)
		}
	}
	// The same digest with another compression is another layer.
	if cache.lookup(manifest.Descriptor{Digest: "sha256:a", MediaType: manifest.MediaTypeOCIImageLayerZstd}) != nil {
		t.Fatal("compression must be part of the key")
	}
	stats := cache.Stats()
	if stats.Layers != 3 || stats.UsedBytes != 300 || stats.Evictions != 1 || stats.Stores != 4 || stats.Hits != 4 || stats.Misses != 2 {
		t.Fatalf("Stats() = %+v", stats)
	}
	if cache.Store(&LayerRecord{key: "x", cacheable: false, size: 1}) {
		t.Fatal("an uncacheable record must not be stored")
	}
}

type countingOpener struct {
	bodies map[string][]byte
	opens  map[string]int
}

func newCountingOpener(testLayers []testLayer) (*countingOpener, []manifest.Descriptor) {
	opener := &countingOpener{bodies: make(map[string][]byte), opens: make(map[string]int)}
	descriptors := make([]manifest.Descriptor, 0, len(testLayers))
	for _, layer := range testLayers {
		opener.bodies[layer.digest] = layer.body
		descriptors = append(descriptors, manifest.Descriptor{Digest: layer.digest, MediaType: manifest.MediaTypeDockerSchema2LayerGzip})
	}
	return opener, descriptors
}

func (o *countingOpener) OpenLayer(_ context.Context, descriptor manifest.Descriptor) (io.ReadCloser, error) {
	o.opens[descriptor.Digest]++
	body, ok := o.bodies[descriptor.Digest]
	if !ok {
		return nil, fmt.Errorf("unknown layer %s", descriptor.Digest)
	}
	return io.NopCloser(bytes.NewReader(body)), nil
}

// withoutContent is the shape a cache-replayed result must have: the same
// artifacts, with text content replaced by its length and the clean marker.
func withoutContent(result ReplayResult) ReplayResult {
	strip := func(items []Artifact) []Artifact {
		stripped := make([]Artifact, 0, len(items))
		for _, item := range items {
			if item.Scannable && item.Content != nil {
				item.ContentLength = int64(len(item.Content))
				item.Content = nil
				item.KnownClean = true
			}
			stripped = append(stripped, item)
		}
		return stripped
	}
	result.FinalFiles = strip(result.FinalFiles)
	result.DeletedArtifacts = strip(result.DeletedArtifacts)
	result.LayerRecords = nil
	return result
}

func cacheTestLayers(t *testing.T) []testLayer {
	t.Helper()
	utf16 := encodeUTF16(t, "setting=value\r\n", binary.LittleEndian, true)
	return []testLayer{
		{digest: "sha256:base", body: gzipLayer(t, []tarEntry{
			{name: "etc/", typeflag: tar.TypeDir},
			{name: "etc/os-release", body: "NAME=test\n"},
			{name: "etc/empty", body: ""},
			{name: "etc/win.ini", body: string(utf16)},
			{name: "bin/tool", body: "\x7fELF\x02\x01\x01\x00binary"},
			{name: "bin/same", typeflag: tar.TypeLink, linkname: "bin/tool"},
			{name: "lib/libc.so.6", body: "\x00\x01\x02binary"},
			{name: "etc/link", typeflag: tar.TypeSymlink, linkname: "os-release"},
			{name: "dev/null", typeflag: tar.TypeChar},
			{name: "meta", typeflag: tar.TypeXGlobalHeader, paxRecords: map[string]string{"comment": "x"}},
		})},
		{digest: "sha256:middle", body: gzipLayer(t, []tarEntry{
			{name: "etc/os-release", body: "NAME=replaced\n"},
			{name: "opt/app/config.yml", body: "debug: true\n"},
			{name: "opt/app/data.bin", body: strings.Repeat("\x00", 2048)},
		})},
		{digest: "sha256:top", body: gzipLayer(t, []tarEntry{
			{name: "opt/app/.wh.config.yml"},
			{name: "etc/.wh..wh..opq"},
			{name: "etc/fresh", body: "fresh\n"},
		})},
	}
}

func TestReplayFromCacheIsIdenticalToReplayFromStream(t *testing.T) {
	testLayers := cacheTestLayers(t)
	options := ReplayOptions{MaxFileBytes: 1 << 20, MaxLayerEntries: 100, MaxTotalEntries: 1000, MaxRetainedBytes: 1 << 30, MaxNestedArchiveBytes: 1 << 20}

	// First sweep target: every layer comes from the stream and is recorded.
	cache := NewLayerCache(1 << 20)
	opener, descriptors := newCountingOpener(testLayers)
	withRecords := options
	withRecords.Cache = cache
	first, err := Replay(context.Background(), descriptors, withRecords, opener)
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if len(first.LayerRecords) != 3 {
		t.Fatalf("LayerRecords = %d, want 3", len(first.LayerRecords))
	}
	for _, record := range first.LayerRecords {
		if !cache.Store(record) {
			t.Fatalf("Store(%s) = false", record.Digest)
		}
	}
	reference, err := Replay(context.Background(), descriptors, options, opener)
	if err != nil {
		t.Fatalf("Replay() reference error = %v", err)
	}

	// Second target: every layer is served from the cache.
	cached, err := Replay(context.Background(), descriptors, withRecords, opener)
	if err != nil {
		t.Fatalf("Replay() from cache error = %v", err)
	}
	for digest, count := range opener.opens {
		if count != 2 {
			t.Fatalf("%s opened %d times, want 2 (recording run and reference run only)", digest, count)
		}
	}
	if stats := cache.Stats(); stats.Hits != 3 {
		t.Fatalf("Stats() = %+v, want 3 hits", stats)
	}
	if !reflect.DeepEqual(withoutContent(reference), withoutContent(cached)) {
		t.Fatalf("cached replay differs from stream replay:\n%+v\n%+v", withoutContent(reference), withoutContent(cached))
	}
	if cached.Coverage != reference.Coverage {
		t.Fatalf("coverage differs: %+v vs %+v", cached.Coverage, reference.Coverage)
	}
	for _, artifact := range cached.FinalFiles {
		if artifact.Scannable && (artifact.Content != nil || !artifact.KnownClean) {
			t.Fatalf("cached artifact %s still carries content or is not marked clean: %+v", artifact.Path, artifact)
		}
		if !artifact.Scannable && artifact.KnownClean {
			t.Fatalf("non-scannable artifact %s marked clean", artifact.Path)
		}
	}
	if len(cached.LayerRecords) != 0 {
		t.Fatalf("a cache hit must not produce new records: %d", len(cached.LayerRecords))
	}
}

func TestReplayFromCacheFailsAtTheSameAggregateLimit(t *testing.T) {
	testLayers := cacheTestLayers(t)
	base := ReplayOptions{MaxFileBytes: 1 << 20, MaxRetainedBytes: 1 << 30}
	opener, descriptors := newCountingOpener(testLayers)

	// Record the layers in a run without aggregate limits.
	cache := NewLayerCache(1 << 20)
	recording := base
	recording.Cache = cache
	recorded, err := Replay(context.Background(), descriptors, recording, opener)
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	for _, record := range recorded.LayerRecords {
		cache.Store(record)
	}
	one, err := Replay(context.Background(), descriptors[:1], base, opener)
	if err != nil {
		t.Fatalf("Replay() first layer error = %v", err)
	}

	for _, tc := range []struct {
		name string
		set  func(*ReplayOptions)
		kind limits.Kind
	}{
		{name: "image bytes mid second layer", set: func(o *ReplayOptions) { o.MaxTotalBytes = one.Coverage.ExpandedBytes + 700 }, kind: limits.Kind("image_layer_bytes")},
		{name: "image bytes at a header boundary", set: func(o *ReplayOptions) { o.MaxTotalBytes = one.Coverage.ExpandedBytes + 512 }, kind: limits.Kind("image_layer_bytes")},
		{name: "image entries", set: func(o *ReplayOptions) { o.MaxTotalEntries = 11 }, kind: limits.Kind("image_entries")},
		{name: "retained bytes", set: func(o *ReplayOptions) { o.MaxRetainedBytes = one.Coverage.RetainedBytes + 600 }, kind: limits.Kind("retained_bytes")},
		{name: "layer bytes", set: func(o *ReplayOptions) { o.MaxLayerBytes = 1500 }, kind: limits.KindLayerBytes},
	} {
		t.Run(tc.name, func(t *testing.T) {
			limited := base
			tc.set(&limited)
			fromStream, streamErr := Replay(context.Background(), descriptors, limited, opener)
			if streamErr == nil {
				t.Fatal("stream replay did not hit the limit; fixture needs adjusting")
			}
			exceeded, ok := limits.AsExceeded(streamErr)
			if !ok || exceeded.Kind != tc.kind {
				t.Fatalf("stream error = %v, want kind %s", streamErr, tc.kind)
			}
			limited.Cache = cache
			fromCache, cacheErr := Replay(context.Background(), descriptors, limited, opener)
			if cacheErr == nil || cacheErr.Error() != streamErr.Error() {
				t.Fatalf("errors differ:\n cache: %v\nstream: %v", cacheErr, streamErr)
			}
			if !reflect.DeepEqual(withoutContent(fromStream), withoutContent(fromCache)) {
				t.Fatalf("partial results differ:\n cache: %+v\nstream: %+v", withoutContent(fromCache), withoutContent(fromStream))
			}
		})
	}
}

func TestReplayFromCacheRefusesHardlinksIntoCachedText(t *testing.T) {
	lower := gzipLayer(t, []tarEntry{{name: "etc/config", body: "key=value\n"}})
	upper := gzipLayer(t, []tarEntry{{name: "etc/alias", typeflag: tar.TypeLink, linkname: "etc/config"}})
	options := ReplayOptions{MaxFileBytes: 1 << 20, MaxRetainedBytes: 1 << 30}
	cache := NewLayerCache(1 << 20)
	options.Cache = cache

	opener, lowerOnly := newCountingOpener([]testLayer{{digest: "sha256:lower", body: lower}})
	recorded, err := Replay(context.Background(), lowerOnly, options, opener)
	if err != nil || len(recorded.LayerRecords) != 1 {
		t.Fatalf("Replay() = %v, records %d", err, len(recorded.LayerRecords))
	}
	cache.Store(recorded.LayerRecords[0])

	opener, both := newCountingOpener([]testLayer{{digest: "sha256:lower", body: lower}, {digest: "sha256:upper", body: upper}})
	_, err = Replay(context.Background(), both, options, opener)
	if !errors.Is(err, ErrCacheUnusable) {
		t.Fatalf("Replay() error = %v, want ErrCacheUnusable", err)
	}
	if opener.opens["sha256:lower"] != 0 {
		t.Fatalf("the cached layer was opened %d times before the fallback", opener.opens["sha256:lower"])
	}

	options.SkipCacheLookup = true
	result, err := Replay(context.Background(), both, options, opener)
	if err != nil {
		t.Fatalf("Replay() with SkipCacheLookup error = %v", err)
	}
	if opener.opens["sha256:lower"] != 1 || len(result.FinalFiles) != 2 || result.FinalFiles[0].Content == nil {
		t.Fatalf("fallback replay = opens %v, files %+v", opener.opens, result.FinalFiles)
	}
	// The lower layer is recorded again; the upper layer hardlinks into another
	// layer and is never cacheable.
	digests := make([]string, 0, len(result.LayerRecords))
	for _, record := range result.LayerRecords {
		digests = append(digests, record.Digest)
	}
	if strings.Join(digests, ",") != "sha256:lower" {
		t.Fatalf("LayerRecords = %v, want only sha256:lower", digests)
	}
}

func TestReplayDoesNotRecordLayersWithNestedArchives(t *testing.T) {
	archive := zipArchive(t, []zipEntry{{name: "inner.txt", body: "x"}})
	testLayers := []testLayer{
		{digest: "sha256:plain", body: gzipLayer(t, []tarEntry{{name: "a", body: "a"}})},
		{digest: "sha256:archive", body: gzipLayer(t, []tarEntry{{name: "b.zip", body: string(archive)}})},
		{digest: "sha256:oversize-archive", body: gzipLayer(t, []tarEntry{{name: "c.zip", body: string(archive)}})},
	}
	opener, descriptors := newCountingOpener(testLayers)
	options := ReplayOptions{MaxFileBytes: 1 << 20, MaxRetainedBytes: 1 << 30, MaxNestedArchiveBytes: 1 << 20, Cache: NewLayerCache(1 << 20)}
	result, err := Replay(context.Background(), descriptors[:2], options, opener)
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	digests := make([]string, 0, len(result.LayerRecords))
	for _, record := range result.LayerRecords {
		digests = append(digests, record.Digest)
	}
	if strings.Join(digests, ",") != "sha256:plain" {
		t.Fatalf("LayerRecords = %v, want only the plain layer", digests)
	}

	// A skipped (too large) archive makes the layer uncacheable as well: the
	// file exceeds MaxFileBytes, so the archive must fit the nested bound to be
	// buffered, and here it does not.
	options.MaxFileBytes = 16
	options.MaxNestedArchiveBytes = 16
	result, err = Replay(context.Background(), descriptors[2:], options, opener)
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if len(result.LayerRecords) != 0 || len(result.NestedSkips) != 1 {
		t.Fatalf("records = %d skips = %d", len(result.LayerRecords), len(result.NestedSkips))
	}
}

func TestLayerLimitReaderAdvanceMirrorsRead(t *testing.T) {
	for _, tc := range []struct {
		name     string
		max      int64
		previous int64
		maxTotal int64
		to       int64
		wantPos  int64
		wantKind limits.Kind
	}{
		{name: "within both", max: 100, previous: 50, maxTotal: 200, to: 90, wantPos: 90},
		{name: "layer limit", max: 100, previous: 0, maxTotal: 1000, to: 150, wantPos: 101, wantKind: limits.KindLayerBytes},
		{name: "image limit", max: 1000, previous: 950, maxTotal: 1000, to: 60, wantPos: 51, wantKind: limits.Kind("image_layer_bytes")},
		{name: "tie goes to the layer", max: 50, previous: 950, maxTotal: 1000, to: 60, wantPos: 51, wantKind: limits.KindLayerBytes},
		{name: "unbounded", to: 1 << 40, wantPos: 1 << 40},
		{name: "image already over", max: 0, previous: 1001, maxTotal: 1000, to: 1, wantPos: 0, wantKind: limits.Kind("image_layer_bytes")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader := newLayerLimitReader(nil, "sha256:x", tc.max, tc.previous, tc.maxTotal)
			err := reader.advance(tc.to)
			if tc.wantKind == "" {
				if err != nil || reader.readBytes != tc.wantPos {
					t.Fatalf("advance() = %v, pos %d", err, reader.readBytes)
				}
				return
			}
			exceeded, ok := limits.AsExceeded(err)
			if !ok || exceeded.Kind != tc.wantKind || reader.readBytes != tc.wantPos {
				t.Fatalf("advance() = %v, pos %d, want kind %s pos %d", err, reader.readBytes, tc.wantKind, tc.wantPos)
			}
		})
	}
}
