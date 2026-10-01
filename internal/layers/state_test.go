package layers

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/limits"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
	"github.com/klauspost/compress/zstd"
)

// legacyTypeRegA is the deprecated archive/tar TypeRegA flag, which the
// reader normalizes to TypeReg; fixtures still emit it to cover old archives.
const legacyTypeRegA = '\x00'

func TestReplayTracksDeletedArtifacts(t *testing.T) {
	layerOne := gzipLayer(t, []tarEntry{
		{name: "app/.env", body: "TOKEN=ghp_123456789012345678901234567890123456"},
	})
	layerTwo := gzipLayer(t, []tarEntry{
		{name: "app/.wh..env", body: ""},
	})

	result, err := Replay(context.Background(), []manifest.Descriptor{
		{Digest: "sha256:one", MediaType: manifest.MediaTypeDockerSchema2LayerGzip},
		{Digest: "sha256:two", MediaType: manifest.MediaTypeDockerSchema2LayerGzip},
	}, ReplayOptions{MaxFileBytes: 1 << 20}, OpenFunc(func(_ context.Context, descriptor manifest.Descriptor) (io.ReadCloser, error) {
		switch descriptor.Digest {
		case "sha256:one":
			return io.NopCloser(bytes.NewReader(layerOne)), nil
		case "sha256:two":
			return io.NopCloser(bytes.NewReader(layerTwo)), nil
		default:
			return nil, io.EOF
		}
	}))
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}

	if len(result.FinalFiles) != 0 {
		t.Fatalf("len(result.FinalFiles) = %d", len(result.FinalFiles))
	}

	if len(result.DeletedArtifacts) != 1 {
		t.Fatalf("len(result.DeletedArtifacts) = %d", len(result.DeletedArtifacts))
	}

	if result.DeletedArtifacts[0].Path != "app/.env" {
		t.Fatalf("result.DeletedArtifacts[0].Path = %q", result.DeletedArtifacts[0].Path)
	}
}

func TestReplayDoesNotNormalizeWhitespaceIntoWhiteoutNames(t *testing.T) {
	lower := gzipLayer(t, []tarEntry{{name: "app/secret", body: "keep"}})
	upper := gzipLayer(t, []tarEntry{{name: "app/.wh.secret ", body: "ordinary file"}})

	result, err := replayTestLayers(t, []testLayer{
		{digest: "sha256:lower", body: lower},
		{digest: "sha256:upper", body: upper},
	}, ReplayOptions{MaxFileBytes: 1 << 20})
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if len(result.DeletedArtifacts) != 0 {
		t.Fatalf("result.DeletedArtifacts = %#v", result.DeletedArtifacts)
	}
	if len(result.FinalFiles) != 1 || result.FinalFiles[0].Path != "app/secret" {
		t.Fatalf("result.FinalFiles = %#v", result.FinalFiles)
	}
}

func TestReplayKeepsWhitespaceDirectorySemanticsExact(t *testing.T) {
	lower := gzipLayer(t, []tarEntry{
		{name: "dir/secret", body: "plain"},
		{name: " dir /secret", body: "spaced"},
	})
	upper := gzipLayer(t, []tarEntry{{name: " dir ", body: "replacement"}})

	result, err := replayTestLayers(t, []testLayer{
		{digest: "sha256:lower", body: lower},
		{digest: "sha256:upper", body: upper},
	}, ReplayOptions{MaxFileBytes: 1 << 20})
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if len(result.FinalFiles) != 2 || result.FinalFiles[0].Path != " dir " || result.FinalFiles[1].Path != "dir/secret" {
		t.Fatalf("result.FinalFiles = %#v", result.FinalFiles)
	}
	if len(result.DeletedArtifacts) != 1 || result.DeletedArtifacts[0].Path != " dir /secret" {
		t.Fatalf("result.DeletedArtifacts = %#v", result.DeletedArtifacts)
	}
}

func TestReplayMarksInvalidHardlinksIncomplete(t *testing.T) {
	layer := gzipLayer(t, []tarEntry{
		{name: "app/traversal", typeflag: tar.TypeLink, linkname: "../secret"},
		{name: "app/missing", typeflag: tar.TypeLink, linkname: "app/not-there"},
	})
	result, err := replayTestLayers(t, []testLayer{{digest: "sha256:hardlinks", body: layer}}, ReplayOptions{MaxFileBytes: 1 << 20})
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if result.Coverage.EntriesSkippedUnsafe != 2 {
		t.Fatalf("result.Coverage = %#v", result.Coverage)
	}
}

func TestReplayTracksOverwrittenFilesAndOpaqueWhiteout(t *testing.T) {
	layerOne := gzipLayer(t, []tarEntry{
		{name: "app/secret.txt", body: "old"},
		{name: "app/notes.txt", body: "keep"},
	})
	layerTwo := gzipLayer(t, []tarEntry{
		{name: "app/secret.txt", body: "new"},
		{name: "app/.wh..wh..opq", body: ""},
		{name: "app/final.txt", body: "done"},
	})

	result, err := Replay(context.Background(), []manifest.Descriptor{
		{Digest: "sha256:one", MediaType: manifest.MediaTypeDockerSchema2LayerGzip},
		{Digest: "sha256:two", MediaType: manifest.MediaTypeDockerSchema2LayerGzip},
	}, ReplayOptions{MaxFileBytes: 1 << 20}, OpenFunc(func(_ context.Context, descriptor manifest.Descriptor) (io.ReadCloser, error) {
		switch descriptor.Digest {
		case "sha256:one":
			return io.NopCloser(bytes.NewReader(layerOne)), nil
		case "sha256:two":
			return io.NopCloser(bytes.NewReader(layerTwo)), nil
		default:
			return nil, io.EOF
		}
	}))
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}

	if len(result.FinalFiles) != 2 {
		t.Fatalf("len(result.FinalFiles) = %d", len(result.FinalFiles))
	}
	if result.FinalFiles[0].Path != "app/final.txt" || result.FinalFiles[1].Path != "app/secret.txt" {
		t.Fatalf("result.FinalFiles paths = %q, %q", result.FinalFiles[0].Path, result.FinalFiles[1].Path)
	}

	if len(result.DeletedArtifacts) < 2 {
		t.Fatalf("len(result.DeletedArtifacts) = %d", len(result.DeletedArtifacts))
	}
}

func TestReplaySupportsZstd(t *testing.T) {
	layer := zstdLayer(t, []tarEntry{
		{name: "app/config.json", body: `{"auth":"dXNlcjpwYXNz"}`},
	})

	result, err := Replay(context.Background(), []manifest.Descriptor{
		{Digest: "sha256:zstd", MediaType: manifest.MediaTypeOCIImageLayerZstd},
	}, ReplayOptions{MaxFileBytes: 1 << 20}, OpenFunc(func(_ context.Context, _ manifest.Descriptor) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(layer)), nil
	}))
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}

	if len(result.FinalFiles) != 1 {
		t.Fatalf("len(result.FinalFiles) = %d", len(result.FinalFiles))
	}
}

func TestReplayRejectsOversizedPAXPathAndLink(t *testing.T) {
	oversized := strings.Repeat("p", maxArchivePathBytes+1)
	layer := gzipLayer(t, []tarEntry{
		{name: oversized, format: tar.FormatPAX},
		{name: "app/link", typeflag: tar.TypeSymlink, linkname: oversized, format: tar.FormatPAX},
		{name: "app/safe"},
	})

	result, err := replayTestLayers(t, []testLayer{{digest: "sha256:pax-metadata", body: layer}}, ReplayOptions{
		MaxFileBytes:     1 << 20,
		MaxRetainedBytes: 1 << 20,
	})
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if len(result.FinalFiles) != 1 || result.FinalFiles[0].Path != "app/safe" {
		t.Fatalf("result.FinalFiles = %#v", result.FinalFiles)
	}
	if result.Coverage.EntriesSkippedUnsafe != 2 {
		t.Fatalf("result.Coverage = %#v", result.Coverage)
	}
	wantRetained := retainedMapStringBytes("app") + retainedFinalArtifactBytes(Artifact{Path: "app/safe"})
	if result.Coverage.RetainedBytes != wantRetained {
		t.Fatalf("result.Coverage.RetainedBytes = %d, want %d", result.Coverage.RetainedBytes, wantRetained)
	}
}

func TestReplayAccountsForZeroContentPaths(t *testing.T) {
	const artifactPath = "empty"
	layer := gzipLayer(t, []tarEntry{{name: artifactPath}})
	wantRetained := retainedFinalArtifactBytes(Artifact{Path: artifactPath})
	peakRetained := wantRetained + retainedMapStringBytes(artifactPath)

	result, err := replayTestLayers(t, []testLayer{{digest: "sha256:empty-path", body: layer}}, ReplayOptions{
		MaxFileBytes:     1 << 20,
		MaxRetainedBytes: peakRetained,
	})
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if result.Coverage.RetainedBytes != wantRetained || result.Coverage.RetainedBytes == 0 {
		t.Fatalf("result.Coverage.RetainedBytes = %d, want %d", result.Coverage.RetainedBytes, wantRetained)
	}

	limited, err := replayTestLayers(t, []testLayer{{digest: "sha256:empty-path", body: layer}}, ReplayOptions{
		MaxFileBytes:     1 << 20,
		MaxRetainedBytes: wantRetained - 1,
	})
	if exceeded, ok := limits.AsExceeded(err); !ok || exceeded.Kind != limits.Kind("retained_bytes") {
		t.Fatalf("Replay() error = %v", err)
	}
	if len(limited.FinalFiles) != 0 || limited.Coverage.RetainedBytes != 0 {
		t.Fatalf("limited result = %#v", limited)
	}
}

func TestReplayAccountsForDeletedArtifactMetadata(t *testing.T) {
	lower := gzipLayer(t, []tarEntry{{name: "secret"}})
	upper := gzipLayer(t, []tarEntry{{name: ".wh.secret"}})
	result, err := replayTestLayers(t, []testLayer{
		{digest: "sha256:lower-metadata", body: lower},
		{digest: "sha256:upper-metadata", body: upper},
	}, ReplayOptions{MaxFileBytes: 1 << 20, MaxRetainedBytes: 1 << 20})
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if len(result.FinalFiles) != 0 || len(result.DeletedArtifacts) != 1 {
		t.Fatalf("result = %#v", result)
	}
	wantRetained := retainedDeletedArtifactBytes(Artifact{Path: "secret"})
	if result.Coverage.RetainedBytes != wantRetained || result.Coverage.RetainedBytes == 0 {
		t.Fatalf("result.Coverage.RetainedBytes = %d, want %d", result.Coverage.RetainedBytes, wantRetained)
	}
}

func TestReplayAccountsForSymlinkTargets(t *testing.T) {
	const artifactPath = "link"
	linkname := strings.Repeat("target", 16)
	layer := gzipLayer(t, []tarEntry{{name: artifactPath, typeflag: tar.TypeSymlink, linkname: linkname}})
	wantRetained := retainedFinalArtifactBytes(Artifact{Path: artifactPath, Linkname: linkname})
	peakRetained := wantRetained + retainedMapStringBytes(artifactPath)

	result, err := replayTestLayers(t, []testLayer{{digest: "sha256:symlink-metadata", body: layer}}, ReplayOptions{
		MaxFileBytes:     1 << 20,
		MaxRetainedBytes: peakRetained,
	})
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if result.Coverage.RetainedBytes != wantRetained {
		t.Fatalf("result.Coverage.RetainedBytes = %d, want %d", result.Coverage.RetainedBytes, wantRetained)
	}

	limited, err := replayTestLayers(t, []testLayer{{digest: "sha256:symlink-metadata", body: layer}}, ReplayOptions{
		MaxFileBytes:     1 << 20,
		MaxRetainedBytes: wantRetained - 1,
	})
	if exceeded, ok := limits.AsExceeded(err); !ok || exceeded.Kind != limits.Kind("retained_bytes") {
		t.Fatalf("Replay() error = %v", err)
	}
	if limited.Coverage.RetainedBytes != 0 {
		t.Fatalf("limited result = %#v", limited)
	}
}

func TestReplayBoundsArchiveMetadataBookkeeping(t *testing.T) {
	tests := []struct {
		name             string
		entry            tarEntry
		maxRetainedBytes int64
	}{
		{
			name:             "current paths",
			entry:            tarEntry{name: "empty"},
			maxRetainedBytes: retainedFinalArtifactBytes(Artifact{Path: "empty"}),
		},
		{
			name:  "directories",
			entry: tarEntry{name: "a/b/c", typeflag: tar.TypeDir},
			maxRetainedBytes: retainedMapStringBytes("a") +
				retainedMapStringBytes("a/b") + retainedMapStringBytes("a/b/c") - 1,
		},
		{
			name:             "whiteouts",
			entry:            tarEntry{name: ".wh." + strings.Repeat("w", 64)},
			maxRetainedBytes: retainedSliceStringBytes(strings.Repeat("w", 64)) - 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			layer := gzipLayer(t, []tarEntry{test.entry})
			result, err := replayTestLayers(t, []testLayer{{digest: "sha256:metadata-budget", body: layer}}, ReplayOptions{
				MaxFileBytes:     1 << 20,
				MaxRetainedBytes: test.maxRetainedBytes,
			})
			if exceeded, ok := limits.AsExceeded(err); !ok || exceeded.Kind != limits.Kind("retained_bytes") {
				t.Fatalf("Replay() error = %v", err)
			}
			if len(result.FinalFiles) != 0 || len(result.DeletedArtifacts) != 0 || result.Coverage.RetainedBytes != 0 {
				t.Fatalf("result = %#v", result)
			}
		})
	}
}

func TestReplayRejectsHostileZstdWindowWithoutMaterialAllocation(t *testing.T) {
	// This valid frame header declares a 256 MiB window and is followed by an
	// empty final raw block. An uncapped streaming decoder allocates its history
	// buffer before processing that block.
	layer := []byte{
		0x28, 0xb5, 0x2f, 0xfd,
		0x00,
		0x90,
		0x01, 0x00, 0x00,
	}
	descriptors := []manifest.Descriptor{{
		Digest:    "sha256:zstd-hostile-window",
		MediaType: manifest.MediaTypeOCIImageLayerZstd,
	}}
	opener := OpenFunc(func(context.Context, manifest.Descriptor) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(layer)), nil
	})

	for _, test := range []struct {
		name          string
		maxLayerBytes int64
	}{
		{name: "derived limit", maxLayerBytes: 1 << 20},
		{name: "safe fallback"},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime.GC()
			var before runtime.MemStats
			runtime.ReadMemStats(&before)
			_, err := Replay(context.Background(), descriptors, ReplayOptions{
				MaxFileBytes:  1 << 20,
				MaxLayerBytes: test.maxLayerBytes,
			}, opener)
			var after runtime.MemStats
			runtime.ReadMemStats(&after)

			if !errors.Is(err, zstd.ErrWindowSizeExceeded) && !errors.Is(err, zstd.ErrDecoderSizeExceeded) {
				t.Fatalf("Replay() error = %v", err)
			}
			if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 16<<20 {
				t.Fatalf("Replay() allocated %d bytes while rejecting the zstd window", allocated)
			}
		})
	}
}

func TestReplayClassifiesRegularFilesBeforeScanning(t *testing.T) {
	layer := gzipLayer(t, []tarEntry{
		{name: "app/config.env", body: "TOKEN=ghp_123456789012345678901234567890123456"},
		{name: "usr/bin/tool", body: "ELF\x00payload"},
		{name: "usr/lib/libpam.so.0", body: "\x7fELF\x02\x01\x01\x00shared"},
		{name: "var/lib/app/blob.bin", body: "line\x00with\x01control"},
		{name: "var/lib/app/encoded.dat", body: "\x01\x02\x03\x04\x05TEXT"},
	})

	result, err := Replay(context.Background(), []manifest.Descriptor{
		{Digest: "sha256:classified", MediaType: manifest.MediaTypeDockerSchema2LayerGzip},
	}, ReplayOptions{MaxFileBytes: 1 << 20}, OpenFunc(func(_ context.Context, _ manifest.Descriptor) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(layer)), nil
	}))
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}

	classes := make(map[string]Artifact)
	for _, artifact := range result.FinalFiles {
		classes[artifact.Path] = artifact
	}

	tests := []struct {
		path      string
		wantClass ContentClass
		scannable bool
		keepBody  bool
	}{
		{path: "app/config.env", wantClass: ContentClassText, scannable: true, keepBody: true},
		{path: "usr/bin/tool", wantClass: ContentClassBinaryNUL, scannable: false, keepBody: false},
		{path: "usr/lib/libpam.so.0", wantClass: ContentClassBinarySharedObject, scannable: false, keepBody: false},
		{path: "var/lib/app/blob.bin", wantClass: ContentClassBinaryNUL, scannable: false, keepBody: false},
		{path: "var/lib/app/encoded.dat", wantClass: ContentClassBinaryLowPrintable, scannable: false, keepBody: false},
	}

	for _, tt := range tests {
		artifact, ok := classes[tt.path]
		if !ok {
			t.Fatalf("missing artifact %q", tt.path)
		}
		if artifact.ContentClass != tt.wantClass {
			t.Fatalf("%s ContentClass = %q", tt.path, artifact.ContentClass)
		}
		if artifact.Scannable != tt.scannable {
			t.Fatalf("%s Scannable = %t", tt.path, artifact.Scannable)
		}
		if tt.keepBody && len(artifact.Content) == 0 {
			t.Fatalf("%s content unexpectedly empty", tt.path)
		}
		if !tt.keepBody && len(artifact.Content) != 0 {
			t.Fatalf("%s content length = %d", tt.path, len(artifact.Content))
		}
	}
}

func TestReplayReturnsPartialResultWhenGzipLayerByteLimitExceeded(t *testing.T) {
	layer := gzipLayer(t, []tarEntry{
		{name: "app/one.txt", body: "one"},
		{name: "app/two.txt", body: "two"},
	})

	result, err := Replay(context.Background(), []manifest.Descriptor{
		{Digest: "sha256:limited", MediaType: manifest.MediaTypeDockerSchema2LayerGzip},
	}, ReplayOptions{
		MaxFileBytes:  1 << 20,
		MaxLayerBytes: 1536,
	}, OpenFunc(func(_ context.Context, _ manifest.Descriptor) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(layer)), nil
	}))
	if err == nil {
		t.Fatal("Replay() error = nil")
	}

	exceeded, ok := limits.AsExceeded(err)
	if !ok {
		t.Fatalf("err = %v", err)
	}
	if exceeded.Kind != limits.KindLayerBytes {
		t.Fatalf("exceeded.Kind = %q", exceeded.Kind)
	}
	if exceeded.Subject != "layer sha256:limited" {
		t.Fatalf("exceeded.Subject = %q", exceeded.Subject)
	}
	if len(result.FinalFiles) != 0 {
		t.Fatalf("len(result.FinalFiles) = %d", len(result.FinalFiles))
	}
}

func TestReplayReturnsPartialResultWhenZstdLayerByteLimitExceeded(t *testing.T) {
	layer := zstdLayer(t, []tarEntry{
		{name: "app/one.txt", body: "one"},
		{name: "app/two.txt", body: "two"},
	})

	result, err := Replay(context.Background(), []manifest.Descriptor{
		{Digest: "sha256:zstdlimited", MediaType: manifest.MediaTypeOCIImageLayerZstd},
	}, ReplayOptions{
		MaxFileBytes:  1 << 20,
		MaxLayerBytes: 1536,
	}, OpenFunc(func(_ context.Context, _ manifest.Descriptor) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(layer)), nil
	}))
	if err == nil {
		t.Fatal("Replay() error = nil")
	}

	exceeded, ok := limits.AsExceeded(err)
	if !ok {
		t.Fatalf("err = %v", err)
	}
	if exceeded.Kind != limits.KindLayerBytes {
		t.Fatalf("exceeded.Kind = %q", exceeded.Kind)
	}
	if len(result.FinalFiles) != 0 {
		t.Fatalf("len(result.FinalFiles) = %d", len(result.FinalFiles))
	}
}

func TestReplayBoundsSparseLogicalLayerBytes(t *testing.T) {
	const logicalSize = 1 << 30
	layer := gzipSparseLayer(t, "app/sparse", logicalSize)
	if len(layer) >= 4096 {
		t.Fatalf("sparse layer physical size = %d", len(layer))
	}

	result, err := replayTestLayers(t, []testLayer{{digest: "sha256:sparse", body: layer}}, ReplayOptions{
		MaxFileBytes:  1 << 20,
		MaxLayerBytes: 1 << 20,
	})
	exceeded, ok := limits.AsExceeded(err)
	if !ok || exceeded.Kind != limits.KindLayerBytes || exceeded.Limit != 1<<20 {
		t.Fatalf("Replay() error = %v", err)
	}
	if result.Coverage.ExpandedBytes != logicalSize {
		t.Fatalf("result.Coverage.ExpandedBytes = %d, want %d", result.Coverage.ExpandedBytes, logicalSize)
	}
	if len(result.FinalFiles) != 0 || result.Coverage.FilesSeen != 0 {
		t.Fatalf("result = %#v", result)
	}
}

func TestLogicalLayerBudgetRejectsAccountingOverflow(t *testing.T) {
	t.Run("layer", func(t *testing.T) {
		budget := newLogicalLayerBudget("sha256:overflow", 0, 0, 0)
		if err := budget.add(math.MaxInt64); err != nil {
			t.Fatalf("add(MaxInt64) error = %v", err)
		}
		err := budget.add(1)
		exceeded, ok := limits.AsExceeded(err)
		if !ok || exceeded.Kind != limits.KindLayerBytes || exceeded.Limit != math.MaxInt64 {
			t.Fatalf("add(1) error = %v", err)
		}
		if budget.bytes != math.MaxInt64 {
			t.Fatalf("budget.bytes = %d", budget.bytes)
		}
	})

	t.Run("image", func(t *testing.T) {
		budget := newLogicalLayerBudget("sha256:overflow", 0, math.MaxInt64-1, math.MaxInt64)
		err := budget.add(2)
		exceeded, ok := limits.AsExceeded(err)
		if !ok || exceeded.Kind != limits.Kind("image_layer_bytes") || exceeded.Limit != math.MaxInt64 {
			t.Fatalf("add(2) error = %v", err)
		}
	})

	if got := expandedBytesAfterLayer(math.MaxInt64-1, 2, 1); got != math.MaxInt64 {
		t.Fatalf("expandedBytesAfterLayer() = %d", got)
	}
}

func TestReplayBoundsSparseLogicalImageBytes(t *testing.T) {
	const logicalSize = 8 << 20
	regular := gzipLayer(t, []tarEntry{{name: "app/regular", body: "regular"}})
	sparse := gzipSparseLayer(t, "app/sparse", logicalSize)
	baseline, err := replayTestLayers(t, []testLayer{{digest: "sha256:regular", body: regular}}, ReplayOptions{MaxFileBytes: 1 << 20})
	if err != nil {
		t.Fatalf("Replay() baseline error = %v", err)
	}

	result, err := replayTestLayers(t, []testLayer{
		{digest: "sha256:regular", body: regular},
		{digest: "sha256:sparse", body: sparse},
	}, ReplayOptions{
		MaxFileBytes:  1 << 20,
		MaxTotalBytes: baseline.Coverage.ExpandedBytes + logicalSize - 1,
	})
	exceeded, ok := limits.AsExceeded(err)
	if !ok || exceeded.Kind != limits.Kind("image_layer_bytes") {
		t.Fatalf("Replay() error = %v", err)
	}
	if len(result.FinalFiles) != 1 || result.FinalFiles[0].Path != "app/regular" {
		t.Fatalf("result.FinalFiles = %#v", result.FinalFiles)
	}
	if result.Coverage.ExpandedBytes != baseline.Coverage.ExpandedBytes+logicalSize {
		t.Fatalf("result.Coverage.ExpandedBytes = %d, want %d", result.Coverage.ExpandedBytes, baseline.Coverage.ExpandedBytes+logicalSize)
	}
}

func TestReplayReturnsPartialResultWhenLayerEntryLimitExceeded(t *testing.T) {
	layer := gzipLayer(t, []tarEntry{
		{name: "app/one.txt", body: "one"},
		{name: "app/two.txt", body: "two"},
	})

	result, err := Replay(context.Background(), []manifest.Descriptor{
		{Digest: "sha256:entries", MediaType: manifest.MediaTypeDockerSchema2LayerGzip},
	}, ReplayOptions{
		MaxFileBytes:    1 << 20,
		MaxLayerEntries: 1,
	}, OpenFunc(func(_ context.Context, _ manifest.Descriptor) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(layer)), nil
	}))
	if err == nil {
		t.Fatal("Replay() error = nil")
	}

	exceeded, ok := limits.AsExceeded(err)
	if !ok {
		t.Fatalf("err = %v", err)
	}
	if exceeded.Kind != limits.KindLayerEntries {
		t.Fatalf("exceeded.Kind = %q", exceeded.Kind)
	}
	if exceeded.Subject != "layer sha256:entries" {
		t.Fatalf("exceeded.Subject = %q", exceeded.Subject)
	}
	if len(result.FinalFiles) != 0 {
		t.Fatalf("len(result.FinalFiles) = %d", len(result.FinalFiles))
	}
}

func TestReplayWhiteoutsOnlyRemoveLowerLayerEntries(t *testing.T) {
	tests := []struct {
		name    string
		entries []tarEntry
	}{
		{
			name: "whiteout first",
			entries: []tarEntry{
				{name: "app/.wh..wh..opq"},
				{name: "app/.wh.secret.txt"},
				{name: "app/secret.txt", body: "new"},
			},
		},
		{
			name: "whiteout last",
			entries: []tarEntry{
				{name: "app/secret.txt", body: "new"},
				{name: "app/.wh.secret.txt"},
				{name: "app/.wh..wh..opq"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lower := gzipLayer(t, []tarEntry{
				{name: "app/secret.txt", body: "old"},
				{name: "app/lower.txt", body: "remove"},
			})
			upper := gzipLayer(t, tt.entries)
			result, err := replayTestLayers(t, []testLayer{
				{digest: "sha256:lower", body: lower},
				{digest: "sha256:upper", body: upper},
			}, ReplayOptions{MaxFileBytes: 1 << 20})
			if err != nil {
				t.Fatalf("Replay() error = %v", err)
			}
			if len(result.FinalFiles) != 1 || result.FinalFiles[0].Path != "app/secret.txt" || string(result.FinalFiles[0].Content) != "new" {
				t.Fatalf("result.FinalFiles = %#v", result.FinalFiles)
			}
			if len(result.DeletedArtifacts) != 2 {
				t.Fatalf("len(result.DeletedArtifacts) = %d", len(result.DeletedArtifacts))
			}
		})
	}
}

func TestReplayHandlesFileDirectoryTransitions(t *testing.T) {
	file := gzipLayer(t, []tarEntry{{name: "app", body: "old"}})
	directory := gzipLayer(t, []tarEntry{
		{name: "app", typeflag: tar.TypeDir},
		{name: "app/config", body: "new"},
	})
	replacement := gzipLayer(t, []tarEntry{{name: "app", body: "final"}})

	result, err := replayTestLayers(t, []testLayer{
		{digest: "sha256:file", body: file},
		{digest: "sha256:directory", body: directory},
		{digest: "sha256:replacement", body: replacement},
	}, ReplayOptions{MaxFileBytes: 1 << 20})
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if len(result.FinalFiles) != 1 || result.FinalFiles[0].Path != "app" || string(result.FinalFiles[0].Content) != "final" {
		t.Fatalf("result.FinalFiles = %#v", result.FinalFiles)
	}
	if len(result.DeletedArtifacts) != 2 {
		t.Fatalf("len(result.DeletedArtifacts) = %d", len(result.DeletedArtifacts))
	}
}

func TestReplayHandlesDeepPathsWithoutRewalkingKnownAncestors(t *testing.T) {
	// 1024 files under a shared 2040-component (4 KiB) prefix. Re-deriving and
	// re-hashing every ancestor for every entry cost ~12 ms per entry, i.e.
	// minutes for a layer within the default entry limits; with the shared
	// prefix recognised once the whole layer takes milliseconds.
	const entries = 1024
	items := make([]tarEntry, 0, entries)
	for index := 0; index < entries; index++ {
		items = append(items, tarEntry{name: strings.Repeat("a/", 2040) + fmt.Sprintf("f%04d", index), body: "x"})
	}
	layer := gzipLayer(t, items)

	start := time.Now()
	result, err := replayTestLayers(t, []testLayer{{digest: "sha256:deep", body: layer}}, ReplayOptions{
		MaxFileBytes:     4096,
		MaxLayerEntries:  50000,
		MaxTotalEntries:  250000,
		MaxRetainedBytes: 1 << 30,
	})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if len(result.FinalFiles) != entries || result.Coverage.FilesScanned != entries {
		t.Fatalf("result = %d files, coverage %#v", len(result.FinalFiles), result.Coverage)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("Replay() of %d deep-path entries took %v", entries, elapsed)
	}
}

func TestReplayHandlesHighCardinalityDirectoryPrefixChurn(t *testing.T) {
	const (
		unrelatedDirectories = 10000
		replacements         = 1000
	)
	layers := directoryPrefixChurnLayers(t, unrelatedDirectories, replacements)

	result, err := replayTestLayers(t, layers, ReplayOptions{
		MaxFileBytes:     1 << 20,
		MaxLayerEntries:  50000,
		MaxTotalEntries:  250000,
		MaxRetainedBytes: 1 << 30,
	})
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if len(result.FinalFiles) != 1 || result.FinalFiles[0].Path != "target" {
		t.Fatalf("result.FinalFiles = %#v", result.FinalFiles)
	}
	if result.Coverage.LayersCompleted != 2 || result.Coverage.FilesSeen != replacements*2 {
		t.Fatalf("result.Coverage = %#v", result.Coverage)
	}
}

func BenchmarkReplayDirectoryPrefixChurn(b *testing.B) {
	layers := directoryPrefixChurnLayers(b, 5000, 500)
	options := ReplayOptions{
		MaxFileBytes:     1 << 20,
		MaxLayerEntries:  50000,
		MaxTotalEntries:  250000,
		MaxRetainedBytes: 1 << 30,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := replayTestLayers(b, layers, options); err != nil {
			b.Fatal(err)
		}
	}
}

func TestReplayRollsBackFailedLayer(t *testing.T) {
	lower := gzipLayer(t, []tarEntry{{name: "app/lower.txt", body: "lower"}})
	upper := gzipLayer(t, []tarEntry{
		{name: "app/first.txt", body: "first"},
		{name: "app/second.txt", body: "second"},
	})

	result, err := replayTestLayers(t, []testLayer{
		{digest: "sha256:lower", body: lower},
		{digest: "sha256:upper", body: upper},
	}, ReplayOptions{MaxFileBytes: 1 << 20, MaxLayerEntries: 1})
	if err == nil {
		t.Fatal("Replay() error = nil")
	}
	if len(result.FinalFiles) != 1 || result.FinalFiles[0].Path != "app/lower.txt" {
		t.Fatalf("result.FinalFiles = %#v", result.FinalFiles)
	}
	if result.Coverage.LayersSeen != 2 || result.Coverage.LayersCompleted != 1 {
		t.Fatalf("result.Coverage = %#v", result.Coverage)
	}
	if result.Coverage.FilesSeen != 2 || result.Coverage.ExpandedBytes == 0 {
		t.Fatalf("failed layer observations were lost: %#v", result.Coverage)
	}
}

func TestReplayEnforcesAggregateLimitsTransactionally(t *testing.T) {
	lower := gzipLayer(t, []tarEntry{{name: "app/lower.txt", body: "lower"}})
	upper := gzipLayer(t, []tarEntry{{name: "app/upper.txt", body: "upper"}})
	layers := []testLayer{
		{digest: "sha256:lower", body: lower},
		{digest: "sha256:upper", body: upper},
	}

	t.Run("entries", func(t *testing.T) {
		result, err := replayTestLayers(t, layers, ReplayOptions{MaxFileBytes: 1 << 20, MaxTotalEntries: 1})
		if err == nil {
			t.Fatal("Replay() error = nil")
		}
		exceeded, ok := limits.AsExceeded(err)
		if !ok || exceeded.Kind != limits.Kind("image_entries") {
			t.Fatalf("err = %v", err)
		}
		if len(result.FinalFiles) != 1 || result.FinalFiles[0].Path != "app/lower.txt" {
			t.Fatalf("result.FinalFiles = %#v", result.FinalFiles)
		}
	})

	t.Run("expanded bytes", func(t *testing.T) {
		one, err := replayTestLayers(t, layers[:1], ReplayOptions{MaxFileBytes: 1 << 20})
		if err != nil {
			t.Fatalf("Replay() baseline error = %v", err)
		}
		result, err := replayTestLayers(t, layers, ReplayOptions{
			MaxFileBytes:  1 << 20,
			MaxTotalBytes: one.Coverage.ExpandedBytes + 1,
		})
		if err == nil {
			t.Fatal("Replay() error = nil")
		}
		exceeded, ok := limits.AsExceeded(err)
		if !ok || exceeded.Kind != limits.Kind("image_layer_bytes") {
			t.Fatalf("err = %v", err)
		}
		if len(result.FinalFiles) != 1 || result.FinalFiles[0].Path != "app/lower.txt" {
			t.Fatalf("result.FinalFiles = %#v", result.FinalFiles)
		}
	})

	t.Run("retained bytes", func(t *testing.T) {
		result, err := replayTestLayers(t, layers[:1], ReplayOptions{MaxFileBytes: 1 << 20, MaxRetainedBytes: 4})
		if err == nil {
			t.Fatal("Replay() error = nil")
		}
		if len(result.FinalFiles) != 0 {
			t.Fatalf("result.FinalFiles = %#v", result.FinalFiles)
		}
	})

	t.Run("retained bytes within one layer", func(t *testing.T) {
		layer := gzipLayer(t, []tarEntry{
			{name: "app/one", body: "123"},
			{name: "app/two", body: "456"},
		})
		maxRetainedBytes := retainedMapStringBytes("app") +
			retainedFinalArtifactBytes(Artifact{Path: "app/one", Content: []byte("123")}) +
			retainedMapStringBytes("app/one")
		result, err := replayTestLayers(t, []testLayer{{digest: "sha256:retained", body: layer}}, ReplayOptions{
			MaxFileBytes:     1 << 20,
			MaxRetainedBytes: maxRetainedBytes,
		})
		if err == nil {
			t.Fatal("Replay() error = nil")
		}
		exceeded, ok := limits.AsExceeded(err)
		if !ok || exceeded.Kind != limits.Kind("retained_bytes") {
			t.Fatalf("err = %v", err)
		}
		if len(result.FinalFiles) != 0 || result.Coverage.RetainedBytes != 0 || result.Coverage.FilesSeen != 2 {
			t.Fatalf("result = %#v", result)
		}
	})
}

func TestReplayReportsCoverageAndCancellation(t *testing.T) {
	layer := gzipLayer(t, []tarEntry{
		{name: "app/text", body: "hello"},
		{name: "app/binary", body: "a\x00b"},
		{name: "app/large", body: "123456"},
	})
	result, err := replayTestLayers(t, []testLayer{{digest: "sha256:coverage", body: layer}}, ReplayOptions{MaxFileBytes: 5})
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	coverage := result.Coverage
	wantRetained := retainedMapStringBytes("app") +
		retainedFinalArtifactBytes(Artifact{Path: "app/text", Content: []byte("hello")}) +
		retainedFinalArtifactBytes(Artifact{Path: "app/binary"}) +
		retainedFinalArtifactBytes(Artifact{Path: "app/large"})
	if coverage.LayersSeen != 1 || coverage.LayersCompleted != 1 || coverage.FilesSeen != 3 || coverage.FilesScanned != 1 || coverage.FilesSkippedOversize != 1 || coverage.FilesExcludedBinary != 1 || coverage.ExpandedBytes <= 0 || coverage.RetainedBytes != wantRetained {
		t.Fatalf("result.Coverage = %#v", coverage)
	}

	ctx, cancel := context.WithCancel(context.Background())
	_, cancelErr := Replay(ctx, []manifest.Descriptor{{Digest: "sha256:cancel", MediaType: manifest.MediaTypeDockerSchema2LayerGzip}}, ReplayOptions{MaxFileBytes: 1 << 20}, OpenFunc(func(context.Context, manifest.Descriptor) (io.ReadCloser, error) {
		cancel()
		return io.NopCloser(bytes.NewReader(layer)), nil
	}))
	if !errors.Is(cancelErr, context.Canceled) {
		t.Fatalf("Replay() error = %v", cancelErr)
	}
}

func TestReplayReportsForeignLayersAsUnsupportedWithoutOpeningBlobs(t *testing.T) {
	regular := gzipLayer(t, []tarEntry{{name: "app/config", body: "clean"}})
	for _, test := range []struct {
		name      string
		mediaType string
	}{
		{name: "docker foreign gzip", mediaType: manifest.MediaTypeDockerSchema2ForeignLayerGzip},
		{name: "docker foreign tar", mediaType: manifest.MediaTypeDockerSchema2ForeignLayer},
		{name: "oci nondistributable zstd", mediaType: manifest.MediaTypeOCIImageLayerNonDistributableZstd},
		{name: "unknown media type", mediaType: "application/octet-stream"},
	} {
		t.Run(test.name, func(t *testing.T) {
			opened := 0
			result, err := Replay(context.Background(), []manifest.Descriptor{
				{Digest: "sha256:regular", MediaType: manifest.MediaTypeDockerSchema2LayerGzip},
				{Digest: "sha256:foreign", MediaType: test.mediaType, URLs: []string{"https://example.invalid/layer"}},
			}, ReplayOptions{MaxFileBytes: 1 << 20}, OpenFunc(func(context.Context, manifest.Descriptor) (io.ReadCloser, error) {
				opened++
				return io.NopCloser(bytes.NewReader(regular)), nil
			}))

			var unsupported *UnsupportedLayerError
			if !errors.As(err, &unsupported) || !IsUnsupportedLayer(err) {
				t.Fatalf("Replay() error = %v", err)
			}
			if unsupported.Digest != "sha256:foreign" || unsupported.MediaType != test.mediaType || unsupported.Index != 1 {
				t.Fatalf("UnsupportedLayerError = %#v", unsupported)
			}
			if limits.IsExceeded(err) || manifest.IsIntegrityError(err) {
				t.Fatalf("unsupported layer was classified as a limit or integrity failure: %v", err)
			}
			if opened != 0 {
				t.Fatalf("opened %d blobs for an unscannable manifest", opened)
			}
			if result.Coverage.LayersSeen != 0 || result.Coverage.LayersCompleted != 0 || len(result.FinalFiles) != 0 {
				t.Fatalf("result = %#v", result)
			}
		})
	}
}

func TestReplayScansOldGNUSparseAndContiguousFiles(t *testing.T) {
	t.Run("gnu sparse", func(t *testing.T) {
		// Written by GNU tar 1.35 with `tar --sparse --format=gnu`: a 2 MiB file
		// whose only data fragment carries a marker in the middle of the hole.
		layer, err := os.ReadFile("testdata/gnu-sparse.tar.gz")
		if err != nil {
			t.Fatalf("ReadFile() error = %v", err)
		}
		gzipReader, err := gzip.NewReader(bytes.NewReader(layer))
		if err != nil {
			t.Fatalf("gzip.NewReader() error = %v", err)
		}
		header, err := tar.NewReader(gzipReader).Next()
		if err != nil {
			t.Fatalf("tar.Next() error = %v", err)
		}
		if header.Typeflag != tar.TypeGNUSparse || header.Name != "sparse.log" || header.Size != 2<<20 {
			t.Fatalf("fixture header = %#v", header)
		}

		result, err := replayTestLayers(t, []testLayer{{digest: "sha256:gnu-sparse", body: layer}}, ReplayOptions{MaxFileBytes: 4 << 20})
		if err != nil {
			t.Fatalf("Replay() error = %v", err)
		}
		files := make(map[string]Artifact)
		for _, artifact := range result.FinalFiles {
			files[artifact.Path] = artifact
		}
		// The sparse entry is a regular file whose logical content is read in
		// full. Its holes are NUL bytes, so content classification excludes it
		// exactly as it would any other regular file with the same bytes; what
		// matters is that the file is seen and counted instead of being hidden
		// as an "other" artifact while coverage claims completeness.
		sparse, ok := files["sparse.log"]
		if !ok || sparse.Type != ArtifactTypeRegularFile || sparse.Size != 2<<20 {
			t.Fatalf("sparse.log artifact = %#v", sparse)
		}
		if sparse.ContentClass != ContentClassBinaryNUL || sparse.Scannable || len(sparse.Content) != 0 {
			t.Fatalf("sparse.log classification = %#v", sparse)
		}
		plain, ok := files["app/plain.txt"]
		if !ok || !plain.Scannable || string(plain.Content) != "plain\n" {
			t.Fatalf("result.FinalFiles = %#v", result.FinalFiles)
		}
		coverage := result.Coverage
		if coverage.LayersCompleted != 1 || coverage.FilesSeen != 2 || coverage.FilesScanned != 1 || coverage.FilesExcludedBinary != 1 || coverage.EntriesSkippedUnsafe != 0 || coverage.ExpandedBytes < 2<<20 {
			t.Fatalf("result.Coverage = %#v", coverage)
		}
	})

	t.Run("gnu contiguous", func(t *testing.T) {
		layer := gzipLayer(t, []tarEntry{{name: "app/contiguous", body: "contiguous-body", typeflag: tar.TypeCont}})
		result, err := replayTestLayers(t, []testLayer{{digest: "sha256:contiguous", body: layer}}, ReplayOptions{MaxFileBytes: 1 << 20})
		if err != nil {
			t.Fatalf("Replay() error = %v", err)
		}
		if len(result.FinalFiles) != 1 || result.FinalFiles[0].Path != "app/contiguous" || string(result.FinalFiles[0].Content) != "contiguous-body" || !result.FinalFiles[0].Scannable {
			t.Fatalf("result.FinalFiles = %#v", result.FinalFiles)
		}
		if result.Coverage.FilesSeen != 1 || result.Coverage.FilesScanned != 1 {
			t.Fatalf("result.Coverage = %#v", result.Coverage)
		}
	})
}

func TestReplayIgnoresRootDirectoryEntries(t *testing.T) {
	entries := []tarEntry{
		{name: "./", typeflag: tar.TypeDir},
		{name: "./app/", typeflag: tar.TypeDir},
		{name: "./app/safe", body: "safe"},
		{name: ".", typeflag: tar.TypeDir},
	}
	layer := gzipLayer(t, entries)
	result, err := replayTestLayers(t, []testLayer{{digest: "sha256:root", body: layer}}, ReplayOptions{MaxFileBytes: 1 << 20})
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if result.Coverage.EntriesSkippedUnsafe != 0 {
		t.Fatalf("root directory entries were counted as unsafe: %#v", result.Coverage)
	}
	if len(result.FinalFiles) != 1 || result.FinalFiles[0].Path != "app/safe" {
		t.Fatalf("result.FinalFiles = %#v", result.FinalFiles)
	}

	// Root entries still count against the entry limits, as container runtimes count them.
	if _, err := replayTestLayers(t, []testLayer{{digest: "sha256:root", body: layer}}, ReplayOptions{MaxFileBytes: 1 << 20, MaxLayerEntries: len(entries)}); err != nil {
		t.Fatalf("Replay(MaxLayerEntries=%d) error = %v", len(entries), err)
	}
	_, err = replayTestLayers(t, []testLayer{{digest: "sha256:root", body: layer}}, ReplayOptions{MaxFileBytes: 1 << 20, MaxLayerEntries: len(entries) - 1})
	if exceeded, ok := limits.AsExceeded(err); !ok || exceeded.Kind != limits.KindLayerEntries {
		t.Fatalf("Replay(MaxLayerEntries=%d) error = %v", len(entries)-1, err)
	}
}

func TestReplayCapsZstdWindowIndependentlyOfLayerLimits(t *testing.T) {
	// A valid frame header declaring a 512 MiB window (descriptor 0x98)
	// followed by an empty final raw block. With the documented production
	// default LAYERLEAK_MAX_LAYER_BYTES the decoder used to allocate 513 MiB of
	// history for these ten bytes before noticing the stream was empty.
	frame := []byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x98, 0x09, 0x00, 0x00, 0x78}
	opener := OpenFunc(func(context.Context, manifest.Descriptor) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(frame)), nil
	})
	for _, test := range []struct {
		name          string
		maxLayerBytes int64
	}{
		{name: "production default", maxLayerBytes: 512 << 20},
		{name: "above the window maximum", maxLayerBytes: 4 << 30},
		{name: "disabled", maxLayerBytes: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime.GC()
			var before runtime.MemStats
			runtime.ReadMemStats(&before)
			_, err := Replay(context.Background(), []manifest.Descriptor{{Digest: "sha256:zstd-window", MediaType: manifest.MediaTypeOCIImageLayerZstd}}, ReplayOptions{
				MaxFileBytes:  1 << 20,
				MaxLayerBytes: test.maxLayerBytes,
			}, opener)
			var after runtime.MemStats
			runtime.ReadMemStats(&after)
			if !errors.Is(err, zstd.ErrWindowSizeExceeded) && !errors.Is(err, zstd.ErrDecoderSizeExceeded) {
				t.Fatalf("Replay() error = %v", err)
			}
			if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 16<<20 {
				t.Fatalf("Replay() allocated %d bytes while rejecting the zstd window", allocated)
			}
		})
	}
}

func TestReplayHonoursCancellationWhileDrainingSparseHoles(t *testing.T) {
	// With both byte limits disabled nothing bounds a sparse hole except the
	// caller's context. archive/tar synthesises hole bytes without touching
	// the compressed stream, so the per-entry reader must observe ctx itself.
	layer := gzipSparseLayer(t, "app/sparse", 512<<30)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	_, err := Replay(ctx, []manifest.Descriptor{{Digest: "sha256:sparse-cancel", MediaType: manifest.MediaTypeDockerSchema2LayerGzip}}, ReplayOptions{
		MaxFileBytes:  1 << 20,
		MaxLayerBytes: 0,
		MaxTotalBytes: 0,
	}, OpenFunc(func(context.Context, manifest.Descriptor) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(layer)), nil
	}))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Replay() error = %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Replay() took %v to observe cancellation inside a sparse hole", elapsed)
	}
}

func TestReplaySkipsPAXGlobalHeadersWithoutMaterializingThem(t *testing.T) {
	lower := gzipLayer(t, []tarEntry{{name: "pax_global_header", body: "real file"}})
	upper := gzipLayer(t, []tarEntry{
		{name: "pax_global_header", typeflag: tar.TypeXGlobalHeader, paxRecords: map[string]string{"comment": "generated"}},
		{name: "app/x", body: "x"},
	})

	// MaxLayerEntries 1 proves the metadata record does not consume entry budget.
	result, err := replayTestLayers(t, []testLayer{
		{digest: "sha256:lower", body: lower},
		{digest: "sha256:upper", body: upper},
	}, ReplayOptions{MaxFileBytes: 1 << 20, MaxLayerEntries: 1})
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if len(result.FinalFiles) != 2 || result.FinalFiles[0].Path != "app/x" || result.FinalFiles[1].Path != "pax_global_header" {
		t.Fatalf("result.FinalFiles = %#v", result.FinalFiles)
	}
	if result.FinalFiles[1].Type != ArtifactTypeRegularFile || string(result.FinalFiles[1].Content) != "real file" || result.FinalFiles[1].LayerDigest != "sha256:lower" {
		t.Fatalf("pax_global_header artifact = %#v", result.FinalFiles[1])
	}
	if len(result.DeletedArtifacts) != 0 {
		t.Fatalf("result.DeletedArtifacts = %#v", result.DeletedArtifacts)
	}
	if result.Coverage.FilesSeen != 2 || result.Coverage.EntriesSkippedUnsafe != 0 {
		t.Fatalf("result.Coverage = %#v", result.Coverage)
	}
}

func TestReplayClassifiesTrailingDataAfterCompressedStream(t *testing.T) {
	base := gzipLayer(t, []tarEntry{{name: "app/a", body: "a"}})
	second := gzipLayer(t, []tarEntry{{name: "app/b", body: "b"}})

	t.Run("concatenated gzip members", func(t *testing.T) {
		// One tar stream compressed as two gzip members (as parallel gzip
		// implementations emit); the multistream reader must join them.
		archive := tarArchive(t, []tarEntry{{name: "app/a", body: "a"}, {name: "app/b", body: "b"}})
		split := len(archive) / 2
		layer := append(gzipBytes(t, archive[:split]), gzipBytes(t, archive[split:])...)
		result, err := replayTestLayers(t, []testLayer{{digest: "sha256:members", body: layer}}, ReplayOptions{MaxFileBytes: 1 << 20})
		if err != nil {
			t.Fatalf("Replay() error = %v", err)
		}
		if len(result.FinalFiles) != 2 || result.Coverage.LayersCompleted != 1 {
			t.Fatalf("result = %#v", result)
		}
	})

	for _, test := range []struct {
		name   string
		suffix []byte
	}{
		{name: "trailing zeros", suffix: make([]byte, 512)},
		{name: "trailing garbage", suffix: []byte("trailing-garbage")},
		{name: "short trailing fragment", suffix: []byte{0x1f}},
	} {
		t.Run(test.name, func(t *testing.T) {
			layer := append(append([]byte(nil), base...), test.suffix...)
			result, err := replayTestLayers(t, []testLayer{{digest: "sha256:trailing", body: layer}}, ReplayOptions{MaxFileBytes: 1 << 20})
			var trailing *TrailingDataError
			if !errors.As(err, &trailing) || !IsTrailingData(err) || trailing.Digest != "sha256:trailing" {
				t.Fatalf("Replay() error = %v", err)
			}
			if limits.IsExceeded(err) {
				t.Fatalf("trailing data classified as a limit failure: %v", err)
			}
			if len(result.FinalFiles) != 0 || result.Coverage.LayersCompleted != 0 {
				t.Fatalf("result = %#v", result)
			}
		})
	}

	t.Run("zstd trailing garbage", func(t *testing.T) {
		layer := append(zstdLayer(t, []tarEntry{{name: "app/z", body: "z"}}), []byte("trailing-garbage")...)
		_, err := Replay(context.Background(), []manifest.Descriptor{{Digest: "sha256:zstd-trailing", MediaType: manifest.MediaTypeOCIImageLayerZstd}}, ReplayOptions{MaxFileBytes: 1 << 20}, OpenFunc(func(context.Context, manifest.Descriptor) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(layer)), nil
		}))
		if !IsTrailingData(err) {
			t.Fatalf("Replay() error = %v", err)
		}
	})

	t.Run("corrupt gzip checksum is not trailing data", func(t *testing.T) {
		layer := append([]byte(nil), base...)
		layer[len(layer)-8] ^= 0xff // CRC-32 of the single member
		_, err := replayTestLayers(t, []testLayer{{digest: "sha256:checksum", body: layer}}, ReplayOptions{MaxFileBytes: 1 << 20})
		if err == nil || IsTrailingData(err) || !errors.Is(err, gzip.ErrChecksum) {
			t.Fatalf("Replay() error = %v", err)
		}
	})

	t.Run("layer byte limit during drain stays a limit error", func(t *testing.T) {
		layer := append(append([]byte(nil), base...), second...)
		_, err := replayTestLayers(t, []testLayer{{digest: "sha256:members", body: layer}}, ReplayOptions{MaxFileBytes: 1 << 20, MaxLayerBytes: 2048})
		if !limits.IsExceeded(err) || IsTrailingData(err) {
			t.Fatalf("Replay() error = %v", err)
		}
	})
}

func TestReplayHardlinksToNonFilesDoNotCountAsFiles(t *testing.T) {
	layer := gzipLayer(t, []tarEntry{
		{name: "link", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"},
		{name: "hl", typeflag: tar.TypeLink, linkname: "link"},
		{name: "d", typeflag: tar.TypeDir},
		{name: "hld", typeflag: tar.TypeLink, linkname: "d"},
		{name: "hlroot", typeflag: tar.TypeLink, linkname: "."},
		{name: "file", body: "data"},
		{name: "hlf", typeflag: tar.TypeLink, linkname: "file"},
	})
	result, err := replayTestLayers(t, []testLayer{{digest: "sha256:hardlinks", body: layer}}, ReplayOptions{MaxFileBytes: 1 << 20})
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if len(result.FinalFiles) != 2 || result.FinalFiles[0].Path != "file" || result.FinalFiles[1].Path != "hlf" {
		t.Fatalf("result.FinalFiles = %#v", result.FinalFiles)
	}
	if result.FinalFiles[1].Type != ArtifactTypeHardlink || string(result.FinalFiles[1].Content) != "data" {
		t.Fatalf("hardlink artifact = %#v", result.FinalFiles[1])
	}
	coverage := result.Coverage
	if coverage.FilesSeen != 2 || coverage.FilesScanned != 2 || coverage.FilesExcludedBinary != 0 || coverage.FilesSkippedOversize != 0 || coverage.EntriesSkippedUnsafe != 0 {
		t.Fatalf("result.Coverage = %#v", coverage)
	}
}

func TestReplayArchiveEntryFixtures(t *testing.T) {
	paths := func(items []Artifact) []string {
		result := make([]string, 0, len(items))
		for _, item := range items {
			result = append(result, item.Path)
		}
		return result
	}
	tests := []struct {
		name    string
		layers  [][]byte
		options ReplayOptions
		check   func(t *testing.T, result ReplayResult)
	}{
		{
			name: "device and fifo entries replaced by a regular file",
			layers: [][]byte{
				gzipLayer(t, []tarEntry{
					{name: "dev/console", typeflag: tar.TypeChar},
					{name: "dev/fifo", typeflag: tar.TypeFifo},
					{name: "dev/disk", typeflag: tar.TypeBlock},
				}),
				gzipLayer(t, []tarEntry{{name: "dev/console", body: "now a file"}}),
			},
			check: func(t *testing.T, result ReplayResult) {
				if got := paths(result.FinalFiles); strings.Join(got, ",") != "dev/console" {
					t.Fatalf("FinalFiles = %v", got)
				}
				if len(result.DeletedArtifacts) != 0 || result.Coverage.FilesSeen != 1 || result.Coverage.EntriesSkippedUnsafe != 0 {
					t.Fatalf("result = %#v", result)
				}
			},
		},
		{
			name: "symlinked directory does not write through",
			layers: [][]byte{
				gzipLayer(t, []tarEntry{{name: "app", typeflag: tar.TypeSymlink, linkname: "/etc"}}),
				gzipLayer(t, []tarEntry{{name: "app/secret", body: "value"}}),
			},
			check: func(t *testing.T, result ReplayResult) {
				if got := paths(result.FinalFiles); strings.Join(got, ",") != "app/secret" {
					t.Fatalf("FinalFiles = %v", got)
				}
				if len(result.DeletedArtifacts) != 0 {
					t.Fatalf("DeletedArtifacts = %#v", result.DeletedArtifacts)
				}
			},
		},
		{
			name: "whiteout of a symlink",
			layers: [][]byte{
				gzipLayer(t, []tarEntry{{name: "link", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"}}),
				gzipLayer(t, []tarEntry{{name: ".wh.link"}}),
			},
			check: func(t *testing.T, result ReplayResult) {
				if len(result.FinalFiles) != 0 || len(result.DeletedArtifacts) != 0 || result.Coverage.EntriesSkippedUnsafe != 0 {
					t.Fatalf("result = %#v", result)
				}
			},
		},
		{
			name: "opaque whiteout at the archive root",
			layers: [][]byte{
				gzipLayer(t, []tarEntry{{name: "a", body: "a"}, {name: "d/b", body: "b"}}),
				gzipLayer(t, []tarEntry{{name: ".wh..wh..opq"}, {name: "c", body: "c"}}),
			},
			check: func(t *testing.T, result ReplayResult) {
				if got := paths(result.FinalFiles); strings.Join(got, ",") != "c" {
					t.Fatalf("FinalFiles = %v", got)
				}
				if got := paths(result.DeletedArtifacts); strings.Join(got, ",") != "a,d/b" {
					t.Fatalf("DeletedArtifacts = %v", got)
				}
			},
		},
		{
			name: "max file bytes boundary",
			layers: [][]byte{gzipLayer(t, []tarEntry{
				{name: "exact", body: "1234"},
				{name: "over", body: "12345"},
			})},
			options: ReplayOptions{MaxFileBytes: 4},
			check: func(t *testing.T, result ReplayResult) {
				classes := map[string]Artifact{}
				for _, item := range result.FinalFiles {
					classes[item.Path] = item
				}
				if exact := classes["exact"]; !exact.Scannable || exact.ContentClass != ContentClassText || string(exact.Content) != "1234" {
					t.Fatalf("exact = %#v", exact)
				}
				if over := classes["over"]; over.Scannable || over.ContentClass != ContentClassOversize || len(over.Content) != 0 || over.Size != 5 {
					t.Fatalf("over = %#v", over)
				}
				if result.Coverage.FilesSkippedOversize != 1 || result.Coverage.FilesScanned != 1 {
					t.Fatalf("Coverage = %#v", result.Coverage)
				}
			},
		},
		{
			name: "crlf and latin-1 bodies stay text",
			layers: [][]byte{gzipLayer(t, []tarEntry{
				{name: "crlf.txt", body: "first line\r\nsecond line\r\n"},
				{name: "latin1.txt", body: "caf\xe9 au lait, cr\xe8me br\xfbl\xe9e\n"},
			})},
			check: func(t *testing.T, result ReplayResult) {
				for _, item := range result.FinalFiles {
					if item.ContentClass != ContentClassText || !item.Scannable {
						t.Fatalf("%s = %#v", item.Path, item)
					}
				}
				if result.Coverage.FilesScanned != 2 {
					t.Fatalf("Coverage = %#v", result.Coverage)
				}
			},
		},
		{
			name: "archive truncated at a block boundary is a clean end",
			layers: [][]byte{func() []byte {
				archive := tarArchive(t, []tarEntry{{name: "app/last", body: "value"}})
				return gzipBytes(t, archive[:len(archive)-1024]) // drop the end-of-archive marker
			}()},
			check: func(t *testing.T, result ReplayResult) {
				if got := paths(result.FinalFiles); strings.Join(got, ",") != "app/last" {
					t.Fatalf("FinalFiles = %v", got)
				}
				if result.Coverage.LayersCompleted != 1 {
					t.Fatalf("Coverage = %#v", result.Coverage)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			layers := make([]testLayer, 0, len(test.layers))
			for index, body := range test.layers {
				layers = append(layers, testLayer{digest: fmt.Sprintf("sha256:fixture-%d", index), body: body})
			}
			options := test.options
			if options.MaxFileBytes == 0 {
				options.MaxFileBytes = 1 << 20
			}
			result, err := replayTestLayers(t, layers, options)
			if err != nil {
				t.Fatalf("Replay() error = %v", err)
			}
			test.check(t, result)
		})
	}
}

func TestReplaySupportsZstdSkippableAndMultipleFrames(t *testing.T) {
	archive := tarArchive(t, []tarEntry{{name: "app/a", body: "a"}, {name: "app/b", body: "b"}})
	split := len(archive) / 2
	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatalf("zstd.NewWriter() error = %v", err)
	}
	defer func() { _ = encoder.Close() }()
	// Skippable frame: magic 0x184D2A50, 4-byte little-endian size, payload.
	layer := []byte{0x50, 0x2a, 0x4d, 0x18, 0x04, 0x00, 0x00, 0x00, 'm', 'e', 't', 'a'}
	layer = encoder.EncodeAll(archive[:split], layer)
	layer = encoder.EncodeAll(archive[split:], layer)

	result, err := Replay(context.Background(), []manifest.Descriptor{{Digest: "sha256:zstd-frames", MediaType: manifest.MediaTypeOCIImageLayerZstd}}, ReplayOptions{MaxFileBytes: 1 << 20}, OpenFunc(func(context.Context, manifest.Descriptor) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(layer)), nil
	}))
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if len(result.FinalFiles) != 2 || result.FinalFiles[0].Path != "app/a" || result.FinalFiles[1].Path != "app/b" {
		t.Fatalf("result.FinalFiles = %#v", result.FinalFiles)
	}
}

func TestReplayRepeatedLayerDigestIsDeterministic(t *testing.T) {
	layerA := gzipLayer(t, []tarEntry{{name: "shared", body: "from-a"}, {name: "only-a", body: "a"}})
	layerB := gzipLayer(t, []tarEntry{{name: ".wh.shared"}, {name: "only-b", body: "b"}})
	run := func() (ReplayResult, int) {
		opened := 0
		result, err := Replay(context.Background(), []manifest.Descriptor{
			{Digest: "sha256:a", MediaType: manifest.MediaTypeDockerSchema2LayerGzip},
			{Digest: "sha256:b", MediaType: manifest.MediaTypeDockerSchema2LayerGzip},
			{Digest: "sha256:a", MediaType: manifest.MediaTypeDockerSchema2LayerGzip},
		}, ReplayOptions{MaxFileBytes: 1 << 20}, OpenFunc(func(_ context.Context, descriptor manifest.Descriptor) (io.ReadCloser, error) {
			opened++
			if descriptor.Digest == "sha256:a" {
				return io.NopCloser(bytes.NewReader(layerA)), nil
			}
			return io.NopCloser(bytes.NewReader(layerB)), nil
		}))
		if err != nil {
			t.Fatalf("Replay() error = %v", err)
		}
		return result, opened
	}
	first, opened := run()
	second, _ := run()
	if opened != 3 {
		t.Fatalf("opened %d layers, want 3", opened)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("repeated digests replayed non-deterministically:\n%#v\n%#v", first, second)
	}
	final := map[string]Artifact{}
	for _, item := range first.FinalFiles {
		final[item.Path] = item
	}
	if len(final) != 3 || string(final["shared"].Content) != "from-a" || final["shared"].LayerDigest != "sha256:a" {
		t.Fatalf("first.FinalFiles = %#v", first.FinalFiles)
	}
	if len(first.DeletedArtifacts) != 2 {
		t.Fatalf("first.DeletedArtifacts = %#v", first.DeletedArtifacts)
	}
	if first.Coverage.LayersSeen != 3 || first.Coverage.LayersCompleted != 3 {
		t.Fatalf("first.Coverage = %#v", first.Coverage)
	}
}

// recomputedRetainedBytes derives the retention total from the state's
// contents so the fuzz target can check the incremental accounting.
func recomputedRetainedBytes(state *State) int64 {
	var total int64
	for _, artifact := range state.final {
		total += retainedFinalArtifactBytes(artifact)
	}
	for _, artifact := range state.deleted {
		total += retainedDeletedArtifactBytes(artifact)
	}
	for directory := range state.dirs {
		total += retainedMapStringBytes(directory)
	}
	return total
}

// FuzzApplyLayer feeds arbitrary bytes to the tar replay as an uncompressed
// layer on top of a fixed base layer and checks the engine's invariants: no
// panic, retained-byte accounting matches the recorded state, a failed layer
// leaves the base state untouched, layer counters stay ordered and the result
// is deterministic. Run it longer with
// `go test -run=^$ -fuzz=FuzzApplyLayer -fuzztime=60s ./internal/layers`.
func FuzzApplyLayer(f *testing.F) {
	seeds := [][]byte{
		tarArchive(f, []tarEntry{
			{name: "app/.env", body: "TOKEN=aaaaaaaaaaaaaaaaaaaaaaaa"},
			{name: "app/dir", typeflag: tar.TypeDir},
			{name: "app/link", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"},
			{name: "app/hard", typeflag: tar.TypeLink, linkname: "app/.env"},
			{name: "base/.wh.keep"},
			{name: "base/.wh..wh..opq"},
			{name: "dev/null", typeflag: tar.TypeChar},
		}),
		tarArchive(f, []tarEntry{{name: "./", typeflag: tar.TypeDir}, {name: "./base", body: "replaced"}, {name: "."}}),
		tarArchive(f, []tarEntry{{name: "meta", typeflag: tar.TypeXGlobalHeader, paxRecords: map[string]string{"comment": "x"}}, {name: "app/x", body: "x"}}),
		tarArchive(f, []tarEntry{{name: strings.Repeat("p", maxArchivePathBytes+1)}, {name: "../escape", body: "escape"}}),
		sparseArchive(f, "app/sparse", 64<<10),
		append(tarArchive(f, []tarEntry{{name: "app/trailing", body: "x"}}), []byte("trailing")...),
		tarArchive(f, []tarEntry{{name: "app/last", body: "value"}})[:1024],
		{},
		[]byte("not a tar archive at all"),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	base := tarArchive(f, []tarEntry{
		{name: "base/keep", body: "keep"},
		{name: "base/replaced", body: "old"},
		{name: "base/dir", typeflag: tar.TypeDir},
		{name: "base", body: "file-then-dir"},
	})
	options := ReplayOptions{
		MaxFileBytes:     4096,
		MaxLayerBytes:    1 << 20,
		MaxLayerEntries:  256,
		MaxTotalBytes:    2 << 20,
		MaxTotalEntries:  512,
		MaxRetainedBytes: 1 << 20,
	}
	baseDescriptor := manifest.Descriptor{Digest: "sha256:base", MediaType: manifest.MediaTypeOCIImageLayer}
	fuzzDescriptor := manifest.Descriptor{Digest: "sha256:fuzz", MediaType: manifest.MediaTypeOCIImageLayer}

	f.Fuzz(func(t *testing.T, layer []byte) {
		// Mirror Replay's per-layer bookkeeping so the counters are meaningful.
		apply := func(state *State, descriptor manifest.Descriptor, body []byte) error {
			state.coverage.LayersSeen++
			err := state.applyLayer(context.Background(), descriptor, bytes.NewReader(body), options)
			if err == nil {
				state.coverage.LayersCompleted++
			}
			return err
		}
		run := func() (snapshot, result ReplayResult, recomputed int64, err error) {
			state := NewState()
			if err := apply(state, baseDescriptor, base); err != nil {
				t.Fatalf("base applyLayer() error = %v", err)
			}
			snapshot = state.Result()
			err = apply(state, fuzzDescriptor, layer)
			return snapshot, state.Result(), recomputedRetainedBytes(state), err
		}
		snapshot, result, recomputed, err := run()
		_, again, _, errAgain := run()

		if !reflect.DeepEqual(result, again) || (err == nil) != (errAgain == nil) || (err != nil && err.Error() != errAgain.Error()) {
			t.Fatalf("non-deterministic replay: %v vs %v", err, errAgain)
		}
		coverage := result.Coverage
		if coverage.RetainedBytes < 0 || coverage.RetainedBytes != recomputed {
			t.Fatalf("RetainedBytes = %d, recomputed %d", coverage.RetainedBytes, recomputed)
		}
		if coverage.LayersCompleted > coverage.LayersSeen || coverage.LayersSeen != 2 {
			t.Fatalf("LayersCompleted %d, LayersSeen %d", coverage.LayersCompleted, coverage.LayersSeen)
		}
		if coverage.ExpandedBytes < snapshot.Coverage.ExpandedBytes {
			t.Fatalf("ExpandedBytes decreased from %d to %d", snapshot.Coverage.ExpandedBytes, coverage.ExpandedBytes)
		}
		if err != nil {
			if !reflect.DeepEqual(result.FinalFiles, snapshot.FinalFiles) || !reflect.DeepEqual(result.DeletedArtifacts, snapshot.DeletedArtifacts) {
				t.Fatalf("failed layer leaked state: %v", err)
			}
			if coverage.RetainedBytes != snapshot.Coverage.RetainedBytes {
				t.Fatalf("failed layer changed RetainedBytes from %d to %d", snapshot.Coverage.RetainedBytes, coverage.RetainedBytes)
			}
			return
		}
		for _, artifact := range result.FinalFiles {
			if artifact.Type != ArtifactTypeRegularFile && artifact.Type != ArtifactTypeHardlink {
				t.Fatalf("FinalFiles contains %s artifact %q", artifact.Type, artifact.Path)
			}
			if artifact.Scannable && artifact.ContentClass != ContentClassText {
				t.Fatalf("scannable artifact %q has class %q", artifact.Path, artifact.ContentClass)
			}
			if int64(len(artifact.Content)) > options.MaxFileBytes {
				t.Fatalf("artifact %q retained %d bytes above MaxFileBytes", artifact.Path, len(artifact.Content))
			}
			if _, err := normalizePath(artifact.Path); err != nil || artifact.Path != strings.Trim(artifact.Path, "/") {
				t.Fatalf("artifact path %q is not normalised: %v", artifact.Path, err)
			}
		}
	})
}

func TestReplaySkipsUnsafeArchivePathsAndReportsIncompleteCoverage(t *testing.T) {
	layer := gzipLayer(t, []tarEntry{
		{name: "../../etc/passwd", body: "escape"},
		{name: "/absolute", body: "absolute"},
		{name: `windows\secret`, body: "windows"},
		{name: "app/.wh.", body: "invalid whiteout"},
		{name: "app/safe", body: "safe"},
	})
	result, err := replayTestLayers(t, []testLayer{{digest: "sha256:unsafe", body: layer}}, ReplayOptions{MaxFileBytes: 1 << 20})
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if len(result.FinalFiles) != 1 || result.FinalFiles[0].Path != "app/safe" {
		t.Fatalf("result.FinalFiles = %#v", result.FinalFiles)
	}
	if result.Coverage.EntriesSkippedUnsafe != 4 {
		t.Fatalf("result.Coverage = %#v", result.Coverage)
	}
	for _, value := range []string{"../../etc/passwd", "/etc/passwd", `dir\file`, "a/../b"} {
		if _, err := normalizePath(value); err == nil {
			t.Fatalf("normalizePath(%q) error = nil", value)
		}
	}
}

type testLayer struct {
	digest string
	body   []byte
}

func replayTestLayers(t testing.TB, testLayers []testLayer, options ReplayOptions) (ReplayResult, error) {
	t.Helper()
	descriptors := make([]manifest.Descriptor, 0, len(testLayers))
	bodies := make(map[string][]byte, len(testLayers))
	for _, layer := range testLayers {
		descriptors = append(descriptors, manifest.Descriptor{Digest: layer.digest, MediaType: manifest.MediaTypeDockerSchema2LayerGzip})
		bodies[layer.digest] = layer.body
	}
	return Replay(context.Background(), descriptors, options, OpenFunc(func(_ context.Context, descriptor manifest.Descriptor) (io.ReadCloser, error) {
		body, ok := bodies[descriptor.Digest]
		if !ok {
			return nil, io.EOF
		}
		return io.NopCloser(bytes.NewReader(body)), nil
	}))
}

func directoryPrefixChurnLayers(t testing.TB, unrelatedDirectories, replacements int) []testLayer {
	t.Helper()
	baseEntries := make([]tarEntry, 0, unrelatedDirectories)
	for index := 0; index < unrelatedDirectories; index++ {
		baseEntries = append(baseEntries, tarEntry{
			name:     fmt.Sprintf("unrelated-%05d", index),
			typeflag: tar.TypeDir,
		})
	}
	churnEntries := make([]tarEntry, 0, replacements*2)
	for range replacements {
		churnEntries = append(churnEntries,
			tarEntry{name: "target/child"},
			tarEntry{name: "target"},
		)
	}
	return []testLayer{
		{digest: "sha256:directory-base", body: gzipLayer(t, baseEntries)},
		{digest: "sha256:directory-churn", body: gzipLayer(t, churnEntries)},
	}
}

type tarEntry struct {
	name       string
	body       string
	typeflag   byte
	linkname   string
	format     tar.Format
	paxRecords map[string]string
}

func gzipLayer(t testing.TB, entries []tarEntry) []byte {
	t.Helper()
	return gzipBytes(t, tarArchive(t, entries))
}

func gzipBytes(t testing.TB, archive []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&buffer)
	if _, err := gzipWriter.Write(archive); err != nil {
		t.Fatalf("gzipWriter.Write() error = %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("gzipWriter.Close() error = %v", err)
	}
	return buffer.Bytes()
}

func tarArchive(t testing.TB, entries []tarEntry) []byte {
	t.Helper()

	var buffer bytes.Buffer
	tarWriter := tar.NewWriter(&buffer)
	for _, entry := range entries {
		typeflag := entry.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		header := &tar.Header{
			Name:     entry.name,
			Mode:     0600,
			Size:     int64(len(entry.body)),
			Typeflag: typeflag,
			Linkname: entry.linkname,
			Format:   entry.format,
		}
		if typeflag == tar.TypeXGlobalHeader {
			// archive/tar only accepts Name, Typeflag, PAXRecords and Format here.
			header = &tar.Header{Name: entry.name, Typeflag: typeflag, PAXRecords: entry.paxRecords, Format: tar.FormatPAX}
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatalf("WriteHeader() error = %v", err)
		}
		if typeflag == tar.TypeReg || typeflag == legacyTypeRegA || typeflag == tar.TypeCont {
			if _, err := tarWriter.Write([]byte(entry.body)); err != nil {
				t.Fatalf("Write() error = %v", err)
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatalf("tarWriter.Close() error = %v", err)
	}
	return buffer.Bytes()
}

func gzipSparseLayer(t testing.TB, name string, logicalSize int64) []byte {
	t.Helper()
	return gzipBytes(t, sparseArchive(t, name, logicalSize))
}

// sparseArchive writes a PAX sparse entry whose only data fragment is the last
// byte of a logicalSize-byte file; everything before it is a hole.
func sparseArchive(t testing.TB, name string, logicalSize int64) []byte {
	t.Helper()

	var tarBuffer bytes.Buffer
	tarWriter := tar.NewWriter(&tarBuffer)
	header := &tar.Header{
		Name:     name,
		Mode:     0600,
		Size:     1,
		Typeflag: tar.TypeReg,
		Format:   tar.FormatPAX,
		PAXRecords: map[string]string{
			"TST.sparse.map":       fmt.Sprintf("%d,1", logicalSize-1),
			"TST.sparse.numblocks": "1",
			"TST.sparse.size":      fmt.Sprint(logicalSize),
		},
	}
	if err := tarWriter.WriteHeader(header); err != nil {
		t.Fatalf("WriteHeader() error = %v", err)
	}
	if _, err := tarWriter.Write([]byte{'x'}); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatalf("tarWriter.Close() error = %v", err)
	}

	archive := bytes.ReplaceAll(tarBuffer.Bytes(), []byte("TST.sparse."), []byte("GNU.sparse."))
	if bytes.Contains(archive, []byte("TST.sparse.")) {
		t.Fatal("failed to rewrite sparse PAX records")
	}
	return archive
}

func zstdLayer(t *testing.T, entries []tarEntry) []byte {
	t.Helper()

	var tarBuffer bytes.Buffer
	tarWriter := tar.NewWriter(&tarBuffer)
	for _, entry := range entries {
		header := &tar.Header{
			Name:     entry.name,
			Mode:     0600,
			Size:     int64(len(entry.body)),
			Typeflag: tar.TypeReg,
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatalf("WriteHeader() error = %v", err)
		}
		if _, err := tarWriter.Write([]byte(entry.body)); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatalf("tarWriter.Close() error = %v", err)
	}

	var buffer bytes.Buffer
	encoder, err := zstd.NewWriter(&buffer)
	if err != nil {
		t.Fatalf("zstd.NewWriter() error = %v", err)
	}
	if _, err := encoder.Write(tarBuffer.Bytes()); err != nil {
		t.Fatalf("encoder.Write() error = %v", err)
	}
	if err := encoder.Close(); err != nil {
		t.Fatalf("encoder.Close() error = %v", err)
	}
	return buffer.Bytes()
}
