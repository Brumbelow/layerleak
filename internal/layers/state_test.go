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
	"runtime"
	"strings"
	"testing"

	"github.com/brumbelow/layerleak/internal/limits"
	"github.com/brumbelow/layerleak/internal/manifest"
	"github.com/klauspost/compress/zstd"
)

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
	name     string
	body     string
	typeflag byte
	linkname string
	format   tar.Format
}

func gzipLayer(t testing.TB, entries []tarEntry) []byte {
	t.Helper()

	var buffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gzipWriter)
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
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatalf("WriteHeader() error = %v", err)
		}
		if typeflag == tar.TypeReg || typeflag == tar.TypeRegA {
			if _, err := tarWriter.Write([]byte(entry.body)); err != nil {
				t.Fatalf("Write() error = %v", err)
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatalf("tarWriter.Close() error = %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("gzipWriter.Close() error = %v", err)
	}
	return buffer.Bytes()
}

func gzipSparseLayer(t testing.TB, name string, logicalSize int64) []byte {
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
	encoder.Close()
	return buffer.Bytes()
}
