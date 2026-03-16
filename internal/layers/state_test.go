package layers

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"testing"

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
	}, 1<<20, OpenFunc(func(ctx context.Context, descriptor manifest.Descriptor) (io.ReadCloser, error) {
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
	}, 1<<20, OpenFunc(func(ctx context.Context, descriptor manifest.Descriptor) (io.ReadCloser, error) {
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

	if len(result.FinalFiles) != 1 {
		t.Fatalf("len(result.FinalFiles) = %d", len(result.FinalFiles))
	}

	if result.FinalFiles[0].Path != "app/final.txt" {
		t.Fatalf("result.FinalFiles[0].Path = %q", result.FinalFiles[0].Path)
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
	}, 1<<20, OpenFunc(func(ctx context.Context, descriptor manifest.Descriptor) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(layer)), nil
	}))
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}

	if len(result.FinalFiles) != 1 {
		t.Fatalf("len(result.FinalFiles) = %d", len(result.FinalFiles))
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
	}, 1<<20, OpenFunc(func(ctx context.Context, descriptor manifest.Descriptor) (io.ReadCloser, error) {
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

type tarEntry struct {
	name     string
	body     string
	typeflag byte
	linkname string
}

func gzipLayer(t *testing.T, entries []tarEntry) []byte {
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
