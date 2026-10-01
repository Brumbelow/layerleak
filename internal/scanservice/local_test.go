package scanservice

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brumbelow/layerleak/v3/internal/config"
	"github.com/brumbelow/layerleak/v3/internal/limits"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
)

// The local docker-archive reader refuses a layer list over
// LAYERLEAK_MAX_IMAGE_LAYERS before hashing it, so the configured bound has to
// reach it.
func TestLocalSourceReceivesTheImageLayerLimit(t *testing.T) {
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, file := range []struct{ name, body string }{
		{"config.json", `{"architecture":"amd64","os":"linux"}`},
		{"l/layer.tar", strings.Repeat("x", 1024)},
		{"manifest.json", `[{"Config":"config.json","RepoTags":["app:1.0"],"Layers":["l/layer.tar","l/layer.tar"]}]`},
	} {
		if err := writer.WriteHeader(&tar.Header{Name: file.name, Mode: 0o644, Typeflag: tar.TypeReg, Size: int64(len(file.body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(file.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "app.tar")
	if err := os.WriteFile(archive, buffer.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	reference, err := manifest.ParseLocalReference("docker-archive:" + archive + ":app:1.0")
	if err != nil {
		t.Fatal(err)
	}

	service := New(config.Config{MaxImageLayers: 1}, nil)
	local, closeSource, err := service.blobSource(Request{Reference: reference})
	if err != nil {
		t.Fatal(err)
	}
	defer closeSource()
	_, err = local.FetchManifest(context.Background(), reference.Repository, reference.Identifier())
	exceeded, ok := limits.AsExceeded(err)
	if !ok || exceeded.Kind != limits.Kind("image_layers") || exceeded.Limit != 1 {
		t.Fatalf("FetchManifest() over LAYERLEAK_MAX_IMAGE_LAYERS error = %v", err)
	}
}
