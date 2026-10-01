//go:build unix

package source

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/manifest"
)

// replaceWithFIFO turns path into a named pipe with no writer, which an
// extracted untrusted tarball can contain.
func replaceWithFIFO(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
}

// promptly runs call and fails the test when it does not return within a few
// seconds. A call stuck opening a FIFO is released by opening the FIFO for
// writing, so a failing test does not leave a blocked goroutine behind.
func promptly(t *testing.T, fifo string, call func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- call() }()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		if writer, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = writer.Close()
		}
		<-done
		t.Fatalf("call on a FIFO at %s still blocked after 3s", fifo)
		return nil
	}
}

// A FIFO in place of oci-layout, index.json or a blob is refused at once
// instead of blocking open(2) until a writer appears, which no scan timeout
// can interrupt.
func TestLayoutDirectoryRefusesFIFOsWithoutBlocking(t *testing.T) {
	build := func(t *testing.T) (string, string) {
		t.Helper()
		dir := t.TempDir()
		builder := newLayoutBuilder()
		image := builder.addImage(t, "1.0", linuxAMD64, configJSON(t, linuxAMD64), secretLayer(t, "app/.env"))
		builder.writeDir(t, dir)
		document, err := manifest.ParseDocument(manifest.MediaTypeOCIImageManifest, builder.blobs[image.Digest])
		if err != nil {
			t.Fatal(err)
		}
		return dir, document.Manifest.Layers[0].Digest
	}

	for _, name := range []string{layoutFileName, layoutIndexName} {
		t.Run(name, func(t *testing.T) {
			dir, _ := build(t)
			fifo := filepath.Join(dir, name)
			replaceWithFIFO(t, fifo)
			err := promptly(t, fifo, func() error {
				_, err := Open(parseLocal(t, "oci:"+dir), Options{})
				return err
			})
			if err == nil || !strings.Contains(err.Error(), "not a regular file") {
				t.Fatalf("Open() with a FIFO %s error = %v", name, err)
			}
		})
	}

	t.Run("blob", func(t *testing.T) {
		dir, layerDigest := build(t)
		algorithm, encoded, _ := strings.Cut(layerDigest, ":")
		fifo := filepath.Join(dir, layoutBlobsDir, algorithm, encoded)
		replaceWithFIFO(t, fifo)
		opened := openSource(t, "oci:"+dir+":1.0", Options{})
		err := promptly(t, fifo, func() error {
			_, err := opened.OpenBlob(context.Background(), "", layerDigest)
			return err
		})
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("OpenBlob() on a FIFO error = %v", err)
		}
	})

	t.Run("manifest", func(t *testing.T) {
		dir, _ := build(t)
		index, err := os.ReadFile(filepath.Join(dir, layoutIndexName))
		if err != nil {
			t.Fatal(err)
		}
		document, err := manifest.ParseDocument(manifest.MediaTypeOCIImageIndex, index)
		if err != nil {
			t.Fatal(err)
		}
		algorithm, encoded, _ := strings.Cut(document.Index.Manifests[0].Digest, ":")
		fifo := filepath.Join(dir, layoutBlobsDir, algorithm, encoded)
		replaceWithFIFO(t, fifo)
		opened := openSource(t, "oci:"+dir+":1.0", Options{})
		err = promptly(t, fifo, func() error {
			_, err := opened.FetchManifest(context.Background(), "", "1.0")
			return err
		})
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("FetchManifest() on a FIFO error = %v", err)
		}
	})
}
