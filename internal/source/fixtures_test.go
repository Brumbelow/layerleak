package source

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/brumbelow/layerleak/v3/internal/manifest"
)

// syntheticToken has the shape of a GitHub token and is obviously not one.
const syntheticToken = "ghp_123456789012345678901234567890123456"

type tarFile struct {
	name     string
	body     []byte
	typeflag byte
	linkname string
}

// tarBytes builds a tar archive in memory. A zero typeflag means a regular
// file.
func tarBytes(t *testing.T, files []tarFile) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, file := range files {
		header := &tar.Header{Name: file.name, Mode: 0o644, Typeflag: file.typeflag, Linkname: file.linkname}
		if file.typeflag == 0 || file.typeflag == tar.TypeReg {
			header.Typeflag = tar.TypeReg
			header.Size = int64(len(file.body))
		}
		if file.typeflag == tar.TypeDir {
			header.Mode = 0o755
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatalf("WriteHeader(%s) error = %v", file.name, err)
		}
		if header.Typeflag == tar.TypeReg {
			if _, err := writer.Write(file.body); err != nil {
				t.Fatalf("Write(%s) error = %v", file.name, err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("tar Close() error = %v", err)
	}
	return buffer.Bytes()
}

func gzipBytes(t *testing.T, body []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(body); err != nil {
		t.Fatalf("gzip Write() error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("gzip Close() error = %v", err)
	}
	return buffer.Bytes()
}

func writeFile(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("MkdirAll(%s) error = %v", path, err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", path, err)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	return body
}

func digestOf(t *testing.T, body []byte) string {
	t.Helper()
	digest, err := manifest.DigestBytes("sha256", body)
	if err != nil {
		t.Fatalf("DigestBytes() error = %v", err)
	}
	return digest
}

func descriptorOf(t *testing.T, mediaType string, body []byte) manifest.Descriptor {
	t.Helper()
	return manifest.Descriptor{MediaType: mediaType, Digest: digestOf(t, body), Size: int64(len(body))}
}

// configJSON is a minimal image config for the platform with the given env.
func configJSON(t *testing.T, platform manifest.Platform, env ...string) []byte {
	t.Helper()
	return mustJSON(t, map[string]any{
		"architecture": platform.Architecture,
		"os":           platform.OS,
		"config":       map[string]any{"Env": env},
	})
}

// secretLayer is a gzip tar layer with one file holding the synthetic token.
func secretLayer(t *testing.T, path string) []byte {
	t.Helper()
	return gzipBytes(t, tarBytes(t, []tarFile{{name: path, body: []byte("TOKEN=" + syntheticToken + "\n")}}))
}

var linuxAMD64 = manifest.Platform{OS: "linux", Architecture: "amd64"}

// layoutBuilder assembles an OCI image layout in memory and writes it as a
// directory or a tar archive.
type layoutBuilder struct {
	blobs     map[string][]byte
	manifests []manifest.Descriptor
}

func newLayoutBuilder() *layoutBuilder {
	return &layoutBuilder{blobs: make(map[string][]byte)}
}

func (b *layoutBuilder) addBlob(t *testing.T, mediaType string, body []byte) manifest.Descriptor {
	t.Helper()
	descriptor := descriptorOf(t, mediaType, body)
	b.blobs[descriptor.Digest] = body
	return descriptor
}

// addImage adds an image manifest (config and gzip layers) to the index under
// tag (empty for an untagged entry) and returns its descriptor.
func (b *layoutBuilder) addImage(t *testing.T, tag string, platform manifest.Platform, config []byte, layers ...[]byte) manifest.Descriptor {
	t.Helper()
	configDescriptor := b.addBlob(t, manifest.MediaTypeOCIImageConfig, config)
	layerDescriptors := make([]manifest.Descriptor, 0, len(layers))
	for _, layer := range layers {
		layerDescriptors = append(layerDescriptors, b.addBlob(t, manifest.MediaTypeOCIImageLayerGzip, layer))
	}
	body := mustJSON(t, manifest.ImageManifest{
		SchemaVersion: 2,
		MediaType:     manifest.MediaTypeOCIImageManifest,
		Config:        configDescriptor,
		Layers:        layerDescriptors,
	})
	descriptor := b.addBlob(t, manifest.MediaTypeOCIImageManifest, body)
	descriptor.Platform = platform
	if tag != "" {
		descriptor.Annotations = map[string]string{refNameAnnotation: tag}
	}
	b.manifests = append(b.manifests, descriptor)
	return descriptor
}

func (b *layoutBuilder) indexJSON(t *testing.T) []byte {
	t.Helper()
	return mustJSON(t, manifest.ImageIndex{SchemaVersion: 2, MediaType: manifest.MediaTypeOCIImageIndex, Manifests: b.manifests})
}

const layoutFileJSON = `{"imageLayoutVersion":"1.0.0"}`

// writeDir writes the layout under dir.
func (b *layoutBuilder) writeDir(t *testing.T, dir string) {
	t.Helper()
	writeFile(t, filepath.Join(dir, layoutFileName), []byte(layoutFileJSON))
	writeFile(t, filepath.Join(dir, layoutIndexName), b.indexJSON(t))
	for digest, body := range b.blobs {
		algorithm, encoded, _ := strings.Cut(digest, ":")
		writeFile(t, filepath.Join(dir, layoutBlobsDir, algorithm, encoded), body)
	}
}

// archiveFiles returns the layout as tar entries, each name prefixed with
// prefix ("" or "./"), in a deterministic order.
func (b *layoutBuilder) archiveFiles(t *testing.T, prefix string) []tarFile {
	t.Helper()
	files := []tarFile{
		{name: prefix + layoutFileName, body: []byte(layoutFileJSON)},
		{name: prefix + layoutIndexName, body: b.indexJSON(t)},
	}
	digests := make([]string, 0, len(b.blobs))
	for digest := range b.blobs {
		digests = append(digests, digest)
	}
	sort.Strings(digests)
	for _, digest := range digests {
		algorithm, encoded, _ := strings.Cut(digest, ":")
		files = append(files, tarFile{name: prefix + layoutBlobsDir + "/" + algorithm + "/" + encoded, body: b.blobs[digest]})
	}
	return files
}

func (b *layoutBuilder) writeArchive(t *testing.T, path, prefix string) {
	t.Helper()
	writeFile(t, path, tarBytes(t, b.archiveFiles(t, prefix)))
}

// dockerImageFixture is one image of a docker save archive.
type dockerImageFixture struct {
	repoTags []string
	config   []byte
	layers   [][]byte // uncompressed tars
}

// dockerArchiveFiles lays the images out as `docker save` does: manifest.json,
// <config digest>.json and <layer id>/layer.tar entries.
func dockerArchiveFiles(t *testing.T, images []dockerImageFixture, repositories map[string]map[string]string) []tarFile {
	t.Helper()
	files := make([]tarFile, 0)
	entries := make([]dockerManifestEntry, 0, len(images))
	for _, image := range images {
		_, configHex, _ := strings.Cut(digestOf(t, image.config), ":")
		entry := dockerManifestEntry{Config: configHex + ".json", RepoTags: image.repoTags}
		files = append(files, tarFile{name: entry.Config, body: image.config})
		for _, layer := range image.layers {
			_, layerHex, _ := strings.Cut(digestOf(t, layer), ":")
			files = append(files, tarFile{name: layerHex, typeflag: tar.TypeDir}, tarFile{name: layerHex + "/layer.tar", body: layer})
			entry.Layers = append(entry.Layers, layerHex+"/layer.tar")
		}
		entries = append(entries, entry)
	}
	files = append(files, tarFile{name: dockerManifestName, body: mustJSON(t, entries)})
	if repositories != nil {
		files = append(files, tarFile{name: dockerRepositoriesName, body: mustJSON(t, repositories)})
	}
	return files
}

func writeDockerArchive(t *testing.T, path string, images []dockerImageFixture, repositories map[string]map[string]string) {
	t.Helper()
	writeFile(t, path, tarBytes(t, dockerArchiveFiles(t, images, repositories)))
}
