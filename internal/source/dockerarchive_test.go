package source

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/limits"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
)

// expiringContext reports no error for its first live Err calls and
// context.DeadlineExceeded from then on, so a test can make a deadline pass at
// a deterministic point inside a source operation.
type expiringContext struct {
	context.Context
	live  int
	calls int
}

func (c *expiringContext) Err() error {
	c.calls++
	if c.calls > c.live {
		return context.DeadlineExceeded
	}
	return nil
}

// repeatedLayerArchive writes a docker save archive whose single image lists
// one layer entry references times, with a layer of layerBytes bytes.
func repeatedLayerArchive(t *testing.T, references, layerBytes int) string {
	t.Helper()
	layers := make([]string, references)
	for index := range layers {
		layers[index] = "l/layer.tar"
	}
	archive := filepath.Join(t.TempDir(), "repeated.tar")
	writeFile(t, archive, tarBytes(t, []tarFile{
		{name: "config.json", body: configJSON(t, linuxAMD64)},
		{name: "l/layer.tar", body: []byte(strings.Repeat("x", layerBytes))},
		{name: dockerManifestName, body: mustJSON(t, []dockerManifestEntry{{Config: "config.json", RepoTags: []string{"app:1.0"}, Layers: layers}})},
	}))
	return archive
}

// A manifest.json that lists one layer thousands of times must not hash the
// layer once per reference past the scan deadline.
func TestDockerArchiveRepeatedLayerHonoursTheDeadline(t *testing.T) {
	archive := repeatedLayerArchive(t, 2000, 1<<20)
	source := openSource(t, "docker-archive:"+archive, Options{})
	ctx := &expiringContext{Context: context.Background(), live: 1}

	started := time.Now()
	_, err := source.FetchManifest(ctx, "", "app:1.0")
	elapsed := time.Since(started)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("FetchManifest() past the deadline error = %v after %s", err, elapsed)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("FetchManifest() returned %s after the deadline passed", elapsed)
	}
}

// The deadline is also checked while one large entry is being hashed.
func TestDockerArchiveHashingStopsMidEntryAtTheDeadline(t *testing.T) {
	archive := repeatedLayerArchive(t, 1, 3*hashChunkBytes)
	opened := openSource(t, "docker-archive:"+archive, Options{})
	docker, ok := opened.(*dockerArchive)
	if !ok {
		t.Fatalf("Open() = %T, want *dockerArchive", opened)
	}
	ctx := &expiringContext{Context: context.Background(), live: 1}
	docker.mu.Lock()
	_, err := docker.describeEntry(ctx, "l/layer.tar", "")
	docker.mu.Unlock()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("describeEntry() past the deadline error = %v", err)
	}
	if ctx.calls > 3 {
		t.Fatalf("describeEntry() read %d chunks past the deadline", ctx.calls-1)
	}
}

// A repeated layer reference is hashed once, across every image of the
// archive, and the synthesised manifest still lists every reference.
func TestDockerArchiveHashesARepeatedLayerOnce(t *testing.T) {
	layers := make([]string, 2000)
	for index := range layers {
		layers[index] = "./l/layer.tar"
	}
	archive := filepath.Join(t.TempDir(), "shared.tar")
	writeFile(t, archive, tarBytes(t, []tarFile{
		{name: "one.json", body: configJSON(t, linuxAMD64, "IMAGE=one")},
		{name: "two.json", body: configJSON(t, linuxAMD64, "IMAGE=two")},
		{name: "l/layer.tar", body: []byte(strings.Repeat("x", 1<<20))},
		{name: dockerManifestName, body: mustJSON(t, []dockerManifestEntry{
			{Config: "one.json", RepoTags: []string{"app:one"}, Layers: layers},
			{Config: "two.json", RepoTags: []string{"app:two"}, Layers: []string{"l/layer.tar"}},
		})},
	}))
	opened := openSource(t, "docker-archive:"+archive, Options{})
	docker, ok := opened.(*dockerArchive)
	if !ok {
		t.Fatalf("Open() = %T, want *dockerArchive", opened)
	}
	ctx := context.Background()

	two, err := opened.FetchManifest(ctx, "", "app:two")
	if err != nil {
		t.Fatal(err)
	}
	one, err := opened.FetchManifest(ctx, "", "app:one")
	if err != nil {
		t.Fatal(err)
	}
	document, err := manifest.ParseDocument(one.MediaType, one.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(document.Manifest.Layers) != len(layers) {
		t.Fatalf("synthesised manifest lists %d layers, want %d", len(document.Manifest.Layers), len(layers))
	}
	if docker.hashedEntries != 3 {
		t.Fatalf("hashed %d archive entries, want 3 (two configs and one layer)", docker.hashedEntries)
	}
	if _, err := opened.FetchManifest(ctx, "", two.Digest); err != nil {
		t.Fatalf("FetchManifest(@digest) error = %v", err)
	}
	if docker.hashedEntries != 3 {
		t.Fatalf("digest selection hashed again: %d entries", docker.hashedEntries)
	}
}

// An image whose layer list is longer than MaxImageLayers is refused before a
// byte of it is hashed, with the scanner's image_layers limit kind.
func TestDockerArchiveBoundsTheLayerList(t *testing.T) {
	archive := repeatedLayerArchive(t, 4, 1024)
	opened := openSource(t, "docker-archive:"+archive, Options{MaxImageLayers: 3})
	_, err := opened.FetchManifest(context.Background(), "", "app:1.0")
	exceeded, ok := limits.AsExceeded(err)
	if !ok || exceeded.Kind != limits.Kind("image_layers") || exceeded.Limit != 3 {
		t.Fatalf("FetchManifest() over the layer limit error = %v", err)
	}
	docker, ok := opened.(*dockerArchive)
	if !ok {
		t.Fatalf("Open() = %T, want *dockerArchive", opened)
	}
	if docker.hashedEntries != 0 {
		t.Fatalf("hashed %d entries before refusing the layer list", docker.hashedEntries)
	}

	atLimit := openSource(t, "docker-archive:"+archive, Options{MaxImageLayers: 4})
	if _, err := atLimit.FetchManifest(context.Background(), "", "app:1.0"); err != nil {
		t.Fatalf("FetchManifest() at the layer limit error = %v", err)
	}
}

// The synthesised manifest is a document like any other and is bounded by
// MaxManifestBytes even when manifest.json itself fits.
func TestDockerArchiveBoundsTheSynthesisedManifest(t *testing.T) {
	archive := repeatedLayerArchive(t, 64, 1024)
	opened := openSource(t, "docker-archive:"+archive, Options{MaxManifestBytes: 2048})
	_, err := opened.FetchManifest(context.Background(), "", "app:1.0")
	exceeded, ok := limits.AsExceeded(err)
	if !ok || exceeded.Kind != limits.KindManifestBytes || exceeded.Limit != 2048 {
		t.Fatalf("FetchManifest() with an oversize synthesised manifest error = %v", err)
	}
}

// Selecting by digest skips an image of the archive that is over a limit, so
// an unrelated oversize image does not make an in-limit image unselectable;
// asking for a digest no in-limit image has still reports the limit.
func TestDockerArchiveDigestSelectionSkipsAnOverLimitImage(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "two.tar")
	writeFile(t, archive, tarBytes(t, []tarFile{
		{name: "one.json", body: configJSON(t, linuxAMD64, "IMAGE=one")},
		{name: "two.json", body: configJSON(t, linuxAMD64, "IMAGE=two")},
		{name: "a.tar", body: []byte(strings.Repeat("a", 1024))},
		{name: "b.tar", body: []byte(strings.Repeat("b", 1024))},
		{name: dockerManifestName, body: mustJSON(t, []dockerManifestEntry{
			{Config: "one.json", RepoTags: []string{"app:one"}, Layers: []string{"a.tar", "a.tar", "a.tar"}},
			{Config: "two.json", RepoTags: []string{"app:two"}, Layers: []string{"b.tar"}},
		})},
	}))
	ctx := context.Background()

	byName, err := openSource(t, "docker-archive:"+archive, Options{MaxImageLayers: 2}).FetchManifest(ctx, "", "app:two")
	if err != nil {
		t.Fatalf("FetchManifest(app:two) error = %v", err)
	}
	byDigest, err := openSource(t, "docker-archive:"+archive, Options{MaxImageLayers: 2}).FetchManifest(ctx, "", byName.Digest)
	if err != nil {
		t.Fatalf("FetchManifest(@digest) with an over-limit sibling error = %v", err)
	}
	if byDigest.Digest != byName.Digest {
		t.Fatalf("FetchManifest(@digest) digest = %s, want %s", byDigest.Digest, byName.Digest)
	}

	missing := "sha256:" + strings.Repeat("0", 64)
	_, err = openSource(t, "docker-archive:"+archive, Options{MaxImageLayers: 2}).FetchManifest(ctx, "", missing)
	exceeded, ok := limits.AsExceeded(err)
	if !ok || exceeded.Kind != limits.Kind("image_layers") || !strings.Contains(err.Error(), missing) {
		t.Fatalf("FetchManifest(@unknown digest) with an over-limit image error = %v", err)
	}
}

// Layer entries are validated, hashed and deduplicated in manifest.json
// order, and the errors name the image and layer position.
func TestDockerArchiveReportsLayerEntryErrors(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, layers ...string) string {
		path := filepath.Join(dir, name)
		writeFile(t, path, tarBytes(t, []tarFile{
			{name: "config.json", body: configJSON(t, linuxAMD64)},
			{name: "a.tar", body: []byte("same bytes")},
			{name: "b.tar", body: []byte("same bytes")},
			{name: dockerManifestName, body: mustJSON(t, []dockerManifestEntry{{Config: "config.json", RepoTags: []string{"app:1"}, Layers: layers}})},
		}))
		return path
	}
	ctx := context.Background()

	unsafe := write("unsafe.tar", "a.tar", "../a.tar")
	_, err := openSource(t, "docker-archive:"+unsafe, Options{}).FetchManifest(ctx, "", "app:1")
	if !errors.Is(err, errUnsafeArchivePath) || !strings.HasPrefix(err.Error(), "docker archive "+unsafe+": image 0 layer 1: ") {
		t.Fatalf("unsafe layer path error = %v", err)
	}

	missing := write("missing.tar", "a.tar", "a.tar", "c.tar")
	_, err = openSource(t, "docker-archive:"+missing, Options{}).FetchManifest(ctx, "", "app:1")
	if !errors.Is(err, os.ErrNotExist) || !strings.HasPrefix(err.Error(), "docker archive "+missing+": image 0 layer 2: ") {
		t.Fatalf("missing layer error = %v", err)
	}

	duplicate := write("duplicate.tar", "a.tar", "b.tar")
	_, err = openSource(t, "docker-archive:"+duplicate, Options{}).FetchManifest(ctx, "", "app:1")
	if err == nil || err.Error() != "docker archive "+duplicate+": image 0: entries a.tar and b.tar have the same digest" {
		t.Fatalf("duplicate digest error = %v", err)
	}
}

// An archive with several images needs a selector; a name carried by two
// images or a digest no image has is refused with the matching message.
func TestDockerArchiveSelectionErrors(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "two.tar")
	writeFile(t, archive, tarBytes(t, []tarFile{
		{name: "one.json", body: configJSON(t, linuxAMD64, "IMAGE=one")},
		{name: "two.json", body: configJSON(t, linuxAMD64, "IMAGE=two")},
		{name: dockerManifestName, body: mustJSON(t, []dockerManifestEntry{
			{Config: "one.json", RepoTags: []string{"app:shared", "app:one"}},
			{Config: "two.json", RepoTags: []string{"docker.io/library/app:shared"}},
		})},
	}))
	opened := openSource(t, "docker-archive:"+archive, Options{})
	ctx := context.Background()

	if _, err := opened.FetchManifest(ctx, "", " "); err == nil || !strings.HasPrefix(err.Error(), "docker archive "+archive+" holds 2 images; select one with") {
		t.Fatalf("FetchManifest(\"\") error = %v", err)
	}
	if _, err := opened.FetchManifest(ctx, "", "app:shared"); err == nil || err.Error() != "docker archive "+archive+` names 2 images "app:shared"; select one with @<digest>` {
		t.Fatalf("FetchManifest(app:shared) error = %v", err)
	}
	absent := "sha256:" + strings.Repeat("0", 64)
	if _, err := opened.FetchManifest(ctx, "", absent); err == nil || err.Error() != "docker archive "+archive+" has no image with digest "+absent {
		t.Fatalf("FetchManifest(absent digest) error = %v", err)
	}
	one, err := opened.FetchManifest(ctx, "", "app:one")
	if err != nil {
		t.Fatalf("FetchManifest(app:one) error = %v", err)
	}
	byDigest, err := opened.FetchManifest(ctx, "", one.Digest)
	if err != nil || byDigest.Digest != one.Digest {
		t.Fatalf("FetchManifest(@digest) = %s, %v; want %s", byDigest.Digest, err, one.Digest)
	}
}
