package source

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brumbelow/layerleak/v3/internal/detectors"
	"github.com/brumbelow/layerleak/v3/internal/jobs"
	"github.com/brumbelow/layerleak/v3/internal/limits"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
	"github.com/brumbelow/layerleak/v3/internal/scanner"
)

// Every local reader is a scanner.BlobSource.
var _ scanner.BlobSource = Source(nil)

func parseLocal(t *testing.T, raw string) manifest.Reference {
	t.Helper()
	ref, err := manifest.ParseLocalReference(raw)
	if err != nil {
		t.Fatalf("ParseLocalReference(%q) error = %v", raw, err)
	}
	return ref
}

func openSource(t *testing.T, raw string, options Options) Source {
	t.Helper()
	source, err := Open(parseLocal(t, raw), options)
	if err != nil {
		t.Fatalf("Open(%q) error = %v", raw, err)
	}
	t.Cleanup(func() { _ = source.Close() })
	return source
}

// scanLocal runs a scan through the jobs layer exactly as the CLI does.
func scanLocal(t *testing.T, raw string, allTags bool) (jobs.Result, error) {
	t.Helper()
	ref := parseLocal(t, raw)
	source := openSource(t, raw, Options{})
	return jobs.Scan(context.Background(), jobs.Request{
		Reference:    ref,
		Registry:     source,
		Detectors:    detectors.Default(),
		MaxFileBytes: 1 << 20,
		AllTags:      allTags,
	})
}

func TestLayoutDirectoryScanFindsSecretAndRendersLocalReferences(t *testing.T) {
	dir := t.TempDir()
	builder := newLayoutBuilder()
	image := builder.addImage(t, "1.2", linuxAMD64, configJSON(t, linuxAMD64, "A=b"), secretLayer(t, "app/.env"))
	builder.writeDir(t, dir)

	raw := "oci:" + dir + ":1.2"
	result, err := scanLocal(t, raw, false)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if result.Status != jobs.ResultStatusCompleted || result.TotalFindings != 1 {
		t.Fatalf("status=%s findings=%d diagnostics=%+v", result.Status, result.TotalFindings, result.Diagnostics)
	}
	if result.RequestedReference != raw || result.Repository != "oci:"+dir {
		t.Fatalf("requested=%q repository=%q", result.RequestedReference, result.Repository)
	}
	if result.ResolvedReference != "oci:"+dir+"@"+image.Digest || result.RequestedDigest != image.Digest {
		t.Fatalf("resolved=%q digest=%q", result.ResolvedReference, result.RequestedDigest)
	}
	if len(result.TagResults) != 1 || result.TagResults[0].Tag != "1.2" || result.TagResults[0].Status != jobs.TagStatusScanned {
		t.Fatalf("tag results = %+v", result.TagResults)
	}
	if len(result.Targets) != 1 || result.Targets[0].Reference != raw || len(result.Targets[0].PlatformResults) != 1 || result.Targets[0].PlatformResults[0].Platform != linuxAMD64 {
		t.Fatalf("targets = %+v", result.Targets)
	}
	if result.Findings[0].FilePath != "app/.env" || strings.Contains(result.Findings[0].RedactedValue, syntheticToken) {
		t.Fatalf("finding = %+v", result.Findings[0])
	}
}

func TestLayoutSelectsImagesByTagDigestOrSoleEntry(t *testing.T) {
	dir := t.TempDir()
	builder := newLayoutBuilder()
	alpha := builder.addImage(t, "alpha", linuxAMD64, configJSON(t, linuxAMD64, "ONE=1"))
	beta := builder.addImage(t, "beta", linuxAMD64, configJSON(t, linuxAMD64, "TWO=2"))
	builder.addImage(t, "beta", linuxAMD64, configJSON(t, linuxAMD64, "THREE=3"))
	builder.writeDir(t, dir)
	source := openSource(t, "oci:"+dir, Options{})
	ctx := context.Background()

	resolved, err := source.ResolveManifest(ctx, "", "alpha")
	if err != nil || resolved.Digest != alpha.Digest || resolved.MediaType != manifest.MediaTypeOCIImageManifest {
		t.Fatalf("ResolveManifest(alpha) = %+v, %v", resolved, err)
	}
	response, err := source.FetchManifest(ctx, "", alpha.Digest)
	if err != nil || response.Digest != alpha.Digest || response.MediaType != manifest.MediaTypeOCIImageManifest || int64(len(response.Body)) != alpha.Size {
		t.Fatalf("FetchManifest(digest) = %+v, %v", response, err)
	}

	_, err = source.FetchManifest(ctx, "", "")
	if err == nil || !strings.Contains(err.Error(), "holds 3 images") || !strings.Contains(err.Error(), "alpha, beta, beta") {
		t.Fatalf("untagged selection error = %v", err)
	}
	_, err = source.FetchManifest(ctx, "", "gamma")
	if err == nil || !strings.Contains(err.Error(), `no image tagged "gamma"`) || !strings.Contains(err.Error(), "available: alpha, beta, beta") {
		t.Fatalf("missing tag error = %v", err)
	}
	_, err = source.FetchManifest(ctx, "", "beta")
	if err == nil || !strings.Contains(err.Error(), `tags 2 images "beta"`) {
		t.Fatalf("ambiguous tag error = %v", err)
	}
	_, err = source.FetchManifest(ctx, "", "sha256:"+strings.Repeat("0", 64))
	if err == nil || !strings.Contains(err.Error(), "is not in the layout") {
		t.Fatalf("unknown digest error = %v", err)
	}

	tags, err := source.ListTags(ctx, "", 0, 0)
	if err != nil || strings.Join(tags, ",") != "alpha,beta" {
		t.Fatalf("ListTags() = %v, %v", tags, err)
	}
	tags, err = source.ListTags(ctx, "", 0, 1)
	exceeded, ok := limits.AsExceeded(err)
	if !ok || exceeded.Kind != limits.KindRepositoryTags || strings.Join(tags, ",") != "alpha" {
		t.Fatalf("bounded ListTags() = %v, %v", tags, err)
	}

	single := t.TempDir()
	only := newLayoutBuilder()
	descriptor := only.addImage(t, "", linuxAMD64, configJSON(t, linuxAMD64))
	only.writeDir(t, single)
	soleSource := openSource(t, "oci:"+single, Options{})
	resolved, err = soleSource.ResolveManifest(ctx, "", "")
	if err != nil || resolved.Digest != descriptor.Digest {
		t.Fatalf("sole entry ResolveManifest() = %+v, %v", resolved, err)
	}
	if tags, err := soleSource.ListTags(ctx, "", 0, 0); err != nil || len(tags) != 0 {
		t.Fatalf("untagged ListTags() = %v, %v", tags, err)
	}
	_ = beta
}

func TestLayoutRefusesTamperedManifestsAndBlobs(t *testing.T) {
	dir := t.TempDir()
	builder := newLayoutBuilder()
	image := builder.addImage(t, "1.0", linuxAMD64, configJSON(t, linuxAMD64), secretLayer(t, "etc/token"))
	builder.writeDir(t, dir)
	blobFile := func(digest string) string {
		algorithm, encoded, _ := strings.Cut(digest, ":")
		return filepath.Join(dir, layoutBlobsDir, algorithm, encoded)
	}

	// A manifest blob that does not hash to its index descriptor.
	manifestPath := blobFile(image.Digest)
	original, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := []byte(strings.Replace(string(original), `"schemaVersion":2`, `"schemaVersion":3`, 1))
	writeFile(t, manifestPath, tampered)
	source := openSource(t, "oci:"+dir+":1.0", Options{})
	_, err = source.FetchManifest(context.Background(), "", "1.0")
	integrity, ok := manifest.AsIntegrityError(err)
	if !ok || integrity.Kind != manifest.IntegrityDigestMismatch || integrity.Expected != image.Digest {
		t.Fatalf("tampered manifest error = %v", err)
	}
	writeFile(t, manifestPath, original)

	// A layer blob whose bytes changed under its descriptor fails the scan
	// with descriptor_digest_mismatch from the verifying reader.
	var document manifest.Document
	document, err = manifest.ParseDocument(manifest.MediaTypeOCIImageManifest, original)
	if err != nil {
		t.Fatal(err)
	}
	layerPath := blobFile(document.Manifest.Layers[0].Digest)
	layer, err := os.ReadFile(layerPath)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a gzip header MTIME byte: the stream stays decodable and the same
	// length, so only the digest check can notice.
	layer[4] ^= 0xff
	writeFile(t, layerPath, layer)
	result, err := scanLocal(t, "oci:"+dir+":1.0", false)
	integrity, ok = manifest.AsIntegrityError(err)
	if !ok || integrity.Kind != manifest.IntegrityDigestMismatch || result.Status != jobs.ResultStatusFailed {
		t.Fatalf("tampered layer: status=%s err=%v", result.Status, err)
	}

	// A blob shorter than its descriptor is a size mismatch before hashing.
	writeFile(t, layerPath, layer[:len(layer)/2])
	result, err = scanLocal(t, "oci:"+dir+":1.0", false)
	integrity, ok = manifest.AsIntegrityError(err)
	if !ok || integrity.Kind != manifest.IntegritySizeMismatch || result.Status != jobs.ResultStatusFailed {
		t.Fatalf("truncated layer: status=%s err=%v", result.Status, err)
	}
}

func TestLayoutBoundsDocumentReads(t *testing.T) {
	dir := t.TempDir()
	builder := newLayoutBuilder()
	builder.addImage(t, "1.0", linuxAMD64, configJSON(t, linuxAMD64))
	builder.writeDir(t, dir)

	_, err := Open(parseLocal(t, "oci:"+dir), Options{MaxManifestBytes: 64})
	exceeded, ok := limits.AsExceeded(err)
	if !ok || exceeded.Kind != limits.KindManifestBytes || exceeded.Limit != 64 {
		t.Fatalf("oversize index error = %v", err)
	}

	archive := filepath.Join(t.TempDir(), "image.tar")
	builder.writeArchive(t, archive, "")
	_, err = Open(parseLocal(t, "oci-archive:"+archive), Options{MaxManifestBytes: 64})
	exceeded, ok = limits.AsExceeded(err)
	if !ok || exceeded.Kind != limits.KindManifestBytes {
		t.Fatalf("oversize archived index error = %v", err)
	}
}

func TestLayoutDirectoryRefusesSymlinksOutOfTheRoot(t *testing.T) {
	outside := t.TempDir()
	dir := filepath.Join(t.TempDir(), "layout")
	builder := newLayoutBuilder()
	image := builder.addImage(t, "1.0", linuxAMD64, configJSON(t, linuxAMD64), secretLayer(t, "app/.env"))
	builder.writeDir(t, dir)

	document, err := manifest.ParseDocument(manifest.MediaTypeOCIImageManifest, builder.blobs[image.Digest])
	if err != nil {
		t.Fatal(err)
	}
	layerDigest := document.Manifest.Layers[0].Digest
	algorithm, encoded, _ := strings.Cut(layerDigest, ":")
	layerPath := filepath.Join(dir, layoutBlobsDir, algorithm, encoded)
	escaped := filepath.Join(outside, "layer")
	if err := os.Rename(layerPath, escaped); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(escaped, layerPath); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	source := openSource(t, "oci:"+dir+":1.0", Options{})
	_, err = source.OpenBlob(context.Background(), "", layerDigest)
	if err == nil || !strings.Contains(err.Error(), "open blob") {
		t.Fatalf("escaping symlink error = %v", err)
	}
	result, scanErr := scanLocal(t, "oci:"+dir+":1.0", false)
	if scanErr == nil || result.Status != jobs.ResultStatusFailed {
		t.Fatalf("scan through escaping symlink: status=%s err=%v", result.Status, scanErr)
	}

	// A symlinked index.json that leaves the root is refused at open.
	if err := os.Rename(filepath.Join(dir, layoutIndexName), filepath.Join(outside, "index.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "index.json"), filepath.Join(dir, layoutIndexName)); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(parseLocal(t, "oci:"+dir), Options{}); err == nil {
		t.Fatal("Open() with escaping index.json symlink error = nil")
	}
}

func TestLayoutDirectoryRejectsMissingOrInvalidLayout(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(parseLocal(t, "oci:"+dir), Options{}); err == nil || !strings.Contains(err.Error(), layoutFileName) {
		t.Fatalf("empty directory error = %v", err)
	}
	writeFile(t, filepath.Join(dir, layoutFileName), []byte(`{"imageLayoutVersion":"2.0.0"}`))
	if _, err := Open(parseLocal(t, "oci:"+dir), Options{}); err == nil || !strings.Contains(err.Error(), "imageLayoutVersion") {
		t.Fatalf("unsupported version error = %v", err)
	}
	writeFile(t, filepath.Join(dir, layoutFileName), []byte(layoutFileJSON))
	writeFile(t, filepath.Join(dir, layoutIndexName), []byte(`{"schemaVersion":2,"manifests":[]}`))
	if _, err := Open(parseLocal(t, "oci:"+dir), Options{}); err == nil || !manifest.IsIntegrityError(err) {
		t.Fatalf("empty index error = %v", err)
	}
	if _, err := Open(parseLocal(t, "oci:"+filepath.Join(dir, "missing")), Options{}); err == nil {
		t.Fatal("missing directory error = nil")
	}
	file := filepath.Join(dir, "file")
	writeFile(t, file, []byte("x"))
	if _, err := Open(parseLocal(t, "oci:"+file), Options{}); err == nil {
		t.Fatal("regular file as layout directory error = nil")
	}
}

func TestOCIArchiveScansLikeTheDirectory(t *testing.T) {
	for _, prefix := range []string{"", "./"} {
		t.Run("prefix="+prefix, func(t *testing.T) {
			archive := filepath.Join(t.TempDir(), "image.tar")
			builder := newLayoutBuilder()
			image := builder.addImage(t, "1.2", linuxAMD64, configJSON(t, linuxAMD64), secretLayer(t, "srv/config.yaml"))
			builder.writeArchive(t, archive, prefix)

			raw := "oci-archive:" + archive + ":1.2"
			result, err := scanLocal(t, raw, false)
			if err != nil {
				t.Fatalf("Scan() error = %v", err)
			}
			if result.Status != jobs.ResultStatusCompleted || result.TotalFindings != 1 {
				t.Fatalf("status=%s findings=%d", result.Status, result.TotalFindings)
			}
			if result.Repository != "oci-archive:"+archive || result.ResolvedReference != "oci-archive:"+archive+"@"+image.Digest {
				t.Fatalf("repository=%q resolved=%q", result.Repository, result.ResolvedReference)
			}
		})
	}
}

func TestOCIArchiveWithIndexServesMultiPlatformImages(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "image.tar")
	builder := newLayoutBuilder()
	arm64 := manifest.Platform{OS: "linux", Architecture: "arm64"}
	amd := builder.addImage(t, "", linuxAMD64, configJSON(t, linuxAMD64), secretLayer(t, "amd/.env"))
	arm := builder.addImage(t, "", arm64, configJSON(t, arm64), secretLayer(t, "arm/.env"))
	// Replace the two untagged entries with one tagged nested index.
	nested := builder.addBlob(t, manifest.MediaTypeOCIImageIndex, mustJSON(t, manifest.ImageIndex{SchemaVersion: 2, MediaType: manifest.MediaTypeOCIImageIndex, Manifests: []manifest.Descriptor{amd, arm}}))
	nested.Annotations = map[string]string{refNameAnnotation: "multi"}
	builder.manifests = []manifest.Descriptor{nested}
	builder.writeArchive(t, archive, "")

	result, err := scanLocal(t, "oci-archive:"+archive+":multi", false)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if result.ManifestCount != 2 || result.CompletedManifestCount != 2 || result.TotalFindings != 2 {
		t.Fatalf("manifests=%d completed=%d findings=%d", result.ManifestCount, result.CompletedManifestCount, result.TotalFindings)
	}
	if result.RequestedDigest != nested.Digest {
		t.Fatalf("requested digest = %q", result.RequestedDigest)
	}
}

func TestArchiveIndexRefusesUnsafeEntryNames(t *testing.T) {
	builder := newLayoutBuilder()
	builder.addImage(t, "1.0", linuxAMD64, configJSON(t, linuxAMD64))
	tests := []struct {
		name  string
		extra tarFile
		want  string
	}{
		{name: "parent traversal", extra: tarFile{name: "../escape", body: []byte("x")}, want: "parent directory"},
		{name: "nested traversal", extra: tarFile{name: "blobs/../../escape", body: []byte("x")}, want: "parent directory"},
		{name: "absolute path", extra: tarFile{name: "/etc/passwd", body: []byte("x")}, want: "absolute"},
		{name: "backslash", extra: tarFile{name: `blobs\sha256\x`, body: []byte("x")}, want: "backslash"},
		{name: "control character", extra: tarFile{name: "blobs/sha256/\x01", body: []byte("x")}, want: "control"},
		{name: "overlong name", extra: tarFile{name: strings.Repeat("a", maxArchiveEntryPathBytes+1), body: []byte("x")}, want: "longer than"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			archive := filepath.Join(t.TempDir(), "image.tar")
			files := append(builder.archiveFiles(t, ""), tt.extra)
			writeFile(t, archive, tarBytes(t, files))
			_, err := Open(parseLocal(t, "oci-archive:"+archive), Options{})
			if !errors.Is(err, errUnsafeArchivePath) || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Open() error = %v", err)
			}
		})
	}
}

func TestArchiveIndexNeverFollowsLinks(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "outside.json")
	writeFile(t, outside, []byte(layoutFileJSON))
	builder := newLayoutBuilder()
	builder.addImage(t, "1.0", linuxAMD64, configJSON(t, linuxAMD64))
	files := builder.archiveFiles(t, "")
	// Replace oci-layout by a symlink to a file outside the archive and add a
	// hard link named like a blob.
	files[0] = tarFile{name: layoutFileName, typeflag: tar.TypeSymlink, linkname: outside}
	files = append(files, tarFile{name: "blobs/sha256/" + strings.Repeat("f", 64), typeflag: tar.TypeLink, linkname: layoutIndexName})
	archive := filepath.Join(t.TempDir(), "image.tar")
	writeFile(t, archive, tarBytes(t, files))

	_, err := Open(parseLocal(t, "oci-archive:"+archive), Options{})
	if err == nil || !errors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), layoutFileName) {
		t.Fatalf("symlinked oci-layout error = %v", err)
	}
	index, err := openTarIndex(archive, DefaultMaxArchiveEntries)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = index.Close() }()
	if _, ok := index.lookup("blobs/sha256/" + strings.Repeat("f", 64)); ok {
		t.Fatal("hard link was indexed")
	}
}

func TestArchiveIndexBoundsEntriesAndChecksSizes(t *testing.T) {
	builder := newLayoutBuilder()
	builder.addImage(t, "1.0", linuxAMD64, configJSON(t, linuxAMD64))
	files := builder.archiveFiles(t, "")
	archive := filepath.Join(t.TempDir(), "image.tar")
	writeFile(t, archive, tarBytes(t, files))

	_, err := Open(parseLocal(t, "oci-archive:"+archive), Options{MaxArchiveEntries: len(files) - 1})
	exceeded, ok := limits.AsExceeded(err)
	if !ok || exceeded.Kind != limits.KindLayerEntries || exceeded.Limit != int64(len(files)-1) {
		t.Fatalf("entry limit error = %v", err)
	}
	if source, err := Open(parseLocal(t, "oci-archive:"+archive), Options{MaxArchiveEntries: len(files)}); err != nil {
		t.Fatalf("Open() at the limit error = %v", err)
	} else {
		_ = source.Close()
	}

	// A truncated archive whose last entry extends past the end of the file
	// is refused rather than served short.
	body, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, archive, body[:len(body)-1024-512])
	if _, err := Open(parseLocal(t, "oci-archive:"+archive), Options{}); err == nil {
		t.Fatal("truncated archive error = nil")
	}

	// A directory is not an archive and a missing file is reported plainly.
	if _, err := Open(parseLocal(t, "oci-archive:"+t.TempDir()), Options{}); err == nil {
		t.Fatal("directory as archive error = nil")
	}
	if _, err := Open(parseLocal(t, "oci-archive:"+filepath.Join(t.TempDir(), "missing.tar")), Options{}); err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing archive error = %v", err)
	}
}

func TestArchiveSchemesHintAtEachOther(t *testing.T) {
	builder := newLayoutBuilder()
	builder.addImage(t, "1.0", linuxAMD64, configJSON(t, linuxAMD64))
	layoutArchive := filepath.Join(t.TempDir(), "layout.tar")
	builder.writeArchive(t, layoutArchive, "")
	_, err := Open(parseLocal(t, "docker-archive:"+layoutArchive), Options{})
	if err == nil || !strings.Contains(err.Error(), "use oci-archive:"+layoutArchive) {
		t.Fatalf("docker-archive on a layout error = %v", err)
	}

	dockerArchive := filepath.Join(t.TempDir(), "docker.tar")
	writeDockerArchive(t, dockerArchive, []dockerImageFixture{{repoTags: []string{"app:1.0"}, config: configJSON(t, linuxAMD64)}}, nil)
	_, err = Open(parseLocal(t, "oci-archive:"+dockerArchive), Options{})
	if err == nil || !strings.Contains(err.Error(), "use docker-archive:"+dockerArchive) {
		t.Fatalf("oci-archive on a docker save error = %v", err)
	}
}

func TestDockerArchiveScanFindsSecretAndSelectsByImageName(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "app.tar")
	layer := tarBytes(t, []tarFile{{name: "app/.env", body: []byte("TOKEN=" + syntheticToken + "\n")}})
	clean := tarBytes(t, []tarFile{{name: "app/readme", body: []byte("nothing here\n")}})
	writeDockerArchive(t, archive, []dockerImageFixture{
		{repoTags: []string{"app:1.0", "ghcr.io/org/app:1.0"}, config: configJSON(t, linuxAMD64, "A=b"), layers: [][]byte{clean, layer}},
		{repoTags: []string{"app:2.0"}, config: configJSON(t, linuxAMD64, "C=d"), layers: [][]byte{clean}},
	}, nil)

	raw := "docker-archive:" + archive + ":app:1.0"
	result, err := scanLocal(t, raw, false)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if result.Status != jobs.ResultStatusCompleted || result.TotalFindings != 1 || result.Coverage.LayersCompleted != 2 {
		t.Fatalf("status=%s findings=%d coverage=%+v diagnostics=%+v", result.Status, result.TotalFindings, result.Coverage, result.Diagnostics)
	}
	if result.Repository != "docker-archive:"+archive || !strings.HasPrefix(result.ResolvedReference, "docker-archive:"+archive+"@sha256:") {
		t.Fatalf("repository=%q resolved=%q", result.Repository, result.ResolvedReference)
	}
	if len(result.TagResults) != 1 || result.TagResults[0].Tag != "app:1.0" {
		t.Fatalf("tag results = %+v", result.TagResults)
	}

	source := openSource(t, "docker-archive:"+archive, Options{})
	ctx := context.Background()
	first, err := source.ResolveManifest(ctx, "", "app:1.0")
	if err != nil || first.Digest != result.RequestedDigest {
		t.Fatalf("ResolveManifest(app:1.0) = %+v, %v (want %s)", first, err, result.RequestedDigest)
	}
	// Normalised spellings of the same name select the same image.
	for _, name := range []string{"library/app:1.0", "docker.io/library/app:1.0", "ghcr.io/org/app:1.0"} {
		resolved, err := source.ResolveManifest(ctx, "", name)
		if err != nil || resolved.Digest != first.Digest {
			t.Fatalf("ResolveManifest(%s) = %+v, %v", name, resolved, err)
		}
	}
	byDigest, err := source.FetchManifest(ctx, "", first.Digest)
	if err != nil || byDigest.Digest != first.Digest || byDigest.MediaType != manifest.MediaTypeDockerSchema2Manifest {
		t.Fatalf("FetchManifest(digest) = %+v, %v", byDigest, err)
	}
	document, err := manifest.ParseDocument(byDigest.MediaType, byDigest.Body)
	if err != nil || len(document.Manifest.Layers) != 2 || document.Manifest.Layers[0].MediaType != manifest.MediaTypeDockerSchema2Layer || document.Manifest.Layers[1].Size != int64(len(layer)) {
		t.Fatalf("synthesised manifest = %+v, %v", document, err)
	}
	if _, err := source.FetchManifest(ctx, "", ""); err == nil || !strings.Contains(err.Error(), "holds 2 images") || !strings.Contains(err.Error(), "app:1.0, app:2.0, ghcr.io/org/app:1.0") {
		t.Fatalf("untagged selection error = %v", err)
	}
	if _, err := source.FetchManifest(ctx, "", "app:3.0"); err == nil || !strings.Contains(err.Error(), `no image named "app:3.0"`) {
		t.Fatalf("missing name error = %v", err)
	}
	if _, err := source.OpenBlob(ctx, "", "sha256:"+strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), "not in the archive") {
		t.Fatalf("unknown blob error = %v", err)
	}
	tags, err := source.ListTags(ctx, "", 0, 0)
	if err != nil || strings.Join(tags, ",") != "app:1.0,app:2.0,ghcr.io/org/app:1.0" {
		t.Fatalf("ListTags() = %v, %v", tags, err)
	}
}

func TestDockerArchiveSweepEnumeratesRepoTags(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "app.tar")
	layer := tarBytes(t, []tarFile{{name: "app/.env", body: []byte("TOKEN=" + syntheticToken + "\n")}})
	writeDockerArchive(t, archive, []dockerImageFixture{
		{repoTags: []string{"app:1.0", "app:latest"}, config: configJSON(t, linuxAMD64, "A=b"), layers: [][]byte{layer}},
		{repoTags: []string{"app:2.0"}, config: configJSON(t, linuxAMD64, "C=d")},
	}, nil)

	result, err := scanLocal(t, "docker-archive:"+archive, true)
	if err != nil {
		t.Fatalf("Scan(--all-tags) error = %v", err)
	}
	if result.Mode != "repository" || result.TagsEnumerated != 3 || result.TagsResolved != 3 || result.TargetCount != 2 || result.CompletedTargetCount != 2 || result.TotalFindings != 1 {
		t.Fatalf("result = tags=%d/%d targets=%d/%d findings=%d", result.TagsEnumerated, result.TagsResolved, result.TargetCount, result.CompletedTargetCount, result.TotalFindings)
	}
	if result.Repository != "docker-archive:"+archive || result.ResolvedReference != "docker-archive:"+archive {
		t.Fatalf("repository=%q resolved=%q", result.Repository, result.ResolvedReference)
	}
	for _, target := range result.Targets {
		if !strings.HasPrefix(target.Reference, "docker-archive:"+archive+"@sha256:") {
			t.Fatalf("target reference = %q", target.Reference)
		}
	}
}

func TestDockerArchiveFallsBackToTheRepositoriesMap(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "legacy.tar")
	layer := tarBytes(t, []tarFile{{name: "x", body: []byte("y")}})
	_, layerHex, _ := strings.Cut(digestOf(t, layer), ":")
	writeDockerArchive(t, archive, []dockerImageFixture{{config: configJSON(t, linuxAMD64), layers: [][]byte{layer}}}, map[string]map[string]string{"legacy": {"v1": layerHex}})

	source := openSource(t, "docker-archive:"+archive, Options{})
	tags, err := source.ListTags(context.Background(), "", 0, 0)
	if err != nil || strings.Join(tags, ",") != "legacy:v1" {
		t.Fatalf("ListTags() = %v, %v", tags, err)
	}
	if _, err := source.ResolveManifest(context.Background(), "", "legacy:v1"); err != nil {
		t.Fatalf("ResolveManifest(legacy:v1) error = %v", err)
	}
}

func TestDockerArchiveRejectsMalformedManifests(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, files []tarFile) string {
		path := filepath.Join(dir, name)
		writeFile(t, path, tarBytes(t, files))
		return path
	}
	empty := write("empty.tar", []tarFile{{name: dockerManifestName, body: []byte(`[]`)}})
	if _, err := Open(parseLocal(t, "docker-archive:"+empty), Options{}); err == nil || !strings.Contains(err.Error(), "lists no images") {
		t.Fatalf("empty manifest error = %v", err)
	}
	invalid := write("invalid.tar", []tarFile{{name: dockerManifestName, body: []byte(`{`)}})
	if _, err := Open(parseLocal(t, "docker-archive:"+invalid), Options{}); err == nil || !strings.Contains(err.Error(), "decode") {
		t.Fatalf("invalid manifest error = %v", err)
	}
	traversal := write("traversal.tar", []tarFile{{name: dockerManifestName, body: []byte(`[{"Config":"../config.json","RepoTags":["a:1"],"Layers":[]}]`)}})
	source := openSource(t, "docker-archive:"+traversal, Options{})
	if _, err := source.FetchManifest(context.Background(), "", "a:1"); !errors.Is(err, errUnsafeArchivePath) {
		t.Fatalf("traversal config error = %v", err)
	}
	missing := write("missing.tar", []tarFile{{name: dockerManifestName, body: []byte(`[{"Config":"config.json","RepoTags":["a:1"],"Layers":["layer.tar"]}]`)}})
	source = openSource(t, "docker-archive:"+missing, Options{})
	if _, err := source.FetchManifest(context.Background(), "", "a:1"); err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing config error = %v", err)
	}
	oversize := write("oversize.tar", []tarFile{{name: dockerManifestName, body: []byte(`[{"Config":"config.json","RepoTags":["a:1"],"Layers":[]}]`)}})
	if _, err := Open(parseLocal(t, "docker-archive:"+oversize), Options{MaxManifestBytes: 8}); !limits.IsExceeded(err) {
		t.Fatalf("oversize manifest.json error = %v", err)
	}
}

func TestDockerArchiveBlobsAreServedWithTheirSizes(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "app.tar")
	gzipLayer := gzipBytes(t, tarBytes(t, []tarFile{{name: "a", body: []byte("b")}}))
	config := configJSON(t, linuxAMD64)
	writeDockerArchive(t, archive, []dockerImageFixture{{repoTags: []string{"app:1.0"}, config: config, layers: [][]byte{gzipLayer}}}, nil)
	source := openSource(t, "docker-archive:"+archive, Options{})
	ctx := context.Background()

	response, err := source.FetchManifest(ctx, "", "app:1.0")
	if err != nil {
		t.Fatal(err)
	}
	document, err := manifest.ParseDocument(response.MediaType, response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if document.Manifest.Layers[0].MediaType != manifest.MediaTypeDockerSchema2LayerGzip || document.Manifest.Config.MediaType != manifest.MediaTypeDockerContainerConfig {
		t.Fatalf("descriptors = %+v", document.Manifest)
	}
	blob, err := source.OpenBlob(ctx, "", document.Manifest.Config.Digest)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(blob.Body)
	if err != nil || blob.Size != int64(len(config)) || string(body) != string(config) || blob.Digest != document.Manifest.Config.Digest {
		t.Fatalf("config blob = size %d digest %s err %v", blob.Size, blob.Digest, err)
	}
	_ = blob.Body.Close()
	if _, err := source.OpenBlob(ctx, "", "not-a-digest"); err == nil {
		t.Fatal("invalid digest error = nil")
	}
}

func TestOpenRejectsRegistryReferences(t *testing.T) {
	ref, err := manifest.ParseReference("library/app:latest")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ref, Options{}); err == nil {
		t.Fatal("Open(registry reference) error = nil")
	}
}

func TestSourcesHonourContextCancellation(t *testing.T) {
	dir := t.TempDir()
	builder := newLayoutBuilder()
	builder.addImage(t, "1.0", linuxAMD64, configJSON(t, linuxAMD64))
	builder.writeDir(t, dir)
	source := openSource(t, "oci:"+dir, Options{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.FetchManifest(ctx, "", "1.0"); !errors.Is(err, context.Canceled) {
		t.Fatalf("FetchManifest() error = %v", err)
	}
	if _, err := source.ListTags(ctx, "", 0, 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("ListTags() error = %v", err)
	}
}

// buildxRefName is the ref.name BuildKit writes for `-t app:1.2`.
const buildxRefName = "docker.io/library/app:1.2"

func TestLayoutSelectsBuildxStyleRefNames(t *testing.T) {
	dir := t.TempDir()
	builder := newLayoutBuilder()
	app := builder.addImage(t, buildxRefName, linuxAMD64, configJSON(t, linuxAMD64, "ONE=1"))
	stable := builder.addImage(t, "stable", linuxAMD64, configJSON(t, linuxAMD64, "TWO=2"))
	builder.writeDir(t, dir)
	source := openSource(t, "oci:"+dir, Options{})
	ctx := context.Background()

	for _, identifier := range []string{buildxRefName, "app:1.2", "library/app:1.2", "index.docker.io/library/app:1.2"} {
		resolved, err := source.ResolveManifest(ctx, "", identifier)
		if err != nil || resolved.Digest != app.Digest {
			t.Fatalf("ResolveManifest(%q) = %+v, %v", identifier, resolved, err)
		}
		response, err := source.FetchManifest(ctx, "", identifier)
		if err != nil || response.Digest != app.Digest {
			t.Fatalf("FetchManifest(%q) = %+v, %v", identifier, response, err)
		}
	}
	resolved, err := source.ResolveManifest(ctx, "", "stable")
	if err != nil || resolved.Digest != stable.Digest {
		t.Fatalf("ResolveManifest(stable) = %+v, %v", resolved, err)
	}

	// Identifiers with a colon that are not digests are tag lookups, never
	// digest validation failures: a sweep must not abort on them.
	for _, identifier := range []string{"1.2", "app:latest", "other:1.2", "sha256:zz", "md5:" + strings.Repeat("a", 32)} {
		_, err := source.ResolveManifest(ctx, "", identifier)
		if err == nil || !strings.Contains(err.Error(), "no image tagged") || !strings.Contains(err.Error(), buildxRefName) {
			t.Fatalf("ResolveManifest(%q) error = %v", identifier, err)
		}
		if manifest.IsIntegrityError(err) {
			t.Fatalf("ResolveManifest(%q) returned an integrity error: %v", identifier, err)
		}
	}

	tags, err := source.ListTags(ctx, "", 0, 0)
	if err != nil || strings.Join(tags, ",") != buildxRefName+",stable" {
		t.Fatalf("ListTags() = %v, %v", tags, err)
	}

	result, err := scanLocal(t, "oci:"+dir+":app:1.2", false)
	if err != nil || result.Status != jobs.ResultStatusCompleted {
		t.Fatalf("Scan(:app:1.2) = %s, %v", result.Status, err)
	}
	if result.RequestedReference != "oci:"+dir+":app:1.2" || result.Repository != "oci:"+dir || result.ResolvedReference != "oci:"+dir+"@"+app.Digest {
		t.Fatalf("requested=%q repository=%q resolved=%q", result.RequestedReference, result.Repository, result.ResolvedReference)
	}
	if len(result.TagResults) != 1 || result.TagResults[0].Tag != "app:1.2" || result.TagResults[0].Status != jobs.TagStatusScanned {
		t.Fatalf("tag results = %+v", result.TagResults)
	}
}

// sweepLayoutBuilder holds a buildx-style tagged image with a secret, a clean
// plain-tagged image, two images sharing an ambiguous tag and an untagged one.
func sweepLayoutBuilder(t *testing.T) (*layoutBuilder, manifest.Descriptor, manifest.Descriptor) {
	t.Helper()
	builder := newLayoutBuilder()
	app := builder.addImage(t, buildxRefName, linuxAMD64, configJSON(t, linuxAMD64, "A=b"), secretLayer(t, "app/.env"))
	stable := builder.addImage(t, "stable", linuxAMD64, configJSON(t, linuxAMD64, "C=d"))
	builder.addImage(t, "dup", linuxAMD64, configJSON(t, linuxAMD64, "E=f"))
	builder.addImage(t, "dup", linuxAMD64, configJSON(t, linuxAMD64, "G=h"))
	builder.addImage(t, "", linuxAMD64, configJSON(t, linuxAMD64, "I=j"))
	return builder, app, stable
}

// assertLayoutSweep checks a sweep over sweepLayoutBuilder's layout: the
// ambiguous tag fails to resolve, which makes the sweep partial (err is the
// coverage error, as for a registry sweep) without stopping the other
// targets from being scanned.
func assertLayoutSweep(t *testing.T, repository string, result jobs.Result, err error, app, stable manifest.Descriptor) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "coverage is partial") {
		t.Fatalf("sweep error = %v", err)
	}
	if result.Mode != "repository" || result.Status != jobs.ResultStatusPartial {
		t.Fatalf("mode=%s status=%s diagnostics=%+v", result.Mode, result.Status, result.Diagnostics)
	}
	if result.TagsEnumerated != 3 || result.TagsResolved != 2 || result.TagsFailed != 1 || result.TargetCount != 2 || result.CompletedTargetCount != 2 || result.TotalFindings != 1 {
		t.Fatalf("tags=%d/%d failed=%d targets=%d/%d findings=%d", result.TagsEnumerated, result.TagsResolved, result.TagsFailed, result.TargetCount, result.CompletedTargetCount, result.TotalFindings)
	}
	if result.Repository != repository || result.ResolvedReference != repository {
		t.Fatalf("repository=%q resolved=%q", result.Repository, result.ResolvedReference)
	}
	byTag := make(map[string]jobs.TagResult, len(result.TagResults))
	for _, tagResult := range result.TagResults {
		byTag[tagResult.Tag] = tagResult
	}
	if got := byTag[buildxRefName]; got.Status != jobs.TagStatusScanned || got.RootDigest != app.Digest || got.TargetReference != repository+"@"+app.Digest {
		t.Fatalf("buildx tag result = %+v", got)
	}
	if got := byTag["stable"]; got.Status != jobs.TagStatusScanned || got.RootDigest != stable.Digest || got.TargetReference != repository+"@"+stable.Digest {
		t.Fatalf("stable tag result = %+v", got)
	}
	if got := byTag["dup"]; got.Status != jobs.TagStatusFailed || !strings.Contains(got.Error, `tags 2 images "dup"`) {
		t.Fatalf("ambiguous tag result = %+v", got)
	}
	for _, target := range result.Targets {
		if !strings.HasPrefix(target.Reference, repository+"@sha256:") || target.Status != jobs.ResultStatusCompleted {
			t.Fatalf("target = %+v", target)
		}
	}
}

func TestLayoutDirectorySweepEnumeratesRefNames(t *testing.T) {
	dir := t.TempDir()
	builder, app, stable := sweepLayoutBuilder(t)
	builder.writeDir(t, dir)

	result, err := scanLocal(t, "oci:"+dir, true)
	assertLayoutSweep(t, "oci:"+dir, result, err, app, stable)
}

func TestOCIArchiveSweepEnumeratesRefNames(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "app.tar")
	builder, app, stable := sweepLayoutBuilder(t)
	builder.writeArchive(t, archive, "")

	result, err := scanLocal(t, "oci-archive:"+archive, true)
	assertLayoutSweep(t, "oci-archive:"+archive, result, err, app, stable)

	// The README flow: buildx -t app:1.2 -o type=oci,dest=app.tar, then
	// select the image by the name given to buildx.
	single, err := scanLocal(t, "oci-archive:"+archive+":app:1.2", false)
	if err != nil || single.TotalFindings != 1 || single.ResolvedReference != "oci-archive:"+archive+"@"+app.Digest {
		t.Fatalf("Scan(:app:1.2) = findings=%d resolved=%q, %v", single.TotalFindings, single.ResolvedReference, err)
	}
}

// A manifest blob whose length differs from the index descriptor is a size
// mismatch, reported before the digest is computed.
func TestLayoutRefusesManifestOfTheWrongSize(t *testing.T) {
	dir := t.TempDir()
	builder := newLayoutBuilder()
	image := builder.addImage(t, "1.0", linuxAMD64, configJSON(t, linuxAMD64))
	builder.writeDir(t, dir)
	algorithm, encoded, _ := strings.Cut(image.Digest, ":")
	manifestPath := filepath.Join(dir, layoutBlobsDir, algorithm, encoded)
	original, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, manifestPath, append(original, '\n'))

	_, err = openSource(t, "oci:"+dir, Options{}).FetchManifest(context.Background(), "", "1.0")
	integrity, ok := manifest.AsIntegrityError(err)
	if !ok || integrity.Kind != manifest.IntegritySizeMismatch || integrity.Subject != image.Digest || integrity.Expected != fmt.Sprintf("%d", len(original)) || integrity.Actual != fmt.Sprintf("%d", len(original)+1) {
		t.Fatalf("resized manifest error = %v", err)
	}
}
