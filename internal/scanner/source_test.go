package scanner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sort"
	"testing"

	"github.com/brumbelow/layerleak/v3/internal/detectors"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
	"github.com/brumbelow/layerleak/v3/internal/registry"
)

// memorySource is the smallest BlobSource: manifests and blobs held in maps,
// no digests or media types reported, so every verification the scanner does
// has to come from the bodies themselves.
type memorySource struct {
	manifests map[string][]byte // identifier (tag or digest) -> body
	blobs     map[string][]byte // digest -> body
	opened    []string
}

func (s *memorySource) FetchManifest(_ context.Context, _, identifier string) (registry.ManifestResponse, error) {
	body, ok := s.manifests[identifier]
	if !ok {
		return registry.ManifestResponse{}, fmt.Errorf("manifest %q not found", identifier)
	}
	// The scanner insists that the reported media type matches the document,
	// so a source that knows nothing else still reports the declared one.
	document, err := manifest.ParseDocument("", body)
	if err != nil {
		return registry.ManifestResponse{}, err
	}
	mediaType := document.Manifest.MediaType
	if document.Kind == manifest.DocumentKindIndex {
		mediaType = document.Index.MediaType
	}
	return registry.ManifestResponse{MediaType: mediaType, Body: body, Size: int64(len(body))}, nil
}

func (s *memorySource) ResolveManifest(ctx context.Context, repository, identifier string) (registry.ManifestMetadata, error) {
	response, err := s.FetchManifest(ctx, repository, identifier)
	if err != nil {
		return registry.ManifestMetadata{}, err
	}
	digest, err := manifest.DigestBytes("sha256", response.Body)
	if err != nil {
		return registry.ManifestMetadata{}, err
	}
	return registry.ManifestMetadata{Digest: digest}, nil
}

func (s *memorySource) OpenBlob(_ context.Context, _, digest string) (registry.BlobResponse, error) {
	body, ok := s.blobs[digest]
	if !ok {
		return registry.BlobResponse{}, fmt.Errorf("blob %q not found", digest)
	}
	s.opened = append(s.opened, digest)
	return registry.BlobResponse{Body: io.NopCloser(bytes.NewReader(body))}, nil
}

func (s *memorySource) ListTags(context.Context, string, int, int) ([]string, error) {
	tags := make([]string, 0, len(s.manifests))
	for identifier := range s.manifests {
		tags = append(tags, identifier)
	}
	sort.Strings(tags)
	return tags, nil
}

func TestScanRunsAgainstAnyBlobSource(t *testing.T) {
	layer := gzipLayer(t, []tarEntry{{name: "app/.env", body: "GH_TOKEN=ghp_123456789012345678901234567890123456"}})
	config := []byte(`{"architecture":"amd64","os":"linux","config":{"Env":["A=b"]}}`)
	configDescriptor := descriptorFor(t, manifest.MediaTypeOCIImageConfig, config)
	layerDescriptor := descriptorFor(t, manifest.MediaTypeOCIImageLayerGzip, layer)
	body := mustJSON(t, manifest.ImageManifest{
		SchemaVersion: 2,
		MediaType:     manifest.MediaTypeOCIImageManifest,
		Config:        configDescriptor,
		Layers:        []manifest.Descriptor{layerDescriptor},
	})
	source := &memorySource{
		manifests: map[string][]byte{"latest": body},
		blobs:     map[string][]byte{configDescriptor.Digest: config, layerDescriptor.Digest: layer},
	}
	ref, err := manifest.ParseReference("library/app:latest")
	if err != nil {
		t.Fatal(err)
	}

	result, err := Scan(context.Background(), Request{Reference: ref, Registry: source, Detectors: detectors.Default(), MaxFileBytes: 1 << 20})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if result.Status != ResultStatusCompleted || result.TotalFindings != 1 {
		t.Fatalf("result = %+v", result)
	}
	if result.ResolvedReference != "docker.io/library/app@"+digestFor(t, body) {
		t.Fatalf("resolved reference = %q", result.ResolvedReference)
	}
	if len(source.opened) != 2 {
		t.Fatalf("opened blobs = %v", source.opened)
	}

	// A blob whose bytes do not match its descriptor is refused by the
	// verifying reader regardless of what the source reports.
	source.blobs[layerDescriptor.Digest] = append([]byte{}, layer[:len(layer)-1]...)
	result, err = Scan(context.Background(), Request{Reference: ref, Registry: source, Detectors: detectors.Default(), MaxFileBytes: 1 << 20})
	if err == nil || !manifest.IsIntegrityError(err) || result.Status != ResultStatusFailed {
		t.Fatalf("tampered layer: result=%+v err=%v", result.Status, err)
	}
}
