package jobs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/brumbelow/layerleak/v3/internal/detectors"
	"github.com/brumbelow/layerleak/v3/internal/limits"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
	"github.com/brumbelow/layerleak/v3/internal/registry"
)

// memorySource is an in-memory BlobSource for the scan paths that need a
// tag to resolve oddly or a blob read to fail at a chosen moment.
type memorySource struct {
	tags       []string
	manifests  map[string]registry.ManifestResponse
	blobs      map[string][]byte
	resolve    map[string]registry.ManifestMetadata
	onOpenBlob func(digest string) error
}

func newMemorySource(tags ...string) *memorySource {
	return &memorySource{
		tags:      tags,
		manifests: make(map[string]registry.ManifestResponse),
		blobs:     make(map[string][]byte),
		resolve:   make(map[string]registry.ManifestMetadata),
	}
}

func (s *memorySource) FetchManifest(_ context.Context, _, identifier string) (registry.ManifestResponse, error) {
	if response, ok := s.manifests[identifier]; ok {
		return response, nil
	}
	return registry.ManifestResponse{}, fmt.Errorf("manifest %s not found", identifier)
}

func (s *memorySource) ResolveManifest(_ context.Context, _, identifier string) (registry.ManifestMetadata, error) {
	if metadata, ok := s.resolve[identifier]; ok {
		return metadata, nil
	}
	if response, ok := s.manifests[identifier]; ok {
		return registry.ManifestMetadata{Digest: response.Digest, MediaType: response.MediaType}, nil
	}
	return registry.ManifestMetadata{}, fmt.Errorf("tag %s not found", identifier)
}

func (s *memorySource) OpenBlob(_ context.Context, _, digest string) (registry.BlobResponse, error) {
	if s.onOpenBlob != nil {
		if err := s.onOpenBlob(digest); err != nil {
			return registry.BlobResponse{}, err
		}
	}
	body, ok := s.blobs[digest]
	if !ok {
		return registry.BlobResponse{}, fmt.Errorf("blob %s not found", digest)
	}
	return registry.BlobResponse{Digest: digest, Size: int64(len(body)), Body: io.NopCloser(bytes.NewReader(body))}, nil
}

func (s *memorySource) ListTags(context.Context, string, int, int) ([]string, error) {
	return slices.Clone(s.tags), nil
}

// addManifest stores an image manifest for configBody and returns its
// descriptor and its config's digest.
func (s *memorySource) addManifest(t *testing.T, configBody string) (manifest.Descriptor, string) {
	t.Helper()
	config := testDescriptor(t, manifest.MediaTypeOCIImageConfig, []byte(configBody))
	s.blobs[config.Digest] = []byte(configBody)
	body := testManifestBody(t, config, nil)
	descriptor := testDescriptor(t, manifest.MediaTypeOCIImageManifest, body)
	s.manifests[descriptor.Digest] = registry.ManifestResponse{Digest: descriptor.Digest, MediaType: descriptor.MediaType, Size: descriptor.Size, Body: body}
	return descriptor, config.Digest
}

// addImage tags a single-platform image.
func (s *memorySource) addImage(t *testing.T, tag, configBody string) {
	t.Helper()
	descriptor, _ := s.addManifest(t, configBody)
	s.manifests[tag] = s.manifests[descriptor.Digest]
}

// addIndex tags an image index whose platforms are scanned in the given
// order, and returns their config digests.
func (s *memorySource) addIndex(t *testing.T, tag string, configBodies ...string) []string {
	t.Helper()
	architectures := []string{"amd64", "arm64", "s390x"}
	descriptors := make([]manifest.Descriptor, 0, len(configBodies))
	configDigests := make([]string, 0, len(configBodies))
	for index, configBody := range configBodies {
		descriptor, configDigest := s.addManifest(t, configBody)
		descriptor.Platform = manifest.Platform{OS: "linux", Architecture: architectures[index]}
		descriptors = append(descriptors, descriptor)
		configDigests = append(configDigests, configDigest)
	}
	body, err := json.Marshal(manifest.ImageIndex{SchemaVersion: 2, MediaType: manifest.MediaTypeOCIImageIndex, Manifests: descriptors})
	if err != nil {
		t.Fatal(err)
	}
	index := testDescriptor(t, manifest.MediaTypeOCIImageIndex, body)
	response := registry.ManifestResponse{Digest: index.Digest, MediaType: index.MediaType, Size: index.Size, Body: body}
	s.manifests[index.Digest] = response
	s.manifests[tag] = response
	return configDigests
}

func memoryRequest(t *testing.T, source *memorySource, reference string, allTags bool) Request {
	t.Helper()
	ref, err := manifest.ParseReference(reference)
	if err != nil {
		t.Fatal(err)
	}
	return Request{
		Reference:      ref,
		AllTags:        allTags,
		Registry:       source,
		Detectors:      detectors.Default(),
		MaxFileBytes:   1 << 20,
		TagPageSize:    100,
		ScannerVersion: "v3.0.0-test",
	}
}

func platformConfig(architecture, env string) string {
	return `{"architecture":"` + architecture + `","os":"linux","config":{"Env":["` + env + `"]}}`
}

// TestScanRepositoryWithoutScannableTags covers a sweep whose tags all fail
// to resolve, one of them to an empty digest.
func TestScanRepositoryWithoutScannableTags(t *testing.T) {
	source := newMemorySource("a", "b")
	source.resolve["a"] = registry.ManifestMetadata{Digest: "  "}

	result, err := Scan(context.Background(), memoryRequest(t, source, "library/app", true))
	if err == nil || err.Error() != "repository library/app did not resolve any scannable tags" {
		t.Fatalf("Scan() error = %v", err)
	}
	want := []TagResult{
		{Tag: "a", Status: TagStatusFailed, Error: "resolved digest is empty"},
		{Tag: "b", Status: TagStatusFailed, Error: "tag b not found"},
	}
	if !slices.Equal(result.TagResults, want) {
		t.Fatalf("TagResults = %#v, want %#v", result.TagResults, want)
	}
	if result.TagsEnumerated != 2 || result.TagsFailed != 2 || result.TagsResolved != 0 || result.TargetCount != 0 || len(result.Targets) != 0 {
		t.Fatalf("counters = %+v", result)
	}
	if result.Status != ResultStatusFailed || result.ResultSchemaVersion != ResultSchemaVersion {
		t.Fatalf("status = %q, schema = %d", result.Status, result.ResultSchemaVersion)
	}
}

// TestScanRepositoryStopsWhenATargetReachesMaxFindings covers a target that
// itself exhausts the findings budget: the sweep stops after it and accounts
// for the targets it did not reach.
func TestScanRepositoryStopsWhenATargetReachesMaxFindings(t *testing.T) {
	source := newMemorySource("1.0", "2.0")
	source.addImage(t, "1.0", `{"architecture":"amd64","os":"linux","config":{"Env":["GH_TOKEN=ghp_123456789012345678901234567890123456","NPM_TOKEN=npm_123456789012345678901234567890123456"]}}`)
	source.addImage(t, "2.0", platformConfig("amd64", "PLAIN=value"))
	request := memoryRequest(t, source, "library/app", true)
	request.MaxFindings = 1

	result, err := Scan(context.Background(), request)
	if !IsIncomplete(err) {
		t.Fatalf("Scan() error = %v", err)
	}
	if !hasDiagnosticCode(result.Diagnostics, "max_findings_exceeded") || result.TotalFindings != 1 {
		t.Fatalf("diagnostics = %#v, findings = %d", result.Diagnostics, result.TotalFindings)
	}
	if len(result.Targets) != 2 || result.Targets[0].Status != ResultStatusPartial || result.Targets[1].Status != ResultStatusFailed {
		t.Fatalf("targets = %#v", result.Targets)
	}
	if !strings.Contains(result.Targets[1].Error, "scan reached the max findings limit") {
		t.Fatalf("unscanned target error = %q", result.Targets[1].Error)
	}
	if result.TargetCount != 2 || result.PartialTargetCount != 1 || result.CompletedTargetCount != 0 || result.FailedTargetCount != 1 {
		t.Fatalf("target counts = %d/%d/%d/%d", result.TargetCount, result.CompletedTargetCount, result.PartialTargetCount, result.FailedTargetCount)
	}
	if result.TagResults[0].Status != TagStatusPartial || result.TagResults[1].Status != TagStatusSkipped {
		t.Fatalf("tag results = %#v", result.TagResults)
	}
}

// TestScanRepositoryCountsAFailedTargetWithCompletedManifestsAsPartial covers
// a target whose second platform hits a limit after the first completed: the
// target is partial, and the limit stops the sweep.
func TestScanRepositoryCountsAFailedTargetWithCompletedManifestsAsPartial(t *testing.T) {
	source := newMemorySource("1.0", "2.0")
	source.addIndex(t, "1.0", platformConfig("amd64", "A=1"), platformConfig("arm64", "LONG_VALUE="+strings.Repeat("x", 512)))
	source.addImage(t, "2.0", platformConfig("amd64", "PLAIN=value"))
	request := memoryRequest(t, source, "library/app", true)
	request.MaxConfigBytes = 256

	result, err := Scan(context.Background(), request)
	if !limits.IsExceeded(err) {
		t.Fatalf("Scan() error = %v", err)
	}
	if result.PartialTargetCount != 1 || result.FailedTargetCount != 1 || result.CompletedTargetCount != 0 || result.TargetCount != 2 {
		t.Fatalf("target counts = %d/%d/%d/%d", result.TargetCount, result.CompletedTargetCount, result.PartialTargetCount, result.FailedTargetCount)
	}
	if result.Targets[0].Error != err.Error() || result.Targets[0].CompletedManifestCount != 1 || result.Targets[0].FailedManifestCount != 1 {
		t.Fatalf("first target = %#v", result.Targets[0])
	}
	if result.TagResults[0].Status != TagStatusPartial || result.TagResults[0].Error != err.Error() || result.TagResults[1].Status != TagStatusSkipped {
		t.Fatalf("tag results = %#v", result.TagResults)
	}
}

// TestScanSingleReferenceReportsIncompleteAfterACompletedManifest covers a
// reference scan that fails with an ordinary error after one platform
// completed: the result is kept and the error is an IncompleteError.
func TestScanSingleReferenceReportsIncompleteAfterACompletedManifest(t *testing.T) {
	source := newMemorySource()
	configDigests := source.addIndex(t, "1.0", platformConfig("amd64", "A=1"), platformConfig("arm64", "B=2"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	unavailable := errors.New("blob store unavailable")
	source.onOpenBlob = func(digest string) error {
		if digest == configDigests[1] {
			cancel()
			return unavailable
		}
		return nil
	}

	result, err := Scan(ctx, memoryRequest(t, source, "library/app:1.0", false))
	var incomplete *IncompleteError
	if !errors.As(err, &incomplete) || !errors.Is(err, unavailable) || incomplete.Status != ResultStatusPartial {
		t.Fatalf("Scan() error = %v", err)
	}
	if incomplete.CompletedManifestCount != 1 || incomplete.FailedManifestCount != 1 {
		t.Fatalf("incomplete = %+v", incomplete)
	}
	if result.PartialTargetCount != 1 || result.CompletedTargetCount != 0 || result.FailedTargetCount != 0 || result.Status != ResultStatusPartial {
		t.Fatalf("result = %+v", result)
	}
	cause := incomplete.Cause.Error()
	if result.Targets[0].Error != cause || len(result.TagResults) != 1 || result.TagResults[0].Status != TagStatusPartial || result.TagResults[0].Error != cause {
		t.Fatalf("targets = %#v, tag results = %#v", result.Targets, result.TagResults)
	}
}
