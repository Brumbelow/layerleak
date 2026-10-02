package jobs

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/brumbelow/layerleak/v3/internal/detectors"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
	"github.com/brumbelow/layerleak/v3/internal/registry"
)

// sharedLayerRepository is a synthetic registry for library/app with N tags
// whose manifests share K base layers and each add one unique top layer. One
// shared layer carries a (synthetic) secret so it is never cacheable; the
// others are clean and exercise UTF-16 text, binaries, symlinks, a same-layer
// hardlink to text, whiteouts and opaque directories.
type sharedLayerRepository struct {
	transport http.RoundTripper
	mu        sync.Mutex
	blobOpens map[string]int
	layers    map[string]string // digest -> role
}

func utf16LEWithBOM(text string) string {
	units := utf16.Encode([]rune(text))
	buffer := make([]byte, 2, 2+2*len(units))
	buffer[0], buffer[1] = 0xFF, 0xFE
	for _, unit := range units {
		buffer = binary.LittleEndian.AppendUint16(buffer, unit)
	}
	return string(buffer)
}

func newSharedLayerRepository(tb testing.TB, tags, sharedLayers int) *sharedLayerRepository {
	tb.Helper()
	repo := &sharedLayerRepository{blobOpens: make(map[string]int), layers: make(map[string]string)}
	blobs := make(map[string][]byte)
	blobTypes := make(map[string]string)
	addBlob := func(mediaType string, body []byte) manifest.Descriptor {
		descriptor := testDescriptor(tb, mediaType, body)
		blobs[descriptor.Digest] = body
		blobTypes[descriptor.Digest] = mediaType
		return descriptor
	}

	shared := make([]manifest.Descriptor, 0, sharedLayers)
	for i := 0; i < sharedLayers; i++ {
		var entries []tarEntry
		role := fmt.Sprintf("shared-%d", i)
		switch i % 3 {
		case 0:
			entries = []tarEntry{
				{name: "etc/", typeflag: tar.TypeDir},
				{name: fmt.Sprintf("etc/os-release-%d", i), body: "NAME=test\nID=test\n"},
				{name: fmt.Sprintf("etc/win-%d.ini", i), body: utf16LEWithBOM("[settings]\r\nmode=plain\r\n")},
				{name: fmt.Sprintf("usr/lib/lib%d.so", i), body: "\x7fELF\x02\x01\x01\x00" + strings.Repeat("\x00\x01", 64)},
				{name: fmt.Sprintf("etc/alias-%d", i), typeflag: tar.TypeSymlink, linkname: fmt.Sprintf("os-release-%d", i)},
				{name: fmt.Sprintf("etc/same-%d", i), typeflag: tar.TypeLink, linkname: fmt.Sprintf("etc/os-release-%d", i)},
			}
		case 1:
			// The one layer with a finding: synthetic token shape only.
			role = fmt.Sprintf("shared-%d-secret", i)
			entries = []tarEntry{
				{name: fmt.Sprintf("app/%d/config.env", i), body: "GH_TOKEN=ghp_123456789012345678901234567890123456\n"},
				{name: fmt.Sprintf("app/%d/clean.txt", i), body: "nothing to see\n"},
			}
		default:
			entries = []tarEntry{
				{name: fmt.Sprintf("opt/data-%d/", i), typeflag: tar.TypeDir},
				{name: fmt.Sprintf("opt/data-%d/notes.txt", i), body: strings.Repeat("line of plain text\n", 40)},
				{name: fmt.Sprintf("opt/data-%d/blob.bin", i), body: strings.Repeat("\x00", 4096)},
				{name: fmt.Sprintf("opt/data-%d/empty", i), body: ""},
			}
		}
		descriptor := addBlob(manifest.MediaTypeDockerSchema2LayerGzip, gzipLayer(tb, entries))
		repo.layers[descriptor.Digest] = role
		shared = append(shared, descriptor)
	}

	tagNames := make([]string, 0, tags)
	manifests := make(map[string][]byte)
	tagDigests := make(map[string]string)
	for i := 0; i < tags; i++ {
		tag := fmt.Sprintf("v%d", i)
		tagNames = append(tagNames, tag)
		top := []tarEntry{{name: "app/version.txt", body: "version=" + tag + "\n"}}
		if i%2 == 1 && sharedLayers > 1 {
			// Every other tag deletes a clean file of a shared layer, so cached
			// content is reported as deleted-layer content.
			top = append(top, tarEntry{name: "app/1/.wh.clean.txt"})
		}
		if i%3 == 2 && sharedLayers > 0 {
			top = append(top, tarEntry{name: "etc/.wh..wh..opq"})
		}
		topLayer := addBlob(manifest.MediaTypeDockerSchema2LayerGzip, gzipLayer(tb, top))
		repo.layers[topLayer.Digest] = "top-" + tag
		configBody := []byte(fmt.Sprintf(`{"architecture":"amd64","os":"linux","config":{"Env":["TAG=%s"]}}`, tag))
		config := addBlob(manifest.MediaTypeOCIImageConfig, configBody)
		body := testManifestBody(tb, config, append(append([]manifest.Descriptor(nil), shared...), topLayer))
		digest := testDescriptor(tb, manifest.MediaTypeOCIImageManifest, body).Digest
		manifests[digest] = body
		tagDigests[tag] = digest
	}
	repo.serve(tb, blobs, blobTypes, tagNames, manifests, tagDigests)
	return repo
}

// serve installs the registry transport for library/app over the given
// blobs, manifests and tag list.
func (r *sharedLayerRepository) serve(tb testing.TB, blobs map[string][]byte, blobTypes map[string]string, tagNames []string, manifests map[string][]byte, tagDigests map[string]string) {
	tb.Helper()
	tagList, err := json.Marshal(map[string]any{"name": "library/app", "tags": tagNames})
	if err != nil {
		tb.Fatalf("Marshal() error = %v", err)
	}

	r.transport = repoRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "auth.test" {
			body, _ := json.Marshal(map[string]string{"token": "test-token"})
			return repoResponse(http.StatusOK, "application/json", body, nil), nil
		}
		if request.Header.Get("Authorization") != "Bearer test-token" {
			return repoResponse(http.StatusUnauthorized, "", nil, map[string]string{
				"Www-Authenticate": `Bearer realm="https://auth.test/token",service="registry.test",scope="repository:library/app:pull"`,
			}), nil
		}
		path := request.URL.Path
		switch {
		case path == "/v2/library/app/tags/list":
			return repoResponse(http.StatusOK, "application/json", tagList, nil), nil
		case strings.HasPrefix(path, "/v2/library/app/manifests/"):
			reference := strings.TrimPrefix(path, "/v2/library/app/manifests/")
			digest := reference
			if resolved, ok := tagDigests[reference]; ok {
				digest = resolved
			}
			body, ok := manifests[digest]
			if !ok {
				return repoResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
			}
			if request.Method == http.MethodHead {
				body = nil
			}
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, body, map[string]string{"Docker-Content-Digest": digest}), nil
		case strings.HasPrefix(path, "/v2/library/app/blobs/"):
			digest := strings.TrimPrefix(path, "/v2/library/app/blobs/")
			body, ok := blobs[digest]
			if !ok {
				return repoResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
			}
			r.mu.Lock()
			r.blobOpens[digest]++
			r.mu.Unlock()
			return repoResponse(http.StatusOK, blobTypes[digest], body, nil), nil
		default:
			return repoResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
		}
	})
}

func (r *sharedLayerRepository) request(tb testing.TB, cacheBytes int64) Request {
	tb.Helper()
	ref, err := manifest.ParseReference("library/app")
	if err != nil {
		tb.Fatalf("ParseReference() error = %v", err)
	}
	return Request{
		Reference: ref,
		AllTags:   true,
		Registry: registry.MustNewClient(registry.Options{
			BaseURL:           "https://registry.test",
			AllowPrivateHosts: true,
			HTTPClient:        &http.Client{Transport: r.transport},
		}),
		Detectors:          detectors.Default(),
		MaxFileBytes:       1 << 20,
		MaxLayerBytes:      64 << 20,
		MaxLayerEntries:    50000,
		MaxRetainedBytes:   64 << 20,
		MaxFindings:        10000,
		TagPageSize:        100,
		MaxLayerCacheBytes: cacheBytes,
		Now:                func() time.Time { return time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC) },
	}
}

// opensByRole returns the blob fetch count per layer role, resetting the
// counters.
func (r *sharedLayerRepository) opensByRole() map[string]int {
	r.mu.Lock()
	defer r.mu.Unlock()
	opens := make(map[string]int)
	for digest, count := range r.blobOpens {
		if role, ok := r.layers[digest]; ok {
			opens[role] = count
		}
	}
	r.blobOpens = make(map[string]int)
	return opens
}

func sweepJSON(tb testing.TB, repo *sharedLayerRepository, cacheBytes int64) ([]byte, Result) {
	tb.Helper()
	result, err := Scan(context.Background(), repo.request(tb, cacheBytes))
	if err != nil {
		tb.Fatalf("Scan(cache=%d) error = %v", cacheBytes, err)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		tb.Fatalf("Marshal() error = %v", err)
	}
	return encoded, result
}

// newLayerStackRepository serves library/app with one tag per stack; a stack
// names its layers, bottom first, as comma-separated roles.
func newLayerStackRepository(tb testing.TB, layerEntries map[string][]tarEntry, stacks [][2]string) *sharedLayerRepository {
	tb.Helper()
	repo := &sharedLayerRepository{blobOpens: make(map[string]int), layers: make(map[string]string)}
	blobs := make(map[string][]byte)
	blobTypes := make(map[string]string)
	byRole := make(map[string]manifest.Descriptor)
	roles := make([]string, 0, len(layerEntries))
	for role := range layerEntries {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	for _, role := range roles {
		body := gzipLayer(tb, layerEntries[role])
		descriptor := testDescriptor(tb, manifest.MediaTypeDockerSchema2LayerGzip, body)
		blobs[descriptor.Digest] = body
		blobTypes[descriptor.Digest] = manifest.MediaTypeDockerSchema2LayerGzip
		repo.layers[descriptor.Digest] = role
		byRole[role] = descriptor
	}
	tagNames := make([]string, 0, len(stacks))
	manifests := make(map[string][]byte)
	tagDigests := make(map[string]string)
	for _, stack := range stacks {
		tag := stack[0]
		tagNames = append(tagNames, tag)
		descriptors := make([]manifest.Descriptor, 0)
		for _, role := range strings.Split(stack[1], ",") {
			descriptors = append(descriptors, byRole[role])
		}
		configBody := []byte(fmt.Sprintf(`{"architecture":"amd64","os":"linux","config":{"Env":["TAG=%s"]}}`, tag))
		config := testDescriptor(tb, manifest.MediaTypeOCIImageConfig, configBody)
		blobs[config.Digest] = configBody
		blobTypes[config.Digest] = manifest.MediaTypeOCIImageConfig
		body := testManifestBody(tb, config, descriptors)
		digest := testDescriptor(tb, manifest.MediaTypeOCIImageManifest, body).Digest
		manifests[digest] = body
		tagDigests[tag] = digest
	}
	repo.serve(tb, blobs, blobTypes, tagNames, manifests, tagDigests)
	return repo
}

// TestScanRepositoryLayerCacheScansHardlinksRecordedWithoutTarget is the
// regression for a cached layer whose hardlink had no regular-file target in
// the stack it was recorded in (a missing target, or a directory). Replayed
// onto a stack where the target is a clean cached file, the hardlink's own
// path was never scanned, so the path-sensitive .netrc credential was lost
// while coverage reported complete. The cached sweep must report exactly
// what the uncached sweep reports.
func TestScanRepositoryLayerCacheScansHardlinksRecordedWithoutTarget(t *testing.T) {
	// Synthetic credential, assembled at run time.
	netrc := "machine example.com login deploy " + "pass" + "word " + "Sup3r" + "S3cret" + "Passw0rd\n"
	for _, tc := range []struct {
		name  string
		lower []tarEntry
	}{
		{name: "missing target", lower: []tarEntry{{name: "other.txt", body: "plain text\n"}}},
		{name: "directory target", lower: []tarEntry{{name: "app/", typeflag: tar.TypeDir}, {name: "app/notes.txt/", typeflag: tar.TypeDir}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := newLayerStackRepository(t, map[string][]tarEntry{
				"X": tc.lower,
				"L": {{name: ".netrc", typeflag: tar.TypeLink, linkname: "app/notes.txt"}},
				"B": {{name: "app/", typeflag: tar.TypeDir}, {name: "app/notes.txt", body: netrc}},
			}, [][2]string{{"a", "X,L"}, {"b", "B"}, {"c", "B,L"}})

			sweep := func(cacheBytes int64) ([]byte, Result) {
				result, err := Scan(context.Background(), repo.request(t, cacheBytes))
				if err != nil && !IsIncomplete(err) {
					t.Fatalf("Scan(cache=%d) error = %v", cacheBytes, err)
				}
				encoded, err := json.Marshal(result)
				if err != nil {
					t.Fatalf("Marshal() error = %v", err)
				}
				return encoded, result
			}
			findingsFor := func(result Result, tag string) int {
				for _, target := range result.Targets {
					if slices.Contains(target.Tags, tag) {
						return target.FindingsCount
					}
				}
				t.Fatalf("no target for tag %s", tag)
				return 0
			}
			withoutCache, cold := sweep(0)
			withCache, warm := sweep(64 << 20)
			if got := findingsFor(cold, "c"); got != 1 {
				t.Fatalf("uncached sweep: tag c findings = %d, want 1", got)
			}
			if got := findingsFor(warm, "c"); got != 1 {
				t.Fatalf("cached sweep: tag c findings = %d, want 1 (the .netrc hardlink was not scanned)", got)
			}
			if !bytes.Equal(withoutCache, withCache) {
				t.Fatalf("results differ with the layer cache:\n without: %s\n with:    %s", withoutCache, withCache)
			}
		})
	}
}

// TestScanRepositoryLayerCacheIsByteIdentical is the mandatory property of
// PRD-19: with and without the sweep cache, and with a cache so small that it
// evicts on every store, the JSON result of an --all-tags sweep over N tags
// sharing K layers is byte for byte the same, while the cache removes the
// repeated fetches of the clean shared layers.
func TestScanRepositoryLayerCacheIsByteIdentical(t *testing.T) {
	const tags, shared = 6, 4
	repo := newSharedLayerRepository(t, tags, shared)

	withoutCache, reference := sweepJSON(t, repo, 0)
	coldOpens := repo.opensByRole()
	if reference.TargetCount != tags || reference.CompletedTargetCount != tags {
		t.Fatalf("targets = %d completed = %d, want %d", reference.TargetCount, reference.CompletedTargetCount, tags)
	}
	if reference.TotalFindings == 0 {
		t.Fatal("the fixture must produce findings")
	}
	for role, count := range coldOpens {
		if strings.HasPrefix(role, "shared-") && count != tags {
			t.Fatalf("without the cache %s was fetched %d times, want %d", role, count, tags)
		}
	}

	withCache, _ := sweepJSON(t, repo, 1<<20)
	if !bytes.Equal(withoutCache, withCache) {
		t.Fatalf("results differ with the layer cache:\n without: %s\n with:    %s", withoutCache, withCache)
	}
	warmOpens := repo.opensByRole()
	roles := make([]string, 0, len(warmOpens))
	for role := range warmOpens {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	for _, role := range roles {
		count := warmOpens[role]
		switch {
		case strings.HasSuffix(role, "-secret"):
			// A layer with a finding is never cached.
			if count != tags {
				t.Fatalf("%s fetched %d times, want %d (never cached)", role, count, tags)
			}
		case strings.HasPrefix(role, "shared-"):
			if count != 1 {
				t.Fatalf("%s fetched %d times, want 1 (cached after the first target)", role, count)
			}
		default:
			if count != 1 {
				t.Fatalf("%s fetched %d times, want 1", role, count)
			}
		}
	}

	// A cache that can hold only one record evicts constantly and still yields
	// the same bytes.
	tiny, _ := sweepJSON(t, repo, 600)
	if !bytes.Equal(withoutCache, tiny) {
		t.Fatalf("results differ with a tiny layer cache:\n without: %s\n tiny:    %s", withoutCache, tiny)
	}
}

// TestScanRepositoryLayerCacheKeepsCoverageIdentical checks that a cached
// sweep reports the same per-target results and the same
// coverage counters (files scanned, UTF-16 transcodes, bytes) as a cold one.
func TestScanRepositoryLayerCacheKeepsCoverageIdentical(t *testing.T) {
	repo := newSharedLayerRepository(t, 3, 3)
	_, cold := sweepJSON(t, repo, 0)
	_, warm := sweepJSON(t, repo, 1<<20)
	if len(cold.Targets) != len(warm.Targets) {
		t.Fatalf("targets differ: %d vs %d", len(cold.Targets), len(warm.Targets))
	}
	for i := range cold.Targets {
		coldJSON, _ := json.Marshal(cold.Targets[i])
		warmJSON, _ := json.Marshal(warm.Targets[i])
		if !bytes.Equal(coldJSON, warmJSON) {
			t.Fatalf("target %d differs:\n cold: %s\n warm: %s", i, coldJSON, warmJSON)
		}
	}
	if cold.Coverage.FilesScanned == 0 || cold.Coverage.FilesTranscodedUTF16 == 0 {
		t.Fatalf("fixture coverage too thin: %+v", cold.Coverage)
	}
}

// BenchmarkRepositorySweepSharedLayers measures an --all-tags sweep over N
// tags sharing K layers with the layer cache off (the default) and on.
func BenchmarkRepositorySweepSharedLayers(b *testing.B) {
	for _, shape := range []struct{ tags, shared int }{{8, 6}, {32, 12}} {
		repo := newSharedLayerRepository(b, shape.tags, shape.shared)
		for _, cacheBytes := range []int64{0, 64 << 20} {
			name := fmt.Sprintf("tags=%d/shared=%d/cache=%d", shape.tags, shape.shared, cacheBytes)
			b.Run(name, func(b *testing.B) {
				request := repo.request(b, cacheBytes)
				b.ReportAllocs()
				for b.Loop() {
					if _, err := Scan(context.Background(), request); err != nil {
						b.Fatalf("Scan() error = %v", err)
					}
				}
			})
		}
	}
}
