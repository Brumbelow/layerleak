package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/brumbelow/layerleak/v3/internal/detectors"
	"github.com/brumbelow/layerleak/v3/internal/limits"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
	"github.com/brumbelow/layerleak/v3/internal/registry"
)

// TestScanRepositoryStopsResolvingTagsAtTheTargetBound serves a repository
// whose twenty tags each resolve to a distinct digest and sweeps it with a
// target bound of five. Resolution stops at the tag that would be the sixth
// target: six manifest requests instead of twenty, the same
// repository_targets limit error and failed status as before, and every
// enumerated tag accounted for in tag_results.
func TestScanRepositoryStopsResolvingTagsAtTheTargetBound(t *testing.T) {
	const tagCount = 20
	const bound = 5
	tags := make([]string, 0, tagCount)
	for index := range tagCount {
		tags = append(tags, fmt.Sprintf("v%02d", index))
	}
	var manifestRequests atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v2/library/app/tags/list" {
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(map[string]any{"name": "library/app", "tags": tags})
			return
		}
		tag, ok := strings.CutPrefix(request.URL.Path, "/v2/library/app/manifests/")
		if !ok {
			http.NotFound(writer, request)
			return
		}
		manifestRequests.Add(1)
		if request.Method != http.MethodHead {
			t.Errorf("tag resolution sent %s %s, want HEAD", request.Method, request.URL.Path)
		}
		writer.Header().Set("Content-Type", manifest.MediaTypeOCIImageManifest)
		writer.Header().Set("Docker-Content-Digest", "sha256:"+strings.Repeat(tag[1:], 32))
		writer.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	ref, err := manifest.ParseReference("library/app")
	if err != nil {
		t.Fatal(err)
	}
	result, err := Scan(context.Background(), Request{
		Reference: ref,
		AllTags:   true,
		Registry: registry.MustNewClient(registry.Options{
			BaseURL:           server.URL,
			AllowPrivateHosts: true,
			RequestAttempts:   1,
			HTTPClient:        server.Client(),
		}),
		Detectors:            detectors.Default(),
		MaxFileBytes:         1 << 20,
		TagPageSize:          100,
		MaxRepositoryTargets: bound,
	})

	var exceeded *limits.ExceededError
	if !errors.As(err, &exceeded) || exceeded.Kind != limits.KindRepositoryTargets || exceeded.Limit != bound {
		t.Fatalf("Scan() error = %v, want the repository_targets limit of %d", err, bound)
	}
	if got := manifestRequests.Load(); got != bound+1 {
		t.Fatalf("manifest requests = %d, want %d (resolution must stop at the first tag past the bound)", got, bound+1)
	}
	if result.Status != ResultStatusFailed || result.TagsEnumerated != tagCount || result.TagsResolved != bound+1 || result.TagsFailed != 0 {
		t.Fatalf("status=%s enumerated=%d resolved=%d failed=%d", result.Status, result.TagsEnumerated, result.TagsResolved, result.TagsFailed)
	}
	if result.TargetCount != bound+1 || len(result.Targets) != 0 || result.ManifestCount != 0 {
		t.Fatalf("target_count=%d targets=%d manifest_count=%d", result.TargetCount, len(result.Targets), result.ManifestCount)
	}
	if len(result.TagResults) != tagCount {
		t.Fatalf("tag_results has %d entries, want every enumerated tag (%d)", len(result.TagResults), tagCount)
	}
	for index, item := range result.TagResults {
		if item.Tag != tags[index] {
			t.Fatalf("tag_results[%d].tag = %q, want %q", index, item.Tag, tags[index])
		}
		if index <= bound {
			if item.Status != TagStatusResolved || item.RootDigest == "" || item.Error != "" {
				t.Fatalf("resolved tag %s = %#v", item.Tag, item)
			}
			continue
		}
		if item.Status != TagStatusSkipped || item.RootDigest != "" || !strings.Contains(item.Error, "not resolved") || !strings.Contains(item.Error, "max repository targets limit of 5") {
			t.Fatalf("unresolved tag %s = %#v", item.Tag, item)
		}
	}
}

// TestScanRepositoryTargetBoundCountsDistinctDigests keeps tags that share a
// digest inside one target: with a bound of two, five tags over two digests
// resolve fully and the sweep is not stopped by the bound.
func TestScanRepositoryTargetBoundCountsDistinctDigests(t *testing.T) {
	tags := []string{"a", "b", "c", "d", "e"}
	var manifestRequests atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v2/library/app/tags/list" {
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(map[string]any{"name": "library/app", "tags": tags})
			return
		}
		tag, ok := strings.CutPrefix(request.URL.Path, "/v2/library/app/manifests/")
		if !ok || request.Method != http.MethodHead {
			http.NotFound(writer, request)
			return
		}
		manifestRequests.Add(1)
		digest := "sha256:" + strings.Repeat("1", 64)
		if tag == "e" {
			digest = "sha256:" + strings.Repeat("2", 64)
		}
		writer.Header().Set("Content-Type", manifest.MediaTypeOCIImageManifest)
		writer.Header().Set("Docker-Content-Digest", digest)
		writer.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	ref, err := manifest.ParseReference("library/app")
	if err != nil {
		t.Fatal(err)
	}
	result, err := Scan(context.Background(), Request{
		Reference: ref,
		AllTags:   true,
		Registry: registry.MustNewClient(registry.Options{
			BaseURL:           server.URL,
			AllowPrivateHosts: true,
			RequestAttempts:   1,
			HTTPClient:        server.Client(),
		}),
		Detectors:            detectors.Default(),
		MaxFileBytes:         1 << 20,
		TagPageSize:          100,
		MaxRepositoryTargets: 2,
	})
	if limits.IsExceeded(err) {
		t.Fatalf("Scan() error = %v: two distinct digests are within a bound of two", err)
	}
	if got := manifestRequests.Load(); got < int64(len(tags)) {
		t.Fatalf("manifest HEAD requests = %d, want every tag resolved", got)
	}
	if result.TagsResolved != len(tags) || result.TargetCount != 2 {
		t.Fatalf("tags_resolved=%d target_count=%d", result.TagsResolved, result.TargetCount)
	}
}
