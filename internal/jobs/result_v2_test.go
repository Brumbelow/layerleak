package jobs

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/detectors"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
	"github.com/brumbelow/layerleak/v3/internal/registry"
)

// sweepFixture serves a three-tag repository whose tags resolve to three
// distinct single-platform manifests. The first tag carries one env finding.
type sweepFixture struct {
	digests   []string
	transport repoRoundTripFunc
}

func newSweepFixture(t *testing.T) sweepFixture {
	t.Helper()
	configs := [][]byte{
		[]byte(`{"architecture":"amd64","os":"linux","config":{"Env":["GH_TOKEN=ghp_123456789012345678901234567890123456"]}}`),
		[]byte(`{"architecture":"amd64","os":"linux","config":{"Env":["PLAIN=value"]}}`),
		[]byte(`{"architecture":"amd64","os":"linux","config":{"Env":["OTHER=value"]}}`),
	}
	tags := []string{"1.0", "2.0", "3.0"}
	routes := make(map[string]func() *http.Response)
	digests := make([]string, 0, len(configs))
	for index, configBody := range configs {
		config := testDescriptor(t, manifest.MediaTypeOCIImageConfig, configBody)
		manifestBody := testManifestBody(t, config, nil)
		digest := testDescriptor(t, manifest.MediaTypeOCIImageManifest, manifestBody).Digest
		digests = append(digests, digest)
		manifestResponse := func() *http.Response {
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, manifestBody, map[string]string{"Docker-Content-Digest": digest})
		}
		routes["HEAD /v2/library/app/manifests/"+tags[index]] = func() *http.Response {
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, nil, map[string]string{"Docker-Content-Digest": digest})
		}
		routes["GET /v2/library/app/manifests/"+tags[index]] = manifestResponse
		routes["GET /v2/library/app/manifests/"+digest] = manifestResponse
		routes["GET /v2/library/app/blobs/"+config.Digest] = func() *http.Response {
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, configBody, nil)
		}
	}
	transport := repoRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/v2/library/app/tags/list" {
			return repoResponse(http.StatusOK, "application/json", []byte(`{"name":"library/app","tags":["1.0","2.0","3.0","broken"]}`), nil), nil
		}
		if build, ok := routes[request.Method+" "+request.URL.Path]; ok {
			return build(), nil
		}
		return repoResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
	})
	return sweepFixture{digests: digests, transport: transport}
}

func sweepRequest(t *testing.T, fixture sweepFixture) Request {
	t.Helper()
	ref, err := manifest.ParseReference("library/app")
	if err != nil {
		t.Fatalf("ParseReference() error = %v", err)
	}
	return Request{
		Reference: ref,
		AllTags:   true,
		Registry: registry.MustNewClient(registry.Options{
			BaseURL:           "https://registry.test",
			AllowPrivateHosts: true,
			RequestAttempts:   1,
			HTTPClient:        &http.Client{Transport: fixture.transport},
		}),
		Detectors:      detectors.Default(),
		MaxFileBytes:   1 << 20,
		TagPageSize:    100,
		ScannerVersion: "v3.0.0-test",
		Now:            func() time.Time { return time.Date(2026, time.October, 1, 12, 0, 0, 500, time.FixedZone("x", 3600)) },
	}
}

func TestScanRepositoryStoppedEarlyAccountsForEveryTarget(t *testing.T) {
	fixture := newSweepFixture(t)
	request := sweepRequest(t, fixture)
	request.MaxFindings = 1

	result, err := Scan(context.Background(), request)
	if err == nil || !IsIncomplete(err) {
		t.Fatalf("Scan() error = %v", err)
	}
	if result.TargetCount != 3 || len(result.Targets) != 3 {
		t.Fatalf("target_count=%d len(targets)=%d", result.TargetCount, len(result.Targets))
	}
	if sum := result.CompletedTargetCount + result.PartialTargetCount + result.FailedTargetCount; sum != result.TargetCount {
		t.Fatalf("completed+partial+failed = %d, want %d", sum, result.TargetCount)
	}
	if result.CompletedTargetCount != 1 || result.FailedTargetCount != 2 {
		t.Fatalf("completed=%d failed=%d", result.CompletedTargetCount, result.FailedTargetCount)
	}
	statuses := map[string]TagStatus{}
	for _, item := range result.TagResults {
		statuses[item.Tag] = item.Status
	}
	want := map[string]TagStatus{"1.0": TagStatusScanned, "2.0": TagStatusSkipped, "3.0": TagStatusSkipped, "broken": TagStatusFailed}
	for tag, status := range want {
		if statuses[tag] != status {
			t.Fatalf("tag %s status = %q, want %q (all: %#v)", tag, statuses[tag], status, result.TagResults)
		}
	}
	for _, target := range result.Targets[1:] {
		if target.Status != ResultStatusFailed || !strings.Contains(target.Error, "not scanned") {
			t.Fatalf("unscanned target = %#v", target)
		}
	}
	if result.Status != ResultStatusPartial {
		t.Fatalf("status = %q", result.Status)
	}
}

func TestScanRepositoryUpdatesTagStatusAfterEachTarget(t *testing.T) {
	fixture := newSweepFixture(t)
	result, err := Scan(context.Background(), sweepRequest(t, fixture))
	if err == nil || !IsIncomplete(err) {
		t.Fatalf("Scan() error = %v", err)
	}
	for _, item := range result.TagResults {
		switch item.Tag {
		case "broken":
			if item.Status != TagStatusFailed || item.Error == "" {
				t.Fatalf("broken tag = %#v", item)
			}
		default:
			if item.Status != TagStatusScanned {
				t.Fatalf("tag %s status = %q", item.Tag, item.Status)
			}
		}
	}
	if result.ResultSchemaVersion != 2 {
		t.Fatalf("result_schema_version = %d", result.ResultSchemaVersion)
	}
	if result.Scanner.Name != "layerleak" || result.Scanner.Version != "v3.0.0-test" {
		t.Fatalf("scanner = %#v", result.Scanner)
	}
	if got := result.ScannedAt.Format(time.RFC3339Nano); got != "2026-10-01T11:00:00Z" {
		t.Fatalf("scanned_at = %s", got)
	}
}

func TestScanSingleReferenceReportsTagResultsWithoutEnumeration(t *testing.T) {
	fixture := newSweepFixture(t)
	request := sweepRequest(t, fixture)
	request.AllTags = false
	ref, err := manifest.ParseReference("library/app:1.0")
	if err != nil {
		t.Fatal(err)
	}
	request.Reference = ref

	result, err := Scan(context.Background(), request)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if result.TagsEnumerated != 0 || result.TagsResolved != 0 || result.TagsFailed != 0 {
		t.Fatalf("reference mode enumerated tags: %d/%d/%d", result.TagsEnumerated, result.TagsResolved, result.TagsFailed)
	}
	if len(result.TagResults) != 1 || result.TagResults[0].Tag != "1.0" || result.TagResults[0].Status != TagStatusScanned || result.TagResults[0].RootDigest != fixture.digests[0] {
		t.Fatalf("tag_results = %#v", result.TagResults)
	}
	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"tags_enumerated":0`, `"tags_resolved":0`, `"tags_failed":0`, `"suppressed_findings_count":0`, `"suppressed_unique_fingerprints":0`, `"scanned_at":"2026-10-01T11:00:00Z"`, `"scanner":{"name":"layerleak","version":"v3.0.0-test"}`, `"result_schema_version":2`} {
		if !strings.Contains(string(payload), key) {
			t.Fatalf("payload missing %s: %s", key, payload)
		}
	}
	if strings.Contains(string(payload), `"platform":{}`) {
		t.Fatalf("payload carries an empty platform object: %s", payload)
	}
}

func TestScanProgressCountsPartialTargetsAndResolvedTagsOnce(t *testing.T) {
	fixture := newSweepFixture(t)
	request := sweepRequest(t, fixture)
	var updates []ProgressUpdate
	request.Progress = func(update ProgressUpdate) { updates = append(updates, update) }
	if _, err := Scan(context.Background(), request); err == nil {
		t.Fatal("Scan() error = nil, want incomplete (broken tag)")
	}
	targetDone := 0
	for _, update := range updates {
		if update.Phase == ProgressPhaseResolvingTags && update.TagsCompleted+update.TagsFailed > update.TagsTotal {
			t.Fatalf("resolving update double-counts failed tags: %+v", update)
		}
		if update.Phase == ProgressPhaseTargetDone {
			targetDone++
		}
		if update.Phase == ProgressPhaseTargetFailed {
			t.Fatalf("no target failed in this sweep, got %+v", update)
		}
	}
	if targetDone != 3 {
		t.Fatalf("target_done updates = %d, want one per target", targetDone)
	}
	last := updates[len(updates)-1]
	if last.Phase != ProgressPhaseCompleted || last.TagsCompleted != 3 || last.TagsFailed != 1 || last.TagsTotal != 4 {
		t.Fatalf("final update = %+v", last)
	}
	if last.TargetsCompleted+last.TargetsPartial+last.TargetsFailed != last.TargetsTotal {
		t.Fatalf("final update target counts do not add up: %+v", last)
	}
}
