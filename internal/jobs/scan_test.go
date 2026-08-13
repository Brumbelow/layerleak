package jobs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/brumbelow/layerleak/internal/detectors"
	"github.com/brumbelow/layerleak/internal/findings"
	"github.com/brumbelow/layerleak/internal/manifest"
	"github.com/brumbelow/layerleak/internal/registry"
)

func TestScanRepositoryEnumeratesTagsAndDeduplicatesDigests(t *testing.T) {
	configOneBody := []byte(`{"architecture":"amd64","os":"linux","config":{"Env":["GH_TOKEN=ghp_123456789012345678901234567890123456"]}}`)
	configTwoBody := []byte(`{"architecture":"amd64","os":"linux","config":{"Env":["AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF"]}}`)
	configOne := testDescriptor(t, manifest.MediaTypeOCIImageConfig, configOneBody)
	configTwo := testDescriptor(t, manifest.MediaTypeOCIImageConfig, configTwoBody)
	manifestOneBody := testManifestBody(t, configOne, nil)
	manifestTwoBody := testManifestBody(t, configTwo, nil)
	digestOne := testDescriptor(t, manifest.MediaTypeOCIImageManifest, manifestOneBody).Digest
	digestTwo := testDescriptor(t, manifest.MediaTypeOCIImageManifest, manifestTwoBody).Digest

	transport := repoRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "auth.test" {
			body, _ := json.Marshal(map[string]string{"token": "test-token"})
			return repoResponse(http.StatusOK, "application/json", body, nil), nil
		}
		if request.Header.Get("Authorization") != "Bearer test-token" {
			return repoResponse(http.StatusUnauthorized, "", nil, map[string]string{
				"Www-Authenticate": `Bearer realm="https://auth.test/token",service="registry.test",scope="repository:library/app:pull"`,
			}), nil
		}

		switch {
		case request.URL.Path == "/v2/library/app/tags/list" && request.URL.Query().Get("n") == "2" && request.URL.Query().Get("last") == "":
			return repoResponse(http.StatusOK, "application/json", []byte(`{"name":"library/app","tags":["latest","2.0"]}`), map[string]string{
				"Link": `</v2/library/app/tags/list?n=2&last=2.0>; rel="next"`,
			}), nil
		case request.URL.Path == "/v2/library/app/tags/list" && request.URL.Query().Get("n") == "2" && request.URL.Query().Get("last") == "2.0":
			return repoResponse(http.StatusOK, "application/json", []byte(`{"name":"library/app","tags":["1.0"]}`), nil), nil
		case request.URL.Path == "/v2/library/app/manifests/latest" && request.Method == http.MethodHead:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, nil, map[string]string{
				"Docker-Content-Digest": digestOne,
			}), nil
		case request.URL.Path == "/v2/library/app/manifests/2.0" && request.Method == http.MethodHead:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, nil, map[string]string{
				"Docker-Content-Digest": digestOne,
			}), nil
		case request.URL.Path == "/v2/library/app/manifests/1.0" && request.Method == http.MethodHead:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, nil, map[string]string{
				"Docker-Content-Digest": digestTwo,
			}), nil
		case request.URL.Path == "/v2/library/app/manifests/"+digestOne:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, manifestOneBody, map[string]string{
				"Docker-Content-Digest": digestOne,
			}), nil
		case request.URL.Path == "/v2/library/app/manifests/"+digestTwo:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, manifestTwoBody, map[string]string{
				"Docker-Content-Digest": digestTwo,
			}), nil
		case request.URL.Path == "/v2/library/app/blobs/"+configOne.Digest:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, configOneBody, nil), nil
		case request.URL.Path == "/v2/library/app/blobs/"+configTwo.Digest:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, configTwoBody, nil), nil
		default:
			return repoResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
		}
	})

	ref, err := manifest.ParseReference("library/app")
	if err != nil {
		t.Fatalf("ParseReference() error = %v", err)
	}

	progress := make([]ProgressUpdate, 0)
	result, err := Scan(context.Background(), Request{
		Reference: ref,
		AllTags:   true,
		Registry: registry.NewClient(registry.Options{
			BaseURL:           "https://registry.test",
			AllowPrivateHosts: true,
			HTTPClient: &http.Client{
				Transport: transport,
			},
		}),
		Detectors:    detectors.Default(),
		MaxFileBytes: 1 << 20,
		TagPageSize:  2,
		Progress: func(update ProgressUpdate) {
			progress = append(progress, update)
		},
	})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	if result.Mode != "repository" {
		t.Fatalf("result.Mode = %q", result.Mode)
	}
	if result.TagsEnumerated != 3 {
		t.Fatalf("result.TagsEnumerated = %d", result.TagsEnumerated)
	}
	if result.TagsResolved != 3 {
		t.Fatalf("result.TagsResolved = %d", result.TagsResolved)
	}
	if result.TargetCount != 2 {
		t.Fatalf("result.TargetCount = %d", result.TargetCount)
	}
	if result.CompletedTargetCount != 2 {
		t.Fatalf("result.CompletedTargetCount = %d", result.CompletedTargetCount)
	}
	if len(result.TagResults) != 3 {
		t.Fatalf("len(result.TagResults) = %d", len(result.TagResults))
	}
	if len(result.Targets) != 2 {
		t.Fatalf("len(result.Targets) = %d", len(result.Targets))
	}
	if strings.Join(result.Targets[0].Tags, ",") != "1.0" {
		t.Fatalf("result.Targets[0].Tags = %q", strings.Join(result.Targets[0].Tags, ","))
	}
	if strings.Join(result.Targets[1].Tags, ",") != "2.0,latest" {
		t.Fatalf("result.Targets[1].Tags = %q", strings.Join(result.Targets[1].Tags, ","))
	}
	if result.TotalFindings == 0 {
		t.Fatal("result.TotalFindings = 0")
	}
	assertRawFindingFieldsEmpty(t, result.DetailedFindings)
	assertRawFindingFieldsEmpty(t, result.SuppressedDetailedFindings)
	if len(progress) == 0 {
		t.Fatal("len(progress) = 0")
	}
	if progress[len(progress)-1].Phase != ProgressPhaseCompleted {
		t.Fatalf("progress[len(progress)-1].Phase = %q", progress[len(progress)-1].Phase)
	}
}

func TestScanRepositoryReturnsUnderlyingTargetErrorWhenAllTargetsFail(t *testing.T) {
	configBody := []byte(`{"architecture":"amd64","os":"linux","config":{}}`)
	configDescriptor := testDescriptor(t, manifest.MediaTypeOCIImageConfig, configBody)
	manifestBody := testManifestBody(t, configDescriptor, nil)
	manifestDigest := testDescriptor(t, manifest.MediaTypeOCIImageManifest, manifestBody).Digest

	transport := repoRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "auth.test" {
			body, _ := json.Marshal(map[string]string{"token": "test-token"})
			return repoResponse(http.StatusOK, "application/json", body, nil), nil
		}
		if request.Header.Get("Authorization") != "Bearer test-token" {
			return repoResponse(http.StatusUnauthorized, "", nil, map[string]string{
				"Www-Authenticate": `Bearer realm="https://auth.test/token",service="registry.test",scope="repository:library/app:pull"`,
			}), nil
		}

		switch {
		case request.URL.Path == "/v2/library/app/tags/list":
			return repoResponse(http.StatusOK, "application/json", []byte(`{"name":"library/app","tags":["latest"]}`), nil), nil
		case request.URL.Path == "/v2/library/app/manifests/latest" && request.Method == http.MethodHead:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, nil, map[string]string{
				"Docker-Content-Digest": manifestDigest,
			}), nil
		case request.URL.Path == "/v2/library/app/manifests/"+manifestDigest:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, manifestBody, map[string]string{
				"Docker-Content-Digest": manifestDigest,
			}), nil
		case request.URL.Path == "/v2/library/app/blobs/"+configDescriptor.Digest:
			return repoResponse(http.StatusNotFound, "text/plain", []byte("missing config"), nil), nil
		default:
			return repoResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
		}
	})

	ref, err := manifest.ParseReference("library/app")
	if err != nil {
		t.Fatalf("ParseReference() error = %v", err)
	}

	_, err = Scan(context.Background(), Request{
		Reference: ref,
		AllTags:   true,
		Registry: registry.NewClient(registry.Options{
			BaseURL:           "https://registry.test",
			AllowPrivateHosts: true,
			HTTPClient: &http.Client{
				Transport: transport,
			},
		}),
		Detectors:    detectors.Default(),
		MaxFileBytes: 1 << 20,
		TagPageSize:  100,
	})
	if err == nil {
		t.Fatal("Scan() error = nil")
	}
	if !strings.Contains(err.Error(), "fetch config blob") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "status=404") {
		t.Fatalf("err = %v", err)
	}
}

func TestScanRepositoryReturnsPartialResultWhenTargetLimitExceeded(t *testing.T) {
	digestOne := "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	digestTwo := "sha256:2222222222222222222222222222222222222222222222222222222222222222"

	transport := repoRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "auth.test" {
			body, _ := json.Marshal(map[string]string{"token": "test-token"})
			return repoResponse(http.StatusOK, "application/json", body, nil), nil
		}
		if request.Header.Get("Authorization") != "Bearer test-token" {
			return repoResponse(http.StatusUnauthorized, "", nil, map[string]string{
				"Www-Authenticate": `Bearer realm="https://auth.test/token",service="registry.test",scope="repository:library/app:pull"`,
			}), nil
		}

		switch {
		case request.URL.Path == "/v2/library/app/tags/list":
			return repoResponse(http.StatusOK, "application/json", []byte(`{"name":"library/app","tags":["latest","1.0"]}`), nil), nil
		case request.URL.Path == "/v2/library/app/manifests/latest" && request.Method == http.MethodHead:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, nil, map[string]string{
				"Docker-Content-Digest": digestOne,
			}), nil
		case request.URL.Path == "/v2/library/app/manifests/1.0" && request.Method == http.MethodHead:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, nil, map[string]string{
				"Docker-Content-Digest": digestTwo,
			}), nil
		default:
			return repoResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
		}
	})

	ref, err := manifest.ParseReference("library/app")
	if err != nil {
		t.Fatalf("ParseReference() error = %v", err)
	}

	result, err := Scan(context.Background(), Request{
		Reference: ref,
		AllTags:   true,
		Registry: registry.NewClient(registry.Options{
			BaseURL:           "https://registry.test",
			AllowPrivateHosts: true,
			HTTPClient: &http.Client{
				Transport: transport,
			},
		}),
		Detectors:            detectors.Default(),
		MaxFileBytes:         1 << 20,
		TagPageSize:          100,
		MaxRepositoryTargets: 1,
	})
	if err == nil {
		t.Fatal("Scan() error = nil")
	}
	if !strings.Contains(err.Error(), "max repository targets limit") {
		t.Fatalf("err = %v", err)
	}
	if result.TagsResolved != 2 {
		t.Fatalf("result.TagsResolved = %d", result.TagsResolved)
	}
	if result.TargetCount != 2 {
		t.Fatalf("result.TargetCount = %d", result.TargetCount)
	}
	if result.CompletedTargetCount != 0 {
		t.Fatalf("result.CompletedTargetCount = %d", result.CompletedTargetCount)
	}
}

func TestScanRepositoryAbortsOnLimitErrorAndPreservesCompletedTargets(t *testing.T) {
	configOneBody := []byte(`{"architecture":"amd64","os":"linux","config":{"Env":["GH_TOKEN=ghp_123456789012345678901234567890123456"]}}`)
	configTwoBody := []byte(`{"architecture":"amd64","os":"linux","config":{"Env":["GH_TOKEN=ghp_123456789012345678901234567890123456"],"User":"builder","WorkingDir":"https://builder:supersecretvalue@registry.internal/app"}}`)
	configOne := testDescriptor(t, manifest.MediaTypeOCIImageConfig, configOneBody)
	configTwo := testDescriptor(t, manifest.MediaTypeOCIImageConfig, configTwoBody)
	manifestOneBody := testManifestBody(t, configOne, nil)
	manifestTwoBody := testManifestBody(t, configTwo, nil)
	digestOne := testDescriptor(t, manifest.MediaTypeOCIImageManifest, manifestOneBody).Digest
	digestTwo := testDescriptor(t, manifest.MediaTypeOCIImageManifest, manifestTwoBody).Digest

	transport := repoRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "auth.test" {
			body, _ := json.Marshal(map[string]string{"token": "test-token"})
			return repoResponse(http.StatusOK, "application/json", body, nil), nil
		}
		if request.Header.Get("Authorization") != "Bearer test-token" {
			return repoResponse(http.StatusUnauthorized, "", nil, map[string]string{
				"Www-Authenticate": `Bearer realm="https://auth.test/token",service="registry.test",scope="repository:library/app:pull"`,
			}), nil
		}

		switch {
		case request.URL.Path == "/v2/library/app/tags/list":
			return repoResponse(http.StatusOK, "application/json", []byte(`{"name":"library/app","tags":["1.0","latest"]}`), nil), nil
		case request.URL.Path == "/v2/library/app/manifests/1.0" && request.Method == http.MethodHead:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, nil, map[string]string{
				"Docker-Content-Digest": digestOne,
			}), nil
		case request.URL.Path == "/v2/library/app/manifests/latest" && request.Method == http.MethodHead:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, nil, map[string]string{
				"Docker-Content-Digest": digestTwo,
			}), nil
		case request.URL.Path == "/v2/library/app/manifests/"+digestOne:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, manifestOneBody, map[string]string{
				"Docker-Content-Digest": digestOne,
			}), nil
		case request.URL.Path == "/v2/library/app/manifests/"+digestTwo:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, manifestTwoBody, map[string]string{
				"Docker-Content-Digest": digestTwo,
			}), nil
		case request.URL.Path == "/v2/library/app/blobs/"+configOne.Digest:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, configOneBody, nil), nil
		case request.URL.Path == "/v2/library/app/blobs/"+configTwo.Digest:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, configTwoBody, nil), nil
		default:
			return repoResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
		}
	})

	ref, err := manifest.ParseReference("library/app")
	if err != nil {
		t.Fatalf("ParseReference() error = %v", err)
	}

	result, err := Scan(context.Background(), Request{
		Reference: ref,
		AllTags:   true,
		Registry: registry.NewClient(registry.Options{
			BaseURL:           "https://registry.test",
			AllowPrivateHosts: true,
			HTTPClient: &http.Client{
				Transport: transport,
			},
		}),
		Detectors:      detectors.Default(),
		MaxFileBytes:   1 << 20,
		MaxConfigBytes: 128,
		TagPageSize:    100,
	})
	if err == nil {
		t.Fatal("Scan() error = nil")
	}
	if !strings.Contains(err.Error(), "max config bytes limit") {
		t.Fatalf("err = %v", err)
	}
	if result.CompletedTargetCount != 1 {
		t.Fatalf("result.CompletedTargetCount = %d", result.CompletedTargetCount)
	}
	if result.FailedTargetCount != 1 {
		t.Fatalf("result.FailedTargetCount = %d", result.FailedTargetCount)
	}
	if result.TotalFindings == 0 {
		t.Fatal("result.TotalFindings = 0")
	}
	if len(result.Targets) != 2 {
		t.Fatalf("len(result.Targets) = %d", len(result.Targets))
	}
	if result.Targets[1].Error == "" {
		t.Fatal("expected failed target error")
	}
}

func TestScanRepositoryAbortsOnLayerLimitAndPreservesCompletedTargets(t *testing.T) {
	limitedLayer := gzipLayer(t, []tarEntry{
		{name: "app/one.txt", body: "one"},
		{name: "app/two.txt", body: "two"},
	})
	configOneBody := []byte(`{"architecture":"amd64","os":"linux","config":{"Env":["GH_TOKEN=ghp_123456789012345678901234567890123456"]}}`)
	configTwoBody := []byte(`{"architecture":"amd64","os":"linux","config":{"Env":["GH_TOKEN=ghp_123456789012345678901234567890123456"]}}`)
	configOne := testDescriptor(t, manifest.MediaTypeOCIImageConfig, configOneBody)
	configTwo := testDescriptor(t, manifest.MediaTypeOCIImageConfig, configTwoBody)
	layerTwo := testDescriptor(t, manifest.MediaTypeDockerSchema2LayerGzip, limitedLayer)
	manifestOneBody := testManifestBody(t, configOne, nil)
	manifestTwoBody := testManifestBody(t, configTwo, []manifest.Descriptor{layerTwo})
	digestOne := testDescriptor(t, manifest.MediaTypeOCIImageManifest, manifestOneBody).Digest
	digestTwo := testDescriptor(t, manifest.MediaTypeOCIImageManifest, manifestTwoBody).Digest

	transport := repoRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "auth.test" {
			body, _ := json.Marshal(map[string]string{"token": "test-token"})
			return repoResponse(http.StatusOK, "application/json", body, nil), nil
		}
		if request.Header.Get("Authorization") != "Bearer test-token" {
			return repoResponse(http.StatusUnauthorized, "", nil, map[string]string{
				"Www-Authenticate": `Bearer realm="https://auth.test/token",service="registry.test",scope="repository:library/app:pull"`,
			}), nil
		}

		switch {
		case request.URL.Path == "/v2/library/app/tags/list":
			return repoResponse(http.StatusOK, "application/json", []byte(`{"name":"library/app","tags":["1.0","latest"]}`), nil), nil
		case request.URL.Path == "/v2/library/app/manifests/1.0" && request.Method == http.MethodHead:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, nil, map[string]string{
				"Docker-Content-Digest": digestOne,
			}), nil
		case request.URL.Path == "/v2/library/app/manifests/latest" && request.Method == http.MethodHead:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, nil, map[string]string{
				"Docker-Content-Digest": digestTwo,
			}), nil
		case request.URL.Path == "/v2/library/app/manifests/"+digestOne:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, manifestOneBody, map[string]string{
				"Docker-Content-Digest": digestOne,
			}), nil
		case request.URL.Path == "/v2/library/app/manifests/"+digestTwo:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, manifestTwoBody, map[string]string{
				"Docker-Content-Digest": digestTwo,
			}), nil
		case request.URL.Path == "/v2/library/app/blobs/"+configOne.Digest:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, configOneBody, nil), nil
		case request.URL.Path == "/v2/library/app/blobs/"+configTwo.Digest:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, configTwoBody, nil), nil
		case request.URL.Path == "/v2/library/app/blobs/"+layerTwo.Digest:
			return repoResponse(http.StatusOK, manifest.MediaTypeDockerSchema2LayerGzip, limitedLayer, nil), nil
		default:
			return repoResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
		}
	})

	ref, err := manifest.ParseReference("library/app")
	if err != nil {
		t.Fatalf("ParseReference() error = %v", err)
	}

	result, err := Scan(context.Background(), Request{
		Reference: ref,
		AllTags:   true,
		Registry: registry.NewClient(registry.Options{
			BaseURL:           "https://registry.test",
			AllowPrivateHosts: true,
			HTTPClient: &http.Client{
				Transport: transport,
			},
		}),
		Detectors:       detectors.Default(),
		MaxFileBytes:    1 << 20,
		MaxLayerBytes:   1536,
		MaxLayerEntries: 50000,
		TagPageSize:     100,
	})
	if err == nil {
		t.Fatal("Scan() error = nil")
	}
	if !strings.Contains(err.Error(), "max layer bytes limit") {
		t.Fatalf("err = %v", err)
	}
	if result.CompletedTargetCount != 1 {
		t.Fatalf("result.CompletedTargetCount = %d", result.CompletedTargetCount)
	}
	if result.FailedTargetCount != 1 {
		t.Fatalf("result.FailedTargetCount = %d", result.FailedTargetCount)
	}
	if result.TotalFindings == 0 {
		t.Fatal("result.TotalFindings = 0")
	}
	if len(result.Targets) != 2 {
		t.Fatalf("len(result.Targets) = %d", len(result.Targets))
	}
	if result.Targets[1].Error == "" {
		t.Fatal("expected failed target error")
	}
	if !strings.Contains(result.Targets[1].Error, "max layer bytes limit") {
		t.Fatalf("result.Targets[1].Error = %q", result.Targets[1].Error)
	}
}

func TestScanRepositoryPreservesFatalTagResolutionErrors(t *testing.T) {
	goodDigest := "sha256:1111111111111111111111111111111111111111111111111111111111111111"

	tests := []struct {
		name      string
		transport func(*http.Request) (*http.Response, error)
		check     func(error) bool
	}{
		{
			name: "integrity",
			transport: func(request *http.Request) (*http.Response, error) {
				if strings.HasSuffix(request.URL.Path, "/manifests/z-bad") {
					return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, nil, map[string]string{
						"Docker-Content-Digest": "not-a-digest",
					}), nil
				}
				return tagResolutionResponse(request, goodDigest), nil
			},
			check: manifest.IsIntegrityError,
		},
		{
			name: "cancellation",
			transport: func(request *http.Request) (*http.Response, error) {
				if strings.HasSuffix(request.URL.Path, "/manifests/z-bad") {
					return nil, context.Canceled
				}
				return tagResolutionResponse(request, goodDigest), nil
			},
			check: func(err error) bool { return errors.Is(err, context.Canceled) },
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ref, err := manifest.ParseReference("library/app")
			if err != nil {
				t.Fatalf("ParseReference() error = %v", err)
			}
			result, err := Scan(context.Background(), Request{
				Reference: ref,
				AllTags:   true,
				Registry: registry.NewClient(registry.Options{
					BaseURL:           "https://registry.test",
					AllowPrivateHosts: true,
					RequestAttempts:   1,
					HTTPClient:        &http.Client{Transport: repoRoundTripFunc(test.transport)},
				}),
				Detectors:   detectors.Default(),
				TagPageSize: 100,
			})
			if !test.check(err) {
				t.Fatalf("Scan() error = %v", err)
			}
			if result.TagsResolved != 1 || result.TagsFailed != 1 {
				t.Fatalf("tag counts = resolved %d, failed %d", result.TagsResolved, result.TagsFailed)
			}
			if result.TargetCount != 0 || len(result.Targets) != 0 {
				t.Fatalf("scan continued to targets: count %d, results %#v", result.TargetCount, result.Targets)
			}
			if len(result.TagResults) != 2 || result.TagResults[0].Status != "resolved" || result.TagResults[1].Status != "failed" {
				t.Fatalf("result.TagResults = %#v", result.TagResults)
			}
		})
	}
}

func TestScanRepositoryAppliesMaxFindingsAcrossTargets(t *testing.T) {
	firstConfigBody := []byte(`{"architecture":"amd64","os":"linux","config":{"Env":["VALUE=ghp_123456789012345678901234567890123456"]}}`)
	secondConfigBody := []byte(`{"architecture":"amd64","os":"linux","config":{"Env":["NPM_TOKEN=npm_123456789012345678901234567890123456"]}}`)
	secondLayerBody := gzipLayer(t, []tarEntry{{name: "app/.env", body: "NPM_TOKEN=npm_123456789012345678901234567890123456"}})
	firstConfig := testDescriptor(t, manifest.MediaTypeOCIImageConfig, firstConfigBody)
	secondConfig := testDescriptor(t, manifest.MediaTypeOCIImageConfig, secondConfigBody)
	secondLayer := testDescriptor(t, manifest.MediaTypeDockerSchema2LayerGzip, secondLayerBody)
	firstManifestBody := testManifestBody(t, firstConfig, nil)
	secondManifestBody := testManifestBody(t, secondConfig, []manifest.Descriptor{secondLayer})
	firstDigest := testDescriptor(t, manifest.MediaTypeOCIImageManifest, firstManifestBody).Digest
	secondDigest := testDescriptor(t, manifest.MediaTypeOCIImageManifest, secondManifestBody).Digest

	requested := make(map[string]int)
	transport := repoRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requested[request.Method+" "+request.URL.Path]++
		switch {
		case request.URL.Path == "/v2/library/app/tags/list":
			return repoResponse(http.StatusOK, "application/json", []byte(`{"name":"library/app","tags":["1.0","2.0"]}`), nil), nil
		case request.URL.Path == "/v2/library/app/manifests/1.0" && request.Method == http.MethodHead:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, nil, map[string]string{"Docker-Content-Digest": firstDigest}), nil
		case request.URL.Path == "/v2/library/app/manifests/2.0" && request.Method == http.MethodHead:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, nil, map[string]string{"Docker-Content-Digest": secondDigest}), nil
		case request.URL.Path == "/v2/library/app/manifests/"+firstDigest:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, firstManifestBody, map[string]string{"Docker-Content-Digest": firstDigest}), nil
		case request.URL.Path == "/v2/library/app/blobs/"+firstConfig.Digest:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, firstConfigBody, nil), nil
		case request.URL.Path == "/v2/library/app/manifests/"+secondDigest:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, secondManifestBody, map[string]string{"Docker-Content-Digest": secondDigest}), nil
		case request.URL.Path == "/v2/library/app/blobs/"+secondConfig.Digest:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, secondConfigBody, nil), nil
		case request.URL.Path == "/v2/library/app/blobs/"+secondLayer.Digest:
			return repoResponse(http.StatusOK, manifest.MediaTypeDockerSchema2LayerGzip, secondLayerBody, nil), nil
		default:
			return repoResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
		}
	})

	ref, err := manifest.ParseReference("library/app")
	if err != nil {
		t.Fatalf("ParseReference() error = %v", err)
	}
	result, err := Scan(context.Background(), Request{
		Reference: ref,
		AllTags:   true,
		Registry: registry.NewClient(registry.Options{
			BaseURL:           "https://registry.test",
			AllowPrivateHosts: true,
			HTTPClient:        &http.Client{Transport: transport},
		}),
		Detectors:    detectors.Default(),
		MaxFileBytes: 1 << 20,
		MaxFindings:  1,
		TagPageSize:  100,
	})
	if err == nil || !IsIncomplete(err) {
		t.Fatalf("Scan() error = %v", err)
	}
	if result.TotalFindings != 1 {
		t.Fatalf("result.TotalFindings = %d", result.TotalFindings)
	}
	if len(result.Targets) != 1 || result.Targets[0].Status != ResultStatusCompleted {
		t.Fatalf("result.Targets = %#v", result.Targets)
	}
	if !hasDiagnosticCode(result.Diagnostics, "max_findings_exceeded") {
		t.Fatalf("result.Diagnostics = %#v", result.Diagnostics)
	}
	for _, endpoint := range []string{
		"GET /v2/library/app/manifests/" + secondDigest,
		"GET /v2/library/app/blobs/" + secondConfig.Digest,
		"GET /v2/library/app/blobs/" + secondLayer.Digest,
	} {
		if requested[endpoint] != 0 {
			t.Errorf("request count for %q = %d", endpoint, requested[endpoint])
		}
	}
}

func TestScanRepositoryAppliesRawFindingByteLimitAcrossTargets(t *testing.T) {
	firstSecret := "ghp_123456789012345678901234567890123456"
	secondSecret := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	firstEnv := "FIRST=" + firstSecret
	secondEnv := "OTHER=" + secondSecret
	firstConfigBody := []byte(`{"architecture":"amd64","os":"linux","config":{"Env":["` + firstEnv + `"]}}`)
	secondConfigBody := []byte(`{"architecture":"amd64","os":"linux","config":{"Env":["` + secondEnv + `"]}}`)
	firstConfig := testDescriptor(t, manifest.MediaTypeOCIImageConfig, firstConfigBody)
	secondConfig := testDescriptor(t, manifest.MediaTypeOCIImageConfig, secondConfigBody)
	firstManifestBody := testManifestBody(t, firstConfig, nil)
	secondManifestBody := testManifestBody(t, secondConfig, nil)
	firstDigest := testDescriptor(t, manifest.MediaTypeOCIImageManifest, firstManifestBody).Digest
	secondDigest := testDescriptor(t, manifest.MediaTypeOCIImageManifest, secondManifestBody).Digest
	maxRawFindingBytes := int64(len(firstSecret) + len(firstEnv))

	transport := repoRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch {
		case request.URL.Path == "/v2/library/app/tags/list":
			return repoResponse(http.StatusOK, "application/json", []byte(`{"name":"library/app","tags":["1.0","2.0"]}`), nil), nil
		case request.URL.Path == "/v2/library/app/manifests/1.0" && request.Method == http.MethodHead:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, nil, map[string]string{"Docker-Content-Digest": firstDigest}), nil
		case request.URL.Path == "/v2/library/app/manifests/2.0" && request.Method == http.MethodHead:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, nil, map[string]string{"Docker-Content-Digest": secondDigest}), nil
		case request.URL.Path == "/v2/library/app/manifests/"+firstDigest:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, firstManifestBody, map[string]string{"Docker-Content-Digest": firstDigest}), nil
		case request.URL.Path == "/v2/library/app/manifests/"+secondDigest:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, secondManifestBody, map[string]string{"Docker-Content-Digest": secondDigest}), nil
		case request.URL.Path == "/v2/library/app/blobs/"+firstConfig.Digest:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, firstConfigBody, nil), nil
		case request.URL.Path == "/v2/library/app/blobs/"+secondConfig.Digest:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, secondConfigBody, nil), nil
		default:
			return repoResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
		}
	})

	ref, err := manifest.ParseReference("library/app")
	if err != nil {
		t.Fatalf("ParseReference() error = %v", err)
	}
	result, err := Scan(context.Background(), Request{
		Reference: ref,
		AllTags:   true,
		Registry: registry.NewClient(registry.Options{
			BaseURL:           "https://registry.test",
			AllowPrivateHosts: true,
			HTTPClient:        &http.Client{Transport: transport},
		}),
		Detectors:          detectors.Default(),
		MaxFileBytes:       1 << 20,
		RetainRawSecrets:   true,
		MaxRawFindingBytes: maxRawFindingBytes,
		TagPageSize:        100,
	})
	if err == nil || !IsIncomplete(err) {
		t.Fatalf("Scan() error = %v", err)
	}
	if result.Status != ResultStatusPartial {
		t.Fatalf("result.Status = %q", result.Status)
	}
	if result.CompletedTargetCount != 1 || result.PartialTargetCount != 1 {
		t.Fatalf("target counts = completed %d, partial %d", result.CompletedTargetCount, result.PartialTargetCount)
	}
	if len(result.DetailedFindings) != 2 {
		t.Fatalf("len(result.DetailedFindings) = %d", len(result.DetailedFindings))
	}

	findingsByManifest := make(map[string]int)
	for index := range result.DetailedFindings {
		findingsByManifest[result.DetailedFindings[index].ManifestDigest] = index
	}
	firstIndex, ok := findingsByManifest[firstDigest]
	if !ok {
		t.Fatalf("first manifest finding missing: %#v", result.DetailedFindings)
	}
	firstFinding := result.DetailedFindings[firstIndex]
	if firstFinding.Value != firstSecret || firstFinding.RawSnippet != firstEnv {
		t.Fatalf("first finding raw fields = %q/%q", firstFinding.Value, firstFinding.RawSnippet)
	}
	secondIndex, ok := findingsByManifest[secondDigest]
	if !ok {
		t.Fatalf("second manifest finding missing: %#v", result.DetailedFindings)
	}
	secondFinding := result.DetailedFindings[secondIndex]
	if secondFinding.Value != "" || secondFinding.RawSnippet != "" {
		t.Fatalf("second finding retained raw fields = %q/%q", secondFinding.Value, secondFinding.RawSnippet)
	}
	if got := detailedRawBytes(result.DetailedFindings); got != maxRawFindingBytes {
		t.Fatalf("detailedRawBytes() = %d, want %d", got, maxRawFindingBytes)
	}

	foundDiagnostic := false
	for _, diagnostic := range result.Diagnostics {
		if diagnostic.Code != "max_raw_finding_bytes_exceeded" {
			continue
		}
		foundDiagnostic = true
		if diagnostic.Limit != maxRawFindingBytes || diagnostic.Observed <= diagnostic.Limit {
			t.Fatalf("raw finding diagnostic = %#v", diagnostic)
		}
	}
	if !foundDiagnostic {
		t.Fatalf("result.Diagnostics = %#v", result.Diagnostics)
	}
}

func assertRawFindingFieldsEmpty(t *testing.T, items []findings.DetailedFinding) {
	t.Helper()
	for _, item := range items {
		if item.Value != "" || item.RawSnippet != "" {
			t.Fatalf("finding retained raw fields = %q/%q", item.Value, item.RawSnippet)
		}
	}
}

func tagResolutionResponse(request *http.Request, goodDigest string) *http.Response {
	switch {
	case request.URL.Path == "/v2/library/app/tags/list":
		return repoResponse(http.StatusOK, "application/json", []byte(`{"name":"library/app","tags":["a-good","z-bad"]}`), nil)
	case request.URL.Path == "/v2/library/app/manifests/a-good" && request.Method == http.MethodHead:
		return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, nil, map[string]string{"Docker-Content-Digest": goodDigest})
	default:
		return repoResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil)
	}
}

type tarEntry struct {
	name string
	body string
}

func gzipLayer(t *testing.T, entries []tarEntry) []byte {
	t.Helper()

	var buffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, entry := range entries {
		header := &tar.Header{
			Name: entry.name,
			Mode: 0600,
			Size: int64(len(entry.body)),
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatalf("WriteHeader() error = %v", err)
		}
		if _, err := tarWriter.Write([]byte(entry.body)); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatalf("tarWriter.Close() error = %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("gzipWriter.Close() error = %v", err)
	}
	return buffer.Bytes()
}

type repoRoundTripFunc func(request *http.Request) (*http.Response, error)

func (f repoRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func repoResponse(statusCode int, contentType string, body []byte, headers map[string]string) *http.Response {
	header := make(http.Header)
	for key, value := range headers {
		header.Set(key, value)
	}
	if contentType != "" {
		header.Set("Content-Type", contentType)
	}

	return &http.Response{
		StatusCode: statusCode,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader(body)),
	}
}

func testDescriptor(t *testing.T, mediaType string, body []byte) manifest.Descriptor {
	t.Helper()
	digest, err := manifest.DigestBytes("sha256", body)
	if err != nil {
		t.Fatalf("DigestBytes() error = %v", err)
	}
	return manifest.Descriptor{MediaType: mediaType, Digest: digest, Size: int64(len(body))}
}

func testManifestBody(t *testing.T, config manifest.Descriptor, layers []manifest.Descriptor) []byte {
	t.Helper()
	if layers == nil {
		layers = []manifest.Descriptor{}
	}
	body, err := json.Marshal(manifest.ImageManifest{
		SchemaVersion: 2,
		MediaType:     manifest.MediaTypeOCIImageManifest,
		Config:        config,
		Layers:        layers,
	})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	return body
}
