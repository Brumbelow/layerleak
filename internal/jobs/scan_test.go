package jobs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/brumbelow/layerleak/internal/detectors"
	"github.com/brumbelow/layerleak/internal/manifest"
	"github.com/brumbelow/layerleak/internal/registry"
)

func TestScanRepositoryEnumeratesTagsAndDeduplicatesDigests(t *testing.T) {
	digestOne := "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	digestTwo := "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	configOne := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	configTwo := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

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
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, []byte(`{"schemaVersion":2,"mediaType":"`+manifest.MediaTypeOCIImageManifest+`","config":{"mediaType":"`+manifest.MediaTypeOCIImageConfig+`","digest":"`+configOne+`","size":1},"layers":[]}`), map[string]string{
				"Docker-Content-Digest": digestOne,
			}), nil
		case request.URL.Path == "/v2/library/app/manifests/"+digestTwo:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, []byte(`{"schemaVersion":2,"mediaType":"`+manifest.MediaTypeOCIImageManifest+`","config":{"mediaType":"`+manifest.MediaTypeOCIImageConfig+`","digest":"`+configTwo+`","size":1},"layers":[]}`), map[string]string{
				"Docker-Content-Digest": digestTwo,
			}), nil
		case request.URL.Path == "/v2/library/app/blobs/"+configOne:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, []byte(`{"architecture":"amd64","os":"linux","config":{"Env":["GH_TOKEN=ghp_123456789012345678901234567890123456"]}}`), nil), nil
		case request.URL.Path == "/v2/library/app/blobs/"+configTwo:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, []byte(`{"architecture":"amd64","os":"linux","config":{"Env":["AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF"]}}`), nil), nil
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
		Registry: registry.NewClient(registry.Options{
			BaseURL: "https://registry.test",
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
	if len(progress) == 0 {
		t.Fatal("len(progress) = 0")
	}
	if progress[len(progress)-1].Phase != ProgressPhaseCompleted {
		t.Fatalf("progress[len(progress)-1].Phase = %q", progress[len(progress)-1].Phase)
	}
}

func TestScanRepositoryReturnsUnderlyingTargetErrorWhenAllTargetsFail(t *testing.T) {
	manifestDigest := "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	configDigest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

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
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, []byte(`{"schemaVersion":2,"mediaType":"`+manifest.MediaTypeOCIImageManifest+`","config":{"mediaType":"`+manifest.MediaTypeOCIImageConfig+`","digest":"`+configDigest+`","size":1},"layers":[]}`), map[string]string{
				"Docker-Content-Digest": manifestDigest,
			}), nil
		case request.URL.Path == "/v2/library/app/blobs/"+configDigest:
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
		Registry: registry.NewClient(registry.Options{
			BaseURL: "https://registry.test",
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
		Registry: registry.NewClient(registry.Options{
			BaseURL: "https://registry.test",
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
	digestOne := "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	digestTwo := "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	configOne := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	configTwo := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

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
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, []byte(`{"schemaVersion":2,"mediaType":"`+manifest.MediaTypeOCIImageManifest+`","config":{"mediaType":"`+manifest.MediaTypeOCIImageConfig+`","digest":"`+configOne+`","size":1},"layers":[]}`), map[string]string{
				"Docker-Content-Digest": digestOne,
			}), nil
		case request.URL.Path == "/v2/library/app/manifests/"+digestTwo:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, []byte(`{"schemaVersion":2,"mediaType":"`+manifest.MediaTypeOCIImageManifest+`","config":{"mediaType":"`+manifest.MediaTypeOCIImageConfig+`","digest":"`+configTwo+`","size":1},"layers":[]}`), map[string]string{
				"Docker-Content-Digest": digestTwo,
			}), nil
		case request.URL.Path == "/v2/library/app/blobs/"+configOne:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, []byte(`{"architecture":"amd64","os":"linux","config":{"Env":["GH_TOKEN=ghp_123456789012345678901234567890123456"]}}`), nil), nil
		case request.URL.Path == "/v2/library/app/blobs/"+configTwo:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, []byte(`{"architecture":"amd64","os":"linux","config":{"Env":["GH_TOKEN=ghp_123456789012345678901234567890123456"],"User":"builder","WorkingDir":"https://builder:supersecretvalue@registry.internal/app"}}`), nil), nil
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
		Registry: registry.NewClient(registry.Options{
			BaseURL: "https://registry.test",
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
	digestOne := "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	digestTwo := "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	configOne := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	configTwo := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	layerTwo := "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	limitedLayer := gzipLayer(t, []tarEntry{
		{name: "app/one.txt", body: "one"},
		{name: "app/two.txt", body: "two"},
	})

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
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, []byte(`{"schemaVersion":2,"mediaType":"`+manifest.MediaTypeOCIImageManifest+`","config":{"mediaType":"`+manifest.MediaTypeOCIImageConfig+`","digest":"`+configOne+`","size":1},"layers":[]}`), map[string]string{
				"Docker-Content-Digest": digestOne,
			}), nil
		case request.URL.Path == "/v2/library/app/manifests/"+digestTwo:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, []byte(`{"schemaVersion":2,"mediaType":"`+manifest.MediaTypeOCIImageManifest+`","config":{"mediaType":"`+manifest.MediaTypeOCIImageConfig+`","digest":"`+configTwo+`","size":1},"layers":[{"mediaType":"`+manifest.MediaTypeDockerSchema2LayerGzip+`","digest":"`+layerTwo+`","size":1}]}`), map[string]string{
				"Docker-Content-Digest": digestTwo,
			}), nil
		case request.URL.Path == "/v2/library/app/blobs/"+configOne:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, []byte(`{"architecture":"amd64","os":"linux","config":{"Env":["GH_TOKEN=ghp_123456789012345678901234567890123456"]}}`), nil), nil
		case request.URL.Path == "/v2/library/app/blobs/"+configTwo:
			return repoResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, []byte(`{"architecture":"amd64","os":"linux","config":{"Env":["GH_TOKEN=ghp_123456789012345678901234567890123456"]}}`), nil), nil
		case request.URL.Path == "/v2/library/app/blobs/"+layerTwo:
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
		Registry: registry.NewClient(registry.Options{
			BaseURL: "https://registry.test",
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
