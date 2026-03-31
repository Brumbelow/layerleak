package scanservice

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/brumbelow/layerleak/internal/config"
	"github.com/brumbelow/layerleak/internal/limits"
	"github.com/brumbelow/layerleak/internal/manifest"
	"github.com/brumbelow/layerleak/internal/registry"
	"github.com/brumbelow/layerleak/internal/storage"
)

func TestScanAndSavePersistsPartialResultOnLimitError(t *testing.T) {
	firstManifestDigest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	secondManifestDigest := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	firstConfigDigest := "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	secondConfigDigest := "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	indexDigest := "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "auth.test" {
			body, _ := json.Marshal(map[string]string{"token": "test-token"})
			return testResponse(http.StatusOK, "application/json", body, nil), nil
		}

		if request.Header.Get("Authorization") != "Bearer test-token" {
			return testResponse(http.StatusUnauthorized, "", nil, map[string]string{
				"Www-Authenticate": `Bearer realm="https://auth.test/token",service="registry.test",scope="repository:library/app:pull"`,
			}), nil
		}

		switch request.URL.Path {
		case "/v2/library/app/manifests/latest":
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageIndex, []byte(`{
  "schemaVersion":2,
  "mediaType":"`+manifest.MediaTypeOCIImageIndex+`",
  "manifests":[
    {"mediaType":"`+manifest.MediaTypeOCIImageManifest+`","digest":"`+firstManifestDigest+`","size":1,"platform":{"os":"linux","architecture":"amd64"}},
    {"mediaType":"`+manifest.MediaTypeOCIImageManifest+`","digest":"`+secondManifestDigest+`","size":1,"platform":{"os":"linux","architecture":"arm64"}}
  ]
}`), map[string]string{
				"Docker-Content-Digest": indexDigest,
			}), nil
		case "/v2/library/app/manifests/" + firstManifestDigest:
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, []byte(`{"schemaVersion":2,"mediaType":"`+manifest.MediaTypeOCIImageManifest+`","config":{"mediaType":"`+manifest.MediaTypeOCIImageConfig+`","digest":"`+firstConfigDigest+`","size":1},"layers":[]}`), map[string]string{
				"Docker-Content-Digest": firstManifestDigest,
			}), nil
		case "/v2/library/app/manifests/" + secondManifestDigest:
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, []byte(`{"schemaVersion":2,"mediaType":"`+manifest.MediaTypeOCIImageManifest+`","config":{"mediaType":"`+manifest.MediaTypeOCIImageConfig+`","digest":"`+secondConfigDigest+`","size":1},"layers":[]}`), map[string]string{
				"Docker-Content-Digest": secondManifestDigest,
			}), nil
		case "/v2/library/app/blobs/" + firstConfigDigest:
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, []byte(`{"architecture":"amd64","os":"linux","config":{"Env":["GH_TOKEN=ghp_123456789012345678901234567890123456"]}}`), nil), nil
		case "/v2/library/app/blobs/" + secondConfigDigest:
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, []byte(`{"architecture":"arm64","os":"linux","config":{"Env":["GH_TOKEN=ghp_123456789012345678901234567890123456"],"User":"builder","WorkingDir":"https://builder:supersecretvalue@registry.internal/app"}}`), nil), nil
		default:
			return testResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
		}
	})

	store := &recordingStore{}
	service := New(config.Config{
		RegistryBaseURL:         "https://registry.test",
		RegistryAuthURL:         "https://auth.test/token",
		MaxFileBytes:            1 << 20,
		MaxConfigBytes:          128,
		TagPageSize:             100,
		RegistryRequestAttempts: 2,
	}, store)
	service.newRegistryClient = func() *registry.Client {
		return registry.NewClient(registry.Options{
			BaseURL: "https://registry.test",
			AuthURL: "https://auth.test/token",
			HTTPClient: &http.Client{
				Transport: transport,
			},
			RequestAttempts: 2,
		})
	}

	reference, err := manifest.ParseReference("library/app:latest")
	if err != nil {
		t.Fatalf("ParseReference() error = %v", err)
	}

	outcome, err := service.ScanAndSave(context.Background(), Request{Reference: reference})
	if err == nil {
		t.Fatal("ScanAndSave() error = nil")
	}
	if !limits.IsExceeded(err) {
		t.Fatalf("err = %v", err)
	}
	if outcome.ScanRunID != 1 {
		t.Fatalf("outcome.ScanRunID = %d", outcome.ScanRunID)
	}
	if len(store.records) != 1 {
		t.Fatalf("len(store.records) = %d", len(store.records))
	}
	if outcome.Result.TotalFindings == 0 {
		t.Fatal("result.TotalFindings = 0")
	}
	if len(store.records[0].DetailedFindings) == 0 {
		t.Fatal("expected saved partial findings")
	}
	if strings.TrimSpace(store.records[0].Repository) != "library/app" {
		t.Fatalf("store.records[0].Repository = %q", store.records[0].Repository)
	}
}

type recordingStore struct {
	records []storage.ScanRecord
}

func (s *recordingStore) SaveScan(_ context.Context, record storage.ScanRecord) (int64, error) {
	s.records = append(s.records, record)
	return int64(len(s.records)), nil
}

func (s *recordingStore) Name() string {
	return "recording"
}

type roundTripFunc func(request *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func testResponse(statusCode int, contentType string, body []byte, headers map[string]string) *http.Response {
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
