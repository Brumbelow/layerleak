package scanner

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"testing"

	"git.tools.cloudfor.ge/andrew/layerleak/internal/detectors"
	"git.tools.cloudfor.ge/andrew/layerleak/internal/findings"
	"git.tools.cloudfor.ge/andrew/layerleak/internal/manifest"
	"git.tools.cloudfor.ge/andrew/layerleak/internal/registry"
)

func TestScanMultiArchImage(t *testing.T) {
	amd64LayerOne := gzipLayer(t, []tarEntry{
		{name: "app/.env", body: "STRIPE=sk_live_abcdefghijklmnopqrstuvwxyz12"},
		{name: "app/secret.txt", body: "NPM=npm_123456789012345678901234567890123456"},
	})
	amd64LayerTwo := gzipLayer(t, []tarEntry{
		{name: "app/.wh..env", body: ""},
		{name: "app/secret.txt", body: "clean"},
		{name: "app/.docker/config.json", body: `{"auth":"dXNlcjpwYXNz"}`},
	})
	arm64Layer := gzipLayer(t, []tarEntry{
		{name: "root/.netrc", body: "https://user:pass@example.com"},
	})

	indexDigest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	amd64Digest := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	arm64Digest := "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	amd64ConfigDigest := "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	arm64ConfigDigest := "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	amd64LayerOneDigest := "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	amd64LayerTwoDigest := "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	arm64LayerDigest := "sha256:2222222222222222222222222222222222222222222222222222222222222222"

	amd64Config := `{
  "architecture":"amd64",
  "os":"linux",
  "config":{
    "Env":["GH_TOKEN=ghp_123456789012345678901234567890123456"],
    "Labels":{"gitlab":"glpat-12345678901234567890"},
    "User":"builder",
    "WorkingDir":"https://builder:pass@example.com/app"
  },
  "history":[{"created_by":"docker build --build-arg TOKEN=ghp_123456789012345678901234567890123456"}]
}`
	arm64Config := `{
  "architecture":"arm64",
  "os":"linux",
  "config":{
    "Env":["AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF"],
    "Labels":{"jwt":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.signaturetoken"}
  }
}`

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
    {"mediaType":"`+manifest.MediaTypeOCIImageManifest+`","digest":"`+amd64Digest+`","size":1,"platform":{"os":"linux","architecture":"amd64"}},
    {"mediaType":"`+manifest.MediaTypeOCIImageManifest+`","digest":"`+arm64Digest+`","size":1,"platform":{"os":"linux","architecture":"arm64"}}
  ]
}`), map[string]string{
				"Docker-Content-Digest": indexDigest,
			}), nil
		case "/v2/library/app/manifests/" + amd64Digest:
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, []byte(`{"schemaVersion":2,"mediaType":"`+manifest.MediaTypeOCIImageManifest+`","config":{"mediaType":"`+manifest.MediaTypeOCIImageConfig+`","digest":"`+amd64ConfigDigest+`","size":1},"layers":[{"mediaType":"`+manifest.MediaTypeDockerSchema2LayerGzip+`","digest":"`+amd64LayerOneDigest+`","size":1},{"mediaType":"`+manifest.MediaTypeDockerSchema2LayerGzip+`","digest":"`+amd64LayerTwoDigest+`","size":1}]}`), map[string]string{
				"Docker-Content-Digest": amd64Digest,
			}), nil
		case "/v2/library/app/manifests/" + arm64Digest:
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, []byte(`{"schemaVersion":2,"mediaType":"`+manifest.MediaTypeOCIImageManifest+`","config":{"mediaType":"`+manifest.MediaTypeOCIImageConfig+`","digest":"`+arm64ConfigDigest+`","size":1},"layers":[{"mediaType":"`+manifest.MediaTypeDockerSchema2LayerGzip+`","digest":"`+arm64LayerDigest+`","size":1}]}`), map[string]string{
				"Docker-Content-Digest": arm64Digest,
			}), nil
		case "/v2/library/app/blobs/" + amd64ConfigDigest:
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, []byte(amd64Config), nil), nil
		case "/v2/library/app/blobs/" + arm64ConfigDigest:
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, []byte(arm64Config), nil), nil
		case "/v2/library/app/blobs/" + amd64LayerOneDigest:
			return testResponse(http.StatusOK, manifest.MediaTypeDockerSchema2LayerGzip, amd64LayerOne, nil), nil
		case "/v2/library/app/blobs/" + amd64LayerTwoDigest:
			return testResponse(http.StatusOK, manifest.MediaTypeDockerSchema2LayerGzip, amd64LayerTwo, nil), nil
		case "/v2/library/app/blobs/" + arm64LayerDigest:
			return testResponse(http.StatusOK, manifest.MediaTypeDockerSchema2LayerGzip, arm64Layer, nil), nil
		default:
			return testResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
		}
	})

	ref, err := manifest.ParseReference("library/app:latest")
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
		Detectors:    detectors.Default(),
		MaxFileBytes: 1 << 20,
	})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	if result.RequestedDigest != indexDigest {
		t.Fatalf("result.RequestedDigest = %q", result.RequestedDigest)
	}
	if result.ManifestCount != 2 {
		t.Fatalf("result.ManifestCount = %d", result.ManifestCount)
	}
	if result.CompletedManifestCount != 2 {
		t.Fatalf("result.CompletedManifestCount = %d", result.CompletedManifestCount)
	}
	if result.TotalFindings == 0 {
		t.Fatal("result.TotalFindings = 0")
	}
	if result.UniqueFingerprints == 0 {
		t.Fatal("result.UniqueFingerprints = 0")
	}

	sourceTypes := make([]findings.SourceType, 0, len(result.Findings))
	for _, item := range result.Findings {
		sourceTypes = append(sourceTypes, item.SourceType)
	}
	for _, expected := range []findings.SourceType{
		findings.SourceTypeEnv,
		findings.SourceTypeLabel,
		findings.SourceTypeHistory,
		findings.SourceTypeConfig,
		findings.SourceTypeFileFinal,
		findings.SourceTypeFileDeletedLayer,
	} {
		if !slices.Contains(sourceTypes, expected) {
			t.Fatalf("missing source type %q", expected)
		}
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
