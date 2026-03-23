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
	"strings"
	"testing"

	"github.com/brumbelow/layerleak/internal/detectors"
	"github.com/brumbelow/layerleak/internal/findings"
	"github.com/brumbelow/layerleak/internal/layers"
	"github.com/brumbelow/layerleak/internal/manifest"
	"github.com/brumbelow/layerleak/internal/registry"
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
	attestationDigest := "sha256:9999999999999999999999999999999999999999999999999999999999999999"
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
    "WorkingDir":"https://builder:realpass123@registry.internal/app"
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
    {"mediaType":"`+manifest.MediaTypeOCIImageManifest+`","digest":"`+arm64Digest+`","size":1,"platform":{"os":"linux","architecture":"arm64"}},
    {"mediaType":"`+manifest.MediaTypeOCIImageManifest+`","artifactType":"application/vnd.in-toto+json","digest":"`+attestationDigest+`","size":1,"annotations":{"vnd.docker.reference.type":"attestation-manifest"},"platform":{"os":"unknown","architecture":"unknown"}}
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

	progressUpdates := make([]ProgressUpdate, 0)
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
		Progress: func(update ProgressUpdate) {
			progressUpdates = append(progressUpdates, update)
		},
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
	if len(result.DetailedFindings) == 0 {
		t.Fatal("len(result.DetailedFindings) = 0")
	}

	sourceTypes := make([]findings.SourceType, 0, len(result.Findings)+len(result.SuppressedFindings))
	for _, item := range result.Findings {
		sourceTypes = append(sourceTypes, item.SourceType)
	}
	for _, item := range result.SuppressedFindings {
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

	foundRaw := false
	for _, item := range result.DetailedFindings {
		if item.Value == "ghp_123456789012345678901234567890123456" && item.SourceLocation == "env:GH_TOKEN" {
			foundRaw = true
			if !strings.Contains(item.RawSnippet, item.Value) {
				t.Fatalf("item.RawSnippet = %q", item.RawSnippet)
			}
			break
		}
	}
	if !foundRaw {
		t.Fatal("expected raw finding details for env token")
	}
	if len(progressUpdates) == 0 {
		t.Fatal("len(progressUpdates) = 0")
	}
	lastProgress := progressUpdates[len(progressUpdates)-1]
	if lastProgress.Phase != ProgressPhaseCompleted {
		t.Fatalf("lastProgress.Phase = %q", lastProgress.Phase)
	}
	if lastProgress.FindingsFound != result.TotalFindings {
		t.Fatalf("lastProgress.FindingsFound = %d", lastProgress.FindingsFound)
	}
	if lastProgress.ManifestCompleted != result.CompletedManifestCount {
		t.Fatalf("lastProgress.ManifestCompleted = %d", lastProgress.ManifestCompleted)
	}
}

func TestScanArtifactsSkipsNonTextArtifacts(t *testing.T) {
	items := scanArtifacts(
		detectors.Default(),
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		manifest.Platform{OS: "linux", Architecture: "amd64"},
		findings.SourceTypeFileFinal,
		true,
		[]layers.Artifact{
			{
				Path:         "usr/bin/tool",
				LayerDigest:  "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				ContentClass: layers.ContentClassBinaryELF,
				Scannable:    false,
				Content:      []byte("TOKEN=ghp_123456789012345678901234567890123456"),
			},
			{
				Path:         "app/.env",
				LayerDigest:  "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
				ContentClass: layers.ContentClassText,
				Scannable:    true,
				Content:      []byte("TOKEN=ghp_123456789012345678901234567890123456"),
			},
		},
	)

	if len(items) != 1 {
		t.Fatalf("len(items) = %d", len(items))
	}
	if items[0].FilePath != "app/.env" {
		t.Fatalf("items[0].FilePath = %q", items[0].FilePath)
	}
}

func TestScanArtifactsClassifiesExampleTestDirectories(t *testing.T) {
	tests := []struct {
		name            string
		path            string
		wantDisposition findings.Disposition
	}{
		{name: "test directory", path: "app/test/.env", wantDisposition: findings.DispositionExample},
		{name: "tests directory", path: "app/tests/.env", wantDisposition: findings.DispositionExample},
		{name: "case insensitive directory", path: "app/Test/.env", wantDisposition: findings.DispositionExample},
		{name: "filename remains scannable", path: "app/app_test.go", wantDisposition: findings.DispositionActionable},
		{name: "non test substring remains scannable", path: "app/latest/.env", wantDisposition: findings.DispositionActionable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			items := scanArtifacts(
				detectors.Default(),
				"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				manifest.Platform{OS: "linux", Architecture: "amd64"},
				findings.SourceTypeFileFinal,
				true,
				[]layers.Artifact{
					{
						Path:         tt.path,
						LayerDigest:  "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
						ContentClass: layers.ContentClassText,
						Scannable:    true,
						Content:      []byte("TOKEN=ghp_123456789012345678901234567890123456"),
					},
				},
			)

			if len(items) != 1 {
				t.Fatalf("len(items) = %d", len(items))
			}
			if items[0].FilePath != tt.path {
				t.Fatalf("items[0].FilePath = %q", items[0].FilePath)
			}
			if items[0].Disposition != tt.wantDisposition {
				t.Fatalf("items[0].Disposition = %q", items[0].Disposition)
			}
		})
	}
}

func TestScanReturnsUnderlyingManifestFailureWhenAllSelectedManifestsFail(t *testing.T) {
	manifestDigest := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	configDigest := "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

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
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, []byte(`{"schemaVersion":2,"mediaType":"`+manifest.MediaTypeOCIImageManifest+`","config":{"mediaType":"`+manifest.MediaTypeOCIImageConfig+`","digest":"`+configDigest+`","size":1},"layers":[]}`), map[string]string{
				"Docker-Content-Digest": manifestDigest,
			}), nil
		case "/v2/library/app/blobs/" + configDigest:
			return testResponse(http.StatusNotFound, "text/plain", []byte("missing config"), nil), nil
		default:
			return testResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
		}
	})

	ref, err := manifest.ParseReference("library/app:latest")
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
