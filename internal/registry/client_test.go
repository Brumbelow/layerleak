package registry

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"git.tools.cloudfor.ge/andrew/layerleak/internal/manifest"
)

func TestManifestURL(t *testing.T) {
	client := NewClient(Options{
		BaseURL: "https://registry-1.docker.io",
	})

	got := client.ManifestURL("library/alpine", "3.20")
	want := "https://registry-1.docker.io/v2/library/alpine/manifests/3.20"
	if got != want {
		t.Fatalf("ManifestURL() = %q", got)
	}
}

func TestFetchManifestAndBlobWithBearerAuth(t *testing.T) {
	tokenRequests := 0
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "auth.test" {
			tokenRequests++
			body, _ := json.Marshal(map[string]string{"token": "test-token"})
			return jsonResponse(http.StatusOK, "application/json", body, nil), nil
		}

		if request.Header.Get("Authorization") != "Bearer test-token" {
			return jsonResponse(http.StatusUnauthorized, "", nil, map[string]string{
				"Www-Authenticate": `Bearer realm="https://auth.test/token",service="registry.test",scope="repository:library/app:pull"`,
			}), nil
		}

		switch request.URL.Path {
		case "/v2/library/app/manifests/latest":
			return jsonResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, []byte(`{"schemaVersion":2,"mediaType":"`+manifest.MediaTypeOCIImageManifest+`","config":{"mediaType":"`+manifest.MediaTypeOCIImageConfig+`","digest":"sha256:config","size":1},"layers":[]}`), map[string]string{
				"Docker-Content-Digest": "sha256:manifest",
			}), nil
		case "/v2/library/app/blobs/sha256:config":
			return jsonResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, []byte(`{"architecture":"amd64","os":"linux","config":{"Env":["TOKEN=ghp_123456789012345678901234567890123456"]}}`), map[string]string{
				"Docker-Content-Digest": "sha256:config",
			}), nil
		default:
			return jsonResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
		}
	})

	client := NewClient(Options{
		BaseURL: "https://registry.test",
		HTTPClient: &http.Client{
			Transport: transport,
		},
	})

	manifestResponse, err := client.FetchManifest(context.Background(), "library/app", "latest")
	if err != nil {
		t.Fatalf("FetchManifest() error = %v", err)
	}

	if manifestResponse.Digest != "sha256:manifest" {
		t.Fatalf("manifestResponse.Digest = %q", manifestResponse.Digest)
	}

	blobResponse, err := client.OpenBlob(context.Background(), "library/app", "sha256:config")
	if err != nil {
		t.Fatalf("OpenBlob() error = %v", err)
	}
	defer blobResponse.Body.Close()

	body, err := io.ReadAll(blobResponse.Body)
	if err != nil {
		t.Fatalf("ReadAll(blobResponse.Body) error = %v", err)
	}

	if !strings.Contains(string(body), "ghp_123456789012345678901234567890123456") {
		t.Fatalf("blob body = %q", string(body))
	}

	if tokenRequests == 0 {
		t.Fatal("expected token endpoint to be called")
	}
}

type roundTripFunc func(request *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func jsonResponse(statusCode int, contentType string, body []byte, headers map[string]string) *http.Response {
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
		Body:       io.NopCloser(strings.NewReader(string(body))),
	}
}
