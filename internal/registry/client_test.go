package registry

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/brumbelow/layerleak/internal/manifest"
)

func TestManifestURL(t *testing.T) {
	client := NewClient(Options{
		BaseURL:           "https://registry-1.docker.io",
		AllowPrivateHosts: true,
	})

	got := client.ManifestURL("library/alpine", "3.20")
	want := "https://registry-1.docker.io/v2/library/alpine/manifests/3.20"
	if got != want {
		t.Fatalf("ManifestURL() = %q", got)
	}
}

func TestURLValidationErrorsDoNotEchoUntrustedValues(t *testing.T) {
	const marker = "super-secret-marker"
	malformed := "https://registry.test/%ZZ" + marker

	if _, err := parseEndpointURL(malformed, false); err == nil || strings.Contains(err.Error(), marker) {
		t.Fatalf("parseEndpointURL() error = %v", err)
	}
	if _, _, err := nextLinkURL("https://registry.test/v2/tags/list", malformed); err == nil || strings.Contains(err.Error(), marker) {
		t.Fatalf("nextLinkURL() error = %v", err)
	}
	if _, err := appendURLQuery(malformed, map[string]string{"scope": "repository:app:pull"}); err == nil || strings.Contains(err.Error(), marker) {
		t.Fatalf("appendURLQuery() error = %v", err)
	}
}

func TestUnsupportedAuthChallengeDoesNotEchoHeader(t *testing.T) {
	const marker = "super-secret-marker"
	_, err := parseBearerChallenge("Basic " + marker)
	if err == nil || strings.Contains(err.Error(), marker) {
		t.Fatalf("parseBearerChallenge() error = %v", err)
	}
}

func TestDefaultTransportCapsRegistryResponseHeaders(t *testing.T) {
	client := NewClient(Options{BaseURL: "https://registry.example"})
	transport, ok := client.httpClient.Transport.(*pinnedTransport)
	if !ok {
		t.Fatalf("client transport = %T", client.httpClient.Transport)
	}
	if transport.base.MaxResponseHeaderBytes != maxRegistryResponseHeaderBytes {
		t.Fatalf("MaxResponseHeaderBytes = %d", transport.base.MaxResponseHeaderBytes)
	}
}

func TestRegistryTransportRequiresTLS12(t *testing.T) {
	tests := []struct {
		name       string
		configured bool
		minVersion uint16
		want       uint16
	}{
		{name: "default", want: tls.VersionTLS12},
		{name: "TLS 1.0", configured: true, minVersion: tls.VersionTLS10, want: tls.VersionTLS12},
		{name: "TLS 1.3", configured: true, minVersion: tls.VersionTLS13, want: tls.VersionTLS13},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			base := new(http.Transport)
			if test.configured {
				base.TLSClientConfig = &tls.Config{MinVersion: test.minVersion}
			}
			client := NewClient(Options{
				BaseURL:    "https://registry.example",
				HTTPClient: &http.Client{Transport: base},
			})
			transport, ok := client.httpClient.Transport.(*pinnedTransport)
			if !ok {
				t.Fatalf("client transport = %T", client.httpClient.Transport)
			}
			if got := transport.base.TLSClientConfig.MinVersion; got != test.want {
				t.Fatalf("MinVersion = %d, want %d", got, test.want)
			}
			if test.configured {
				if transport.base.TLSClientConfig == base.TLSClientConfig {
					t.Fatal("TLSClientConfig was not cloned")
				}
				if base.TLSClientConfig.MinVersion != test.minVersion {
					t.Fatalf("configured MinVersion = %d, want %d", base.TLSClientConfig.MinVersion, test.minVersion)
				}
			}
		})
	}
}

func TestFetchManifestAndBlobWithBearerAuth(t *testing.T) {
	configDigest := "sha256:" + strings.Repeat("c", 64)
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
			if request.Method == http.MethodHead {
				return jsonResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, nil, map[string]string{
					"Docker-Content-Digest": "sha256:manifest",
				}), nil
			}
			return jsonResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, []byte(`{"schemaVersion":2,"mediaType":"`+manifest.MediaTypeOCIImageManifest+`","config":{"mediaType":"`+manifest.MediaTypeOCIImageConfig+`","digest":"sha256:config","size":1},"layers":[]}`), map[string]string{
				"Docker-Content-Digest": "sha256:manifest",
			}), nil
		case "/v2/library/app/blobs/" + configDigest:
			return jsonResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, []byte(`{"architecture":"amd64","os":"linux","config":{"Env":["TOKEN=ghp_123456789012345678901234567890123456"]}}`), map[string]string{
				"Docker-Content-Digest": configDigest,
			}), nil
		default:
			return jsonResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
		}
	})

	client := NewClient(Options{
		BaseURL:           "https://registry.test",
		AllowPrivateHosts: true,
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

	blobResponse, err := client.OpenBlob(context.Background(), "library/app", configDigest)
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

func TestRequestTimeoutCoversManifestBody(t *testing.T) {
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return delayedResponse(request.Context(), 50*time.Millisecond, http.StatusOK, manifest.MediaTypeOCIImageManifest, []byte(`{"schemaVersion":2}`), nil), nil
	})
	client := NewClient(Options{
		BaseURL:           "https://registry.test",
		AllowPrivateHosts: true,
		RequestTimeout:    10 * time.Millisecond,
		RequestAttempts:   1,
		HTTPClient:        &http.Client{Transport: transport},
	})

	_, err := client.FetchManifest(context.Background(), "library/app", "latest")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("FetchManifest() error = %v", err)
	}
}

func TestRequestTimeoutDoesNotCancelOpenBlobBody(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	body := []byte("slow layer body")
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return delayedResponse(request.Context(), 50*time.Millisecond, http.StatusOK, "application/octet-stream", body, map[string]string{
			"Docker-Content-Digest": digest,
		}), nil
	})
	client := NewClient(Options{
		BaseURL:           "https://registry.test",
		AllowPrivateHosts: true,
		RequestTimeout:    10 * time.Millisecond,
		RequestAttempts:   1,
		HTTPClient:        &http.Client{Transport: transport},
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	response, err := client.OpenBlob(ctx, "library/app", digest)
	if err != nil {
		t.Fatalf("OpenBlob() error = %v", err)
	}
	defer response.Body.Close()
	got, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("body = %q", got)
	}
}

func TestRequestTimeoutCoversAuthTokenBodyForBlob(t *testing.T) {
	digest := "sha256:" + strings.Repeat("b", 64)
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "auth.test" {
			return delayedResponse(request.Context(), 50*time.Millisecond, http.StatusOK, "application/json", []byte(`{"token":"test-token"}`), nil), nil
		}
		return jsonResponse(http.StatusUnauthorized, "", nil, map[string]string{
			"Www-Authenticate": `Bearer realm="https://auth.test/token",service="registry.test",scope="repository:library/app:pull"`,
		}), nil
	})
	client := NewClient(Options{
		BaseURL:           "https://registry.test",
		AuthURL:           "https://auth.test/token",
		AllowPrivateHosts: true,
		RequestTimeout:    10 * time.Millisecond,
		RequestAttempts:   1,
		HTTPClient:        &http.Client{Transport: transport},
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err := client.OpenBlob(ctx, "library/app", digest)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("OpenBlob() error = %v", err)
	}
}

func TestResolveManifestUsesHeadDigest(t *testing.T) {
	resolvedDigest := "sha256:" + strings.Repeat("a", 64)
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "auth.test" {
			body, _ := json.Marshal(map[string]string{"token": "test-token"})
			return jsonResponse(http.StatusOK, "application/json", body, nil), nil
		}
		if request.Header.Get("Authorization") != "Bearer test-token" {
			return jsonResponse(http.StatusUnauthorized, "", nil, map[string]string{
				"Www-Authenticate": `Bearer realm="https://auth.test/token",service="registry.test",scope="repository:library/app:pull"`,
			}), nil
		}
		if request.Method != http.MethodHead || request.URL.Path != "/v2/library/app/manifests/latest" {
			return jsonResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
		}
		return jsonResponse(http.StatusOK, manifest.MediaTypeOCIImageIndex, nil, map[string]string{
			"Docker-Content-Digest": resolvedDigest,
		}), nil
	})

	client := NewClient(Options{
		BaseURL:           "https://registry.test",
		AllowPrivateHosts: true,
		HTTPClient: &http.Client{
			Transport: transport,
		},
	})

	resolved, err := client.ResolveManifest(context.Background(), "library/app", "latest")
	if err != nil {
		t.Fatalf("ResolveManifest() error = %v", err)
	}
	if resolved.Digest != resolvedDigest {
		t.Fatalf("resolved.Digest = %q", resolved.Digest)
	}
	if resolved.MediaType != manifest.MediaTypeOCIImageIndex {
		t.Fatalf("resolved.MediaType = %q", resolved.MediaType)
	}
}

func TestListTagsFollowsPagination(t *testing.T) {
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "auth.test" {
			body, _ := json.Marshal(map[string]string{"token": "test-token"})
			return jsonResponse(http.StatusOK, "application/json", body, nil), nil
		}
		if request.Header.Get("Authorization") != "Bearer test-token" {
			return jsonResponse(http.StatusUnauthorized, "", nil, map[string]string{
				"Www-Authenticate": `Bearer realm="https://auth.test/token",service="registry.test",scope="repository:library/app:pull"`,
			}), nil
		}

		switch {
		case request.URL.Path == "/v2/library/app/tags/list" && request.URL.Query().Get("n") == "2" && request.URL.Query().Get("last") == "":
			return jsonResponse(http.StatusOK, "application/json", []byte(`{"name":"library/app","tags":["2.0","1.0"]}`), map[string]string{
				"Link": `</v2/library/app/tags/list?n=2&last=2.0>; rel="next"`,
			}), nil
		case request.URL.Path == "/v2/library/app/tags/list" && request.URL.Query().Get("n") == "2" && request.URL.Query().Get("last") == "2.0":
			return jsonResponse(http.StatusOK, "application/json", []byte(`{"name":"library/app","tags":["3.0","2.0"]}`), nil), nil
		default:
			return jsonResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
		}
	})

	client := NewClient(Options{
		BaseURL:           "https://registry.test",
		AllowPrivateHosts: true,
		HTTPClient: &http.Client{
			Transport: transport,
		},
	})

	tags, err := client.ListTags(context.Background(), "library/app", 2, 0)
	if err != nil {
		t.Fatalf("ListTags() error = %v", err)
	}
	if len(tags) != 3 {
		t.Fatalf("len(tags) = %d", len(tags))
	}
	if strings.Join(tags, ",") != "1.0,2.0,3.0" {
		t.Fatalf("tags = %q", strings.Join(tags, ","))
	}
}

func TestListTagsReturnsPartialTagsWhenLimitExceeded(t *testing.T) {
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "auth.test" {
			body, _ := json.Marshal(map[string]string{"token": "test-token"})
			return jsonResponse(http.StatusOK, "application/json", body, nil), nil
		}
		if request.Header.Get("Authorization") != "Bearer test-token" {
			return jsonResponse(http.StatusUnauthorized, "", nil, map[string]string{
				"Www-Authenticate": `Bearer realm="https://auth.test/token",service="registry.test",scope="repository:library/app:pull"`,
			}), nil
		}
		return jsonResponse(http.StatusOK, "application/json", []byte(`{"name":"library/app","tags":["latest","2.0","1.0"]}`), nil), nil
	})

	client := NewClient(Options{
		BaseURL:           "https://registry.test",
		AllowPrivateHosts: true,
		HTTPClient: &http.Client{
			Transport: transport,
		},
	})

	tags, err := client.ListTags(context.Background(), "library/app", 100, 2)
	if err == nil {
		t.Fatal("ListTags() error = nil")
	}
	if !strings.Contains(err.Error(), "max repository tags limit") {
		t.Fatalf("err = %v", err)
	}
	if strings.Join(tags, ",") != "2.0,latest" {
		t.Fatalf("tags = %q", strings.Join(tags, ","))
	}
}

func TestListTagsFailsWhenTagResponseExceedsConfiguredBytes(t *testing.T) {
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "auth.test" {
			body, _ := json.Marshal(map[string]string{"token": "test-token"})
			return jsonResponse(http.StatusOK, "application/json", body, nil), nil
		}
		if request.Header.Get("Authorization") != "Bearer test-token" {
			return jsonResponse(http.StatusUnauthorized, "", nil, map[string]string{
				"Www-Authenticate": `Bearer realm="https://auth.test/token",service="registry.test",scope="repository:library/app:pull"`,
			}), nil
		}

		return jsonResponse(http.StatusOK, "application/json", []byte(`{"name":"library/app","tags":["latest","2.0","1.0"]}`), nil), nil
	})

	client := NewClient(Options{
		BaseURL:             "https://registry.test",
		AllowPrivateHosts:   true,
		MaxTagResponseBytes: 12,
		HTTPClient: &http.Client{
			Transport: transport,
		},
	})

	tags, err := client.ListTags(context.Background(), "library/app", 100, 0)
	if err == nil {
		t.Fatal("ListTags() error = nil")
	}
	if !strings.Contains(err.Error(), "max tag response bytes limit") {
		t.Fatalf("err = %v", err)
	}
	if len(tags) != 0 {
		t.Fatalf("len(tags) = %d", len(tags))
	}
}

func TestListTagsReturnsPartialTagsWhenTagResponseLimitExceededMidPagination(t *testing.T) {
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "auth.test" {
			body, _ := json.Marshal(map[string]string{"token": "test-token"})
			return jsonResponse(http.StatusOK, "application/json", body, nil), nil
		}
		if request.Header.Get("Authorization") != "Bearer test-token" {
			return jsonResponse(http.StatusUnauthorized, "", nil, map[string]string{
				"Www-Authenticate": `Bearer realm="https://auth.test/token",service="registry.test",scope="repository:library/app:pull"`,
			}), nil
		}

		switch request.URL.Query().Get("last") {
		case "":
			return jsonResponse(http.StatusOK, "application/json", []byte(`{"name":"library/app","tags":["2.0","1.0"]}`), map[string]string{
				"Link": `</v2/library/app/tags/list?n=2&last=2.0>; rel="next"`,
			}), nil
		case "2.0":
			return jsonResponse(http.StatusOK, "application/json", []byte(`{"name":"library/app","tags":["really-long-tag-name","3.0"]}`), nil), nil
		default:
			return jsonResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
		}
	})

	client := NewClient(Options{
		BaseURL:             "https://registry.test",
		AllowPrivateHosts:   true,
		MaxTagResponseBytes: 48,
		HTTPClient: &http.Client{
			Transport: transport,
		},
	})

	tags, err := client.ListTags(context.Background(), "library/app", 2, 0)
	if err == nil {
		t.Fatal("ListTags() error = nil")
	}
	if !strings.Contains(err.Error(), "max tag response bytes limit") {
		t.Fatalf("err = %v", err)
	}
	if strings.Join(tags, ",") != "1.0,2.0" {
		t.Fatalf("tags = %q", strings.Join(tags, ","))
	}
}

func TestListTagsRejectsPaginationCycle(t *testing.T) {
	transport := roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, "application/json", []byte(`{"name":"library/app","tags":["latest"]}`), map[string]string{
			"Link": `<https://registry.test/v2/library/app/tags/list?n=100>; rel="next"`,
		}), nil
	})
	client := NewClient(Options{
		BaseURL:           "https://registry.test",
		AllowPrivateHosts: true,
		HTTPClient:        &http.Client{Transport: transport},
	})
	_, err := client.ListTags(context.Background(), "library/app", 100, 0)
	if err == nil || !strings.Contains(err.Error(), "pagination cycle") {
		t.Fatalf("ListTags() error = %v", err)
	}
}

func TestListTagsRejectsInvalidDistributionTags(t *testing.T) {
	tests := []struct {
		name string
		tag  string
	}{
		{name: "empty", tag: ""},
		{name: "surrounding whitespace", tag: " latest "},
		{name: "path separator", tag: "release/candidate"},
		{name: "leading period", tag: ".hidden"},
		{name: "too long", tag: strings.Repeat("a", 129)},
		{name: "control characters", tag: "bad\nsecret-marker"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body, err := json.Marshal(map[string]any{"name": "library/app", "tags": []string{"stable", test.tag}})
			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}
			transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
				return jsonResponse(http.StatusOK, "application/json", body, nil), nil
			})
			client := NewClient(Options{
				BaseURL:           "https://registry.test",
				AllowPrivateHosts: true,
				HTTPClient:        &http.Client{Transport: transport},
			})

			tags, err := client.ListTags(context.Background(), "library/app", 100, 0)
			if err == nil || !strings.Contains(err.Error(), "invalid tag syntax") {
				t.Fatalf("ListTags() error = %v", err)
			}
			if test.tag != "" && strings.Contains(err.Error(), test.tag) {
				t.Fatalf("ListTags() error exposed invalid tag: %q", err.Error())
			}
			if len(tags) != 0 {
				t.Fatalf("tags = %q", strings.Join(tags, ","))
			}
		})
	}
}

func TestListTagsRejectsPaginationWithoutNewTags(t *testing.T) {
	requests := 0
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		switch request.URL.Query().Get("last") {
		case "":
			return jsonResponse(http.StatusOK, "application/json", []byte(`{"name":"library/app","tags":["2.0","1.0"]}`), map[string]string{
				"Link": `</v2/library/app/tags/list?n=2&last=2.0>; rel="next"`,
			}), nil
		case "2.0":
			return jsonResponse(http.StatusOK, "application/json", []byte(`{"name":"library/app","tags":["1.0","2.0"]}`), map[string]string{
				"Link": `</v2/library/app/tags/list?n=2&last=3.0>; rel="next"`,
			}), nil
		default:
			return jsonResponse(http.StatusInternalServerError, "text/plain", nil, nil), nil
		}
	})
	client := NewClient(Options{
		BaseURL:           "https://registry.test",
		AllowPrivateHosts: true,
		HTTPClient:        &http.Client{Transport: transport},
	})

	tags, err := client.ListTags(context.Background(), "library/app", 2, 0)
	if err == nil || !strings.Contains(err.Error(), "did not add any new tags") {
		t.Fatalf("ListTags() error = %v", err)
	}
	if strings.Join(tags, ",") != "1.0,2.0" {
		t.Fatalf("tags = %q", strings.Join(tags, ","))
	}
	if requests != 2 {
		t.Fatalf("requests = %d", requests)
	}
}

func TestFetchManifestRefreshesExpiredCachedToken(t *testing.T) {
	tokenRequests := 0
	authorizedRequests := 0
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "auth.test" {
			tokenRequests++
			token := "stale-token"
			if tokenRequests > 1 {
				token = "fresh-token"
			}
			body, _ := json.Marshal(map[string]string{"token": token})
			return jsonResponse(http.StatusOK, "application/json", body, nil), nil
		}

		if request.URL.Path != "/v2/library/app/manifests/latest" {
			return jsonResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
		}
		if request.Header.Get("Authorization") == "" {
			return jsonResponse(http.StatusUnauthorized, "", nil, map[string]string{
				"Www-Authenticate": `Bearer realm="https://auth.test/token",service="registry.test",scope="repository:library/app:pull"`,
			}), nil
		}

		authorizedRequests++
		if request.Header.Get("Authorization") == "Bearer stale-token" {
			return jsonResponse(http.StatusUnauthorized, "", nil, map[string]string{
				"Www-Authenticate": `Bearer realm="https://auth.test/token",service="registry.test",scope="repository:library/app:pull"`,
			}), nil
		}

		return jsonResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, []byte(`{"schemaVersion":2,"mediaType":"`+manifest.MediaTypeOCIImageManifest+`","config":{"mediaType":"`+manifest.MediaTypeOCIImageConfig+`","digest":"sha256:config","size":1},"layers":[]}`), map[string]string{
			"Docker-Content-Digest": "sha256:manifest",
		}), nil
	})

	client := NewClient(Options{
		BaseURL:           "https://registry.test",
		AllowPrivateHosts: true,
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
	if tokenRequests != 2 {
		t.Fatalf("tokenRequests = %d", tokenRequests)
	}
	if authorizedRequests != 2 {
		t.Fatalf("authorizedRequests = %d", authorizedRequests)
	}
}

func TestResolveManifestRetriesRequestTimeout(t *testing.T) {
	resolvedDigest := "sha256:" + strings.Repeat("a", 64)
	requests := 0
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "auth.test" {
			body, _ := json.Marshal(map[string]string{"token": "test-token"})
			return jsonResponse(http.StatusOK, "application/json", body, nil), nil
		}

		requests++
		if requests == 1 {
			return nil, context.DeadlineExceeded
		}
		if request.Header.Get("Authorization") != "Bearer test-token" {
			return jsonResponse(http.StatusUnauthorized, "", nil, map[string]string{
				"Www-Authenticate": `Bearer realm="https://auth.test/token",service="registry.test",scope="repository:library/app:pull"`,
			}), nil
		}
		if request.Method != http.MethodHead || request.URL.Path != "/v2/library/app/manifests/latest" {
			return jsonResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
		}

		return jsonResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, nil, map[string]string{
			"Docker-Content-Digest": resolvedDigest,
		}), nil
	})

	client := NewClient(Options{
		BaseURL:           "https://registry.test",
		AllowPrivateHosts: true,
		HTTPClient: &http.Client{
			Transport: transport,
		},
	})

	resolved, err := client.ResolveManifest(context.Background(), "library/app", "latest")
	if err != nil {
		t.Fatalf("ResolveManifest() error = %v", err)
	}
	if resolved.Digest != resolvedDigest {
		t.Fatalf("resolved.Digest = %q", resolved.Digest)
	}
}

func TestFetchManifestHonorsConfiguredRequestAttempts(t *testing.T) {
	requests := 0
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return nil, context.DeadlineExceeded
	})

	client := NewClient(Options{
		BaseURL:           "https://registry.test",
		AllowPrivateHosts: true,
		RequestAttempts:   1,
		HTTPClient: &http.Client{
			Transport: transport,
		},
	})

	if _, err := client.FetchManifest(context.Background(), "library/app", "latest"); err == nil {
		t.Fatal("FetchManifest() error = nil")
	}
	if requests != 1 {
		t.Fatalf("requests = %d", requests)
	}
}

func TestFetchManifestFailsWhenManifestBodyExceedsLimit(t *testing.T) {
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "auth.test" {
			body, _ := json.Marshal(map[string]string{"token": "test-token"})
			return jsonResponse(http.StatusOK, "application/json", body, nil), nil
		}

		if request.Header.Get("Authorization") != "Bearer test-token" {
			return jsonResponse(http.StatusUnauthorized, "", nil, map[string]string{
				"Www-Authenticate": `Bearer realm="https://auth.test/token",service="registry.test",scope="repository:library/app:pull"`,
			}), nil
		}

		return jsonResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, []byte(`{"schemaVersion":2}`), map[string]string{
			"Docker-Content-Digest": "sha256:manifest",
		}), nil
	})

	client := NewClient(Options{
		BaseURL:           "https://registry.test",
		AllowPrivateHosts: true,
		MaxManifestBytes:  8,
		HTTPClient: &http.Client{
			Transport: transport,
		},
	})

	if _, err := client.FetchManifest(context.Background(), "library/app", "latest"); err == nil {
		t.Fatal("FetchManifest() error = nil")
	} else if !strings.Contains(err.Error(), "max manifest bytes limit") {
		t.Fatalf("err = %v", err)
	}
}

func TestBaseURLForRegistry(t *testing.T) {
	tests := []struct {
		name     string
		registry string
		want     string
	}{
		{name: "empty defaults to docker hub", registry: "", want: "https://registry-1.docker.io"},
		{name: "docker.io canonicalizes", registry: "docker.io", want: "https://registry-1.docker.io"},
		{name: "ghcr.io", registry: "ghcr.io", want: "https://ghcr.io"},
		{name: "quay.io", registry: "quay.io", want: "https://quay.io"},
		{name: "gcr.io", registry: "gcr.io", want: "https://gcr.io"},
		{name: "public.ecr.aws", registry: "public.ecr.aws", want: "https://public.ecr.aws"},
		{name: "mcr.microsoft.com", registry: "mcr.microsoft.com", want: "https://mcr.microsoft.com"},
		{name: "localhost with port", registry: "localhost:5000", want: "https://localhost:5000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := BaseURLForRegistry(tt.registry); got != tt.want {
				t.Fatalf("BaseURLForRegistry(%q) = %q, want %q", tt.registry, got, tt.want)
			}
		})
	}
}

func TestFetchManifestDiscoversAuthRealmForNonDockerHubRegistry(t *testing.T) {
	tokenRequests := 0
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "ghcr.test" && request.URL.Path == "/token" {
			tokenRequests++
			if got := request.URL.Query().Get("service"); got != "ghcr.io" {
				t.Fatalf("token request service = %q", got)
			}
			if got := request.URL.Query().Get("scope"); got != "repository:org/image:pull" {
				t.Fatalf("token request scope = %q", got)
			}
			body, _ := json.Marshal(map[string]string{"token": "ghcr-token"})
			return jsonResponse(http.StatusOK, "application/json", body, nil), nil
		}

		if request.Header.Get("Authorization") != "Bearer ghcr-token" {
			return jsonResponse(http.StatusUnauthorized, "", nil, map[string]string{
				"Www-Authenticate": `Bearer realm="https://ghcr.test/token",service="ghcr.io",scope="repository:org/image:pull"`,
			}), nil
		}

		if request.URL.Path == "/v2/org/image/manifests/latest" {
			return jsonResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, []byte(`{"schemaVersion":2,"mediaType":"`+manifest.MediaTypeOCIImageManifest+`","config":{"mediaType":"`+manifest.MediaTypeOCIImageConfig+`","digest":"sha256:config","size":1},"layers":[]}`), map[string]string{
				"Docker-Content-Digest": "sha256:manifest",
			}), nil
		}
		return jsonResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
	})

	client := NewClient(Options{
		BaseURL:           "https://ghcr.test",
		AllowPrivateHosts: true,
		HTTPClient: &http.Client{
			Transport: transport,
		},
	})

	response, err := client.FetchManifest(context.Background(), "org/image", "latest")
	if err != nil {
		t.Fatalf("FetchManifest() error = %v", err)
	}
	if response.Digest != "sha256:manifest" {
		t.Fatalf("response.Digest = %q", response.Digest)
	}
	if tokenRequests == 0 {
		t.Fatal("expected token endpoint on ghcr.test to be called")
	}
}

func TestClientRejectsDNSRebindingBeforeDial(t *testing.T) {
	lookups := 0
	client := NewClient(Options{
		BaseURL: "https://registry.example",
		LookupIP: func(context.Context, string) ([]net.IPAddr, error) {
			lookups++
			if lookups == 1 {
				return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
			}
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		},
	})

	_, err := client.FetchManifest(context.Background(), "library/app", "latest")
	if err == nil || !strings.Contains(err.Error(), "non-public registry address") {
		t.Fatalf("FetchManifest() error = %v", err)
	}
	if lookups != 2 {
		t.Fatalf("lookups = %d", lookups)
	}
}

func TestClientUsesSeparateExactPrivateHostAllowlists(t *testing.T) {
	lookup := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}
	client := NewClient(Options{
		BaseURL:                     "https://registry.internal:5000",
		AllowedPrivateRegistryHosts: []string{"registry.internal:5000"},
		LookupIP:                    lookup,
	})
	if err := client.validateOutboundURL(context.Background(), "https://registry.internal:5000/v2/", client.baseURL, false, requestKindRegistry); err != nil {
		t.Fatalf("registry validation error = %v", err)
	}
	if err := client.validateOutboundURL(context.Background(), "https://registry.internal:5000/token", nil, true, requestKindAuth); err == nil {
		t.Fatal("auth validation error = nil")
	}

	client = NewClient(Options{
		BaseURL:                 "https://registry.example",
		AllowedPrivateAuthHosts: []string{"auth.internal"},
		LookupIP:                lookup,
	})
	if err := client.validateAuthRealm(context.Background(), "https://auth.internal/token"); err != nil {
		t.Fatalf("auth validation error = %v", err)
	}
	if err := client.validateOutboundURL(context.Background(), "https://auth.internal/v2/", nil, true, requestKindRegistry); err == nil {
		t.Fatal("registry validation error = nil")
	}
}

func TestClientAllowsPublicCrossHostAuthRealm(t *testing.T) {
	client := NewClient(Options{
		BaseURL: "https://registry.example",
		LookupIP: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
		},
	})
	if err := client.validateAuthRealm(context.Background(), "https://auth.example/token"); err != nil {
		t.Fatalf("validateAuthRealm() error = %v", err)
	}
}

func TestNonPublicAddressClassification(t *testing.T) {
	for _, test := range []struct {
		address   string
		nonPublic bool
	}{
		{address: "8.8.8.8"},
		{address: "2606:4700:4700::1111"},
		{address: "10.0.0.1", nonPublic: true},
		{address: "100.64.0.1", nonPublic: true},
		{address: "127.0.0.1", nonPublic: true},
		{address: "169.254.169.254", nonPublic: true},
		{address: "192.0.2.1", nonPublic: true},
		{address: "198.18.0.1", nonPublic: true},
		{address: "203.0.113.1", nonPublic: true},
		{address: "240.0.0.1", nonPublic: true},
		{address: "::1", nonPublic: true},
		{address: "::ffff:127.0.0.1", nonPublic: true},
		{address: "64:ff9b::7f00:1", nonPublic: true},
		{address: "2001:db8::1", nonPublic: true},
		{address: "2002:7f00:1::", nonPublic: true},
		{address: "fc00::1", nonPublic: true},
		{address: "fe80::1", nonPublic: true},
	} {
		t.Run(test.address, func(t *testing.T) {
			if got := isNonPublicAddress(net.ParseIP(test.address)); got != test.nonPublic {
				t.Fatalf("isNonPublicAddress(%q) = %t, want %t", test.address, got, test.nonPublic)
			}
		})
	}
	if !isNonPublicAddress(nil) {
		t.Fatal("isNonPublicAddress(nil) = false")
	}
}

func TestClientAllowsHTTPOnlyForExactPrivateHost(t *testing.T) {
	lookup := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}
	allowed := NewClient(Options{
		BaseURL:                     "http://registry.internal:5000",
		AllowedPrivateRegistryHosts: []string{"registry.internal:5000"},
		LookupIP:                    lookup,
	})
	if err := allowed.validateOutboundURL(context.Background(), allowed.BaseURL(), allowed.baseURL, false, requestKindRegistry); err != nil {
		t.Fatalf("allowed validation error = %v", err)
	}
	rejected := NewClient(Options{
		BaseURL:                     "http://other.internal:5000",
		AllowedPrivateRegistryHosts: []string{"registry.internal:5000"},
		LookupIP:                    lookup,
	})
	if _, err := rejected.FetchManifest(context.Background(), "library/app", "latest"); err == nil || !strings.Contains(err.Error(), "allowlisted") {
		t.Fatalf("FetchManifest() error = %v", err)
	}
}

func TestClientBoundsAuthTokenResponse(t *testing.T) {
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "auth.test" {
			return jsonResponse(http.StatusOK, "application/json", []byte(`{"token":"a-very-long-token"}`), nil), nil
		}
		return jsonResponse(http.StatusUnauthorized, "", nil, map[string]string{
			"Www-Authenticate": `Bearer realm="https://auth.test/token",service="registry.test"`,
		}), nil
	})
	client := NewClient(Options{
		BaseURL:              "https://registry.test",
		AllowPrivateHosts:    true,
		MaxAuthResponseBytes: 8,
		HTTPClient:           &http.Client{Transport: transport},
	})
	if _, err := client.FetchManifest(context.Background(), "library/app", "latest"); err == nil || !strings.Contains(err.Error(), "configured limit of 8") {
		t.Fatalf("FetchManifest() error = %v", err)
	}
}

func TestClientFailsClosedWhenTokenCacheEntryLimitIsReached(t *testing.T) {
	authRequests := 0
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		authRequests++
		return jsonResponse(http.StatusOK, "application/json", []byte(`{"token":"uncached-token"}`), nil), nil
	})
	client := NewClient(Options{
		BaseURL:           "https://registry.test",
		AllowPrivateHosts: true,
		HTTPClient:        &http.Client{Transport: transport},
	})
	for index := 0; index < maxTokenCacheEntries; index++ {
		if err := client.cacheToken(fmt.Sprintf("cache-key-%03d", index), "token"); err != nil {
			t.Fatalf("cacheToken(%d) error = %v", index, err)
		}
	}
	retainedBytes := client.tokenCacheBytes

	_, err := client.fetchToken(context.Background(), bearerChallenge{
		Realm: "https://auth.test/token",
		Scope: "repository:library/app:pull",
	}, true)
	if err == nil || !strings.Contains(err.Error(), "configured limit of 128") {
		t.Fatalf("fetchToken() error = %v", err)
	}
	if authRequests != 0 {
		t.Fatalf("authRequests = %d", authRequests)
	}
	if len(client.tokenCache) != maxTokenCacheEntries || client.tokenCacheBytes != retainedBytes {
		t.Fatalf("token cache changed after rejection: entries=%d bytes=%d", len(client.tokenCache), client.tokenCacheBytes)
	}
}

func TestClientDoesNotCacheTokenBeyondTokenCacheByteLimit(t *testing.T) {
	client := NewClient(Options{
		BaseURL:           "https://registry.test",
		AllowPrivateHosts: true,
	})
	firstKey := "first-cache-key"
	firstToken := strings.Repeat("a", maxTokenCacheBytes-len(firstKey)-8)
	if err := client.cacheToken(firstKey, firstToken); err != nil {
		t.Fatalf("cacheToken(first) error = %v", err)
	}
	retainedBytes := client.tokenCacheBytes

	err := client.cacheToken("second-cache-key", "second-token")
	if err == nil || !strings.Contains(err.Error(), "configured limit of 1048576") {
		t.Fatalf("cacheToken(second) error = %v", err)
	}
	if _, ok := client.tokenCache["second-cache-key"]; ok {
		t.Fatal("second token was cached")
	}
	if len(client.tokenCache) != 1 || client.tokenCacheBytes != retainedBytes {
		t.Fatalf("token cache changed after rejection: entries=%d bytes=%d", len(client.tokenCache), client.tokenCacheBytes)
	}
}

func TestClientAccountsForInvalidatedTokenCacheBytes(t *testing.T) {
	client := NewClient(Options{
		BaseURL:           "https://registry.test",
		AllowPrivateHosts: true,
	})
	challenge := bearerChallenge{Realm: "https://auth.test/token", Scope: "repository:library/app:pull"}
	if err := client.cacheToken(challenge.cacheKey(), "token"); err != nil {
		t.Fatalf("cacheToken() error = %v", err)
	}
	client.invalidateToken(challenge)

	if len(client.tokenCache) != 0 || client.tokenCacheBytes != 0 {
		t.Fatalf("token cache after invalidation: entries=%d bytes=%d", len(client.tokenCache), client.tokenCacheBytes)
	}
}

func TestClientStripsBearerAuthorizationOnCrossHostRedirect(t *testing.T) {
	cdnAuthorization := "unset"
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Host {
		case "auth.test":
			return jsonResponse(http.StatusOK, "application/json", []byte(`{"token":"test-token"}`), nil), nil
		case "cdn.test":
			cdnAuthorization = request.Header.Get("Authorization")
			return jsonResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, []byte(`{"schemaVersion":2}`), nil), nil
		default:
			if request.Header.Get("Authorization") == "" {
				return jsonResponse(http.StatusUnauthorized, "", nil, map[string]string{
					"Www-Authenticate": `Bearer realm="https://auth.test/token",service="registry.test"`,
				}), nil
			}
			return jsonResponse(http.StatusFound, "", nil, map[string]string{"Location": "https://cdn.test/manifest"}), nil
		}
	})
	client := NewClient(Options{
		BaseURL:           "https://registry.test",
		AllowPrivateHosts: true,
		MaxRedirects:      3,
		HTTPClient:        &http.Client{Transport: transport},
	})
	if _, err := client.FetchManifest(context.Background(), "library/app", "latest"); err != nil {
		t.Fatalf("FetchManifest() error = %v", err)
	}
	if cdnAuthorization != "" {
		t.Fatalf("redirect Authorization = %q", cdnAuthorization)
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

func delayedResponse(ctx context.Context, delay time.Duration, statusCode int, contentType string, body []byte, headers map[string]string) *http.Response {
	response := jsonResponse(statusCode, contentType, nil, headers)
	response.ContentLength = int64(len(body))
	response.Body = &delayedBody{
		ctx:    ctx,
		delay:  delay,
		reader: bytes.NewReader(body),
	}
	return response
}

type delayedBody struct {
	ctx    context.Context
	delay  time.Duration
	reader *bytes.Reader
	waited bool
	closed bool
}

func (b *delayedBody) Read(buffer []byte) (int, error) {
	if b.closed {
		return 0, io.ErrClosedPipe
	}
	if !b.waited {
		timer := time.NewTimer(b.delay)
		defer timer.Stop()
		select {
		case <-b.ctx.Done():
			return 0, b.ctx.Err()
		case <-timer.C:
			b.waited = true
		}
	}
	return b.reader.Read(buffer)
}

func (b *delayedBody) Close() error {
	b.closed = true
	return nil
}
