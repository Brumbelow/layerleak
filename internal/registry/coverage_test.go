package registry

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/manifest"
)

func TestRedirectToNonPublicAddressIsRejectedBeforeDial(t *testing.T) {
	_, port, transport := newTLSRegistry(t, func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, "https://cdn.example/blobs/x?sig=SIGNATURE-MARKER", http.StatusTemporaryRedirect)
	})
	lookups := make([]string, 0, 2)
	client := MustNewClient(Options{
		BaseURL:                     "https://example.com:" + port,
		AllowedPrivateRegistryHosts: []string{"example.com:" + port},
		RequestAttempts:             1,
		RequestTimeout:              5 * time.Second,
		HTTPClient:                  &http.Client{Transport: transport},
		LookupIP: func(_ context.Context, host string) ([]net.IPAddr, error) {
			lookups = append(lookups, host)
			if host == "cdn.example" {
				return []net.IPAddr{{IP: net.ParseIP("10.0.0.7")}}, nil
			}
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		},
	})
	dialer := installRecordingDialer(t, client)

	_, err := client.OpenBlob(context.Background(), "library/app", "sha256:"+strings.Repeat("a", 64))
	if err == nil || !strings.Contains(err.Error(), "non-public registry address 10.0.0.7") {
		t.Fatalf("OpenBlob() error = %v", err)
	}
	if strings.Contains(err.Error(), "SIGNATURE-MARKER") {
		t.Fatalf("error echoed the redirect query: %v", err)
	}
	if strings.Join(lookups, ",") != "example.com,cdn.example" {
		t.Fatalf("lookups = %q", lookups)
	}
	for _, target := range dialer.recorded() {
		if !strings.HasPrefix(target, "127.0.0.1:") {
			t.Fatalf("dialed %q, the private redirect target must never be dialed", target)
		}
	}
}

func TestRedirectDowngradeToHTTPIsRejected(t *testing.T) {
	_, port, transport := newTLSRegistry(t, func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, "http://"+request.Host+"/v2/library/app/manifests/latest", http.StatusFound)
	})
	client := MustNewClient(Options{
		BaseURL:                     "https://example.com:" + port,
		AllowedPrivateRegistryHosts: []string{"example.com:" + port},
		RequestAttempts:             1,
		RequestTimeout:              5 * time.Second,
		HTTPClient:                  &http.Client{Transport: transport},
		LookupIP: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		},
	})
	installRecordingDialer(t, client)

	// The host is allowlisted, so plain http would be permitted for a
	// configured endpoint; a redirect must still not downgrade the scheme.
	_, err := client.FetchManifest(context.Background(), "library/app", "latest")
	if err == nil || !strings.Contains(err.Error(), "reject redirect") {
		t.Fatalf("FetchManifest() error = %v", err)
	}
}

func TestRedirectDowngradeForNonAllowlistedHostIsRejected(t *testing.T) {
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Scheme == "http" {
			t.Fatalf("plain http request reached the transport: %s", request.URL)
		}
		return jsonResponse(http.StatusFound, "", nil, map[string]string{"Location": "http://registry.test/v2/library/app/manifests/latest"}), nil
	})
	client := MustNewClient(Options{
		BaseURL:           "https://registry.test",
		AllowPrivateHosts: true,
		RequestAttempts:   1,
		HTTPClient:        &http.Client{Transport: transport},
	})
	_, err := client.FetchManifest(context.Background(), "library/app", "latest")
	if err == nil || !strings.Contains(err.Error(), "reject redirect") || !strings.Contains(err.Error(), "allowlisted") {
		t.Fatalf("FetchManifest() error = %v", err)
	}
}

func TestSHA512DigestsFlowThroughResolveAndBlob(t *testing.T) {
	configBody := []byte(`{"architecture":"amd64","os":"linux"}`)
	sum := sha512.Sum512(configBody)
	digest := "sha512:" + hex.EncodeToString(sum[:])
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch {
		case request.Method == http.MethodHead && request.URL.Path == "/v2/library/app/manifests/latest":
			return jsonResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, nil, map[string]string{"Docker-Content-Digest": digest}), nil
		case request.URL.Path == "/v2/library/app/blobs/"+digest:
			return jsonResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, configBody, map[string]string{"Docker-Content-Digest": digest}), nil
		default:
			return jsonResponse(http.StatusNotFound, "text/plain", nil, nil), nil
		}
	})
	client := MustNewClient(Options{
		BaseURL:           "https://registry.test",
		AllowPrivateHosts: true,
		HTTPClient:        &http.Client{Transport: transport},
	})

	resolved, err := client.ResolveManifest(context.Background(), "library/app", "latest")
	if err != nil {
		t.Fatalf("ResolveManifest() error = %v", err)
	}
	if resolved.Digest != digest {
		t.Fatalf("resolved.Digest = %q", resolved.Digest)
	}
	blob, err := client.OpenBlob(context.Background(), "library/app", digest)
	if err != nil {
		t.Fatalf("OpenBlob() error = %v", err)
	}
	defer func() { _ = blob.Body.Close() }()
	body, err := io.ReadAll(blob.Body)
	if err != nil || string(body) != string(configBody) || blob.Digest != digest {
		t.Fatalf("blob = %+v body = %q err = %v", blob, body, err)
	}
}

func TestResolveManifestFallsBackToGetAndComputesDigest(t *testing.T) {
	manifestBody := []byte(`{"schemaVersion":2,"mediaType":"` + manifest.MediaTypeOCIImageManifest + `","config":{"mediaType":"` + manifest.MediaTypeOCIImageConfig + `","digest":"sha256:` + strings.Repeat("c", 64) + `","size":1},"layers":[]}`)
	expected, err := manifest.DigestBytes("sha256", manifestBody)
	if err != nil {
		t.Fatalf("DigestBytes() error = %v", err)
	}
	methods := make([]string, 0, 2)
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		methods = append(methods, request.Method)
		if request.Method == http.MethodHead {
			return jsonResponse(http.StatusMethodNotAllowed, "text/plain", nil, nil), nil
		}
		return jsonResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, manifestBody, nil), nil
	})
	client := MustNewClient(Options{
		BaseURL:           "https://registry.test",
		AllowPrivateHosts: true,
		RequestAttempts:   1,
		HTTPClient:        &http.Client{Transport: transport},
	})

	resolved, err := client.ResolveManifest(context.Background(), "library/app", "latest")
	if err != nil {
		t.Fatalf("ResolveManifest() error = %v", err)
	}
	if resolved.Digest != expected || resolved.MediaType != manifest.MediaTypeOCIImageManifest {
		t.Fatalf("resolved = %+v, want digest %s", resolved, expected)
	}
	if strings.Join(methods, ",") != "HEAD,GET" {
		t.Fatalf("methods = %q", methods)
	}
}

func TestResolveManifestRejectsMalformedHeadDigest(t *testing.T) {
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodHead {
			return jsonResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, nil, map[string]string{"Docker-Content-Digest": "md5:" + strings.Repeat("a", 32)}), nil
		}
		return jsonResponse(http.StatusNotFound, "text/plain", nil, nil), nil
	})
	client := MustNewClient(Options{
		BaseURL:           "https://registry.test",
		AllowPrivateHosts: true,
		RequestAttempts:   1,
		HTTPClient:        &http.Client{Transport: transport},
	})
	_, err := client.ResolveManifest(context.Background(), "library/app", "latest")
	if err == nil || !strings.Contains(err.Error(), "validate resolved manifest digest") {
		t.Fatalf("ResolveManifest() error = %v", err)
	}
}

func TestTokenEndpointNotFoundIsAuthScoped(t *testing.T) {
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "auth.test" {
			body, _ := json.Marshal(map[string]string{"errors": "missing"})
			return jsonResponse(http.StatusNotFound, "application/json", body, nil), nil
		}
		return jsonResponse(http.StatusUnauthorized, "", nil, map[string]string{
			"Www-Authenticate": `Bearer realm="https://auth.test/token",service="registry.test"`,
		}), nil
	})
	client := MustNewClient(Options{
		BaseURL:           "https://registry.test",
		AllowPrivateHosts: true,
		RequestAttempts:   1,
		HTTPClient:        &http.Client{Transport: transport},
	})
	_, err := client.FetchManifest(context.Background(), "library/app", "latest")
	if IsNotFound(err) {
		t.Fatalf("a 404 from the token endpoint must not read as a missing image: %v", err)
	}
	if code, ok := StatusCode(err); !ok || code != http.StatusNotFound {
		t.Fatalf("StatusCode() = %d, %t for %v", code, ok, err)
	}
}
