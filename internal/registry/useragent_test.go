package registry

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/brumbelow/layerleak/v3/internal/version"
)

func TestRequestsIdentifyLayerleakInUserAgent(t *testing.T) {
	agents := make(map[string]string)
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		agents[request.URL.Host] = request.Header.Get("User-Agent")
		if request.URL.Host == "auth.test" {
			body, _ := json.Marshal(map[string]string{"token": "test-token"})
			return jsonResponse(http.StatusOK, "application/json", body, nil), nil
		}
		if request.Header.Get("Authorization") != "Bearer test-token" {
			return jsonResponse(http.StatusUnauthorized, "", nil, map[string]string{
				"Www-Authenticate": `Bearer realm="https://auth.test/token",service="registry.test"`,
			}), nil
		}
		return jsonResponse(http.StatusOK, "application/vnd.oci.image.manifest.v1+json", []byte(`{"schemaVersion":2}`), nil), nil
	})
	client := NewClient(Options{
		BaseURL:           "https://registry.test",
		AllowPrivateHosts: true,
		HTTPClient:        &http.Client{Transport: transport},
	})

	if _, err := client.FetchManifest(context.Background(), "library/app", "latest"); err != nil {
		t.Fatalf("FetchManifest() error = %v", err)
	}
	want := "layerleak/" + version.Effective()
	if !strings.HasPrefix(want, "layerleak/") || strings.TrimPrefix(want, "layerleak/") == "" {
		t.Fatalf("version produced an empty User-Agent: %q", want)
	}
	for _, host := range []string{"registry.test", "auth.test"} {
		if agents[host] != want {
			t.Fatalf("User-Agent to %s = %q, want %q", host, agents[host], want)
		}
	}
}

func TestUserAgentOptionOverridesDefault(t *testing.T) {
	agent := ""
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		agent = request.Header.Get("User-Agent")
		return jsonResponse(http.StatusOK, "application/vnd.oci.image.manifest.v1+json", []byte(`{"schemaVersion":2}`), nil), nil
	})
	client := NewClient(Options{
		BaseURL:           "https://registry.test",
		AllowPrivateHosts: true,
		UserAgent:         "  layerleak-ci/1.2.3 (+https://ci.example)  ",
		HTTPClient:        &http.Client{Transport: transport},
	})
	if _, err := client.FetchManifest(context.Background(), "library/app", "latest"); err != nil {
		t.Fatalf("FetchManifest() error = %v", err)
	}
	if agent != "layerleak-ci/1.2.3 (+https://ci.example)" {
		t.Fatalf("User-Agent = %q", agent)
	}
}
