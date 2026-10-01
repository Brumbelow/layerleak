package registry

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
)

func TestRegistryStatusFailuresAreTyped(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		wantMessage string
		notFound    bool
		rateLimited bool
		unauthz     bool
		server      bool
	}{
		{name: "missing manifest", status: http.StatusNotFound, wantMessage: "registry request failed: status=404 Not Found", notFound: true},
		{name: "rate limited", status: http.StatusTooManyRequests, wantMessage: "registry request failed: status=429 Too Many Requests", rateLimited: true},
		{name: "forbidden", status: http.StatusForbidden, wantMessage: "registry request failed: status=403 Forbidden", unauthz: true},
		{name: "upstream failure", status: http.StatusBadGateway, wantMessage: "registry request failed: status=502 Bad Gateway", server: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
				return jsonResponse(test.status, "text/plain", []byte("body-marker"), nil), nil
			})
			client := NewClient(Options{
				BaseURL:           "https://registry.test",
				AllowPrivateHosts: true,
				RequestAttempts:   1,
				HTTPClient:        &http.Client{Transport: transport},
			})

			_, err := client.FetchManifest(context.Background(), "library/app", "latest")
			if err == nil {
				t.Fatal("FetchManifest() error = nil")
			}
			var statusErr *StatusError
			if !errors.As(err, &statusErr) {
				t.Fatalf("FetchManifest() error %T %v is not a *StatusError", err, err)
			}
			if statusErr.StatusCode != test.status || statusErr.Method != http.MethodGet || statusErr.Auth {
				t.Fatalf("StatusError = %+v", statusErr)
			}
			if statusErr.URL != "https://registry.test/v2/library/app/manifests/latest" {
				t.Fatalf("StatusError.URL = %q", statusErr.URL)
			}
			if err.Error() != test.wantMessage {
				t.Fatalf("err = %q, want %q", err.Error(), test.wantMessage)
			}
			if strings.Contains(err.Error(), "body-marker") {
				t.Fatalf("err echoed the response body: %q", err.Error())
			}
			if IsNotFound(err) != test.notFound || IsRateLimited(err) != test.rateLimited || IsUnauthorized(err) != test.unauthz || IsServerError(err) != test.server {
				t.Fatalf("classification: notFound=%t rateLimited=%t unauthorized=%t server=%t", IsNotFound(err), IsRateLimited(err), IsUnauthorized(err), IsServerError(err))
			}
			code, ok := StatusCode(err)
			if !ok || code != test.status {
				t.Fatalf("StatusCode() = %d, %t", code, ok)
			}
		})
	}
}

func TestAuthStatusFailuresAreTypedAsAuth(t *testing.T) {
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "auth.test" {
			return jsonResponse(http.StatusForbidden, "application/json", []byte(`{"details":"denied-marker"}`), nil), nil
		}
		return jsonResponse(http.StatusUnauthorized, "", nil, map[string]string{
			"Www-Authenticate": `Bearer realm="https://auth.test/token?secret=query-marker",service="registry.test"`,
		}), nil
	})
	client := NewClient(Options{
		BaseURL:           "https://registry.test",
		AllowPrivateHosts: true,
		RequestAttempts:   1,
		HTTPClient:        &http.Client{Transport: transport},
	})

	_, err := client.FetchManifest(context.Background(), "library/app", "latest")
	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("FetchManifest() error %T %v is not a *StatusError", err, err)
	}
	if !statusErr.Auth || statusErr.StatusCode != http.StatusForbidden || statusErr.URL != "https://auth.test/token" {
		t.Fatalf("StatusError = %+v", statusErr)
	}
	if !strings.Contains(err.Error(), "auth request failed: status=403 Forbidden") {
		t.Fatalf("err = %q", err.Error())
	}
	if strings.Contains(err.Error(), "marker") {
		t.Fatalf("err echoed untrusted content: %q", err.Error())
	}
	if IsNotFound(err) || !IsUnauthorized(err) {
		t.Fatalf("classification: notFound=%t unauthorized=%t", IsNotFound(err), IsUnauthorized(err))
	}
}

func TestStatusHelpersIgnoreOtherErrors(t *testing.T) {
	plain := errors.New("boom")
	if IsNotFound(plain) || IsRateLimited(plain) || IsUnauthorized(plain) || IsServerError(plain) || IsNotFound(nil) {
		t.Fatal("helpers matched a non-status error")
	}
	if _, ok := StatusCode(plain); ok {
		t.Fatal("StatusCode() matched a non-status error")
	}
	if (&StatusError{StatusCode: 499}).Error() != "registry request failed: status=499" {
		t.Fatalf("unknown status text = %q", (&StatusError{StatusCode: 499}).Error())
	}
}

func TestTransportErrorsRedactRedirectTargetQuery(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	resetErr := &net.OpError{Op: "read", Net: "tcp", Err: errors.New("connection reset by peer")}
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Host {
		case "cdn.test":
			return nil, resetErr
		default:
			return jsonResponse(http.StatusTemporaryRedirect, "", nil, map[string]string{
				"Location": "https://cdn.test/blobs/" + digest + "?X-Amz-Credential=AKIA-CREDENTIAL-MARKER&X-Amz-Signature=SIGNATURE-MARKER",
			}), nil
		}
	})
	client := NewClient(Options{
		BaseURL:           "https://registry.test",
		AllowPrivateHosts: true,
		RequestAttempts:   1,
		HTTPClient:        &http.Client{Transport: transport},
	})

	_, err := client.OpenBlob(context.Background(), "library/app", digest)
	if err == nil {
		t.Fatal("OpenBlob() error = nil")
	}
	message := err.Error()
	for _, marker := range []string{"SIGNATURE-MARKER", "CREDENTIAL-MARKER", "X-Amz", "?"} {
		if strings.Contains(message, marker) {
			t.Fatalf("error echoed the pre-signed query (%q): %s", marker, message)
		}
	}
	if !strings.Contains(message, "https://cdn.test/blobs/"+digest) || !strings.Contains(message, "connection reset by peer") {
		t.Fatalf("error lost the redacted target or cause: %s", message)
	}
	if !errors.Is(err, resetErr) {
		t.Fatalf("errors.Is(err, resetErr) = false for %v", err)
	}
	var requestErr *RequestError
	if !errors.As(err, &requestErr) || requestErr.URL != "https://cdn.test/blobs/"+digest {
		t.Fatalf("RequestError = %+v", requestErr)
	}
}

func TestRejectedRedirectErrorsRedactTargetQuery(t *testing.T) {
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "registry.test" {
			return jsonResponse(http.StatusFound, "", nil, map[string]string{
				"Location": "http://cdn.test/manifest?sig=SIGNATURE-MARKER",
			}), nil
		}
		return jsonResponse(http.StatusOK, "text/plain", nil, nil), nil
	})
	client := NewClient(Options{
		BaseURL:           "https://registry.test",
		AllowPrivateHosts: true,
		RequestAttempts:   1,
		HTTPClient:        &http.Client{Transport: transport},
	})

	_, err := client.FetchManifest(context.Background(), "library/app", "latest")
	if err == nil {
		t.Fatal("FetchManifest() error = nil")
	}
	if strings.Contains(err.Error(), "SIGNATURE-MARKER") || strings.Contains(err.Error(), "sig=") {
		t.Fatalf("error echoed the redirect query: %s", err.Error())
	}
	if !strings.Contains(err.Error(), "reject redirect") {
		t.Fatalf("error = %s", err.Error())
	}
}

func TestRedactURL(t *testing.T) {
	tests := map[string]string{
		"https://cdn.test/blobs/x?X-Amz-Signature=abc#frag": "https://cdn.test/blobs/x",
		"https://user:pass@cdn.test:8443/path":              "https://cdn.test:8443/path",
		"https://cdn.test":                                  "https://cdn.test",
		"":                                                  "<redacted>",
		"https://cdn.test/%ZZ":                              "<redacted>",
	}
	for input, want := range tests {
		if got := redactURL(input); got != want {
			t.Fatalf("redactURL(%q) = %q, want %q", input, got, want)
		}
	}
}
