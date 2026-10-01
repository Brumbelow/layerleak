package registry

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/manifest"
)

const testManifestBody = `{"schemaVersion":2,"mediaType":"` + manifest.MediaTypeOCIImageManifest + `","config":{"mediaType":"` + manifest.MediaTypeOCIImageConfig + `","digest":"sha256:config","size":1},"layers":[]}`

// newTLSRegistry starts a TLS registry stub whose certificate is valid for
// example.com and 127.0.0.1 (the httptest certificate) and returns the server,
// its port and a transport trusting it.
func newTLSRegistry(t *testing.T, handler http.HandlerFunc, configure ...func(*httptest.Server)) (*httptest.Server, string, *http.Transport) {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	for _, option := range configure {
		option(server)
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	}
	return server, port, &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: true,
	}
}

func manifestHandler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v2/library/app/manifests/latest" {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", manifest.MediaTypeOCIImageManifest)
		writer.Header().Set("Docker-Content-Digest", "sha256:"+strings.Repeat("a", 64))
		_, _ = writer.Write([]byte(testManifestBody))
	}
}

// recordingDialer wraps the raw dialer and records every dial target in order.
type recordingDialer struct {
	mu      sync.Mutex
	targets []string
	fail    map[string]error
}

func (d *recordingDialer) dial(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.targets = append(d.targets, address)
	err := d.fail[address]
	d.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, address)
}

func (d *recordingDialer) recorded() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.targets...)
}

func installRecordingDialer(t *testing.T, client *Client) *recordingDialer {
	t.Helper()
	transport, ok := client.httpClient.Transport.(*pinnedTransport)
	if !ok {
		t.Fatalf("client transport = %T", client.httpClient.Transport)
	}
	dialer := &recordingDialer{fail: make(map[string]error)}
	transport.dial = dialer.dial
	return dialer
}

// connectProxy is an HTTP proxy that records CONNECT targets and tunnels them
// to a fixed backend address, emulating a hostname-policy egress proxy.
func connectProxy(t *testing.T, backend string) (*httptest.Server, *[]string) {
	t.Helper()
	var mu sync.Mutex
	targets := make([]string, 0, 1)
	proxy := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodConnect {
			http.Error(writer, "only CONNECT is supported", http.StatusMethodNotAllowed)
			return
		}
		mu.Lock()
		targets = append(targets, request.Host)
		mu.Unlock()
		if net.ParseIP(strings.TrimSuffix(strings.Split(request.Host, ":")[0], "]")) != nil || strings.HasPrefix(request.Host, "[") {
			http.Error(writer, "policy denial: IP literal CONNECT targets are refused", http.StatusForbidden)
			return
		}
		upstream, err := net.Dial("tcp", backend)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadGateway)
			return
		}
		hijacker, ok := writer.(http.Hijacker)
		if !ok {
			http.Error(writer, "hijack unsupported", http.StatusInternalServerError)
			return
		}
		conn, buffered, err := hijacker.Hijack()
		if err != nil {
			_ = upstream.Close()
			return
		}
		_, _ = buffered.WriteString("HTTP/1.1 200 Connection established\r\n\r\n")
		_ = buffered.Flush()
		go func() {
			_, _ = io.Copy(upstream, conn)
			_ = upstream.Close()
		}()
		_, _ = io.Copy(conn, upstream)
		_ = conn.Close()
	}))
	t.Cleanup(proxy.Close)
	return proxy, &targets
}

func TestProxiedRequestsConnectByHostnameWithoutLocalResolution(t *testing.T) {
	backend, _, transport := newTLSRegistry(t, manifestHandler(t))
	proxy, targets := connectProxy(t, backend.Listener.Addr().String())
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatalf("Parse(proxy.URL) error = %v", err)
	}
	transport.Proxy = func(*http.Request) (*url.URL, error) { return proxyURL, nil }

	var lookups atomic.Int32
	client := MustNewClient(Options{
		BaseURL:        "https://example.com",
		RequestTimeout: 5 * time.Second,
		HTTPClient:     &http.Client{Transport: transport},
		LookupIP: func(_ context.Context, host string) ([]net.IPAddr, error) {
			lookups.Add(1)
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		},
	})
	dialer := installRecordingDialer(t, client)

	response, err := client.FetchManifest(context.Background(), "library/app", "latest")
	if err != nil {
		t.Fatalf("FetchManifest() through proxy error = %v", err)
	}
	if string(response.Body) != testManifestBody {
		t.Fatalf("manifest body = %q", response.Body)
	}
	if got := strings.Join(*targets, ","); got != "example.com:443" {
		t.Fatalf("CONNECT targets = %q, want hostname example.com:443", got)
	}
	if lookups.Load() != 0 {
		t.Fatalf("local DNS lookups = %d, want 0 when a proxy carries the request", lookups.Load())
	}
	if got := dialer.recorded(); len(got) != 1 || got[0] != proxyURL.Host {
		t.Fatalf("dialed %q, want only the proxy %q", got, proxyURL.Host)
	}
}

func TestProxiedRequestsStillEnforceSchemeAndAllowlistPolicy(t *testing.T) {
	proxy, targets := connectProxy(t, "127.0.0.1:1")
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatalf("Parse(proxy.URL) error = %v", err)
	}
	newClient := func(baseURL string, allowed ...string) (*Client, error) {
		transport := &http.Transport{Proxy: func(*http.Request) (*url.URL, error) { return proxyURL, nil }}
		return NewClient(Options{
			BaseURL:                     baseURL,
			AllowedPrivateRegistryHosts: allowed,
			RequestAttempts:             1,
			HTTPClient:                  &http.Client{Transport: transport},
			LookupIP: func(context.Context, string) ([]net.IPAddr, error) {
				t.Fatal("LookupIP must not be called for proxied requests")
				return nil, nil
			},
		})
	}

	t.Run("plain http stays allowlist-only", func(t *testing.T) {
		if _, err := newClient("http://registry.example"); err == nil || !strings.Contains(err.Error(), "https") {
			t.Fatalf("NewClient() error = %v", err)
		}
		redirected, err := newClient("https://registry.example", "registry.internal:5000")
		if err != nil {
			t.Fatalf("NewClient() error = %v", err)
		}
		if err := redirected.validateOutboundURL("http://registry.example/v2/", redirected.baseURL, true, requestKindRegistry); err == nil || !strings.Contains(err.Error(), "allowlisted") {
			t.Fatalf("http redirect validation error = %v", err)
		}
	})
	t.Run("non-public IP literal is rejected before the proxy", func(t *testing.T) {
		client, err := newClient("https://169.254.169.254")
		if err != nil {
			t.Fatalf("NewClient() error = %v", err)
		}
		_, err = client.FetchManifest(context.Background(), "library/app", "latest")
		if err == nil || !strings.Contains(err.Error(), "non-public registry address") {
			t.Fatalf("FetchManifest() error = %v", err)
		}
	})
	if len(*targets) != 0 {
		t.Fatalf("CONNECT targets = %q, want none", *targets)
	}
}

func TestDirectRequestsPinValidatedAddressesAndReuseConnections(t *testing.T) {
	var connections atomic.Int32
	_, port, transport := newTLSRegistry(t, manifestHandler(t), func(server *httptest.Server) {
		server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
			if state == http.StateNew {
				connections.Add(1)
			}
		}
	})
	var lookups atomic.Int32
	client := MustNewClient(Options{
		BaseURL:                     "https://example.com:" + port,
		AllowedPrivateRegistryHosts: []string{"example.com:" + port},
		RequestTimeout:              5 * time.Second,
		HTTPClient:                  &http.Client{Transport: transport},
		LookupIP: func(_ context.Context, host string) ([]net.IPAddr, error) {
			lookups.Add(1)
			if host != "example.com" {
				return nil, fmt.Errorf("unexpected lookup for %q", host)
			}
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		},
	})
	dialer := installRecordingDialer(t, client)

	for index := 0; index < 3; index++ {
		response, err := client.FetchManifest(context.Background(), "library/app", "latest")
		if err != nil {
			t.Fatalf("FetchManifest(%d) error = %v", index, err)
		}
		if string(response.Body) != testManifestBody {
			t.Fatalf("manifest body = %q", response.Body)
		}
	}
	if got := dialer.recorded(); len(got) != 1 || got[0] != "127.0.0.1:"+port {
		t.Fatalf("dialed %q, want one pinned dial to 127.0.0.1:%s", got, port)
	}
	if connections.Load() != 1 {
		t.Fatalf("server connections = %d, want 1 (keep-alive reuse)", connections.Load())
	}
	if lookups.Load() != 3 {
		t.Fatalf("lookups = %d, want exactly one per request", lookups.Load())
	}
}

func TestPinnedDialFallsBackToNextValidatedAddress(t *testing.T) {
	_, port, transport := newTLSRegistry(t, manifestHandler(t))
	client := MustNewClient(Options{
		BaseURL:                     "https://example.com:" + port,
		AllowedPrivateRegistryHosts: []string{"example.com:" + port},
		RequestTimeout:              5 * time.Second,
		HTTPClient:                  &http.Client{Transport: transport},
		LookupIP: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("2001:db8::1")}, {IP: net.ParseIP("127.0.0.1")}}, nil
		},
	})
	dialer := installRecordingDialer(t, client)
	dialer.fail["[2001:db8::1]:"+port] = errors.New("network is unreachable")

	if _, err := client.FetchManifest(context.Background(), "library/app", "latest"); err != nil {
		t.Fatalf("FetchManifest() error = %v", err)
	}
	if got := strings.Join(dialer.recorded(), ","); got != "[2001:db8::1]:"+port+",127.0.0.1:"+port {
		t.Fatalf("dial order = %q", got)
	}
}

func TestPinnedDialRejectsUnpinnedTargets(t *testing.T) {
	client := MustNewClient(Options{
		BaseURL: "https://example.com",
		LookupIP: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
		},
	})
	transport := client.httpClient.Transport.(*pinnedTransport)
	transport.dial = func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("raw dial must not happen without a pin")
		return nil, nil
	}
	if _, err := transport.dialContext(context.Background(), "tcp", "example.com:443"); err == nil {
		t.Fatal("dialContext() without a pin error = nil")
	}
	pinned := context.WithValue(context.Background(), dialPolicyKey{}, &dialPolicy{pin: &pinnedAddresses{host: "example.com", port: "443"}})
	if _, err := transport.dialContext(pinned, "tcp", "other.example:443"); err == nil {
		t.Fatal("dialContext() for a different host error = nil")
	}
}

func TestClientRejectsNonPublicResolutionBeforeDial(t *testing.T) {
	var lookups atomic.Int32
	client := MustNewClient(Options{
		BaseURL:    "https://registry.example",
		HTTPClient: &http.Client{Transport: &http.Transport{}}, // no environment proxy: exercise the direct path
		LookupIP: func(context.Context, string) ([]net.IPAddr, error) {
			lookups.Add(1)
			return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}, {IP: net.ParseIP("127.0.0.1")}}, nil
		},
	})
	dialer := installRecordingDialer(t, client)

	_, err := client.FetchManifest(context.Background(), "library/app", "latest")
	if err == nil || !strings.Contains(err.Error(), "non-public registry address") {
		t.Fatalf("FetchManifest() error = %v", err)
	}
	if lookups.Load() != 1 {
		t.Fatalf("lookups = %d, want exactly one resolution per request", lookups.Load())
	}
	if got := dialer.recorded(); len(got) != 0 {
		t.Fatalf("dialed %q before the address policy rejected the host", got)
	}
}

func TestBlobRequestsHaveResponseHeaderDeadline(t *testing.T) {
	digest := "sha256:" + strings.Repeat("d", 64)
	_, port, transport := newTLSRegistry(t, func(writer http.ResponseWriter, request *http.Request) {
		if strings.HasPrefix(request.URL.Path, "/v2/library/app/blobs/") {
			<-request.Context().Done()
			return
		}
		manifestHandler(t)(writer, request)
	})
	client := MustNewClient(Options{
		BaseURL:                     "https://example.com:" + port,
		AllowedPrivateRegistryHosts: []string{"example.com:" + port},
		RequestTimeout:              100 * time.Millisecond,
		RequestAttempts:             1,
		HTTPClient:                  &http.Client{Transport: transport},
		LookupIP: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	started := time.Now()
	_, err := client.OpenBlob(ctx, "library/app", digest)
	elapsed := time.Since(started)
	if err == nil {
		t.Fatal("OpenBlob() error = nil")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("OpenBlob() error = %v, want a timeout", err)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("OpenBlob() took %s, want the response-header deadline to fire", elapsed)
	}
}

func TestHardenedTransportDerivesDeadlinesFromRequestTimeout(t *testing.T) {
	client := MustNewClient(Options{BaseURL: "https://registry.example", RequestTimeout: 7 * time.Second})
	transport, ok := client.httpClient.Transport.(*pinnedTransport)
	if !ok {
		t.Fatalf("client transport = %T", client.httpClient.Transport)
	}
	if transport.base.ResponseHeaderTimeout != 7*time.Second {
		t.Fatalf("ResponseHeaderTimeout = %s", transport.base.ResponseHeaderTimeout)
	}
	if transport.base.TLSHandshakeTimeout != 7*time.Second {
		t.Fatalf("TLSHandshakeTimeout = %s", transport.base.TLSHandshakeTimeout)
	}
	if transport.base.DisableKeepAlives {
		t.Fatal("DisableKeepAlives = true")
	}
	if transport.dialTimeout != 7*time.Second {
		t.Fatalf("dialTimeout = %s", transport.dialTimeout)
	}

	unbounded := MustNewClient(Options{BaseURL: "https://registry.example"})
	unboundedTransport := unbounded.httpClient.Transport.(*pinnedTransport)
	if unboundedTransport.base.ResponseHeaderTimeout != defaultResponseHeaderTimeout || unboundedTransport.base.TLSHandshakeTimeout != 10*time.Second {
		t.Fatalf("defaults: ResponseHeaderTimeout = %s TLSHandshakeTimeout = %s", unboundedTransport.base.ResponseHeaderTimeout, unboundedTransport.base.TLSHandshakeTimeout)
	}
}

func TestRequestTimeoutLongerThanDefaultsKeepsBaseHandshakeTimeout(t *testing.T) {
	client := MustNewClient(Options{BaseURL: "https://registry.example", RequestTimeout: 90 * time.Second})
	transport := client.httpClient.Transport.(*pinnedTransport)
	if transport.base.TLSHandshakeTimeout != 10*time.Second {
		t.Fatalf("TLSHandshakeTimeout = %s", transport.base.TLSHandshakeTimeout)
	}
	if transport.dialTimeout != defaultDialTimeout {
		t.Fatalf("dialTimeout = %s", transport.dialTimeout)
	}
}
