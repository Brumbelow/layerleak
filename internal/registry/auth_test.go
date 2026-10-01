package registry

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/manifest"
)

const (
	testToken                 = "synthetic-bearer-token-0001"
	testManifest              = `{"schemaVersion":2,"mediaType":"` + manifest.MediaTypeOCIImageManifest + `","config":{"mediaType":"` + manifest.MediaTypeOCIImageConfig + `","digest":"sha256:config","size":1},"layers":[]}`
	testBearerChallengeHeader = `Bearer realm="https://auth.test/token",service="registry.test",scope="repository:library/app:pull"`
)

func testBasicAuthorization() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(testUsername+":"+testPassword))
}

func assertNoAuthLeak(t *testing.T, label string, err error) {
	t.Helper()
	if err == nil {
		return
	}
	text := fmt.Sprintf("%v | %+v | %q", err, err, err.Error())
	assertNoSecret(t, label, text)
	if strings.Contains(text, testToken) {
		t.Fatalf("%s leaks the bearer token: %q", label, text)
	}
}

// bearerRegistry is a round-trip stub of a registry behind a token service.
// It records what the realm and the registry received.
type bearerRegistry struct {
	mu                 sync.Mutex
	realmAuthorization []string
	registryAuth       []string
	tokenRequests      int
	realmStatus        int
	tokenBody          string
	realmScheme        string
}

func (r *bearerRegistry) roundTrip(request *http.Request) (*http.Response, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if request.URL.Host == "auth.test" || request.URL.Host == "auth.internal" {
		r.tokenRequests++
		r.realmAuthorization = append(r.realmAuthorization, request.Header.Get("Authorization"))
		status := r.realmStatus
		if status == 0 {
			status = http.StatusOK
		}
		if status != http.StatusOK {
			return jsonResponse(status, "application/json", []byte(`{"errors":[{"code":"UNAUTHORIZED"}]}`), nil), nil
		}
		body := r.tokenBody
		if body == "" {
			body = `{"token":"` + testToken + `"}`
		}
		return jsonResponse(http.StatusOK, "application/json", []byte(body), nil), nil
	}
	authorization := request.Header.Get("Authorization")
	r.registryAuth = append(r.registryAuth, authorization)
	if authorization != "Bearer "+testToken {
		challenge := testBearerChallengeHeader
		if r.realmScheme != "" {
			challenge = strings.Replace(challenge, "https://auth.test", r.realmScheme+"://auth.internal", 1)
		}
		return jsonResponse(http.StatusUnauthorized, "", nil, map[string]string{"Www-Authenticate": challenge}), nil
	}
	return jsonResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, []byte(testManifest), map[string]string{"Docker-Content-Digest": "sha256:manifest"}), nil
}

func newBearerClient(t *testing.T, registry *bearerRegistry, credentials CredentialSource) *Client {
	t.Helper()
	return MustNewClient(Options{
		BaseURL:           "https://registry.test",
		AllowPrivateHosts: true,
		HTTPClient:        &http.Client{Transport: roundTripFunc(registry.roundTrip)},
		Credentials:       credentials,
	})
}

func TestBearerChallengeSendsBasicCredentialsToRealm(t *testing.T) {
	registry := &bearerRegistry{}
	client := newBearerClient(t, registry, StaticCredentials("registry.test", testUsername, testPassword))

	response, err := client.FetchManifest(context.Background(), "library/app", "latest")
	if err != nil {
		t.Fatalf("FetchManifest() error = %v", err)
	}
	if response.Digest != "sha256:manifest" {
		t.Fatalf("Digest = %q", response.Digest)
	}
	if registry.tokenRequests != 1 || registry.realmAuthorization[0] != testBasicAuthorization() {
		t.Fatalf("realm requests = %d, authorization = %q", registry.tokenRequests, registry.realmAuthorization)
	}
	for _, authorization := range registry.registryAuth {
		if strings.HasPrefix(authorization, "Basic ") {
			t.Fatal("Basic credentials were sent to the registry in a Bearer flow")
		}
	}
	if len(client.tokenCache) != 1 {
		t.Fatalf("token cache entries = %d", len(client.tokenCache))
	}
	identity := Credential{Username: testUsername, Password: testPassword}.identity()
	for key := range client.tokenCache {
		if !strings.HasSuffix(key, "|"+identity) || !strings.HasPrefix(key, "registry.test|") {
			t.Fatalf("cache key %q is not scoped to the registry host and credential identity", key)
		}
		assertNoSecret(t, "cache key", key)
	}

	// A second client with other credentials for the same scope must not share the token.
	anonymous := newBearerClient(t, registry, nil)
	if _, err := anonymous.FetchManifest(context.Background(), "library/app", "latest"); err != nil {
		t.Fatalf("anonymous FetchManifest() error = %v", err)
	}
	if registry.tokenRequests != 2 || registry.realmAuthorization[1] != "" {
		t.Fatalf("anonymous realm authorization = %q", registry.realmAuthorization)
	}
	for key := range anonymous.tokenCache {
		if !strings.HasSuffix(key, "|anonymous") {
			t.Fatalf("anonymous cache key %q", key)
		}
	}
}

func TestAnonymousFlowIsUnchangedWhenNoCredentialMatches(t *testing.T) {
	registry := &bearerRegistry{}
	client := newBearerClient(t, registry, ChainCredentials(
		StaticCredentials("other.example", testUsername, testPassword),
		DockerConfigCredentials(writeDockerConfig(t, `{"auths": {"ghcr.io": {"username": "u", "password": "p"}}}`)),
	))
	if _, err := client.FetchManifest(context.Background(), "library/app", "latest"); err != nil {
		t.Fatalf("FetchManifest() error = %v", err)
	}
	if registry.tokenRequests != 1 || registry.realmAuthorization[0] != "" {
		t.Fatalf("realm authorization = %q, want anonymous", registry.realmAuthorization)
	}
	if registry.registryAuth[0] != "" {
		t.Fatalf("first registry request authorization = %q, want anonymous probe", registry.registryAuth[0])
	}
}

func TestBearerWrongPasswordSurfacesUnauthorizedWithoutLeaking(t *testing.T) {
	registry := &bearerRegistry{realmStatus: http.StatusUnauthorized}
	client := newBearerClient(t, registry, StaticCredentials("registry.test", testUsername, testPassword))

	_, err := client.FetchManifest(context.Background(), "library/app", "latest")
	if !IsUnauthorized(err) {
		t.Fatalf("FetchManifest() error = %v, want unauthorized", err)
	}
	code, ok := StatusCode(err)
	var statusErr *StatusError
	if !ok || code != http.StatusUnauthorized || !errors.As(err, &statusErr) || !statusErr.Auth {
		t.Fatalf("status = (%d, %v), auth = %v", code, ok, statusErr)
	}
	assertNoAuthLeak(t, "wrong password", err)
	if len(client.tokenCache) != 0 {
		t.Fatal("a rejected token request left a cache entry")
	}
}

func TestBearerCredentialsRequireHTTPSRealm(t *testing.T) {
	registry := &bearerRegistry{realmScheme: "http"}
	client := MustNewClient(Options{
		BaseURL:                 "https://registry.test",
		AllowPrivateHosts:       true,
		AllowedPrivateAuthHosts: []string{"auth.internal"},
		HTTPClient:              &http.Client{Transport: roundTripFunc(registry.roundTrip)},
		Credentials:             StaticCredentials("registry.test", testUsername, testPassword),
	})
	_, err := client.FetchManifest(context.Background(), "library/app", "latest")
	if !errors.Is(err, ErrCredentialsRequireHTTPS) {
		t.Fatalf("FetchManifest() error = %v, want ErrCredentialsRequireHTTPS", err)
	}
	if registry.tokenRequests != 0 {
		t.Fatalf("realm contacted %d times over http with a credential", registry.tokenRequests)
	}
	assertNoAuthLeak(t, "http realm", err)

	// The same realm is fine without a credential: the anonymous flow is unchanged.
	anonymous := MustNewClient(Options{
		BaseURL:                 "https://registry.test",
		AllowPrivateHosts:       true,
		AllowedPrivateAuthHosts: []string{"auth.internal"},
		HTTPClient:              &http.Client{Transport: roundTripFunc(registry.roundTrip)},
	})
	if _, err := anonymous.FetchManifest(context.Background(), "library/app", "latest"); err != nil {
		t.Fatalf("anonymous FetchManifest() error = %v", err)
	}
}

func TestBearerRealmMustPassAllowlistEvenWithCredentials(t *testing.T) {
	registry := &bearerRegistry{realmScheme: "http"}
	client := newBearerClient(t, registry, StaticCredentials("registry.test", testUsername, testPassword))
	_, err := client.FetchManifest(context.Background(), "library/app", "latest")
	if err == nil || !strings.Contains(err.Error(), "reject auth realm") {
		t.Fatalf("FetchManifest() error = %v, want realm rejection", err)
	}
	if registry.tokenRequests != 0 {
		t.Fatal("a rejected realm was contacted")
	}
	assertNoAuthLeak(t, "rejected realm", err)
}

func TestCredentialLookupErrorAbortsTheRequest(t *testing.T) {
	registry := &bearerRegistry{}
	failure := &UnsupportedCredentialError{Host: "registry.test", Mechanism: "credential helper test"}
	client := newBearerClient(t, registry, &stubCredentialSource{err: failure})
	_, err := client.FetchManifest(context.Background(), "library/app", "latest")
	var unsupported *UnsupportedCredentialError
	if !errors.As(err, &unsupported) || !strings.Contains(err.Error(), "resolve registry credentials for registry.test") {
		t.Fatalf("FetchManifest() error = %v, want the lookup failure", err)
	}
	if registry.tokenRequests != 0 {
		t.Fatal("token requested despite a credential lookup failure")
	}
}

func TestTokenCacheHonoursAdvertisedExpiry(t *testing.T) {
	registry := &bearerRegistry{tokenBody: `{"token":"` + testToken + `","expires_in":30}`}
	client := newBearerClient(t, registry, StaticCredentials("registry.test", testUsername, testPassword))
	start := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	now := start
	client.now = func() time.Time { return now }

	fetch := func(label string, wantTokenRequests int) {
		t.Helper()
		if _, err := client.FetchManifest(context.Background(), "library/app", "latest"); err != nil {
			t.Fatalf("%s: FetchManifest() error = %v", label, err)
		}
		if registry.tokenRequests != wantTokenRequests {
			t.Fatalf("%s: tokenRequests = %d, want %d", label, registry.tokenRequests, wantTokenRequests)
		}
	}
	fetch("first", 1)
	now = start.Add(15 * time.Second)
	fetch("within lifetime minus margin", 1)
	now = start.Add(21 * time.Second)
	fetch("after lifetime minus margin", 2)
	if len(client.tokenCache) != 1 {
		t.Fatalf("token cache entries = %d, want the refreshed token only", len(client.tokenCache))
	}
	for _, authorization := range registry.realmAuthorization {
		if authorization != testBasicAuthorization() {
			t.Fatalf("refresh token request authorization = %q", authorization)
		}
	}
}

func TestTokenCacheDefaultsToSixtySecondsWithoutExpiresIn(t *testing.T) {
	registry := &bearerRegistry{}
	client := newBearerClient(t, registry, nil)
	start := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	now := start
	client.now = func() time.Time { return now }

	for _, step := range []struct {
		offset time.Duration
		want   int
	}{{0, 1}, {45 * time.Second, 1}, {51 * time.Second, 2}, {52 * time.Second, 2}} {
		now = start.Add(step.offset)
		if _, err := client.FetchManifest(context.Background(), "library/app", "latest"); err != nil {
			t.Fatalf("offset %s: FetchManifest() error = %v", step.offset, err)
		}
		if registry.tokenRequests != step.want {
			t.Fatalf("offset %s: tokenRequests = %d, want %d", step.offset, registry.tokenRequests, step.want)
		}
	}
}

func TestTokenShorterThanSafetyMarginIsNeverCached(t *testing.T) {
	registry := &bearerRegistry{tokenBody: `{"token":"` + testToken + `","expires_in":5}`}
	client := newBearerClient(t, registry, nil)
	for index := 1; index <= 2; index++ {
		if _, err := client.FetchManifest(context.Background(), "library/app", "latest"); err != nil {
			t.Fatalf("FetchManifest() error = %v", err)
		}
		if registry.tokenRequests != index {
			t.Fatalf("tokenRequests = %d, want %d", registry.tokenRequests, index)
		}
	}
	if len(client.tokenCache) != 0 || client.tokenCacheBytes != 0 {
		t.Fatalf("short-lived token cached: entries=%d bytes=%d", len(client.tokenCache), client.tokenCacheBytes)
	}
}

// basicRegistry is a TLS httptest registry that offers only Basic
// authentication and optionally redirects blobs to another server.
type basicRegistry struct {
	server      *httptest.Server
	mu          sync.Mutex
	received    []string
	redirectTo  string
	rejectAll   bool
	blobRequest int
}

func newBasicRegistry(t *testing.T) *basicRegistry {
	t.Helper()
	registry := &basicRegistry{}
	registry.server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		registry.mu.Lock()
		registry.received = append(registry.received, request.Header.Get("Authorization"))
		redirectTo := registry.redirectTo
		rejectAll := registry.rejectAll
		registry.mu.Unlock()
		if request.Header.Get("Authorization") != testBasicAuthorization() || rejectAll {
			writer.Header().Set("Www-Authenticate", `Basic realm="registry"`)
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case strings.Contains(request.URL.Path, "/blobs/"):
			registry.mu.Lock()
			registry.blobRequest++
			registry.mu.Unlock()
			if redirectTo != "" {
				http.Redirect(writer, request, redirectTo, http.StatusTemporaryRedirect)
				return
			}
			writer.Header().Set("Content-Type", manifest.MediaTypeOCIImageConfig)
			_, _ = writer.Write([]byte(`{"os":"linux"}`))
		case strings.Contains(request.URL.Path, "/manifests/"):
			writer.Header().Set("Content-Type", manifest.MediaTypeOCIImageManifest)
			writer.Header().Set("Docker-Content-Digest", "sha256:manifest")
			_, _ = writer.Write([]byte(testManifest))
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(registry.server.Close)
	return registry
}

func (r *basicRegistry) host() string {
	parsed, _ := url.Parse(r.server.URL)
	return parsed.Host
}

func (r *basicRegistry) client(t *testing.T, credentials CredentialSource) *Client {
	t.Helper()
	return MustNewClient(Options{
		BaseURL:           r.server.URL,
		AllowPrivateHosts: true,
		HTTPClient:        r.server.Client(),
		Credentials:       credentials,
	})
}

func TestBasicOnlyChallengeIsAnsweredWithCredentialsOverTLS(t *testing.T) {
	registry := newBasicRegistry(t)
	client := registry.client(t, StaticCredentials(registry.host(), testUsername, testPassword))

	response, err := client.FetchManifest(context.Background(), "library/app", "latest")
	if err != nil {
		t.Fatalf("FetchManifest() error = %v", err)
	}
	if response.Digest != "sha256:manifest" {
		t.Fatalf("Digest = %q", response.Digest)
	}
	if len(registry.received) != 2 || registry.received[0] != "" || registry.received[1] != testBasicAuthorization() {
		t.Fatalf("received authorization = %q, want anonymous probe then Basic", registry.received)
	}
	if len(client.tokenCache) != 0 {
		t.Fatal("Basic credentials must not enter the token cache")
	}
}

func TestBasicOnlyChallengeWithoutCredentialsFailsAsBefore(t *testing.T) {
	registry := newBasicRegistry(t)
	for name, credentials := range map[string]CredentialSource{
		"nil":          nil,
		"other host":   StaticCredentials("other.example", testUsername, testPassword),
		"empty chain":  ChainCredentials(),
		"empty static": StaticCredentials(registry.host(), "", ""),
	} {
		client := registry.client(t, credentials)
		_, err := client.FetchManifest(context.Background(), "library/app", "latest")
		if err == nil || !strings.Contains(err.Error(), "unsupported registry auth challenge") {
			t.Fatalf("%s: FetchManifest() error = %v", name, err)
		}
		assertNoAuthLeak(t, name, err)
	}
	for _, authorization := range registry.received {
		if authorization != "" {
			t.Fatalf("credential sent without a match: %q", authorization)
		}
	}
}

func TestBasicWrongPasswordSurfacesUnauthorizedWithoutLeaking(t *testing.T) {
	registry := newBasicRegistry(t)
	registry.rejectAll = true
	client := registry.client(t, StaticCredentials(registry.host(), testUsername, testPassword))

	_, err := client.FetchManifest(context.Background(), "library/app", "latest")
	if !IsUnauthorized(err) {
		t.Fatalf("FetchManifest() error = %v, want unauthorized", err)
	}
	var statusErr *StatusError
	if !errors.As(err, &statusErr) || statusErr.Auth || statusErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status error = %+v", statusErr)
	}
	assertNoAuthLeak(t, "basic wrong password", err)
	if len(registry.received) != 2 {
		t.Fatalf("requests = %d, want exactly one Basic retry", len(registry.received))
	}
}

func TestBasicAuthorizationIsDroppedOnCrossHostRedirect(t *testing.T) {
	var cdnAuthorization []string
	var cdnMu sync.Mutex
	cdn := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		cdnMu.Lock()
		cdnAuthorization = append(cdnAuthorization, request.Header.Get("Authorization"))
		cdnMu.Unlock()
		_, _ = writer.Write([]byte(`{"os":"linux"}`))
	}))
	t.Cleanup(cdn.Close)
	registry := newBasicRegistry(t)
	registry.redirectTo = cdn.URL + "/presigned-blob?X-Amz-Signature=synthetic"
	client := registry.client(t, StaticCredentials(registry.host(), testUsername, testPassword))

	blob, err := client.OpenBlob(context.Background(), "library/app", "sha256:"+strings.Repeat("a", 64))
	if err != nil {
		t.Fatalf("OpenBlob() error = %v", err)
	}
	_ = blob.Body.Close()
	if registry.blobRequest != 1 {
		t.Fatalf("registry blob requests = %d", registry.blobRequest)
	}
	if len(cdnAuthorization) != 1 || cdnAuthorization[0] != "" {
		t.Fatalf("cdn authorization = %q, want the header dropped", cdnAuthorization)
	}
}

func TestBasicCredentialsAreNotSentOverPlainHTTP(t *testing.T) {
	var received []string
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		received = append(received, request.Header.Get("Authorization"))
		return jsonResponse(http.StatusUnauthorized, "", nil, map[string]string{"Www-Authenticate": `Basic realm="registry"`}), nil
	})
	client := MustNewClient(Options{
		BaseURL:                     "http://registry.internal:5000",
		AllowedPrivateRegistryHosts: []string{"registry.internal:5000"},
		AllowPrivateHosts:           true,
		HTTPClient:                  &http.Client{Transport: transport},
		Credentials:                 StaticCredentials("registry.internal:5000", testUsername, testPassword),
	})
	_, err := client.FetchManifest(context.Background(), "library/app", "latest")
	if !errors.Is(err, ErrCredentialsRequireHTTPS) {
		t.Fatalf("FetchManifest() error = %v, want ErrCredentialsRequireHTTPS", err)
	}
	if len(received) != 1 || received[0] != "" {
		t.Fatalf("received authorization = %q", received)
	}
	assertNoAuthLeak(t, "plain http", err)
}

func TestClientFormattingNeverRevealsCachedTokens(t *testing.T) {
	registry := &bearerRegistry{}
	client := newBearerClient(t, registry, StaticCredentials("registry.test", testUsername, testPassword))
	if _, err := client.FetchManifest(context.Background(), "library/app", "latest"); err != nil {
		t.Fatalf("FetchManifest() error = %v", err)
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		text := fmt.Sprintf(verb, client)
		assertNoSecret(t, "Client "+verb, text)
		if strings.Contains(text, testToken) {
			t.Fatalf("Client %s reveals a cached token: %q", verb, text)
		}
		if !strings.Contains(text, "registry.test") {
			t.Fatalf("Client %s = %q, want the registry host", verb, text)
		}
	}
	var nilClient *Client
	if fmt.Sprint(nilClient) == "" {
		t.Fatal("nil client must still format")
	}
}

func TestOffersBasicChallenge(t *testing.T) {
	tests := map[string]struct {
		headers []string
		want    bool
	}{
		"basic":            {headers: []string{`Basic realm="registry"`}, want: true},
		"basic lower":      {headers: []string{`basic realm="registry"`}, want: true},
		"bearer only":      {headers: []string{testBearerChallengeHeader}, want: false},
		"bearer and basic": {headers: []string{testBearerChallengeHeader, `Basic realm="registry"`}, want: true},
		"none":             {headers: nil, want: false},
		"malformed":        {headers: []string{`=broken`}, want: false},
	}
	for name, test := range tests {
		if got := offersBasicChallenge(test.headers); got != test.want {
			t.Fatalf("%s: offersBasicChallenge() = %v, want %v", name, got, test.want)
		}
	}
}
