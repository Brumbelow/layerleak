package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Synthetic tokens: repeated characters, 40 bytes, never real credentials.
const (
	authTokenA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	authTokenB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	authTokenC = "cccccccccccccccccccccccccccccccccccccccc"
)

func tokenDigest(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

func authenticatedHandler(t *testing.T, logs *bytes.Buffer, tokens ...string) http.Handler {
	t.Helper()
	digests := make([][]byte, 0, len(tokens))
	for _, token := range tokens {
		digests = append(digests, tokenDigest(token))
	}
	var logger *slog.Logger
	if logs != nil {
		logger = slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	} else {
		logger = testLogger(nil)
	}
	return NewHandlerWithOptions(&stubScanner{}, &stubReadStore{}, HandlerOptions{Logger: logger, BearerTokenDigests: digests})
}

func assertUnauthorized(t *testing.T, recorder *httptest.ResponseRecorder, wantChallenge string) {
	t.Helper()
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("WWW-Authenticate"); got != wantChallenge {
		t.Fatalf("WWW-Authenticate = %q, want %q", got, wantChallenge)
	}
	errorObject, _ := decodeErrorBody(t, recorder.Body.Bytes())
	if errorObject["code"] != "unauthorized" || errorObject["message"] != "a valid bearer token is required" {
		t.Fatalf("error = %v", errorObject)
	}
	if errorObject["request_id"] == "" {
		t.Fatalf("error has no request_id: %v", errorObject)
	}
	for header, want := range map[string]string{
		"Cache-Control":          "no-store",
		"X-Content-Type-Options": "nosniff",
		"Content-Type":           "application/json; charset=utf-8",
	} {
		if got := recorder.Header().Get(header); got != want {
			t.Fatalf("%s = %q, want %q", header, got, want)
		}
	}
	if recorder.Header().Get("X-Request-ID") == "" {
		t.Fatal("X-Request-ID missing on 401")
	}
}

// TestBearerAuthRejectsMissingMalformedAndWrongTokens pins the 401 contract:
// the JSON envelope, the fixed message, the WWW-Authenticate challenge and the
// security headers, with no token material in the body.
func TestBearerAuthRejectsMissingMalformedAndWrongTokens(t *testing.T) {
	tests := []struct {
		name      string
		header    string
		challenge string
	}{
		{name: "missing", header: "", challenge: `Bearer realm="layerleak"`},
		{name: "basic scheme", header: "Basic " + authTokenA, challenge: `Bearer realm="layerleak", error="invalid_token"`},
		{name: "bearer without token", header: "Bearer", challenge: `Bearer realm="layerleak", error="invalid_token"`},
		{name: "bearer with blank token", header: "Bearer   ", challenge: `Bearer realm="layerleak", error="invalid_token"`},
		{name: "token with inner space", header: "Bearer " + authTokenA + " extra", challenge: `Bearer realm="layerleak", error="invalid_token"`},
		{name: "wrong token", header: "Bearer " + authTokenC, challenge: `Bearer realm="layerleak", error="invalid_token"`},
		{name: "prefix of a token", header: "Bearer " + authTokenA[:39], challenge: `Bearer realm="layerleak", error="invalid_token"`},
		{name: "token with suffix", header: "Bearer " + authTokenA + "a", challenge: `Bearer realm="layerleak", error="invalid_token"`},
		{name: "oversized header", header: "Bearer " + strings.Repeat("a", maxAuthorizationHeaderBytes), challenge: `Bearer realm="layerleak", error="invalid_token"`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			logs := &bytes.Buffer{}
			handler := authenticatedHandler(t, logs, authTokenA, authTokenB)
			for _, target := range []string{"/api/v1/repositories", "/api/v1/scans/1", "/api/v1/findings/7", "/api/v1/repositories/library/app/scans"} {
				request := httptest.NewRequest(http.MethodGet, target, nil)
				if test.header != "" {
					request.Header.Set("Authorization", test.header)
				}
				recorder := httptest.NewRecorder()
				handler.ServeHTTP(recorder, request)
				assertUnauthorized(t, recorder, test.challenge)
			}
			request := newJSONScanRequest(`{"reference":"library/app:latest"}`)
			if test.header != "" {
				request.Header.Set("Authorization", test.header)
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			assertUnauthorized(t, recorder, test.challenge)

			if strings.Contains(logs.String(), authTokenA[:16]) || strings.Contains(logs.String(), authTokenC[:16]) {
				t.Fatalf("logs contain token material: %s", logs.String())
			}
			if !strings.Contains(logs.String(), `"msg":"api request unauthorized"`) || !strings.Contains(logs.String(), `"status":401`) {
				t.Fatalf("rejection not logged: %s", logs.String())
			}
		})
	}
}

// TestBearerAuthAcceptsConfiguredTokens: any configured token, in any list
// position and with a case-insensitive scheme, reaches the handler.
func TestBearerAuthAcceptsConfiguredTokens(t *testing.T) {
	tests := []struct {
		name   string
		header string
	}{
		{name: "first token", header: "Bearer " + authTokenA},
		{name: "last token", header: "Bearer " + authTokenC},
		{name: "lowercase scheme", header: "bearer " + authTokenB},
		{name: "extra spaces", header: "Bearer   " + authTokenB + "  "},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			logs := &bytes.Buffer{}
			handler := authenticatedHandler(t, logs, authTokenA, authTokenB, authTokenC)
			request := httptest.NewRequest(http.MethodGet, "/api/v1/repositories", nil)
			request.Header.Set("Authorization", test.header)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusOK || recorder.Header().Get("WWW-Authenticate") != "" {
				t.Fatalf("status = %d WWW-Authenticate=%q body=%s", recorder.Code, recorder.Header().Get("WWW-Authenticate"), recorder.Body.String())
			}
			token := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(test.header, "Bearer"), "bearer"))
			wantID := hex.EncodeToString(tokenDigest(token))[:tokenIDLength]
			if !strings.Contains(logs.String(), `"msg":"api request authenticated"`) || !strings.Contains(logs.String(), `"token_id":"`+wantID+`"`) {
				t.Fatalf("token id not logged at debug: %s", logs.String())
			}
			if strings.Contains(logs.String(), token[:16]) {
				t.Fatalf("logs contain the token: %s", logs.String())
			}
		})
	}
}

// TestBearerAuthExemptsHealthProbes: /health, /livez and /readyz answer
// without a token so orchestrators need no credentials, while unknown paths
// outside /api/ stay plain 404s.
func TestBearerAuthExemptsHealthProbes(t *testing.T) {
	handler := authenticatedHandler(t, nil, authTokenA)
	for target, want := range map[string]int{"/health": http.StatusOK, "/livez": http.StatusOK, "/readyz": http.StatusOK, "/missing": http.StatusNotFound, "/api": http.StatusNotFound} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, target, nil))
		if recorder.Code != want || recorder.Header().Get("WWW-Authenticate") != "" {
			t.Fatalf("%s: status = %d WWW-Authenticate=%q body=%s", target, recorder.Code, recorder.Header().Get("WWW-Authenticate"), recorder.Body.String())
		}
	}
	// Unclean protected paths keep the JSON 404 and reveal nothing about auth.
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1//repositories", nil))
	if recorder.Code != http.StatusNotFound || recorder.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("unclean path: status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	// Unknown paths under /api/ are protected, so the subtree is opaque to
	// unauthenticated probing.
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v2/anything", nil))
	assertUnauthorized(t, recorder, `Bearer realm="layerleak"`)
}

// TestBearerAuthDisabledByDefault: without digests the handler never emits a
// challenge, so the default deployment is byte-for-byte unchanged.
func TestBearerAuthDisabledByDefault(t *testing.T) {
	handler := NewHandler(&stubScanner{}, &stubReadStore{})
	for _, target := range []string{"/api/v1/repositories", "/api/v1/scans/1", "/missing"} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, target, nil)
		request.Header.Set("Authorization", "Bearer "+authTokenC)
		handler.ServeHTTP(recorder, request)
		if recorder.Code == http.StatusUnauthorized || recorder.Header().Get("WWW-Authenticate") != "" {
			t.Fatalf("%s: status = %d WWW-Authenticate=%q", target, recorder.Code, recorder.Header().Get("WWW-Authenticate"))
		}
	}
}

// TestBearerAuthMatcherComparesEveryDigest exercises the constant-time path
// directly: the matcher hashes the presented token once and compares it with
// every configured digest, so a match in any position succeeds, a near miss
// fails, and the token id is the digest prefix rather than the token.
func TestBearerAuthMatcherComparesEveryDigest(t *testing.T) {
	auth, err := newBearerAuth([][]byte{tokenDigest(authTokenA), tokenDigest(authTokenB), tokenDigest(authTokenC)})
	if err != nil {
		t.Fatalf("newBearerAuth() error = %v", err)
	}
	for _, token := range []string{authTokenA, authTokenB, authTokenC} {
		id, failure, challenge := auth.authenticate("Bearer " + token)
		if failure != "" || challenge != "" {
			t.Fatalf("authenticate(%s...) = failure %q", token[:4], failure)
		}
		if want := hex.EncodeToString(tokenDigest(token))[:tokenIDLength]; id != want || strings.Contains(token, id) {
			t.Fatalf("token id = %q, want digest prefix %q", id, want)
		}
	}
	if _, failure, _ := auth.authenticate("Bearer " + strings.Repeat("d", 40)); failure != authUnknown {
		t.Fatalf("unknown token failure = %q", failure)
	}
	if _, failure, _ := auth.authenticate(""); failure != authMissing {
		t.Fatalf("missing token failure = %q", failure)
	}
	if _, failure, _ := auth.authenticate("Token " + authTokenA); failure != authMalformed {
		t.Fatalf("other scheme failure = %q", failure)
	}
	if _, err := newBearerAuth([][]byte{[]byte("short")}); err == nil {
		t.Fatal("newBearerAuth() accepted a digest that is not SHA-256 sized")
	}
	var disabled *bearerAuth
	if disabled.enabled() {
		t.Fatal("nil matcher reports enabled")
	}
	empty, _ := newBearerAuth(nil)
	if empty.enabled() {
		t.Fatal("empty matcher reports enabled")
	}
}

func TestWarnAboutOpenListener(t *testing.T) {
	tests := []struct {
		addr          string
		authenticated bool
		warn          bool
	}{
		{addr: "127.0.0.1:8080", warn: false},
		{addr: "[::1]:8080", warn: false},
		{addr: "localhost:8080", warn: false},
		{addr: "0.0.0.0:8080", warn: true},
		{addr: ":8080", warn: true},
		{addr: "[::]:8080", warn: true},
		{addr: "api.internal:8080", warn: true},
		{addr: "0.0.0.0:8080", authenticated: true, warn: false},
	}
	for _, test := range tests {
		t.Run(test.addr, func(t *testing.T) {
			logs := &bytes.Buffer{}
			warnAboutOpenListener(test.addr, test.authenticated, testLogger(logs))
			if got := strings.Contains(logs.String(), "api authentication is disabled"); got != test.warn {
				t.Fatalf("warned = %t, want %t (authenticated=%t): %s", got, test.warn, test.authenticated, logs.String())
			}
		})
	}
}
