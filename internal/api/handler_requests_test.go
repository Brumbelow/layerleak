package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/brumbelow/layerleak/v3/internal/storage"
)

// failingStore returns a synthetic error from every read so the 503
// storage_unavailable path can be exercised on each endpoint.
type failingStore struct {
	*stubReadStore
	err error
}

func (s *failingStore) ListRepositories(context.Context, int, int, *storage.RepositoryCursor) ([]storage.RepositorySummary, error) {
	return nil, s.err
}

func (s *failingStore) ListRepositoryScans(context.Context, string, string, int, int, *storage.ScanRunCursor) ([]storage.ScanRunSummary, error) {
	return nil, s.err
}

func (s *failingStore) ListRepositoryFindings(context.Context, string, string, storage.FindingDispositionFilter, int, int, *storage.FindingCursor) ([]storage.FindingSummary, error) {
	return nil, s.err
}

func (s *failingStore) GetScanRun(context.Context, int64) (storage.ScanRunDetail, error) {
	return storage.ScanRunDetail{}, s.err
}

func (s *failingStore) GetFinding(context.Context, int64) (storage.FindingDetail, error) {
	return storage.FindingDetail{}, s.err
}

func serve(handler http.Handler, method, target string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(method, target, nil))
	return recorder
}

func TestHandleGetScanReturnsNotFound(t *testing.T) {
	store := &stubReadStore{scanDetailErr: storage.ErrNotFound}
	recorder := serve(NewHandler(&stubScanner{}, store), http.MethodGet, "/api/v1/scans/41")

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	errorObject, _ := decodeErrorBody(t, recorder.Body.Bytes())
	if errorObject["code"] != "not_found" || errorObject["message"] != "scan run not found" {
		t.Fatalf("error = %v", errorObject)
	}
	if store.scanID != 41 {
		t.Fatalf("store.scanID = %d", store.scanID)
	}
}

// TestStorageErrorsReturnServiceUnavailable covers the 503 path on every read
// endpoint and keeps the storage error text out of the body.
func TestStorageErrorsReturnServiceUnavailable(t *testing.T) {
	store := &failingStore{stubReadStore: &stubReadStore{}, err: errors.New("synthetic-pq-detail")}
	handler := NewHandler(&stubScanner{}, store)
	targets := []string{
		"/api/v1/repositories",
		"/api/v1/repositories/library/app/scans",
		"/api/v1/repositories/library/app/findings",
		"/api/v1/scans/7",
		"/api/v1/findings/7",
	}
	for _, target := range targets {
		t.Run(target, func(t *testing.T) {
			recorder := serve(handler, http.MethodGet, target)
			if recorder.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
			}
			errorObject, _ := decodeErrorBody(t, recorder.Body.Bytes())
			if errorObject["code"] != "storage_unavailable" || errorObject["message"] != "database request failed" {
				t.Fatalf("error = %v", errorObject)
			}
			if strings.Contains(recorder.Body.String(), "synthetic-pq-detail") {
				t.Fatalf("body leaked storage detail: %s", recorder.Body.String())
			}
		})
	}
}

// TestHeadAndOptionsRequests: GET routes also serve HEAD without a body, and
// other methods get 405 with an Allow header naming the one accepted method.
func TestHeadAndOptionsRequests(t *testing.T) {
	handler := NewHandler(&stubScanner{}, &stubReadStore{})

	// net/http strips the body of a HEAD response on the wire; the recorder
	// keeps it, so only the status is asserted here.
	recorder := serve(handler, http.MethodHead, "/health")
	if recorder.Code != http.StatusOK {
		t.Fatalf("HEAD /health: status = %d body=%q", recorder.Code, recorder.Body.String())
	}

	tests := []struct {
		method string
		target string
		allow  string
	}{
		{method: http.MethodOptions, target: "/api/v1/scans", allow: "POST"},
		{method: http.MethodHead, target: "/api/v1/scans", allow: "POST"},
		{method: http.MethodGet, target: "/api/v1/scans", allow: "POST"},
		{method: http.MethodPost, target: "/api/v1/scans/7", allow: "GET"},
		{method: http.MethodDelete, target: "/api/v1/repositories", allow: "GET"},
		{method: http.MethodPut, target: "/api/v1/repositories/library/app/scans", allow: "GET"},
		{method: http.MethodPatch, target: "/api/v1/findings/7", allow: "GET"},
		{method: http.MethodOptions, target: "/health", allow: "GET"},
		{method: http.MethodPost, target: "/readyz", allow: "GET"},
	}
	for _, test := range tests {
		t.Run(test.method+" "+test.target, func(t *testing.T) {
			recorder := serve(handler, test.method, test.target)
			if recorder.Code != http.StatusMethodNotAllowed {
				t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
			}
			if recorder.Header().Get("Allow") != test.allow {
				t.Fatalf("Allow = %q, want %q", recorder.Header().Get("Allow"), test.allow)
			}
			if !strings.Contains(recorder.Body.String(), `"method_not_allowed"`) {
				t.Fatalf("body = %s", recorder.Body.String())
			}
		})
	}
}

// TestSecurityHeadersOnEveryResponse: success, client errors, server errors
// and pre-mux rejections all carry the fixed headers.
func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	panicking := &panickingStore{stubReadStore: &stubReadStore{}, value: "boom"}
	handler := NewHandlerWithOptions(&stubScanner{}, panicking, HandlerOptions{Logger: testLogger(nil)})
	requests := []struct {
		method string
		target string
		status int
	}{
		{method: http.MethodGet, target: "/health", status: http.StatusOK},
		{method: http.MethodGet, target: "/missing", status: http.StatusNotFound},
		{method: http.MethodGet, target: "//missing", status: http.StatusNotFound},
		{method: http.MethodPut, target: "/api/v1/scans", status: http.StatusMethodNotAllowed},
		{method: http.MethodGet, target: "/api/v1/scans/abc", status: http.StatusBadRequest},
		{method: http.MethodGet, target: "/api/v1/repositories", status: http.StatusInternalServerError},
	}
	for _, request := range requests {
		t.Run(request.method+" "+request.target, func(t *testing.T) {
			recorder := serve(handler, request.method, request.target)
			if recorder.Code != request.status {
				t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
			}
			headers := recorder.Header()
			if headers.Get("Cache-Control") != "no-store" || headers.Get("X-Content-Type-Options") != "nosniff" {
				t.Fatalf("headers = %v", headers)
			}
			if headers.Get("X-Request-ID") == "" || !strings.HasPrefix(headers.Get("Content-Type"), "application/json") {
				t.Fatalf("headers = %v", headers)
			}
		})
	}
}

// TestInvalidRequestIDsAreReplaced: the caller's X-Request-ID is echoed only
// when it is a short token of safe characters; anything else is replaced by
// a generated id and never reflected.
func TestInvalidRequestIDsAreReplaced(t *testing.T) {
	generated := regexp.MustCompile(`^[0-9a-f]{32}$`)
	tests := []struct {
		name   string
		header string
		echoed bool
	}{
		{name: "token", header: "trace-1.a_B", echoed: true},
		{name: "128 characters", header: strings.Repeat("a", 128), echoed: true},
		{name: "129 characters", header: strings.Repeat("a", 129)},
		{name: "space", header: "trace 1"},
		{name: "semicolon", header: "trace;1"},
		{name: "newline", header: "trace\n1"},
		{name: "non ascii", header: "tréce"},
		{name: "empty", header: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/missing", nil)
			request.Header.Set("X-Request-ID", test.header)
			recorder := httptest.NewRecorder()
			NewHandler(&stubScanner{}, &stubReadStore{}).ServeHTTP(recorder, request)

			id := recorder.Header().Get("X-Request-ID")
			if test.echoed {
				if id != test.header {
					t.Fatalf("X-Request-ID = %q, want echo", id)
				}
				return
			}
			if !generated.MatchString(id) {
				t.Fatalf("X-Request-ID = %q, want a generated id", id)
			}
			if test.header != "" && strings.Contains(recorder.Body.String(), strings.TrimSpace(test.header)) {
				t.Fatalf("body reflected the rejected header: %s", recorder.Body.String())
			}
		})
	}
}

// TestInvalidPathAndQueryParametersAreRejected covers the 400 messages for
// ids, pagination and the disposition filter.
func TestInvalidPathAndQueryParametersAreRejected(t *testing.T) {
	tests := []struct {
		target  string
		message string
	}{
		{target: "/api/v1/scans/abc", message: "scan run id must be a positive integer"},
		{target: "/api/v1/scans/0", message: "scan run id must be a positive integer"},
		{target: "/api/v1/scans/-1", message: "scan run id must be a positive integer"},
		{target: "/api/v1/scans/99999999999999999999", message: "scan run id must be a positive integer"},
		{target: "/api/v1/findings/abc", message: "finding id must be a positive integer"},
		{target: "/api/v1/findings/0", message: "finding id must be a positive integer"},
		{target: "/api/v1/repositories?limit=abc", message: "limit must be an integer"},
		{target: "/api/v1/repositories?limit=0", message: "limit must be greater than zero"},
		{target: "/api/v1/repositories?limit=-5", message: "limit must be greater than zero"},
		{target: "/api/v1/repositories?offset=abc", message: "offset must be an integer"},
		{target: "/api/v1/repositories?offset=-1", message: "offset must be greater than or equal to zero"},
		{target: "/api/v1/repositories/library/app/scans?limit=1.5", message: "limit must be an integer"},
		{target: "/api/v1/repositories/library/app/findings?disposition=everything", message: "disposition must be one of actionable, suppressed, or all"},
		{target: "/api/v1/repositories/library/app/findings?disposition=Actionable", message: "disposition must be one of actionable, suppressed, or all"},
	}
	for _, test := range tests {
		t.Run(test.target, func(t *testing.T) {
			store := &stubReadStore{}
			recorder := serve(NewHandler(&stubScanner{}, store), http.MethodGet, test.target)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
			}
			errorObject, _ := decodeErrorBody(t, recorder.Body.Bytes())
			if errorObject["code"] != "invalid_request" || errorObject["message"] != test.message {
				t.Fatalf("error = %v", errorObject)
			}
			if store.limit != 0 || store.scanID != 0 || store.findingID != 0 {
				t.Fatalf("store was queried: %+v", store)
			}
		})
	}
}

// TestRepositoryFindingsQueryValidationOrder pins which 400 message wins when
// several query parameters of the repository findings route are invalid:
// disposition, then pagination, then registry, then cursor.
func TestRepositoryFindingsQueryValidationOrder(t *testing.T) {
	const base = "/api/v1/repositories/library/app/findings?"
	tests := []struct {
		query   string
		message string
	}{
		{query: "disposition=everything&limit=abc&registry=bad_host&cursor=bogus", message: "disposition must be one of actionable, suppressed, or all"},
		{query: "disposition=all&limit=abc&registry=bad_host&cursor=bogus", message: "limit must be an integer"},
		{query: "disposition=all&offset=-1&registry=bad_host&cursor=bogus", message: "offset must be greater than or equal to zero"},
		{query: "disposition=all&limit=5&registry=bad_host&cursor=bogus", message: errInvalidRegistryFilter.Error()},
		{query: "disposition=all&limit=5&registry=quay.io&cursor=bogus", message: "cursor is invalid"},
	}
	for _, test := range tests {
		t.Run(test.query, func(t *testing.T) {
			store := &stubReadStore{}
			recorder := serve(NewHandler(&stubScanner{}, store), http.MethodGet, base+test.query)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
			}
			errorObject, _ := decodeErrorBody(t, recorder.Body.Bytes())
			if errorObject["code"] != "invalid_request" || errorObject["message"] != test.message {
				t.Fatalf("error = %v", errorObject)
			}
			if store.limit != 0 {
				t.Fatalf("store was queried: %+v", store)
			}
		})
	}
}

// TestPaginationClampsLimitAndDefaults pins the documented clamp: limit above
// 200 is reduced to 200 rather than rejected.
func TestPaginationClampsLimitAndDefaults(t *testing.T) {
	store := &stubReadStore{}
	recorder := serve(NewHandler(&stubScanner{}, store), http.MethodGet, "/api/v1/repositories?limit=500&offset=3")
	if recorder.Code != http.StatusOK || store.limit != 200 || store.offset != 3 {
		t.Fatalf("status = %d limit = %d offset = %d", recorder.Code, store.limit, store.offset)
	}
	if !strings.Contains(recorder.Body.String(), `"limit": 200`) {
		t.Fatalf("body = %s", recorder.Body.String())
	}
}

// TestScanRequestBodyIsStrict: unknown fields, trailing values, wrong types,
// empty bodies and malformed JSON are 400 invalid_request with the fixed
// messages and no echo of the body.
func TestScanRequestBodyIsStrict(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		message string
	}{
		{name: "unknown field", body: `{"reference":"library/app:latest","token":"synthetic-value"}`, message: "request body must be valid JSON"},
		{name: "trailing value", body: `{"reference":"library/app:latest"} {"reference":"other"}`, message: "request body must contain a single JSON object"},
		{name: "trailing scalar", body: `{"reference":"library/app:latest"} 1`, message: "request body must contain a single JSON object"},
		{name: "array", body: `[{"reference":"library/app:latest"}]`, message: "request body must be valid JSON"},
		{name: "wrong type", body: `{"reference":42}`, message: "request body must be valid JSON"},
		{name: "truncated", body: `{"reference":"library/app:latest"`, message: "request body must be valid JSON"},
		{name: "empty", body: ``, message: "request body is required"},
		{name: "missing reference", body: `{}`, message: "image reference is required"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scanner := &stubScanner{}
			recorder := httptest.NewRecorder()
			NewHandler(scanner, &stubReadStore{}).ServeHTTP(recorder, newJSONScanRequest(test.body))

			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
			}
			errorObject, _ := decodeErrorBody(t, recorder.Body.Bytes())
			if errorObject["code"] != "invalid_request" || errorObject["message"] != test.message {
				t.Fatalf("error = %v", errorObject)
			}
			if strings.Contains(recorder.Body.String(), "synthetic-value") || strings.Contains(recorder.Body.String(), "library/app") {
				t.Fatalf("body echoed the request: %s", recorder.Body.String())
			}
			if scanner.request.Reference.Repository != "" {
				t.Fatal("scanner was invoked for an invalid body")
			}
		})
	}
}

// TestScanRequestErrorsNeverEchoInput: a reference the parser rejects and
// trailing non-JSON data after the body are 400 invalid_request with fixed
// messages. Neither the submitted reference, the upstream parser text nor the
// JSON decoder text (which quotes request bytes) reaches the client.
func TestScanRequestErrorsNeverEchoInput(t *testing.T) {
	const probe = "probesecretname"
	tests := []struct {
		name    string
		body    string
		message string
	}{
		{name: "uppercase repository", body: `{"reference":"ghcr.io/Org/` + strings.ToUpper(probe) + `:1"}`, message: "reference is not a valid image reference"},
		{name: "invalid tag", body: `{"reference":"library/app:` + probe + `!"}`, message: "reference is not a valid image reference"},
		{name: "invalid digest", body: `{"reference":"library/app@sha256:` + probe + `"}`, message: "reference is not a valid image reference"},
		{name: "invalid registry port", body: `{"reference":"` + probe + `.example:99999/app"}`, message: "reference is not a valid image reference"},
		{name: "invalid path component", body: `{"reference":"library/` + probe + `--/app"}`, message: "reference is not a valid image reference"},
		{name: "trailing garbage", body: `{"reference":"library/app:latest"} ` + probe, message: "request body must contain a single JSON object"},
		{name: "trailing truncated value", body: `{"reference":"library/app:latest"} {"` + probe, message: "request body must contain a single JSON object"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scanner := &stubScanner{}
			recorder := httptest.NewRecorder()
			NewHandler(scanner, &stubReadStore{}).ServeHTTP(recorder, newJSONScanRequest(test.body))

			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
			}
			errorObject, _ := decodeErrorBody(t, recorder.Body.Bytes())
			if errorObject["code"] != "invalid_request" || errorObject["message"] != test.message {
				t.Fatalf("error = %v", errorObject)
			}
			lowered := strings.ToLower(recorder.Body.String())
			for _, leaked := range []string{probe, "invalid character", "invalid reference format", "parse image reference"} {
				if strings.Contains(lowered, leaked) {
					t.Fatalf("response echoes %q: %s", leaked, recorder.Body.String())
				}
			}
			if scanner.request.Reference.Original != "" {
				t.Fatalf("scanner was invoked for %q", scanner.request.Reference.Original)
			}
		})
	}
}

// TestScanRequestAcceptsJSONMediaTypeVariants: application/json with a
// charset and structured +json suffixes are accepted; others are 415.
func TestScanRequestAcceptsJSONMediaTypeVariants(t *testing.T) {
	accepted := []string{"application/json", "application/json; charset=utf-8", "application/vnd.layerleak+json"}
	for _, contentType := range accepted {
		request := newJSONScanRequest(`{"reference":"library/app:latest"}`)
		request.Header.Set("Content-Type", contentType)
		recorder := httptest.NewRecorder()
		NewHandler(&stubScanner{}, &stubReadStore{}).ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s: status = %d body=%s", contentType, recorder.Code, recorder.Body.String())
		}
	}
	for _, contentType := range []string{"text/plain", "application/x-www-form-urlencoded", "json"} {
		request := newJSONScanRequest(`{"reference":"library/app:latest"}`)
		request.Header.Set("Content-Type", contentType)
		recorder := httptest.NewRecorder()
		NewHandler(&stubScanner{}, &stubReadStore{}).ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("%s: status = %d body=%s", contentType, recorder.Code, recorder.Body.String())
		}
	}
}
