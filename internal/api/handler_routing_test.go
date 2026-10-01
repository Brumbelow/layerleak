package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestUncleanPathsReturnJSONNotFound pins API-24: paths that http.ServeMux
// would answer with a 301 text/html redirect (repeated slashes, dot segments)
// get the JSON 404 envelope instead, so every response stays JSON.
func TestUncleanPathsReturnJSONNotFound(t *testing.T) {
	paths := []string{
		"/api/v1/repositories//library/app/scans",
		"/api/v1/repositories/library/../app/scans",
		"/api/v1/repositories/./library/app/scans",
		"//health",
		"/api/v1/scans/../scans",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			store := &stubReadStore{}
			recorder := httptest.NewRecorder()
			NewHandler(&stubScanner{}, store).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))

			if recorder.Code != http.StatusNotFound {
				t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
			}
			if location := recorder.Header().Get("Location"); location != "" {
				t.Fatalf("Location = %q", location)
			}
			if !strings.Contains(recorder.Header().Get("Content-Type"), "application/json") || !strings.Contains(recorder.Body.String(), `"not_found"`) {
				t.Fatalf("content-type=%q body=%s", recorder.Header().Get("Content-Type"), recorder.Body.String())
			}
			if store.repository != "" {
				t.Fatalf("store was queried for %q", store.repository)
			}
		})
	}
}

// TestRepositorySubtreeRouting pins API-09: the repository segment is decoded
// exactly once, validated against the OCI distribution grammar, and the
// /scans and /findings suffixes must be separate segments.
func TestRepositorySubtreeRouting(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		status     int
		repository string
		code       string
	}{
		{name: "literal slash", path: "/api/v1/repositories/library/app/scans", status: http.StatusOK, repository: "library/app"},
		{name: "encoded slash", path: "/api/v1/repositories/library%2Fapp/scans", status: http.StatusOK, repository: "library/app"},
		{name: "findings literal slash", path: "/api/v1/repositories/library/app/findings", status: http.StatusOK, repository: "library/app"},
		{name: "separators", path: "/api/v1/repositories/my-org/my__app.v2/scans", status: http.StatusOK, repository: "my-org/my__app.v2"},
		{name: "single component", path: "/api/v1/repositories/app/scans", status: http.StatusOK, repository: "app"},
		{name: "repository named scans", path: "/api/v1/repositories/scans/scans", status: http.StatusOK, repository: "scans"},
		{name: "repository named findings", path: "/api/v1/repositories/findings/scans", status: http.StatusOK, repository: "findings"},
		{name: "double encoded slash is not decoded twice", path: "/api/v1/repositories/library%252Fapp/scans", status: http.StatusBadRequest, code: "invalid_request"},
		{name: "uppercase", path: "/api/v1/repositories/UPPER/Case%20Name/scans", status: http.StatusBadRequest, code: "invalid_request"},
		{name: "tag separator", path: "/api/v1/repositories/library/app%3Alatest/scans", status: http.StatusBadRequest, code: "invalid_request"},
		{name: "triple hyphen is fine but leading hyphen is not", path: "/api/v1/repositories/-app/scans", status: http.StatusBadRequest, code: "invalid_request"},
		{name: "overlong", path: "/api/v1/repositories/" + strings.Repeat("a", 256) + "/scans", status: http.StatusBadRequest, code: "invalid_request"},
		{name: "suffix without repository", path: "/api/v1/repositories/scans", status: http.StatusNotFound, code: "not_found"},
		{name: "findings suffix without repository", path: "/api/v1/repositories/findings", status: http.StatusNotFound, code: "not_found"},
		{name: "unknown suffix", path: "/api/v1/repositories/library/app/tags", status: http.StatusNotFound, code: "not_found"},
		{name: "trailing slash", path: "/api/v1/repositories/library/app/scans/", status: http.StatusNotFound, code: "not_found"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &stubReadStore{}
			recorder := httptest.NewRecorder()
			NewHandler(&stubScanner{}, store).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, test.path, nil))

			if recorder.Code != test.status {
				t.Fatalf("status = %d, want %d; body=%s", recorder.Code, test.status, recorder.Body.String())
			}
			if store.repository != test.repository {
				t.Fatalf("store.repository = %q, want %q", store.repository, test.repository)
			}
			if test.code != "" && !strings.Contains(recorder.Body.String(), `"code": "`+test.code+`"`) {
				t.Fatalf("body = %s", recorder.Body.String())
			}
			if test.status == http.StatusOK && !strings.Contains(recorder.Body.String(), `"repository": "`+test.repository+`"`) {
				t.Fatalf("body = %s", recorder.Body.String())
			}
		})
	}
}

// TestInvalidRepositoryNameMessageIsNeutral keeps the 400 message free of the
// submitted path.
func TestInvalidRepositoryNameMessageIsNeutral(t *testing.T) {
	recorder := httptest.NewRecorder()
	NewHandler(&stubScanner{}, &stubReadStore{}).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/repositories/Bad%20Name/scans", nil))

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "Bad Name") || strings.Contains(recorder.Body.String(), "Bad%20Name") {
		t.Fatalf("body echoed the path: %s", recorder.Body.String())
	}
}
