package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/brumbelow/layerleak/v3/internal/jobs"
	"github.com/brumbelow/layerleak/v3/internal/registry"
	"github.com/brumbelow/layerleak/v3/internal/scanservice"
)

// decodeErrorBody returns the error object of an API response plus the
// decoded top-level document.
func decodeErrorBody(t *testing.T, body []byte) (map[string]any, map[string]any) {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatalf("decode response: %v\n%s", err, body)
	}
	errorObject, _ := document["error"].(map[string]any)
	if errorObject == nil {
		t.Fatalf("response has no error object: %s", body)
	}
	return errorObject, document
}

func scanErrorFor(err error) error {
	return &scanservice.Error{Phase: scanservice.ErrorPhaseScan, Err: err}
}

// TestHandleScanMapsNestedTimeoutsToBadGateway pins API-03: a registry
// request that timed out or was canceled inside the scan is an upstream
// failure, not the API's own deadline, while the request is still alive.
func TestHandleScanMapsNestedTimeoutsToBadGateway(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "nested deadline", err: fmt.Errorf("perform registry request: %w", context.DeadlineExceeded)},
		{name: "nested cancel", err: fmt.Errorf("perform registry request: %w", context.Canceled)},
		{name: "transport deadline", err: &registry.RequestError{Method: "GET", URL: "https://registry.example/v2/", Err: context.DeadlineExceeded}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scanner := &stubScanner{
				outcome: scanservice.Outcome{Result: jobs.Result{RequestedReference: "library/app:latest", Status: jobs.ResultStatusFailed}},
				err:     scanErrorFor(test.err),
			}
			recorder := httptest.NewRecorder()
			NewHandler(scanner, &stubReadStore{}).ServeHTTP(recorder, newJSONScanRequest(`{"reference":"library/app:latest"}`))

			if recorder.Code != http.StatusBadGateway {
				t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
			}
			errorObject, document := decodeErrorBody(t, recorder.Body.Bytes())
			if errorObject["code"] != "scan_failed" {
				t.Fatalf("code = %v", errorObject["code"])
			}
			if _, ok := document["result"]; !ok {
				t.Fatalf("failed result missing: %s", recorder.Body.String())
			}
			if strings.Contains(recorder.Body.String(), "registry.example") {
				t.Fatalf("body leaked the registry host: %s", recorder.Body.String())
			}
		})
	}
}

// TestHandleScanReportsClientCancellation keeps 408 scan_canceled for the one
// case it describes: the request context ended before the scan finished.
func TestHandleScanReportsClientCancellation(t *testing.T) {
	request := newJSONScanRequest(`{"reference":"library/app:latest"}`)
	ctx, cancel := context.WithCancel(request.Context())
	defer cancel()
	request = request.WithContext(ctx)
	scanner := &cancelingScanner{cancel: cancel}
	recorder := httptest.NewRecorder()

	NewHandler(scanner, &stubReadStore{}).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusRequestTimeout {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	errorObject, _ := decodeErrorBody(t, recorder.Body.Bytes())
	if errorObject["code"] != "scan_canceled" {
		t.Fatalf("code = %v", errorObject["code"])
	}
}

// cancelingScanner cancels the request context mid-scan, as a client
// disconnect would, and returns the resulting context error.
type cancelingScanner struct {
	cancel context.CancelFunc
}

func (s *cancelingScanner) ScanAndSave(ctx context.Context, _ scanservice.Request) (scanservice.Outcome, error) {
	s.cancel()
	<-ctx.Done()
	return scanservice.Outcome{}, scanErrorFor(fmt.Errorf("resolve manifest: %w", ctx.Err()))
}

// TestHandleScanMapsRegistryStatusErrors pins REG-16's API half: typed
// registry responses select distinct codes with neutral messages.
func TestHandleScanMapsRegistryStatusErrors(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		status     int
		code       string
		retryAfter bool
	}{
		{
			name:   "manifest not found",
			err:    fmt.Errorf("resolve manifest: %w", &registry.StatusError{StatusCode: http.StatusNotFound, Method: "HEAD", URL: "https://registry.example/v2/library/app/manifests/latest"}),
			status: http.StatusNotFound,
			code:   "image_not_found",
		},
		{
			name:       "rate limited",
			err:        &registry.StatusError{StatusCode: http.StatusTooManyRequests, Method: "GET", URL: "https://registry.example/v2/library/app/tags/list"},
			status:     http.StatusServiceUnavailable,
			code:       "registry_rate_limited",
			retryAfter: true,
		},
		{
			name:       "token endpoint rate limited",
			err:        &registry.StatusError{StatusCode: http.StatusTooManyRequests, Method: "GET", URL: "https://auth.example/token", Auth: true},
			status:     http.StatusServiceUnavailable,
			code:       "registry_rate_limited",
			retryAfter: true,
		},
		{
			name:   "unauthorized",
			err:    &registry.StatusError{StatusCode: http.StatusUnauthorized, Method: "GET", URL: "https://registry.example/v2/library/app/manifests/latest"},
			status: http.StatusBadGateway,
			code:   "registry_unauthorized",
		},
		{
			name:   "forbidden token",
			err:    &registry.StatusError{StatusCode: http.StatusForbidden, Method: "GET", URL: "https://auth.example/token", Auth: true},
			status: http.StatusBadGateway,
			code:   "registry_unauthorized",
		},
		{
			name:   "token endpoint not found is not an image lookup",
			err:    &registry.StatusError{StatusCode: http.StatusNotFound, Method: "GET", URL: "https://auth.example/token", Auth: true},
			status: http.StatusBadGateway,
			code:   "scan_failed",
		},
		{
			name:   "server error",
			err:    &registry.StatusError{StatusCode: http.StatusBadGateway, Method: "GET", URL: "https://registry.example/v2/"},
			status: http.StatusBadGateway,
			code:   "scan_failed",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scanner := &stubScanner{
				outcome: scanservice.Outcome{Result: jobs.Result{RequestedReference: "library/app:latest", Status: jobs.ResultStatusFailed}},
				err:     scanErrorFor(test.err),
			}
			recorder := httptest.NewRecorder()
			NewHandler(scanner, &stubReadStore{}).ServeHTTP(recorder, newJSONScanRequest(`{"reference":"library/app:latest"}`))

			if recorder.Code != test.status {
				t.Fatalf("status = %d, want %d; body=%s", recorder.Code, test.status, recorder.Body.String())
			}
			errorObject, document := decodeErrorBody(t, recorder.Body.Bytes())
			if errorObject["code"] != test.code {
				t.Fatalf("code = %v, want %s", errorObject["code"], test.code)
			}
			if _, ok := document["result"]; !ok {
				t.Fatalf("failed result missing: %s", recorder.Body.String())
			}
			body := recorder.Body.String()
			for _, leaked := range []string{"registry.example", "auth.example", "status=", "/v2/"} {
				if strings.Contains(body, leaked) {
					t.Fatalf("body leaked %q: %s", leaked, body)
				}
			}
			if got := recorder.Header().Get("Retry-After"); (got != "") != test.retryAfter {
				t.Fatalf("Retry-After = %q, want present=%v", got, test.retryAfter)
			}
		})
	}
}

// TestHandleScanKeepsIncompleteOverRegistryCause: a partial multi-manifest
// scan whose cause was a registry 404 stays 422 with its coverage counts.
func TestHandleScanKeepsIncompleteOverRegistryCause(t *testing.T) {
	scanner := &stubScanner{
		outcome: scanservice.Outcome{ScanRunID: 7, Result: jobs.Result{RequestedReference: "library/app:latest", Status: jobs.ResultStatusPartial}},
		err: scanErrorFor(&jobs.IncompleteError{
			Status:                 jobs.ResultStatusPartial,
			CompletedManifestCount: 1,
			FailedManifestCount:    1,
			Cause:                  &registry.StatusError{StatusCode: http.StatusNotFound, Method: "GET", URL: "https://registry.example/v2/library/app/blobs/sha256:aaaa"},
		}),
	}
	recorder := httptest.NewRecorder()
	NewHandler(scanner, &stubReadStore{}).ServeHTTP(recorder, newJSONScanRequest(`{"reference":"library/app:latest"}`))

	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	errorObject, _ := decodeErrorBody(t, recorder.Body.Bytes())
	if errorObject["code"] != "scan_incomplete" {
		t.Fatalf("code = %v", errorObject["code"])
	}
}
