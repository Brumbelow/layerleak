package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/brumbelow/layerleak/v3/internal/storage"

	"github.com/brumbelow/layerleak/v3/internal/jobs"
	"github.com/brumbelow/layerleak/v3/internal/limits"
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

// TestHandleScanLimitExceededUsesFixedMessage pins API-26: the
// scan_limit_exceeded message is built from the limit kind and value, never
// from the wrapped error chain, and the additive limit fields are machine
// readable.
func TestHandleScanLimitExceededUsesFixedMessage(t *testing.T) {
	scanner := &stubScanner{
		outcome: scanservice.Outcome{ScanRunID: 42, Result: jobs.Result{RequestedReference: "library/app:latest", Status: jobs.ResultStatusFailed}},
		err: scanErrorFor(fmt.Errorf("read config blob: %w", limits.NewExceeded(
			limits.KindConfigBytes, 128, "config blob sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		))),
	}
	recorder := httptest.NewRecorder()
	NewHandler(scanner, &stubReadStore{}).ServeHTTP(recorder, newJSONScanRequest(`{"reference":"library/app:latest"}`))

	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	errorObject, document := decodeErrorBody(t, recorder.Body.Bytes())
	if errorObject["code"] != "scan_limit_exceeded" {
		t.Fatalf("code = %v", errorObject["code"])
	}
	if errorObject["message"] != "the scan exceeded the configured config bytes limit of 128" {
		t.Fatalf("message = %v", errorObject["message"])
	}
	if errorObject["limit_kind"] != "config_bytes" || errorObject["limit"] != json.Number("128") && errorObject["limit"] != float64(128) {
		t.Fatalf("limit fields = %v / %v", errorObject["limit_kind"], errorObject["limit"])
	}
	if document["scan_run_id"] != float64(42) {
		t.Fatalf("scan_run_id = %v", document["scan_run_id"])
	}
	body := recorder.Body.String()
	for _, leaked := range []string{"read config blob", "config blob sha256", "bbbbbbbb"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("body leaked %q: %s", leaked, body)
		}
	}
}

// TestHandleScanNonLimitErrorsOmitLimitFields keeps the additive fields out of
// every other error object.
func TestHandleScanNonLimitErrorsOmitLimitFields(t *testing.T) {
	scanner := &stubScanner{err: scanErrorFor(fmt.Errorf("synthetic upstream detail"))}
	recorder := httptest.NewRecorder()
	NewHandler(scanner, &stubReadStore{}).ServeHTTP(recorder, newJSONScanRequest(`{"reference":"library/app:latest"}`))

	errorObject, _ := decodeErrorBody(t, recorder.Body.Bytes())
	if _, ok := errorObject["limit_kind"]; ok {
		t.Fatalf("limit_kind present: %s", recorder.Body.String())
	}
	if _, ok := errorObject["limit"]; ok {
		t.Fatalf("limit present: %s", recorder.Body.String())
	}
}

// panickingStore panics from a read endpoint so the middleware's recovery
// can be observed from outside.
type panickingStore struct {
	*stubReadStore
	value any
}

func (s *panickingStore) ListRepositories(_ context.Context, _, _ int) ([]storage.RepositorySummary, error) {
	panic(s.value)
}

// TestMiddlewareRepanicsErrAbortHandler pins API-17: net/http's abort
// sentinel must propagate so the server closes the connection silently
// instead of answering 500 JSON.
func TestMiddlewareRepanicsErrAbortHandler(t *testing.T) {
	logs := &bytes.Buffer{}
	handler := NewHandlerWithOptions(&stubScanner{}, &panickingStore{stubReadStore: &stubReadStore{}, value: http.ErrAbortHandler}, HandlerOptions{Logger: testLogger(logs)})
	recorder := httptest.NewRecorder()

	var recovered any
	func() {
		defer func() { recovered = recover() }()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/repositories", nil))
	}()

	err, ok := recovered.(error)
	if !ok || !errors.Is(err, http.ErrAbortHandler) {
		t.Fatalf("recovered = %#v, want http.ErrAbortHandler", recovered)
	}
	if recorder.Body.Len() != 0 {
		t.Fatalf("body written after abort: %s", recorder.Body.String())
	}
	if strings.Contains(logs.String(), "panic serving api request") {
		t.Fatalf("abort was logged as a panic: %s", logs.String())
	}
}

// TestMiddlewareRecoversPanicsWithStack: an ordinary panic yields the 500
// envelope and a log line with the panic type and stack, never the value.
func TestMiddlewareRecoversPanicsWithStack(t *testing.T) {
	logs := &bytes.Buffer{}
	handler := NewHandlerWithOptions(&stubScanner{}, &panickingStore{stubReadStore: &stubReadStore{}, value: errors.New("synthetic-panic-detail")}, HandlerOptions{Logger: testLogger(logs)})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/repositories", nil)
	request.Header.Set("X-Request-ID", "panic-test")

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	errorObject, _ := decodeErrorBody(t, recorder.Body.Bytes())
	if errorObject["code"] != "internal_error" || errorObject["request_id"] != "panic-test" {
		t.Fatalf("error = %v", errorObject)
	}
	if strings.Contains(recorder.Body.String(), "synthetic-panic-detail") {
		t.Fatalf("body leaked the panic value: %s", recorder.Body.String())
	}
	logged := logs.String()
	if !strings.Contains(logged, `"msg":"panic serving api request"`) || !strings.Contains(logged, `"panic_type":"*errors.errorString"`) || !strings.Contains(logged, `"request_id":"panic-test"`) {
		t.Fatalf("panic log = %s", logged)
	}
	if !strings.Contains(logged, `"stack":"goroutine `) || !strings.Contains(logged, "panickingStore") {
		t.Fatalf("panic log lacks a stack: %s", logged)
	}
	if strings.Contains(logged, "synthetic-panic-detail") {
		t.Fatalf("panic log leaked the panic value: %s", logged)
	}
}

// accessLogRecords returns the decoded "api request" records in logs.
func accessLogRecords(t *testing.T, logs *bytes.Buffer) []map[string]any {
	t.Helper()
	var records []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		if line == "" {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("log line is not JSON: %v: %q", err, line)
		}
		if record["msg"] == "api request" {
			records = append(records, record)
		}
	}
	return records
}

// TestAccessLogRecordsRoutePatternNotPath pins API-11: every request logs one
// Info record with the method, the matched route pattern, status, bytes,
// duration, request id and remote address, and never the path or query that
// may carry repository names or reference strings.
func TestAccessLogRecordsRoutePatternNotPath(t *testing.T) {
	logs := &bytes.Buffer{}
	store := &stubReadStore{}
	handler := NewHandlerWithOptions(&stubScanner{}, store, HandlerOptions{Logger: testLogger(logs)})
	request := httptest.NewRequest(http.MethodGet, "/api/v1/repositories/library/app/scans?registry=ghcr.io&limit=5", nil)
	request.Header.Set("X-Request-ID", "access-1")
	request.RemoteAddr = "192.0.2.10:4242"
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	records := accessLogRecords(t, logs)
	if len(records) != 1 {
		t.Fatalf("access records = %d: %s", len(records), logs.String())
	}
	record := records[0]
	if record["level"] != "INFO" || record["method"] != "GET" || record["route"] != "GET /api/v1/repositories/" || record["status"] != float64(200) || record["request_id"] != "access-1" || record["remote_addr"] != "192.0.2.10:4242" {
		t.Fatalf("record = %v", record)
	}
	if bytes, ok := record["bytes"].(float64); !ok || int(bytes) != recorder.Body.Len() {
		t.Fatalf("bytes = %v, want %d", record["bytes"], recorder.Body.Len())
	}
	if _, ok := record["duration_ms"].(float64); !ok {
		t.Fatalf("duration_ms = %v", record["duration_ms"])
	}
	for _, leaked := range []string{"library/app", "registry=", "ghcr.io", "limit=5"} {
		if strings.Contains(logs.String(), leaked) {
			t.Fatalf("access log leaked %q: %s", leaked, logs.String())
		}
	}
}

// TestAccessLogCoversErrorPathsAndOmitsBodies: scan requests, panics and
// pre-mux rejections are logged with their final status, without the body.
func TestAccessLogCoversErrorPathsAndOmitsBodies(t *testing.T) {
	logs := &bytes.Buffer{}
	handler := NewHandlerWithOptions(&stubScanner{err: scanErrorFor(fmt.Errorf("synthetic upstream detail"))}, &panickingStore{stubReadStore: &stubReadStore{}, value: "boom"}, HandlerOptions{Logger: testLogger(logs)})

	handler.ServeHTTP(httptest.NewRecorder(), newJSONScanRequest(`{"reference":"library/app:latest"}`))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/repositories", nil))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1//repositories", nil))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodDelete, "/api/v1/scans", nil))

	records := accessLogRecords(t, logs)
	if len(records) != 4 {
		t.Fatalf("access records = %d: %s", len(records), logs.String())
	}
	want := []struct {
		method string
		route  string
		status float64
	}{
		{method: "POST", route: "POST /api/v1/scans", status: 502},
		{method: "GET", route: "GET /api/v1/repositories", status: 500},
		{method: "GET", route: "", status: 404},
		{method: "DELETE", route: "/api/v1/scans", status: 405},
	}
	for index, expected := range want {
		record := records[index]
		if record["method"] != expected.method || record["route"] != expected.route || record["status"] != expected.status {
			t.Fatalf("record %d = %v, want %+v", index, record, expected)
		}
	}
	if strings.Contains(logs.String(), "library/app:latest") || strings.Contains(logs.String(), "synthetic upstream detail") {
		t.Fatalf("access log leaked request detail: %s", logs.String())
	}
}
