package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/jobs"
	"github.com/brumbelow/layerleak/v3/internal/scanservice"
)

// TestMetricsExpositionMatchesGolden renders a fixed set of observations and
// compares the hand-written exposition format against testdata/metrics.golden.
// Regenerate with LAYERLEAK_UPDATE_METRICS_GOLDEN=1 after an intentional
// format change.
func TestMetricsExpositionMatchesGolden(t *testing.T) {
	registry := newMetrics("v3.0.0-test", time.Date(2026, time.September, 30, 17, 30, 0, 0, time.UTC))
	registry.observeRequest("GET /health", http.StatusOK, 1*time.Millisecond)
	registry.observeRequest("GET /health", http.StatusOK, 4*time.Millisecond)
	registry.observeRequest(scanRoutePattern, http.StatusOK, 1500*time.Millisecond)
	registry.observeRequest(scanRoutePattern, http.StatusBadGateway, 200*time.Millisecond)
	registry.observeRequest(scanRoutePattern, http.StatusUnprocessableEntity, 2*time.Hour)
	registry.observeRequest(routeNone, http.StatusNotFound, 500*time.Microsecond)
	registry.observeRequest("GET /api/v1/repositories", http.StatusServiceUnavailable, 20*time.Millisecond)
	registry.observeScan("completed")
	registry.observeScan("failed")
	registry.observeScan("partial")
	registry.observeScan("completed")
	registry.observeScanError("scan_failed")
	registry.observeScanError("scan_incomplete")
	registry.scanStarted()

	var rendered bytes.Buffer
	if err := registry.write(&rendered); err != nil {
		t.Fatalf("write() error = %v", err)
	}
	path := filepath.Join("testdata", "metrics.golden")
	if os.Getenv("LAYERLEAK_UPDATE_METRICS_GOLDEN") == "1" {
		if err := os.WriteFile(path, rendered.Bytes(), 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if rendered.String() != string(want) {
		t.Fatalf("exposition differs from %s; regenerate with LAYERLEAK_UPDATE_METRICS_GOLDEN=1\n--- got ---\n%s", path, rendered.String())
	}
	// Every family declares HELP and TYPE exactly once, in that order.
	for _, name := range []string{"layerleak_build_info", "layerleak_process_start_time_seconds", "layerleak_api_requests_total", "layerleak_api_request_duration_seconds", "layerleak_scans_total", "layerleak_scan_errors_total", "layerleak_scans_in_flight"} {
		if strings.Count(rendered.String(), "# HELP "+name+" ") != 1 || strings.Count(rendered.String(), "# TYPE "+name+" ") != 1 {
			t.Fatalf("family %s is not declared exactly once", name)
		}
	}
}

// TestMetricsEscapesLabelValuesAndHelp: the exposition format escapes
// backslash, double quote and newline in label values and backslash and
// newline in HELP text.
func TestMetricsEscapesLabelValuesAndHelp(t *testing.T) {
	registry := newMetrics("v\"3\\0\n", time.Unix(0, 0))
	registry.observeRequest("GET /weird\"\\\n", http.StatusOK, time.Millisecond)
	var rendered bytes.Buffer
	if err := registry.write(&rendered); err != nil {
		t.Fatalf("write() error = %v", err)
	}
	if !strings.Contains(rendered.String(), `layerleak_build_info{version="v\"3\\0\n"} 1`) {
		t.Fatalf("version label not escaped:\n%s", rendered.String())
	}
	if !strings.Contains(rendered.String(), `layerleak_api_requests_total{route="GET /weird\"\\\n",status_class="2xx"} 1`) {
		t.Fatalf("route label not escaped:\n%s", rendered.String())
	}
	if escapeHelp("a\\b\nc") != `a\\b\nc` {
		t.Fatalf("escapeHelp = %q", escapeHelp("a\\b\nc"))
	}
	for _, line := range strings.Split(rendered.String(), "\n") {
		if strings.HasPrefix(line, "layerleak_") && strings.Count(line, "\n") != 0 {
			t.Fatalf("sample line contains a raw newline: %q", line)
		}
	}
}

func TestMetricsStatusClassAndRouteLabel(t *testing.T) {
	for status, want := range map[int]string{200: "2xx", 304: "3xx", 404: "4xx", 503: "5xx", 99: "unknown", 600: "unknown"} {
		if got := statusClass(status); got != want {
			t.Fatalf("statusClass(%d) = %q, want %q", status, got, want)
		}
	}
	if routeLabel("") != routeNone || routeLabel("  ") != routeNone || routeLabel("GET /health") != "GET /health" {
		t.Fatal("routeLabel mapping is wrong")
	}
	var nilRegistry *metrics
	nilRegistry.observeRequest("x", 200, time.Second)
	nilRegistry.observeScan("completed")
	nilRegistry.observeScanError("code")
	nilRegistry.scanStarted()
	nilRegistry.scanFinished()
}

func scrape(t *testing.T, handler http.Handler) string {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("metrics status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Content-Type"); got != metricsContentType {
		t.Fatalf("metrics Content-Type = %q", got)
	}
	return recorder.Body.String()
}

func requireLine(t *testing.T, exposition, line string) {
	t.Helper()
	if !strings.Contains(exposition, line+"\n") {
		t.Fatalf("exposition lacks %q:\n%s", line, exposition)
	}
}

// TestHandlerRecordsRequestScanAndErrorMetrics drives the handler through
// health probes, a completed scan, a failed scan, a request rejected before
// the scanner ran and an unmatched path, then checks the counters. Labels are
// route patterns and codes only: the reference never appears.
func TestHandlerRecordsRequestScanAndErrorMetrics(t *testing.T) {
	scanner := &sequenceScanner{outcomes: []scanReplyOutcome{
		{outcome: scanservice.Outcome{ScanRunID: 1, Result: jobs.Result{RequestedReference: "library/app:latest", Status: jobs.ResultStatusCompleted}}},
		{outcome: scanservice.Outcome{Result: jobs.Result{RequestedReference: "library/app:latest", Status: jobs.ResultStatusFailed}}, err: scanErrorFor(errors.New("synthetic upstream detail"))},
		{outcome: scanservice.Outcome{Result: jobs.Result{RequestedReference: "library/app:latest", Status: jobs.ResultStatusCompleted}}, err: &scanservice.Error{Phase: scanservice.ErrorPhaseSave, Err: errors.New("synthetic storage detail")}},
	}}
	handler := newHandler(scanner, &stubReadStore{}, HandlerOptions{Logger: testLogger(nil)})

	serve(handler, http.MethodGet, "/health")
	serve(handler, http.MethodGet, "/health")
	serve(handler, http.MethodGet, "/api/v1/repositories")
	serve(handler, http.MethodGet, "/api/v1//unclean")
	for range 3 {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, newJSONScanRequest(`{"reference":"library/app:latest"}`))
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, newJSONScanRequest(`{"reference":"https://not-a-reference"}`))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid scan status = %d", recorder.Code)
	}

	exposition := scrape(t, handler.MetricsHandler())
	requireLine(t, exposition, `layerleak_api_requests_total{route="GET /health",status_class="2xx"} 2`)
	requireLine(t, exposition, `layerleak_api_requests_total{route="GET /api/v1/repositories",status_class="2xx"} 1`)
	requireLine(t, exposition, `layerleak_api_requests_total{route="POST /api/v1/scans",status_class="2xx"} 1`)
	requireLine(t, exposition, `layerleak_api_requests_total{route="POST /api/v1/scans",status_class="4xx"} 1`)
	requireLine(t, exposition, `layerleak_api_requests_total{route="POST /api/v1/scans",status_class="5xx"} 2`)
	requireLine(t, exposition, `layerleak_api_requests_total{route="none",status_class="4xx"} 1`)
	requireLine(t, exposition, `layerleak_api_request_duration_seconds_count{route="GET /health"} 2`)
	requireLine(t, exposition, `layerleak_scans_total{outcome="completed"} 2`)
	requireLine(t, exposition, `layerleak_scans_total{outcome="failed"} 1`)
	requireLine(t, exposition, `layerleak_scan_errors_total{code="scan_failed"} 1`)
	requireLine(t, exposition, `layerleak_scan_errors_total{code="storage_unavailable"} 1`)
	requireLine(t, exposition, `layerleak_scan_errors_total{code="invalid_request"} 1`)
	requireLine(t, exposition, `layerleak_scans_in_flight 0`)
	if strings.Contains(exposition, "library/app") || strings.Contains(exposition, "not-a-reference") || strings.Contains(exposition, "unclean") {
		t.Fatalf("exposition carries request detail:\n%s", exposition)
	}
	// Scan errors are attributed only to the scan route: the repository read
	// above produced no error code and nothing else is counted.
	if strings.Count(exposition, "layerleak_scan_errors_total{") != 3 {
		t.Fatalf("unexpected scan error codes:\n%s", exposition)
	}
}

type scanReplyOutcome struct {
	outcome scanservice.Outcome
	err     error
}

// sequenceScanner answers each call with the next scripted outcome.
type sequenceScanner struct {
	outcomes []scanReplyOutcome
	calls    int
}

func (s *sequenceScanner) ScanAndSave(context.Context, scanservice.Request) (scanservice.Outcome, error) {
	index := min(s.calls, len(s.outcomes)-1)
	s.calls++
	return s.outcomes[index].outcome, s.outcomes[index].err
}

// TestMetricsInFlightGaugeTracksRunningScans: the gauge rises while a scan
// holds a slot and returns to zero afterwards; a scan refused for capacity
// is not counted as in flight.
func TestMetricsInFlightGaugeTracksRunningScans(t *testing.T) {
	scanner := &signalingScanner{started: make(chan struct{})}
	handler := newHandler(scanner, &stubReadStore{}, HandlerOptions{Logger: testLogger(nil), MaxConcurrentScans: 1})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, newJSONScanRequest(`{"reference":"library/app:latest"}`).WithContext(ctx))
	}()
	select {
	case <-scanner.started:
	case <-time.After(5 * time.Second):
		t.Fatal("scan did not start")
	}
	requireLine(t, scrape(t, handler.MetricsHandler()), `layerleak_scans_in_flight 1`)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, newJSONScanRequest(`{"reference":"library/app:latest"}`))
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("second scan status = %d", recorder.Code)
	}
	requireLine(t, scrape(t, handler.MetricsHandler()), `layerleak_scans_in_flight 1`)

	cancel()
	<-done
	exposition := scrape(t, handler.MetricsHandler())
	requireLine(t, exposition, `layerleak_scans_in_flight 0`)
	requireLine(t, exposition, `layerleak_scan_errors_total{code="scan_capacity_exceeded"} 1`)
	requireLine(t, exposition, `layerleak_scan_errors_total{code="scan_canceled"} 1`)
}

// TestMetricsHandlerRoutes: only GET/HEAD /metrics is served; the handler
// carries no bearer-token check because it is mounted on its own listener.
func TestMetricsHandlerRoutes(t *testing.T) {
	handler := newHandler(&stubScanner{}, &stubReadStore{}, HandlerOptions{Logger: testLogger(nil), BearerTokenDigests: [][]byte{tokenDigest(authTokenA)}})
	metricsHandler := handler.MetricsHandler()

	exposition := scrape(t, metricsHandler)
	if !strings.HasPrefix(exposition, "# HELP layerleak_build_info ") {
		t.Fatalf("exposition = %q", exposition)
	}

	recorder := httptest.NewRecorder()
	metricsHandler.ServeHTTP(recorder, httptest.NewRequest(http.MethodHead, "/metrics", nil))
	if recorder.Code != http.StatusOK || recorder.Body.Len() != 0 || recorder.Header().Get("Content-Type") != metricsContentType {
		t.Fatalf("HEAD: status = %d body=%q", recorder.Code, recorder.Body.String())
	}

	recorder = httptest.NewRecorder()
	metricsHandler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/metrics", nil))
	if recorder.Code != http.StatusMethodNotAllowed || recorder.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("POST: status = %d Allow=%q", recorder.Code, recorder.Header().Get("Allow"))
	}

	recorder = httptest.NewRecorder()
	metricsHandler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("GET /: status = %d", recorder.Code)
	}
	for _, header := range []string{"Cache-Control", "X-Content-Type-Options"} {
		if recorder.Header().Get(header) == "" {
			t.Fatalf("%s missing on metrics 404", header)
		}
	}

	// The API mux itself never serves /metrics.
	recorder = httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	request.Header.Set("Authorization", "Bearer "+authTokenA)
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound || !strings.Contains(recorder.Body.String(), `"not_found"`) {
		t.Fatalf("API /metrics: status = %d body=%s", recorder.Code, recorder.Body.String())
	}
}

// TestServerServesMetricsOnSeparateListener: the metrics listener answers
// scrapes while the API runs and through the drain, and both listeners are
// closed when ServeListeners returns.
func TestServerServesMetricsOnSeparateListener(t *testing.T) {
	logs := &bytes.Buffer{}
	server := NewServer(&stubScanner{}, &stubReadStore{}, ServerOptions{PreStopDelay: 200 * time.Millisecond, Logger: testLogger(logs)})
	apiListener := listenLoopback(t)
	metricsListener := listenLoopback(t)
	apiURL := "http://" + apiListener.Addr().String()
	metricsURL := "http://" + metricsListener.Addr().String()
	client := &http.Client{Timeout: 5 * time.Second}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- server.ServeListeners(ctx, apiListener, metricsListener) }()

	if status, body := httpGet(t, client, apiURL+"/health"); status != http.StatusOK {
		t.Fatalf("health: status = %d body=%s", status, body)
	}
	status, body := httpGet(t, client, metricsURL+"/metrics")
	if status != http.StatusOK || !strings.Contains(body, "layerleak_api_requests_total{route=\"GET /health\",status_class=\"2xx\"} 1") {
		t.Fatalf("metrics: status = %d body=%s", status, body)
	}
	if status, body := httpGet(t, client, apiURL+"/metrics"); status != http.StatusNotFound || !strings.Contains(body, `"not_found"`) {
		t.Fatalf("API port must not serve metrics: status = %d body=%s", status, body)
	}

	cancel()
	// Metrics stay scrapeable during the pre-stop window.
	deadline := time.Now().Add(2 * time.Second)
	for {
		status, _ := httpGet(t, client, apiURL+"/readyz")
		if status == http.StatusServiceUnavailable {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("readyz did not turn 503 while draining")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if status, body := httpGet(t, client, metricsURL+"/metrics"); status != http.StatusOK || !strings.Contains(body, "layerleak_scans_in_flight 0") {
		t.Fatalf("metrics during drain: status = %d body=%s", status, body)
	}

	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("ServeListeners() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ServeListeners() did not return")
	}
	for name, address := range map[string]string{"api": apiListener.Addr().String(), "metrics": metricsListener.Addr().String()} {
		if _, err := net.DialTimeout("tcp", address, time.Second); err == nil {
			t.Fatalf("%s listener still accepts connections after shutdown", name)
		}
	}
	if !strings.Contains(logs.String(), `"msg":"api stopped"`) {
		t.Fatalf("stop not logged: %s", logs.String())
	}
}

// TestServerListenAndServeReportsMetricsBindFailure: a busy metrics address
// fails startup and releases the API listener instead of serving half-configured.
func TestServerListenAndServeReportsMetricsBindFailure(t *testing.T) {
	busy := listenLoopback(t)
	defer func() { _ = busy.Close() }()
	free := listenLoopback(t)
	apiAddr := free.Addr().String()
	_ = free.Close()

	server := NewServer(&stubScanner{}, &stubReadStore{}, ServerOptions{Addr: apiAddr, MetricsAddr: busy.Addr().String(), Logger: testLogger(nil)})
	err := server.ListenAndServe(context.Background())
	if err == nil || !strings.Contains(err.Error(), "metrics address") {
		t.Fatalf("ListenAndServe() error = %v", err)
	}
	if _, dialErr := net.DialTimeout("tcp", apiAddr, 200*time.Millisecond); dialErr == nil {
		t.Fatal("API listener was left open after the metrics bind failed")
	}
}

// TestMetricsStalledScraperDoesNotBlockObservations: a scrape client that
// never reads its response must not wedge the API. The exposition is
// rendered under the metrics mutex, so if the handler wrote to the socket
// while holding it, every API request's deferred observeRequest would block
// behind one stalled scraper. The handler also sets a write deadline, so the
// stalled response is abandoned and the server can drain.
func TestMetricsStalledScraperDoesNotBlockObservations(t *testing.T) {
	handler := newHandler(&stubScanner{}, &stubReadStore{}, HandlerOptions{ResponseTimeout: 500 * time.Millisecond, Logger: testLogger(nil)})
	// Enough routes that a single exposition dwarfs any loopback socket buffer.
	for index := range 4000 {
		handler.metrics.observeRequest(fmt.Sprintf("GET /api/v1/route-%04d", index), http.StatusOK, time.Millisecond)
	}

	server := httptest.NewServer(handler.MetricsHandler())
	t.Cleanup(server.Close)
	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	// Pipeline scrapes without ever reading: the first response fills the
	// socket buffers and the handler's write stalls.
	var pipeline strings.Builder
	for range 40 {
		pipeline.WriteString("GET /metrics HTTP/1.1\r\nHost: metrics\r\n\r\n")
	}
	if _, err := io.WriteString(conn, pipeline.String()); err != nil {
		t.Fatalf("send pipelined scrapes: %v", err)
	}
	time.Sleep(300 * time.Millisecond)

	observed := make(chan struct{})
	go func() {
		handler.metrics.observeRequest("GET /health", http.StatusOK, time.Millisecond)
		close(observed)
	}()
	select {
	case <-observed:
	case <-time.After(3 * time.Second):
		t.Fatal("observeRequest blocked for 3s: metrics mutex is held while writing to a stalled scrape client")
	}

	// The stalled handler hits its write deadline and returns, so closing
	// the server (which waits for in-flight requests) completes without the
	// client ever reading.
	closed := make(chan struct{})
	go func() {
		server.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("metrics server could not close: stalled scrape never timed out")
	}
}
