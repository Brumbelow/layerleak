package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/scanservice"
)

// signalingScanner reports when a scan starts and blocks until its context
// ends, like a long registry scan would.
type signalingScanner struct {
	started chan struct{}
}

func (s *signalingScanner) ScanAndSave(ctx context.Context, _ scanservice.Request) (scanservice.Outcome, error) {
	close(s.started)
	<-ctx.Done()
	return scanservice.Outcome{}, scanErrorFor(fmt.Errorf("resolve manifest: %w", ctx.Err()))
}

func testLogger(buffer *bytes.Buffer) *slog.Logger {
	if buffer == nil {
		return slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	return slog.New(slog.NewJSONHandler(buffer, nil))
}

func listenLoopback(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return listener
}

// httpGet returns the status code and body of a GET against a test listener.
func httpGet(t *testing.T, client *http.Client, url string) (int, string) {
	t.Helper()
	response, err := client.Get(url) //nolint:noctx // loopback test probe
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	return response.StatusCode, string(body)
}

// postScan returns the status code and body of a scan request.
func postScan(client *http.Client, baseURL string) (int, string, error) {
	response, err := client.Post(baseURL+"/api/v1/scans", "application/json", strings.NewReader(`{"reference":"library/app:latest"}`)) //nolint:noctx // loopback test request
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	return response.StatusCode, string(body), err
}

type scanReply struct {
	status int
	body   string
	err    error
}

// TestServerDrainsInFlightScansAndStopsCleanly pins the API-04 drain
// sequence: cancelling the serve context turns /readyz into 503 not_ready
// while requests are still served, new scans are refused, the in-flight scan
// is cancelled after the pre-stop delay and reports 503
// server_shutting_down, and Serve returns nil.
func TestServerDrainsInFlightScansAndStopsCleanly(t *testing.T) {
	scanner := &signalingScanner{started: make(chan struct{})}
	logs := &bytes.Buffer{}
	server := NewServer(scanner, &stubReadStore{}, ServerOptions{
		PreStopDelay:    300 * time.Millisecond,
		ShutdownTimeout: 5 * time.Second,
		Logger:          testLogger(logs),
	})
	listener := listenLoopback(t)
	baseURL := "http://" + listener.Addr().String()
	client := &http.Client{Timeout: 5 * time.Second}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- server.Serve(ctx, listener) }()

	inFlight := make(chan scanReply, 1)
	go func() {
		status, body, err := postScan(client, baseURL)
		inFlight <- scanReply{status: status, body: body, err: err}
	}()
	select {
	case <-scanner.started:
	case <-time.After(5 * time.Second):
		t.Fatal("scan did not start")
	}

	if status, body := httpGet(t, client, baseURL+"/readyz"); status != http.StatusOK {
		t.Fatalf("readyz before drain: status = %d body=%s", status, body)
	}

	drainStarted := time.Now()
	cancel()

	deadline := time.Now().Add(2 * time.Second)
	for {
		status, body := httpGet(t, client, baseURL+"/readyz")
		if status == http.StatusServiceUnavailable {
			if !strings.Contains(body, `"not_ready"`) {
				t.Fatalf("readyz while draining: body=%s", body)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("readyz did not turn 503 while draining; last status %d", status)
		}
		time.Sleep(10 * time.Millisecond)
	}

	status, body, err := postScan(client, baseURL)
	if err != nil {
		t.Fatalf("scan during drain: %v", err)
	}
	if status != http.StatusServiceUnavailable || !strings.Contains(body, `"server_shutting_down"`) {
		t.Fatalf("scan during drain: status = %d body=%s", status, body)
	}

	select {
	case reply := <-inFlight:
		if reply.err != nil {
			t.Fatalf("in-flight scan: %v", reply.err)
		}
		if reply.status != http.StatusServiceUnavailable || !strings.Contains(reply.body, `"server_shutting_down"`) {
			t.Fatalf("in-flight scan: status = %d body=%s", reply.status, reply.body)
		}
		if elapsed := time.Since(drainStarted); elapsed < 250*time.Millisecond {
			t.Fatalf("in-flight scan was cancelled after %s, before the pre-stop delay", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight scan did not finish")
	}

	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("Serve() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve() did not return")
	}

	if _, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second); err == nil {
		t.Fatal("listener still accepts connections after shutdown")
	}
	if !strings.Contains(logs.String(), `"msg":"api draining"`) || !strings.Contains(logs.String(), `"msg":"api stopped"`) {
		t.Fatalf("drain lifecycle not logged: %s", logs.String())
	}
}

// TestServerStopsPromptlyWithoutPreStopDelay: with no pre-stop delay and no
// in-flight work, cancelling the context returns quickly and cleanly.
func TestServerStopsPromptlyWithoutPreStopDelay(t *testing.T) {
	server := NewServer(&stubScanner{}, &stubReadStore{}, ServerOptions{Logger: testLogger(nil)})
	listener := listenLoopback(t)
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- server.Serve(ctx, listener) }()

	client := &http.Client{Timeout: 5 * time.Second}
	if status, body := httpGet(t, client, "http://"+listener.Addr().String()+"/health"); status != http.StatusOK {
		t.Fatalf("health: status = %d body=%s", status, body)
	}

	started := time.Now()
	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("Serve() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve() did not return")
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("shutdown took %s", elapsed)
	}
}

// TestServerReportsListenerFailure: a dead listener surfaces as an error
// rather than a silent exit.
func TestServerReportsListenerFailure(t *testing.T) {
	server := NewServer(&stubScanner{}, &stubReadStore{}, ServerOptions{Logger: testLogger(nil)})
	listener := listenLoopback(t)
	_ = listener.Close()

	err := server.Serve(context.Background(), listener)
	if err == nil || errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("Serve() error = %v", err)
	}
}

// TestServerListenAndServeRejectsBusyAddress: ListenAndServe returns the
// bind error instead of running.
func TestServerListenAndServeRejectsBusyAddress(t *testing.T) {
	listener := listenLoopback(t)
	defer func() { _ = listener.Close() }()
	server := NewServer(&stubScanner{}, &stubReadStore{}, ServerOptions{Addr: listener.Addr().String(), Logger: testLogger(nil)})

	if err := server.ListenAndServe(context.Background()); err == nil {
		t.Fatal("ListenAndServe() error = nil")
	}
}

// TestHandlerDrainingResponses covers the handler side of draining without a
// listener: readiness is 503 not_ready, new scans are refused, and a request
// whose context was cancelled by the drain reports server_shutting_down.
func TestHandlerDrainingResponses(t *testing.T) {
	handler := newHandler(&stubScanner{}, &stubReadStore{}, HandlerOptions{Logger: testLogger(nil)})
	handler.startDraining()

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), `"not_ready"`) {
		t.Fatalf("readyz: status = %d body=%s", recorder.Code, recorder.Body.String())
	}

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, newJSONScanRequest(`{"reference":"library/app:latest"}`))
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), `"server_shutting_down"`) {
		t.Fatalf("scan: status = %d body=%s", recorder.Code, recorder.Body.String())
	}

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/health", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("health while draining: status = %d body=%s", recorder.Code, recorder.Body.String())
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/repositories", nil).WithContext(ctx))
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), `"server_shutting_down"`) {
		t.Fatalf("cancelled request while draining: status = %d body=%s", recorder.Code, recorder.Body.String())
	}
}

// TestHandleScanCancelledByDrainReportsShuttingDown: an in-flight scan whose
// request context the drain cancelled maps to 503 server_shutting_down, not
// 408 scan_canceled.
func TestHandleScanCancelledByDrainReportsShuttingDown(t *testing.T) {
	handler := newHandler(nil, &stubReadStore{}, HandlerOptions{Logger: testLogger(nil)})
	request := newJSONScanRequest(`{"reference":"library/app:latest"}`)
	ctx, cancel := context.WithCancel(request.Context())
	defer cancel()
	request = request.WithContext(ctx)
	handler.scanner = &drainingScanner{handler: handler, cancel: cancel}
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), `"server_shutting_down"`) {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
}

// drainingScanner starts the drain mid-scan, as Serve does, and returns the
// cancellation it observes.
type drainingScanner struct {
	handler *Handler
	cancel  context.CancelFunc
}

func (s *drainingScanner) ScanAndSave(ctx context.Context, _ scanservice.Request) (scanservice.Outcome, error) {
	s.handler.startDraining()
	s.cancel()
	<-ctx.Done()
	return scanservice.Outcome{}, scanErrorFor(ctx.Err())
}

// TestServerRoutesHTTPErrorLogThroughSlog pins API-18: net/http's internal
// logger writes JSON records through the configured slog handler instead of
// plain text on stderr.
func TestServerRoutesHTTPErrorLogThroughSlog(t *testing.T) {
	logs := &bytes.Buffer{}
	server := NewServer(&stubScanner{}, &stubReadStore{}, ServerOptions{Logger: testLogger(logs)})

	server.httpServer.ErrorLog.Printf("http: accept error: %s", "synthetic")

	line := logs.String()
	if !strings.Contains(line, `"level":"ERROR"`) || !strings.Contains(line, `"msg":"http: accept error: synthetic"`) {
		t.Fatalf("ErrorLog output = %q", line)
	}
	var record map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &record); err != nil {
		t.Fatalf("ErrorLog output is not one JSON object: %v: %q", err, line)
	}
}
