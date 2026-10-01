package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/jobs"
	"github.com/brumbelow/layerleak/v3/internal/scanservice"
)

// slowScanner completes after a fixed delay unless the context ends first.
type slowScanner struct {
	delay time.Duration
}

func (s *slowScanner) ScanAndSave(ctx context.Context, _ scanservice.Request) (scanservice.Outcome, error) {
	select {
	case <-time.After(s.delay):
		return scanservice.Outcome{ScanRunID: 5, Result: jobs.Result{RequestedReference: "library/app:latest", Status: jobs.ResultStatusCompleted}}, nil
	case <-ctx.Done():
		return scanservice.Outcome{}, scanErrorFor(ctx.Err())
	}
}

// TestLongScanOutlivesServerReadTimeout locks in the verified behaviour that
// http.Server.ReadTimeout bounds reading the request, not the handler: a scan
// longer than ReadTimeout still answers 200.
func TestLongScanOutlivesServerReadTimeout(t *testing.T) {
	server := httptest.NewUnstartedServer(NewHandlerWithOptions(&slowScanner{delay: 500 * time.Millisecond}, &stubReadStore{}, HandlerOptions{Logger: testLogger(nil)}))
	server.Config.ReadTimeout = 100 * time.Millisecond
	server.Config.ReadHeaderTimeout = 100 * time.Millisecond
	server.Start()
	defer server.Close()

	status, body, err := postScan(&http.Client{Timeout: 5 * time.Second}, server.URL)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if status != http.StatusOK || !strings.Contains(body, `"scan_run_id": 5`) {
		t.Fatalf("status = %d body=%s", status, body)
	}
}

// observingScanner reports when it starts and records the context error it
// saw when the request ended.
type observingScanner struct {
	started chan struct{}
	done    chan error
}

func (s *observingScanner) ScanAndSave(ctx context.Context, _ scanservice.Request) (scanservice.Outcome, error) {
	close(s.started)
	select {
	case <-ctx.Done():
		s.done <- ctx.Err()
		return scanservice.Outcome{}, scanErrorFor(ctx.Err())
	case <-time.After(5 * time.Second):
		s.done <- errors.New("scan context never ended")
		return scanservice.Outcome{}, nil
	}
}

// TestClientDisconnectCancelsScan: closing the client connection mid-scan
// cancels the scanner's context, so no work continues for a reader that is
// gone and nothing is saved by the handler.
func TestClientDisconnectCancelsScan(t *testing.T) {
	scanner := &observingScanner{started: make(chan struct{}), done: make(chan error, 1)}
	server := httptest.NewServer(NewHandlerWithOptions(scanner, &stubReadStore{}, HandlerOptions{Logger: testLogger(nil)}))
	defer server.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	body := `{"reference":"library/app:latest"}`
	request := fmt.Sprintf("POST /api/v1/scans HTTP/1.1\r\nHost: api.test\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	select {
	case <-scanner.started:
	case <-time.After(5 * time.Second):
		t.Fatal("scan did not start")
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	select {
	case err := <-scanner.done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("scanner context error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("scanner never observed the disconnect")
	}
}
