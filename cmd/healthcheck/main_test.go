package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func setHealthcheckArgs(t *testing.T, args ...string) {
	t.Helper()
	oldArgs := os.Args
	os.Args = append([]string{"layerleak-healthcheck"}, args...)
	t.Cleanup(func() { os.Args = oldArgs })
}

func TestRunRejectsInvalidAPIAddress(t *testing.T) {
	t.Setenv("LAYERLEAK_API_ADDR", "not-an-address")
	setHealthcheckArgs(t)

	if err := run(); err == nil || !strings.Contains(err.Error(), "parse LAYERLEAK_API_ADDR") {
		t.Fatalf("run() error = %v", err)
	}
}

func TestRunRejectsArguments(t *testing.T) {
	setHealthcheckArgs(t, "extra")

	if err := run(); err == nil {
		t.Fatal("run() error = nil")
	}
}

// probeServer serves /readyz with the given status and records the path and
// method the probe used.
func probeServer(t *testing.T, status int) (*httptest.Server, *http.Request) {
	t.Helper()
	var seen http.Request
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		seen = *request
		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		writer.WriteHeader(status)
		_, _ = writer.Write([]byte(`{"status":"ready","version":"dev"}`))
	}))
	t.Cleanup(server.Close)
	return server, &seen
}

func TestRunSucceedsWhenReadinessIsOK(t *testing.T) {
	server, seen := probeServer(t, http.StatusOK)
	t.Setenv("LAYERLEAK_API_ADDR", strings.TrimPrefix(server.URL, "http://"))
	setHealthcheckArgs(t)

	if err := run(); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if seen.Method != http.MethodGet || seen.URL.Path != "/readyz" {
		t.Fatalf("probe used %s %s", seen.Method, seen.URL.Path)
	}
}

func TestRunFailsWhenReadinessIsUnavailable(t *testing.T) {
	server, _ := probeServer(t, http.StatusServiceUnavailable)
	t.Setenv("LAYERLEAK_API_ADDR", strings.TrimPrefix(server.URL, "http://"))
	setHealthcheckArgs(t)

	err := run()
	if err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("run() error = %v", err)
	}
}

// TestRunProbesLoopbackForWildcardBind: the container binds 0.0.0.0 but the
// probe must dial the loopback address on the same port.
func TestRunProbesLoopbackForWildcardBind(t *testing.T) {
	server, _ := probeServer(t, http.StatusOK)
	_, port, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatalf("split server address: %v", err)
	}
	t.Setenv("LAYERLEAK_API_ADDR", "0.0.0.0:"+port)
	setHealthcheckArgs(t)

	if err := run(); err != nil {
		t.Fatalf("run() error = %v", err)
	}
}

func TestRunDoesNotFollowRedirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, "/health", http.StatusFound)
	}))
	t.Cleanup(server.Close)
	t.Setenv("LAYERLEAK_API_ADDR", strings.TrimPrefix(server.URL, "http://"))
	setHealthcheckArgs(t)

	err := run()
	if err == nil || !strings.Contains(err.Error(), "302") {
		t.Fatalf("run() error = %v", err)
	}
}

func TestRunFailsWhenNothingListens(t *testing.T) {
	listener := httptest.NewServer(http.NotFoundHandler())
	address := strings.TrimPrefix(listener.URL, "http://")
	listener.Close()
	t.Setenv("LAYERLEAK_API_ADDR", address)
	setHealthcheckArgs(t)

	err := run()
	if err == nil || !strings.Contains(err.Error(), "readiness probe failed") {
		t.Fatalf("run() error = %v", err)
	}
}
