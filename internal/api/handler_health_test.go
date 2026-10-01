package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/brumbelow/layerleak/v3/internal/version"
)

// TestHealthEndpointsReportVersion pins API-20: /health, /livez and a ready
// /readyz carry the build version so operators can ask a running instance
// which build it is.
func TestHealthEndpointsReportVersion(t *testing.T) {
	tests := []struct {
		path   string
		status string
	}{
		{path: "/health", status: "ok"},
		{path: "/livez", status: "ok"},
		{path: "/readyz", status: "ready"},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			NewHandler(&stubScanner{}, &stubReadStore{}).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, test.path, nil))

			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
			}
			var body map[string]string
			if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if body["status"] != test.status {
				t.Fatalf("status field = %q", body["status"])
			}
			if body["version"] == "" || body["version"] != version.Effective() {
				t.Fatalf("version = %q, want %q", body["version"], version.Effective())
			}
			if len(body) != 2 {
				t.Fatalf("unexpected fields: %v", body)
			}
		})
	}
}
