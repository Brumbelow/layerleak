package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Local image sources are a CLI feature: the API never reads the server's
// filesystem, so a local scheme in the request body is an invalid request.
func TestHandleScanRejectsLocalImageSources(t *testing.T) {
	for _, reference := range []string{"oci:/srv/images/app:1.2", "oci-archive:/tmp/app.tar", "docker-archive:/tmp/app.tar:alpine:3.20", "OCI:/srv/images/app"} {
		t.Run(reference, func(t *testing.T) {
			scanner := &stubScanner{}
			body, err := json.Marshal(map[string]any{"reference": reference})
			if err != nil {
				t.Fatal(err)
			}
			recorder := httptest.NewRecorder()
			NewHandler(scanner, &stubReadStore{}).ServeHTTP(recorder, newJSONScanRequest(string(body)))

			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
			}
			var payload struct {
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
				t.Fatalf("body is not JSON: %v: %s", err, recorder.Body.String())
			}
			if payload.Error.Code != "invalid_request" || !strings.Contains(payload.Error.Message, "only supported by the layerleak CLI") {
				t.Fatalf("error = %+v", payload.Error)
			}
			if strings.Contains(recorder.Body.String(), "/srv/") || strings.Contains(recorder.Body.String(), "/tmp/") {
				t.Fatalf("response echoes the caller's path: %s", recorder.Body.String())
			}
			if scanner.request.Reference.Original != "" {
				t.Fatalf("scanner was invoked for %q", scanner.request.Reference.Original)
			}
		})
	}
}
