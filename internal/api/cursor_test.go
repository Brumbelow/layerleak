package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/storage"
)

func TestCursorRoundTripKeepsMicrosecondPrecision(t *testing.T) {
	seenAt := time.Date(2026, time.September, 30, 17, 30, 0, 123456000, time.FixedZone("x", 3600))
	encoded := encodeCursor(cursorPayload{Kind: cursorKindFinding, Micros: seenAt.UnixMicro(), ID: 7})
	if strings.ContainsAny(encoded, "=+/") {
		t.Fatalf("cursor is not base64url without padding: %q", encoded)
	}
	payload, err := decodeCursor(encoded, cursorKindFinding)
	if err != nil {
		t.Fatalf("decodeCursor() error = %v", err)
	}
	if !payload.time().Equal(seenAt) || payload.time().Location() != time.UTC || payload.ID != 7 {
		t.Fatalf("decoded = %+v (%s), want %s id 7", payload, payload.time(), seenAt)
	}
}

func TestDecodeCursorRejectsMalformedAndForeignCursors(t *testing.T) {
	valid := encodeCursor(cursorPayload{Kind: cursorKindScan, Micros: 1_000_000, ID: 41})
	raw := func(value string) string { return base64.RawURLEncoding.EncodeToString([]byte(value)) }
	tests := map[string]string{
		"empty":                  "",
		"not base64":             "!!!",
		"not json":               raw("nonsense"),
		"wrong kind":             encodeCursor(cursorPayload{Kind: cursorKindFinding, Micros: 1_000_000, ID: 41}),
		"repository kind":        encodeCursor(cursorPayload{Kind: cursorKindRepository, Micros: 1_000_000, Repository: "library/app", Registry: "docker.io"}),
		"zero id":                encodeCursor(cursorPayload{Kind: cursorKindScan, Micros: 1_000_000}),
		"negative id":            encodeCursor(cursorPayload{Kind: cursorKindScan, Micros: 1_000_000, ID: -1}),
		"zero time":              encodeCursor(cursorPayload{Kind: cursorKindScan, ID: 41}),
		"unknown field":          raw(`{"k":"s","t":1000000,"id":41,"x":1}`),
		"trailing value":         raw(`{"k":"s","t":1000000,"id":41} 1`),
		"repository fields":      encodeCursor(cursorPayload{Kind: cursorKindScan, Micros: 1_000_000, ID: 41, Repository: "library/app"}),
		"oversized":              strings.Repeat("A", maxCursorLength+1),
		"padding added":          valid + "=",
		"standard base64 letter": strings.ReplaceAll(valid, "_", "/") + "+",
	}
	for name, value := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeCursor(value, cursorKindScan); err == nil {
				t.Fatalf("decodeCursor(%q) accepted", value)
			}
		})
	}
	if _, err := decodeCursor(valid, cursorKindScan); err != nil {
		t.Fatalf("valid cursor rejected: %v", err)
	}
	if _, err := decodeCursor(encodeCursor(cursorPayload{Kind: cursorKindRepository, Micros: 1, Repository: "library/app", Registry: "docker.io"}), cursorKindRepository); err != nil {
		t.Fatalf("valid repository cursor rejected: %v", err)
	}
	if _, err := decodeCursor(encodeCursor(cursorPayload{Kind: cursorKindRepository, Micros: 1, Repository: "library/app"}), cursorKindRepository); err == nil {
		t.Fatal("repository cursor without registry accepted")
	}
}

// TestListEndpointsPaginateByCursor: a full page returns a next_cursor that
// decodes to the last row's ordering key and is forwarded to the store on the
// following request; a short page returns an empty next_cursor.
func TestListEndpointsPaginateByCursor(t *testing.T) {
	lastSeen := time.Date(2026, time.September, 30, 17, 30, 0, 250000000, time.UTC)
	store := contractReadStore()
	store.repositories[1].LastSeenAt = lastSeen

	recorder := serve(NewHandler(&stubScanner{}, store), http.MethodGet, "/api/v1/repositories?limit=2")
	var page struct {
		NextCursor string `json:"next_cursor"`
		Limit      int    `json:"limit"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &page); err != nil || recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s err=%v", recorder.Code, recorder.Body.String(), err)
	}
	if page.NextCursor == "" || page.Limit != 2 {
		t.Fatalf("full page must carry next_cursor: %+v", page)
	}
	payload, err := decodeCursor(page.NextCursor, cursorKindRepository)
	if err != nil || payload.Repository != "brumbelow/layerleak" || payload.Registry != "ghcr.io" || !payload.time().Equal(lastSeen) {
		t.Fatalf("next_cursor = %+v err=%v", payload, err)
	}

	recorder = serve(NewHandler(&stubScanner{}, store), http.MethodGet, "/api/v1/repositories?limit=2&cursor="+page.NextCursor)
	if recorder.Code != http.StatusOK {
		t.Fatalf("cursor page status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if store.repositoryAfter == nil || store.repositoryAfter.Repository != "brumbelow/layerleak" || store.repositoryAfter.Registry != "ghcr.io" || !store.repositoryAfter.LastSeenAt.Equal(lastSeen) || store.offset != 0 {
		t.Fatalf("store cursor = %+v offset=%d", store.repositoryAfter, store.offset)
	}

	// Short pages: the stub holds one finding and two scans.
	recorder = serve(NewHandler(&stubScanner{}, store), http.MethodGet, "/api/v1/repositories/library/example/findings?disposition=all")
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"next_cursor": ""`) {
		t.Fatalf("short findings page: status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if store.findingAfter != nil {
		t.Fatalf("findings cursor forwarded without a cursor parameter: %+v", store.findingAfter)
	}
	recorder = serve(NewHandler(&stubScanner{}, store), http.MethodGet, "/api/v1/repositories/library/example/scans?limit=2")
	var scansPage struct {
		NextCursor string `json:"next_cursor"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &scansPage); err != nil || scansPage.NextCursor == "" {
		t.Fatalf("full scans page: body=%s err=%v", recorder.Body.String(), err)
	}
	scanCursor, err := decodeCursor(scansPage.NextCursor, cursorKindScan)
	if err != nil || scanCursor.ID != 40 {
		t.Fatalf("scans next_cursor = %+v err=%v", scanCursor, err)
	}
	recorder = serve(NewHandler(&stubScanner{}, store), http.MethodGet, "/api/v1/repositories/library/example/scans?cursor="+scansPage.NextCursor)
	if recorder.Code != http.StatusOK || store.scanAfter == nil || store.scanAfter.ID != 40 {
		t.Fatalf("scans cursor page: status = %d cursor=%+v", recorder.Code, store.scanAfter)
	}
	findingCursor := encodeCursor(cursorPayload{Kind: cursorKindFinding, Micros: lastSeen.UnixMicro(), ID: 7})
	recorder = serve(NewHandler(&stubScanner{}, store), http.MethodGet, "/api/v1/repositories/library/example/findings?cursor="+findingCursor)
	if recorder.Code != http.StatusOK || store.findingAfter == nil || store.findingAfter.ID != 7 || !store.findingAfter.LastSeenAt.Equal(lastSeen) {
		t.Fatalf("findings cursor page: status = %d cursor=%+v", recorder.Code, store.findingAfter)
	}
}

// TestListEndpointsRejectInvalidCursors: malformed, foreign and offset-combined
// cursors are 400 invalid_request with fixed messages and the store is not
// queried.
func TestListEndpointsRejectInvalidCursors(t *testing.T) {
	scanCursor := encodeCursor(cursorPayload{Kind: cursorKindScan, Micros: 1_000_000, ID: 41})
	tests := []struct {
		target  string
		message string
	}{
		{target: "/api/v1/repositories?cursor=%21%21", message: "cursor is invalid"},
		{target: "/api/v1/repositories?cursor=" + scanCursor, message: "cursor is invalid"},
		{target: "/api/v1/repositories/library/app/scans?cursor=nonsense", message: "cursor is invalid"},
		{target: "/api/v1/repositories/library/app/findings?cursor=" + scanCursor, message: "cursor is invalid"},
		{target: "/api/v1/repositories/library/app/scans?offset=5&cursor=" + scanCursor, message: "cursor cannot be combined with a non-zero offset"},
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
			if store.limit != 0 {
				t.Fatalf("store was queried: %+v", store)
			}
		})
	}
	// offset=0 beside a cursor is allowed: it is the default.
	store := &stubReadStore{}
	recorder := serve(NewHandler(&stubScanner{}, store), http.MethodGet, "/api/v1/repositories/library/app/scans?offset=0&cursor="+scanCursor)
	if recorder.Code != http.StatusOK || store.scanAfter == nil {
		t.Fatalf("offset=0 with cursor: status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	var _ storage.ReadStore = store
}
