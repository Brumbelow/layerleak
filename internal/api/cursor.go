package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/storage"
)

// Cursor kinds bind an opaque cursor to one endpoint's ordering so a value
// from another listing is rejected instead of silently misapplied.
const (
	cursorKindRepository = "r"
	cursorKindScan       = "s"
	cursorKindFinding    = "f"
	// maxCursorLength bounds the query value before it is decoded.
	maxCursorLength = 512
)

var (
	errCursorInvalid    = errors.New("cursor is invalid")
	errCursorWithOffset = errors.New("cursor cannot be combined with a non-zero offset")
)

// cursorPayload is the decoded form of the opaque `cursor` query value: the
// ordering key of the last row of the previous page. Timestamps travel as Unix
// microseconds, the precision PostgreSQL stores, so they round-trip exactly.
type cursorPayload struct {
	Kind       string `json:"k"`
	Micros     int64  `json:"t"`
	ID         int64  `json:"id,omitempty"`
	Repository string `json:"repo,omitempty"`
	Registry   string `json:"reg,omitempty"`
}

func (p cursorPayload) time() time.Time {
	return time.UnixMicro(p.Micros).UTC()
}

func encodeCursor(payload cursorPayload) string {
	body, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(body)
}

// decodeCursor parses an opaque cursor of the given kind. Any defect (length,
// encoding, unknown fields, wrong kind, missing key parts) is the one fixed
// error so the response reveals nothing about the cursor's structure.
func decodeCursor(value, kind string) (cursorPayload, error) {
	if value == "" || len(value) > maxCursorLength {
		return cursorPayload{}, errCursorInvalid
	}
	payload, ok := unmarshalCursor(value)
	if !ok {
		return cursorPayload{}, errCursorInvalid
	}
	if payload.Kind != kind || payload.Micros <= 0 {
		return cursorPayload{}, errCursorInvalid
	}
	if !cursorKeyComplete(payload, kind) {
		return cursorPayload{}, errCursorInvalid
	}
	return payload, nil
}

// unmarshalCursor decodes the base64url JSON body of a cursor, rejecting
// unknown fields and any data after the single JSON object.
func unmarshalCursor(value string) (cursorPayload, bool) {
	body, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return cursorPayload{}, false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var payload cursorPayload
	if err := decoder.Decode(&payload); err != nil || requireSingleJSONValue(decoder) != nil {
		return cursorPayload{}, false
	}
	return payload, true
}

// cursorKeyComplete reports whether payload carries exactly the key parts of
// its kind: repository cursors a repository and registry, the others an ID.
func cursorKeyComplete(payload cursorPayload, kind string) bool {
	switch kind {
	case cursorKindRepository:
		return payload.ID == 0 && payload.Repository != "" && payload.Registry != ""
	default:
		return payload.ID > 0 && payload.Repository == "" && payload.Registry == ""
	}
}

// parseCursorParam reads the optional cursor query value. A cursor together
// with a non-zero offset is rejected: the two select different pages.
func parseCursorParam(values url.Values, kind string, offset int) (*cursorPayload, error) {
	raw := strings.TrimSpace(values.Get("cursor"))
	if raw == "" {
		return nil, nil
	}
	if offset != 0 {
		return nil, errCursorWithOffset
	}
	payload, err := decodeCursor(raw, kind)
	if err != nil {
		return nil, err
	}
	return &payload, nil
}

func repositoryCursorFrom(payload *cursorPayload) *storage.RepositoryCursor {
	if payload == nil {
		return nil
	}
	return &storage.RepositoryCursor{LastSeenAt: payload.time(), Repository: payload.Repository, Registry: payload.Registry}
}

func scanRunCursorFrom(payload *cursorPayload) *storage.ScanRunCursor {
	if payload == nil {
		return nil
	}
	return &storage.ScanRunCursor{ScannedAt: payload.time(), ID: payload.ID}
}

func findingCursorFrom(payload *cursorPayload) *storage.FindingCursor {
	if payload == nil {
		return nil
	}
	return &storage.FindingCursor{LastSeenAt: payload.time(), ID: payload.ID}
}

// nextRepositoryCursor is the cursor for the page after items, or "" when the
// page was not full, which means the listing is exhausted.
func nextRepositoryCursor(items []storage.RepositorySummary, limit int) string {
	if len(items) < limit || len(items) == 0 {
		return ""
	}
	last := items[len(items)-1]
	return encodeCursor(cursorPayload{Kind: cursorKindRepository, Micros: last.LastSeenAt.UnixMicro(), Repository: last.Repository, Registry: last.Registry})
}

func nextScanRunCursor(items []storage.ScanRunSummary, limit int) string {
	if len(items) < limit || len(items) == 0 {
		return ""
	}
	last := items[len(items)-1]
	return encodeCursor(cursorPayload{Kind: cursorKindScan, Micros: last.ScannedAt.UnixMicro(), ID: last.ID})
}

func nextFindingCursor(items []storage.FindingSummary, limit int) string {
	if len(items) < limit || len(items) == 0 {
		return ""
	}
	last := items[len(items)-1]
	return encodeCursor(cursorPayload{Kind: cursorKindFinding, Micros: last.LastSeenAt.UnixMicro(), ID: last.ID})
}
