package cli

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// TestBaselineFromSourceErrorTexts pins the exact error for each rejected
// source shape, so an operator sees which schema version was found.
func TestBaselineFromSourceErrorTexts(t *testing.T) {
	tests := map[string]string{
		`{"result_schema_version": 1}`: "unsupported result_schema_version 1 (this build reads version 2)",
		`{"findings": []}`:             "unsupported result_schema_version 0 (this build reads version 2)",
		`{"record_schema_version": 3, "result": {"result_schema_version": 2}}`: "unsupported record_schema_version 3 (this build reads version 2)",
		`{"record_schema_version": 2}`:                                         "unsupported record_schema_version 2 (this build reads version 2)",
		`{"record_schema_version": 2, "result": {"result_schema_version": 7}}`: "unsupported result_schema_version 7 (this build reads version 2)",
	}
	for body, want := range tests {
		_, err := baselineFromSource(strings.NewReader(body), "r")
		if err == nil || err.Error() != want {
			t.Errorf("baselineFromSource(%s) error = %v, want %q", body, err, want)
		}
	}
	_, err := baselineFromSource(strings.NewReader("findings"), "r")
	var syntax *json.SyntaxError
	if err == nil || !strings.HasPrefix(err.Error(), "not a JSON result: ") || !errors.As(err, &syntax) {
		t.Errorf("baselineFromSource(not json) error = %v, want a wrapped *json.SyntaxError", err)
	}
	_, err = baselineFromSource(failingReader{}, "r")
	if err == nil || err.Error() != "read: "+errFailingReader.Error() || !errors.Is(err, errFailingReader) {
		t.Errorf("baselineFromSource(failing reader) error = %v", err)
	}
}

// TestBaselineFromSourceEntryFiltering pins which findings become entries:
// actionable or unset dispositions with a well-formed fingerprint and
// detector, normalised, de-duplicated per detector and fingerprint, sorted by
// fingerprint then detector. A source with none yields an empty, non-nil list.
func TestBaselineFromSourceEntryFiltering(t *testing.T) {
	body := `{"result_schema_version": 2, "findings": [
  {"detector_name": " github_token ", "fingerprint": " ` + strings.ToUpper(testFingerprintB) + ` "},
  {"detector_name": "aws_access_key_id", "disposition": "baselined", "fingerprint": "` + testFingerprintA + `"},
  {"detector_name": "aws_access_key_id", "disposition": "example", "fingerprint": "` + testFingerprintA + `"},
  {"detector_name": "Bad Detector", "disposition": "actionable", "fingerprint": "` + testFingerprintA + `"},
  {"detector_name": "slack_token", "disposition": "actionable", "fingerprint": "abc"},
  {"detector_name": "aws_access_key_id", "disposition": "actionable", "fingerprint": "` + testFingerprintB + `"},
  {"detector_name": "github_token", "disposition": "actionable", "fingerprint": "` + testFingerprintB + `"}
 ]}`
	document, err := baselineFromSource(strings.NewReader(body), "why")
	if err != nil {
		t.Fatal(err)
	}
	want := []baselineEntry{
		{Fingerprint: testFingerprintB, Detector: "aws_access_key_id", Reason: "why"},
		{Fingerprint: testFingerprintB, Detector: "github_token", Reason: "why"},
	}
	if len(document.Entries) != len(want) {
		t.Fatalf("entries = %+v, want %+v", document.Entries, want)
	}
	for index := range want {
		if document.Entries[index] != want[index] {
			t.Fatalf("entries[%d] = %+v, want %+v", index, document.Entries[index], want[index])
		}
	}

	empty, err := baselineFromSource(strings.NewReader(`{"result_schema_version": 2}`), "r")
	if err != nil || empty.Entries == nil || len(empty.Entries) != 0 {
		t.Fatalf("empty source = %+v, %v; want a non-nil empty entry list", empty, err)
	}
}

var errFailingReader = errors.New("boom")

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errFailingReader
}
