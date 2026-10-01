package storage

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/findings"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
)

func TestSanitizeScanRecordReplacesControlCharacters(t *testing.T) {
	original := ScanRecord{
		Registry:     "docker.io",
		Repository:   "library/app",
		Mode:         "reference",
		Status:       ScanRunStatusCompleted,
		ErrorMessage: "scan\x00failed",
		ResultJSON:   json.RawMessage(`{"findings":[{"key":"config.env.A\u0000B","context_snippet":"x\u0001y","n":1.50}],"na\u0000me":"v","ok":"<kept>"}`),
		ScannedAt:    time.Date(2026, time.September, 30, 12, 0, 0, 0, time.UTC),
		Tags: []TagRecord{{
			Name:           "lat\x00est",
			ManifestDigest: "sha256:bbb",
			Platform:       manifest.Platform{OS: "linux\x00", Architecture: "amd64"},
			Status:         "failed",
			Error:          "manifest\x00unreadable",
		}},
		Targets: []TargetRecord{{
			Reference: "docker.io/library/app:latest",
			Tags:      []string{"lat\x00est"},
			Error:     "boom\x1f",
			Manifests: []ManifestRecord{{Digest: "sha256:bbb", Status: "failed", Error: "layer\x00broken", Platform: manifest.Platform{Variant: "v\x008"}}},
		}},
		DetailedFindings: []findings.DetailedFinding{{
			Finding: findings.Finding{
				DetectorName:   "github_token",
				SourceType:     findings.SourceTypeEnv,
				ManifestDigest: "sha256:bbb",
				Platform:       manifest.Platform{OS: "linux"},
				FilePath:       "a\x01b",
				Key:            "config.env.A\x00B",
				RedactedValue:  "ab\x00**cd",
				Fingerprint:    "fingerprint-one",
				ContextSnippet: "A\x00B=[REDACTED]\ttab kept\nnewline kept",
			},
			Value:          "raw\x00value",
			RawSnippet:     "raw\x00snippet",
			SourceLocation: "env:config.env.A\x00B",
		}},
	}
	snapshot := original.DetailedFindings[0]

	got, err := sanitizeScanRecord(original)
	if err != nil {
		t.Fatalf("sanitizeScanRecord() error = %v", err)
	}

	if got.ErrorMessage != "scan�failed" {
		t.Errorf("ErrorMessage = %q", got.ErrorMessage)
	}
	tag := got.Tags[0]
	if tag.Name != "lat�est" || tag.Error != "manifest�unreadable" || tag.Platform.OS != "linux�" {
		t.Errorf("Tags[0] = %+v", tag)
	}
	target := got.Targets[0]
	if target.Tags[0] != "lat�est" || target.Error != "boom�" {
		t.Errorf("Targets[0] = %+v", target)
	}
	if target.Manifests[0].Error != "layer�broken" || target.Manifests[0].Platform.Variant != "v�8" {
		t.Errorf("Targets[0].Manifests[0] = %+v", target.Manifests[0])
	}
	finding := got.DetailedFindings[0]
	want := map[string][2]string{
		"FilePath":       {finding.FilePath, "a�b"},
		"Key":            {finding.Key, "config.env.A�B"},
		"RedactedValue":  {finding.RedactedValue, "ab�**cd"},
		"ContextSnippet": {finding.ContextSnippet, "A�B=[REDACTED]\ttab kept\nnewline kept"},
		"Value":          {finding.Value, "raw�value"},
		"RawSnippet":     {finding.RawSnippet, "raw�snippet"},
		"SourceLocation": {finding.SourceLocation, "env:config.env.A�B"},
		"Fingerprint":    {finding.Fingerprint, "fingerprint-one"},
	}
	for name, pair := range want {
		if pair[0] != pair[1] {
			t.Errorf("DetailedFindings[0].%s = %q, want %q", name, pair[0], pair[1])
		}
	}

	var decoded struct {
		Findings []map[string]any `json:"findings"`
		Name     string           `json:"na�me"`
		OK       string           `json:"ok"`
	}
	if err := json.Unmarshal(got.ResultJSON, &decoded); err != nil {
		t.Fatalf("ResultJSON is not valid JSON: %v (%s)", err, got.ResultJSON)
	}
	if len(decoded.Findings) != 1 || decoded.Findings[0]["key"] != "config.env.A�B" || decoded.Findings[0]["context_snippet"] != "x�y" {
		t.Errorf("ResultJSON findings = %+v", decoded.Findings)
	}
	if decoded.Name != "v" || decoded.OK != "<kept>" {
		t.Errorf("ResultJSON keys/values = %+v", decoded)
	}
	if !bytes.Contains(got.ResultJSON, []byte(`1.50`)) {
		t.Errorf("ResultJSON numbers were rewritten: %s", got.ResultJSON)
	}
	if bytes.Contains(got.ResultJSON, []byte(`\u0000`)) || bytes.Contains(got.ResultJSON, []byte(`\u0001`)) {
		t.Errorf("ResultJSON still carries control escapes: %s", got.ResultJSON)
	}

	if original.DetailedFindings[0] != snapshot {
		t.Error("sanitizeScanRecord mutated the caller's findings slice")
	}
	if original.Tags[0].Name != "lat\x00est" || original.Targets[0].Tags[0] != "lat\x00est" {
		t.Error("sanitizeScanRecord mutated the caller's tag slices")
	}
}

func TestSanitizeResultJSONLeavesCleanDocumentsUntouched(t *testing.T) {
	body := json.RawMessage(`{"requested_reference":"library/app:latest","findings":[{"key":"TOKEN","note":"a<b>&c"}],"count":1.50,"tab":"a\tb"}`)

	got, err := sanitizeResultJSON(body)
	if err != nil {
		t.Fatalf("sanitizeResultJSON() error = %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("sanitizeResultJSON() rewrote a clean document:\n got %s\nwant %s", got, body)
	}
	if &got[0] != &body[0] {
		t.Fatal("sanitizeResultJSON() copied a clean document instead of returning it")
	}
}

func TestSanitizeResultJSONRejectsMalformedInput(t *testing.T) {
	if _, err := sanitizeResultJSON(json.RawMessage(`{"key":"\u0000"`)); err == nil {
		t.Fatal("sanitizeResultJSON() error = nil for malformed JSON")
	}
}
