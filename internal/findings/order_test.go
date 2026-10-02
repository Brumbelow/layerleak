package findings

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/brumbelow/layerleak/v3/internal/detectors"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
)

// DET-23: Deduplicate must order public findings totally, so two findings
// that differ only in their match offsets come out in the same order whatever
// the input order.
func TestDeduplicateOrderIsIndependentOfInputOrder(t *testing.T) {
	base := Finding{
		DetectorName:   "keyword_entropy",
		Confidence:     "low",
		Disposition:    DispositionActionable,
		SourceType:     SourceTypeFileFinal,
		ManifestDigest: "sha256:a",
		FilePath:       "app/.env",
		LineNumber:     1,
		Fingerprint:    "same",
		ContextSnippet: "token=[REDACTED] token=[REDACTED]",
	}
	first := base
	first.MatchStart, first.MatchEnd = 10, 30
	second := base
	second.MatchStart, second.MatchEnd = 30, 50

	forward := Deduplicate([]Finding{first, second})
	backward := Deduplicate([]Finding{second, first})
	if len(forward) != 2 || len(backward) != 2 {
		t.Fatalf("len = %d, %d", len(forward), len(backward))
	}
	if forward[0].MatchStart != 10 || backward[0].MatchStart != 10 {
		t.Fatalf("order depends on input: forward %d, backward %d", forward[0].MatchStart, backward[0].MatchStart)
	}
	if compareFindings(first, second) == 0 {
		t.Fatal("compareFindings treats findings with different offsets as equal")
	}
}

// DET-25: no public field of a finding may carry the raw value. Every corpus
// fixture is scanned with the default set and every match normalised; the
// public JSON must not contain any matched value.
func TestPublicFindingsNeverCarryTheRawValue(t *testing.T) {
	root := filepath.Join("..", "scanner", "testdata", "corpus")
	paths, err := filepath.Glob(filepath.Join(root, "*", "*.json"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("corpus fixtures: %v (%d)", err, len(paths))
	}
	sort.Strings(paths)
	set := detectors.Default()
	checked := 0
	for _, path := range paths {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var fixture struct {
			SourceType SourceType `json:"source_type"`
			Path       string     `json:"path"`
			Key        string     `json:"key"`
			Content    string     `json:"content"`
		}
		if err := json.Unmarshal(body, &fixture); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		matches := set.Scan(detectors.ScanInput{Content: fixture.Content, Path: fixture.Path, Key: fixture.Key})
		if len(matches) == 0 {
			continue
		}
		input := Input{
			ManifestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Platform:       manifest.Platform{OS: "linux", Architecture: "amd64"},
			SourceType:     fixture.SourceType,
			FilePath:       fixture.Path,
			Key:            fixture.Key,
			Content:        fixture.Content,
		}
		normalizer, err := NewDetailedNormalizer(input, matches)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		for _, match := range matches {
			finding, err := normalizer.Normalize(match)
			if err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			public, err := json.Marshal(finding.PublicFinding())
			if err != nil {
				t.Fatal(err)
			}
			for _, other := range matches {
				if len(other.Value) >= 8 && strings.Contains(string(public), other.Value) {
					t.Fatalf("%s: public finding carries a raw value: %s", path, public)
				}
			}
			checked++
		}
	}
	if checked < 20 {
		t.Fatalf("only %d findings checked", checked)
	}
}

// compareFindings orders by a fixed key sequence. For each key, two findings
// that tie on every earlier key and differ on it must follow that key alone,
// even when every later key points the other way.
func TestCompareFindingsKeyPrecedence(t *testing.T) {
	keys := []struct {
		name string
		set  func(item *Finding, high bool)
	}{
		{"manifest_digest", func(item *Finding, high bool) { item.ManifestDigest = pickOrder(high, "sha256:a", "sha256:b") }},
		{"platform", func(item *Finding, high bool) {
			item.Platform = manifest.Platform{OS: "linux", Architecture: pickOrder(high, "amd64", "arm64")}
		}},
		{"source_type", func(item *Finding, high bool) { item.SourceType = SourceType(pickOrder(high, "a", "b")) }},
		{"disposition", func(item *Finding, high bool) { item.Disposition = Disposition(pickOrder(high, "a", "b")) }},
		{"file_path", func(item *Finding, high bool) { item.FilePath = pickOrder(high, "a", "b") }},
		{"layer_digest", func(item *Finding, high bool) { item.LayerDigest = pickOrder(high, "a", "b") }},
		{"detector_name", func(item *Finding, high bool) { item.DetectorName = pickOrder(high, "a", "b") }},
		{"line_number", func(item *Finding, high bool) { item.LineNumber = pickOrder(high, 1, 2) }},
		{"fingerprint", func(item *Finding, high bool) { item.Fingerprint = pickOrder(high, "a", "b") }},
		{"match_start", func(item *Finding, high bool) { item.MatchStart = pickOrder(high, 1, 2) }},
		{"match_end", func(item *Finding, high bool) { item.MatchEnd = pickOrder(high, 1, 2) }},
		{"key", func(item *Finding, high bool) { item.Key = pickOrder(high, "a", "b") }},
		{"confidence", func(item *Finding, high bool) { item.Confidence = pickOrder(high, "a", "b") }},
		{"disposition_reason", func(item *Finding, high bool) {
			item.DispositionReason = DispositionReason(pickOrder(high, "a", "b"))
		}},
		{"redacted_value", func(item *Finding, high bool) { item.RedactedValue = pickOrder(high, "a", "b") }},
		{"context_snippet", func(item *Finding, high bool) { item.ContextSnippet = pickOrder(high, "a", "b") }},
		{"present_in_final_image", func(item *Finding, high bool) { item.PresentInFinalImage = high }},
	}
	for index, key := range keys {
		var low, high Finding
		for _, earlier := range keys[:index] {
			earlier.set(&low, false)
			earlier.set(&high, false)
		}
		key.set(&low, false)
		key.set(&high, true)
		for _, later := range keys[index+1:] {
			later.set(&low, true)
			later.set(&high, false)
		}
		if got := compareFindings(low, high); got >= 0 {
			t.Errorf("%s: compareFindings(low, high) = %d, want < 0", key.name, got)
		}
		if got := compareFindings(high, low); got <= 0 {
			t.Errorf("%s: compareFindings(high, low) = %d, want > 0", key.name, got)
		}
		if got := compareFindings(low, low); got != 0 {
			t.Errorf("%s: compareFindings(low, low) = %d, want 0", key.name, got)
		}
	}
}

func pickOrder[T any](high bool, low, highValue T) T {
	if high {
		return highValue
	}
	return low
}
