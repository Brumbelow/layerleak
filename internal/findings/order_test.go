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
