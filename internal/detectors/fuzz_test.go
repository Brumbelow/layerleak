package detectors

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

// FuzzDetectorSetScan drives the whole default set with arbitrary content,
// path and key (PRD-22). The detector set consumes untrusted image bytes, so
// it must never panic, every reported span must address its value in the
// content, two scans of one input must agree, and the wall time per input
// must stay far below anything catastrophic backtracking or a quadratic
// pass would produce.
func FuzzDetectorSetScan(f *testing.F) {
	for _, document := range loadCorpusDocuments(f) {
		f.Add(document.Content, document.Path, document.Key)
	}
	f.Add(strings.Repeat("sk-", 2000), "/app/.env", "OPENAI_API_KEY")
	f.Add(strings.Repeat("A", 5000)+"."+strings.Repeat("b", 7)+"."+strings.Repeat("c", 40), "", "")
	f.Add(strings.Repeat("12345678:", 500), "", "")
	f.Add(strings.Repeat("https://u:p@", 300)+"host", "", "")
	f.Add("-----BEGIN RSA PRIVATE KEY-----\n"+strings.Repeat("MIIE\n", 400), "/root/.ssh/id_rsa", "")
	f.Add(strings.Repeat("token=\"\" ", 1000), "/app/config.yaml", "")
	f.Add("\uFEFF[prod]\naws_access_key_id = AKIA\n", "/root/.aws/credentials", "")

	set := Default()
	f.Fuzz(func(t *testing.T, content, path, key string) {
		input := ScanInput{Content: content, Path: path, Key: key}

		started := time.Now()
		matches := set.Scan(input)
		elapsed := time.Since(started)

		// 16 MiB/s would be slow for this set; allow generous CI jitter on top.
		budget := 250*time.Millisecond + time.Duration(len(content))*time.Microsecond
		if elapsed > budget {
			t.Fatalf("scan of %d bytes took %v (budget %v)", len(content), elapsed, budget)
		}

		for _, match := range matches {
			if match.Start < 0 || match.End <= match.Start || match.End > len(content) {
				t.Fatalf("invalid span [%d:%d] for %d bytes: %#v", match.Start, match.End, len(content), match)
			}
			if content[match.Start:match.End] != match.Value {
				t.Fatalf("span does not address its value: %#v", match)
			}
			if match.Detector == "" {
				t.Fatalf("match without a detector id: %#v", match)
			}
		}

		if again := set.Scan(input); !reflect.DeepEqual(matches, again) {
			t.Fatalf("scan is not deterministic: %#v vs %#v", matches, again)
		}
	})
}
