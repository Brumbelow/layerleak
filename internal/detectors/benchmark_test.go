package detectors

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// corpusDocument is the shape of one fixture under internal/scanner/testdata/corpus.
type corpusDocument struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Key     string `json:"key"`
	Content string `json:"content"`
	// ContentBase64 mirrors the scanner corpus loader: fixtures whose literal
	// shape would trip secret scanners are stored base64-encoded.
	ContentBase64 string `json:"content_base64,omitempty"`
}

func loadCorpusDocuments(tb testing.TB) []corpusDocument {
	tb.Helper()
	root := filepath.Join("..", "scanner", "testdata", "corpus")
	paths, err := filepath.Glob(filepath.Join(root, "*", "*.json"))
	if err != nil {
		tb.Fatalf("Glob(%q) error = %v", root, err)
	}
	if len(paths) == 0 {
		tb.Fatalf("no corpus fixtures under %q", root)
	}
	sort.Strings(paths)
	documents := make([]corpusDocument, 0, len(paths))
	for _, path := range paths {
		body, err := os.ReadFile(path)
		if err != nil {
			tb.Fatalf("ReadFile(%q) error = %v", path, err)
		}
		var document corpusDocument
		if err := json.Unmarshal(body, &document); err != nil {
			tb.Fatalf("Unmarshal(%q) error = %v", path, err)
		}
		if document.ContentBase64 != "" {
			decoded, err := base64.StdEncoding.DecodeString(document.ContentBase64)
			if err != nil {
				tb.Fatalf("%s: content_base64 is not valid base64: %v", path, err)
			}
			document.Content = string(decoded)
			document.ContentBase64 = ""
		}
		documents = append(documents, document)
	}
	return documents
}

// secretFreeText builds a deterministic, realistic-looking document of about
// the requested size: prose, log lines, JSON, YAML, shell and URLs with no
// credential in it. Throughput on secret-free text is what dominates a scan
// of a real image.
func secretFreeText(size int) string {
	rng := newTestRand(0xBE11C4)
	words := strings.Fields("the quick brown fox jumps over the lazy dog while reading configuration " +
		"files from the container image and writing structured logs to stdout for the collector " +
		"service to forward downstream with retries backoff timeouts and metrics attached")
	var builder strings.Builder
	builder.Grow(size + 256)
	line := 0
	for builder.Len() < size {
		switch line % 7 {
		case 0:
			for index := 0; index < 12; index++ {
				builder.WriteString(words[rng.Intn(len(words))])
				builder.WriteByte(' ')
			}
		case 1:
			builder.WriteString("2026-09-30T12:34:56Z INFO request completed method=GET path=/api/v1/items/")
			builder.WriteString(strings.Repeat("0", 3))
			builder.WriteString(" status=200 duration_ms=12")
		case 2:
			builder.WriteString(`{"level":"info","msg":"cache warmed","entries":4096,"region":"eu-west-1","host":"app-7f3c2a.internal"}`)
		case 3:
			builder.WriteString("  - name: ")
			builder.WriteString(words[rng.Intn(len(words))])
			builder.WriteString("\n    image: registry.internal/platform/service:1.")
			builder.WriteString(strings.Repeat("2", 2))
		case 4:
			builder.WriteString("RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*")
		case 5:
			builder.WriteString("See https://docs.example.internal/guides/")
			builder.WriteString(words[rng.Intn(len(words))])
			builder.WriteString(" for the full reference.")
		case 6:
			builder.WriteString("Package: lib")
			builder.WriteString(words[rng.Intn(len(words))])
			builder.WriteString("-dev\nVersion: 2.")
			builder.WriteString(strings.Repeat("4", 1))
			builder.WriteString(".1-3ubuntu2\nDescription: development files")
		}
		builder.WriteByte('\n')
		line++
	}
	return builder.String()
}

// BenchmarkDefaultSetScanCorpus scans one document made of every corpus
// fixture embedded in about a mebibyte of secret-free text, which keeps the
// detector mix realistic (every rule in the corpus fires at least once) while
// measuring throughput in bytes per second.
func BenchmarkDefaultSetScanCorpus(b *testing.B) {
	documents := loadCorpusDocuments(b)
	filler := secretFreeText(1 << 20)
	var builder strings.Builder
	chunk := len(filler) / (len(documents) + 1)
	for index, document := range documents {
		builder.WriteString(filler[index*chunk : (index+1)*chunk])
		builder.WriteString(document.Content)
		builder.WriteByte('\n')
	}
	content := builder.String()
	set := Default()
	input := ScanInput{Path: "/app/mixed.txt", Content: content}

	b.SetBytes(int64(len(content)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if matches := set.Scan(input); len(matches) == 0 {
			b.Fatal("expected matches over the corpus document")
		}
	}
}

// BenchmarkDefaultSetScanSecretFreeText measures the common case: a file that
// contains no credential at all.
func BenchmarkDefaultSetScanSecretFreeText(b *testing.B) {
	content := secretFreeText(1 << 20)
	set := Default()
	input := ScanInput{Path: "/usr/share/doc/app/README", Content: content}

	b.SetBytes(int64(len(content)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if matches := set.Scan(input); len(matches) != 0 {
			b.Fatalf("unexpected matches in secret-free text: %#v", matches)
		}
	}
}

// BenchmarkDefaultSetScanCorpusFixtures scans every corpus fixture on its own,
// the way metadata values and small files reach the detector set.
func BenchmarkDefaultSetScanCorpusFixtures(b *testing.B) {
	documents := loadCorpusDocuments(b)
	set := Default()
	total := 0
	inputs := make([]ScanInput, 0, len(documents))
	for _, document := range documents {
		inputs = append(inputs, ScanInput{Path: document.Path, Key: document.Key, Content: document.Content})
		total += len(document.Content)
	}

	b.SetBytes(int64(total))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		for _, input := range inputs {
			set.Scan(input)
		}
	}
}
