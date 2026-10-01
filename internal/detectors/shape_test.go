package detectors

import (
	"math/rand"
	"regexp"
	"strings"
	"testing"
)

// The hand-rolled shape scanners must agree with the regular expressions they
// replace on every input, so both are driven over random concatenations of
// the pieces that make or break a match.
func TestShapeScannersMatchTheirExpressions(t *testing.T) {
	rng := rand.New(rand.NewSource(0x5A5A)) //nolint:gosec // deterministic test data
	alnum := func(length int) string {
		const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		buffer := make([]byte, length)
		for index := range buffer {
			buffer[index] = alphabet[rng.Intn(len(alphabet))]
		}
		return string(buffer)
	}
	digits := func(length int) string {
		buffer := make([]byte, length)
		for index := range buffer {
			buffer[index] = byte('0' + rng.Intn(10))
		}
		return string(buffer)
	}
	separators := []string{" ", "\n", "\"", "=", "_", "-", ".", ":", "", "x", "9"}
	separator := func() string { return separators[rng.Intn(len(separators))] }
	token := func(length int) string {
		const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
		buffer := make([]byte, length)
		for index := range buffer {
			buffer[index] = alphabet[rng.Intn(len(alphabet))]
		}
		return string(buffer)
	}
	// Each piece is a candidate token whose segment lengths straddle the
	// windows of the two shapes (23..28, 6..8, 27..38 and 8..10, 35), glued to
	// its neighbours with separators that do or do not form a word boundary.
	piece := func() string {
		switch rng.Intn(6) {
		case 0:
			return separator() + alnum(21+rng.Intn(10)) + "." + token(4+rng.Intn(7)) + "." + token(25+rng.Intn(16)) + separator()
		case 1:
			return separator() + digits(6+rng.Intn(7)) + ":" + token(33+rng.Intn(5)) + separator()
		case 2:
			return separator() + alnum(1+rng.Intn(30))
		case 3:
			return "." + token(rng.Intn(10))
		case 4:
			return ":" + digits(rng.Intn(12))
		default:
			return separator()
		}
	}

	tests := []struct {
		name       string
		expression *regexp.Regexp
		scan       func(ScanInput) []Match
	}{
		{
			name:       "discord_bot_token",
			expression: regexp.MustCompile(`\b([A-Za-z0-9]{23,28})\.([A-Za-z0-9_-]{6,8})\.([A-Za-z0-9_-]{27,38})`),
			scan: func(input ScanInput) []Match {
				// Compare spans before the validator so the shape itself is tested.
				matches := make([]Match, 0)
				content := input.Content
				position := 0
				for position < len(content) {
					offset := strings.IndexByte(content[position:], '.')
					if offset < 0 {
						break
					}
					dot := position + offset
					start, end, ok := discordBotTokenAt(content, position, dot)
					if !ok {
						position = dot + 1
						continue
					}
					matches = append(matches, Match{Start: start, End: end})
					position = end
				}
				return matches
			},
		},
		{
			name: "telegram_bot_token",
			// The reference consumes the terminator; the scanner reports the token
			// alone, so the comparison trims one byte from a terminated reference.
			expression: regexp.MustCompile(`\b\d{8,10}:[A-Za-z0-9_-]{35}(?:[^A-Za-z0-9_-]|$)`),
			scan: func(input ScanInput) []Match {
				matches := telegramBotTokenDetector{}.Scan(input)
				for index := range matches {
					if matches[index].End < len(input.Content) {
						matches[index].End++
					}
				}
				return matches
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agreements := 0
			for trial := 0; trial < 4000; trial++ {
				var builder strings.Builder
				for count := 2 + rng.Intn(8); count > 0; count-- {
					builder.WriteString(piece())
				}
				content := builder.String()
				want := tt.expression.FindAllStringIndex(content, -1)
				got := tt.scan(ScanInput{Content: content})
				if len(want) != len(got) {
					t.Fatalf("%q: scanner found %d spans, expression %d: %v vs %v", content, len(got), len(want), got, want)
				}
				for index := range want {
					if got[index].Start != want[index][0] || got[index].End != want[index][1] {
						t.Fatalf("%q: span %d = [%d:%d], expression [%d:%d]", content, index, got[index].Start, got[index].End, want[index][0], want[index][1])
					}
				}
				if len(want) > 0 {
					agreements++
				}
			}
			if agreements < 100 {
				t.Fatalf("only %d trials produced a match; the generator is not exercising the shape", agreements)
			}
		})
	}
}

func TestCredentialedURLDetectorMatchesUppercaseSchemeFromLoweredContent(t *testing.T) {
	detector := newCredentialedURLDetector("basic_auth_url", basicAuthURLSchemes, urlHostClass)
	content := `x = "HTTPS://Deploy:Sup3rS3cretPwXyz@Registry.Internal/v2"`
	matches := detector.Scan(ScanInput{Content: content})
	if len(matches) != 1 || matches[0].Value != "HTTPS://Deploy:Sup3rS3cretPwXyz@Registry.Internal" {
		t.Fatalf("matches = %#v", matches)
	}
	if content[matches[0].Start:matches[0].End] != matches[0].Value {
		t.Fatal("span does not cover the value in the original content")
	}
}

func TestCredentialedURLDetectorDoesNotDoubleReportNestedSchemes(t *testing.T) {
	detector := newCredentialedURLDetector("connection_url_credentials", connectionURLSchemes, urlHostListClass)
	for _, content := range []string{
		"sftp://deploy:Sup3rS3cretPwXyz@files.internal/",
		"mongodb+srv://app:Sup3rS3cretPwXyz@cluster.mongodb.net/db",
		"rediss://default:Sup3rS3cretPwXyz@cache.internal:6380",
	} {
		matches := detector.Scan(ScanInput{Content: content})
		if len(matches) != 1 {
			t.Fatalf("%q: matches = %#v", content, matches)
		}
	}
}
