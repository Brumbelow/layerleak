package detectors

import (
	"fmt"
	"strings"
	"testing"
)

const hexDigits = "0123456789abcdef"

func newSeededRand(seed int64) *testRand {
	return newTestRand(uint64(seed)) //nolint:gosec // seeds are small positive literals
}

func randomHex(rng *testRand, length int) string {
	buffer := make([]byte, length)
	for index := range buffer {
		buffer[index] = hexDigits[rng.Intn(len(hexDigits))]
	}
	return string(buffer)
}

func randomUUID(rng *testRand) string {
	hex := randomHex(rng, 32)
	return hex[:8] + "-" + hex[8:12] + "-" + hex[12:16] + "-" + hex[16:20] + "-" + hex[20:]
}

func detectionRate(t *testing.T, trials int, build func(rng *testRand) (ScanInput, string)) float64 {
	t.Helper()
	set := Default()
	rng := newSeededRand(0x0DE7EC7)
	found := 0
	for trial := 0; trial < trials; trial++ {
		input, want := build(rng)
		for _, match := range set.Scan(input) {
			if match.Value == want {
				found++
				break
			}
		}
	}
	return float64(found) / float64(trials)
}

// DET-05: a fixed 3.75-bit threshold rejected most hex secrets because a hex
// string cannot exceed 4 bits and its plug-in entropy sits well below that
// at 32-40 characters.
func TestPassesEntropyAcceptsRandomHexSecrets(t *testing.T) {
	rng := newSeededRand(42)
	tests := []struct {
		name  string
		build func() string
		want  float64
	}{
		{name: "hex32", build: func() string { return randomHex(rng, 32) }, want: 0.97},
		{name: "hex40", build: func() string { return randomHex(rng, 40) }, want: 0.97},
		{name: "hex64", build: func() string { return randomHex(rng, 64) }, want: 0.97},
		{name: "uppercase hex32", build: func() string { return strings.ToUpper(randomHex(rng, 32)) }, want: 0.97},
		{name: "uuid", build: func() string { return randomUUID(rng) }, want: 0.97},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			passed := 0
			const trials = 2000
			for trial := 0; trial < trials; trial++ {
				if passesEntropy(tt.build()) {
					passed++
				}
			}
			if rate := float64(passed) / trials; rate < tt.want {
				t.Fatalf("pass rate = %.3f, want at least %.2f", rate, tt.want)
			}
		})
	}
}

func TestPassesEntropyStillRejectsLowEntropyAndDigitOnlyValues(t *testing.T) {
	rng := newSeededRand(7)
	for _, value := range []string{
		strings.Repeat("0", 32),
		"deadbeefdeadbeefdeadbeefdeadbeef",
		"0123456789012345678901234567890123456789",
		"aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb",
		"abababababababababababababababab",
	} {
		if passesEntropy(value) {
			t.Fatalf("passesEntropy(%q) = true", value)
		}
	}
	digits := make([]byte, 40)
	for trial := 0; trial < 500; trial++ {
		for index := range digits {
			digits[index] = byte('0' + rng.Intn(10))
		}
		if passesEntropy(string(digits)) {
			t.Fatalf("random digit string %q passed entropy", digits)
		}
	}
}

func TestKeywordEntropyFindsHexSecretsEndToEnd(t *testing.T) {
	tests := []struct {
		name  string
		build func(rng *testRand) (ScanInput, string)
	}{
		{name: "quoted hex32 client secret in .env", build: func(rng *testRand) (ScanInput, string) {
			secret := randomHex(rng, 32)
			return ScanInput{Path: "/app/.env", Content: "CLIENT_SECRET=\"" + secret + "\"\n"}, secret
		}},
		{name: "unquoted hex32 datadog key in .env", build: func(rng *testRand) (ScanInput, string) {
			secret := randomHex(rng, 32)
			return ScanInput{Path: "/app/.env", Content: "DD_API_KEY=" + secret + "\n"}, secret
		}},
		{name: "hex40 in yaml", build: func(rng *testRand) (ScanInput, string) {
			secret := randomHex(rng, 40)
			return ScanInput{Path: "/app/config.yaml", Content: "api_key: " + secret + "\n"}, secret
		}},
		{name: "uuid token", build: func(rng *testRand) (ScanInput, string) {
			secret := randomUUID(rng)
			return ScanInput{Path: "/app/config.yaml", Content: "postmark_token: " + secret + "\n"}, secret
		}},
		{name: "hex32 env source", build: func(rng *testRand) (ScanInput, string) {
			secret := randomHex(rng, 32)
			return ScanInput{Key: "MAILGUN_API_KEY", Content: "MAILGUN_API_KEY=" + secret}, secret
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if rate := detectionRate(t, 300, tt.build); rate < 0.97 {
				t.Fatalf("detection rate = %.3f, want at least 0.97", rate)
			}
		})
	}
}

// DET-05 guard: hex that is a content digest must not become a finding once
// the hex threshold admits it.
func TestKeywordEntropySkipsContentDigests(t *testing.T) {
	rng := newSeededRand(99)
	sha256Hex := randomHex(rng, 64)
	sha1Hex := randomHex(rng, 40)
	md5Hex := randomHex(rng, 32)
	set := Default()
	tests := []ScanInput{
		{Path: "/app/requirements.txt", Content: "oauthlib==3.2.2 --hash=sha256:" + sha256Hex + "\n"},
		{Path: "/app/poetry.lock", Content: "[[package]]\nname = \"oauthlib\"\nfiles = [{file = \"oauthlib.tar.gz\", hash = \"sha256:" + sha256Hex + "\"}]\n"},
		{Path: "/app/Cargo.lock", Content: "[[package]]\nname = \"oauth2\"\nchecksum = \"" + sha256Hex + "\"\n"},
		{Path: "/app/yarn.lock", Content: "passport-token@1.0.0:\n  resolved \"https://registry.yarnpkg.com/passport-token/-/passport-token-1.0.0.tgz#" + sha1Hex + "\"\n"},
		{Path: "/app/composer.lock", Content: "\"name\": \"league/oauth2-client\",\n\"reference\": \"" + sha1Hex + "\",\n"},
		{Path: "/app/go.sum", Content: "golang.org/x/oauth2 v0.1.0 h1:QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg=\n"},
		{Key: "config.labels.auth.image.digest", Content: "auth.image.digest=sha256:" + sha256Hex},
		{Path: "/app/manifest.txt", Content: "token-service.tar md5=" + md5Hex + "\n"},
		{Path: "/app/build.env", Content: "AUTH_SERVICE_COMMIT_SHA=" + sha1Hex + "\n"},
		{Path: "/app/build.env", Content: "AUTH_SERVICE_IMAGE_DIGEST=" + sha256Hex + "\n"},
		{Path: "/app/.env", Content: "TOKEN_SERVICE_ETAG=\"" + md5Hex + "\"\n"},
	}
	for _, input := range tests {
		t.Run(strings.TrimSpace(input.Path+" "+input.Key), func(t *testing.T) {
			for _, match := range set.Scan(input) {
				if match.Detector == "keyword_entropy" {
					t.Fatalf("unexpected keyword_entropy match on a digest: %#v", match)
				}
			}
		})
	}

	// Control: the same hex under a plain secret key is a finding.
	matches := set.Scan(ScanInput{Path: "/app/.env", Content: "API_TOKEN=" + sha256Hex + "\n"})
	if _, ok := findDetectorMatch(matches, "keyword_entropy"); !ok {
		t.Fatalf("expected keyword_entropy for a hex token in %#v", matches)
	}
}

// DET-37: lowercase values with separators are what UUIDs, Mailgun keys and
// base64url tokens look like; the blanket suppression must only catch
// word-like slugs.
func TestKeywordEntropyFindsLowercaseSeparatedSecrets(t *testing.T) {
	set := Default()
	tests := []struct {
		name  string
		input ScanInput
		want  string
	}{
		{name: "mailgun key", input: ScanInput{Path: "/app/.env", Content: "MAILGUN_API_KEY=\"key-3ax6xnjp29jd6fds4gc373sgvjxteol0\"\n"}, want: "key-3ax6xnjp29jd6fds4gc373sgvjxteol0"},
		{name: "uuid token", input: ScanInput{Path: "/app/config.yaml", Content: "postmark_token: 7f3c2a1e-9b8d-4c6f-a5e2-1d0b9c8a7f6e\n"}, want: "7f3c2a1e-9b8d-4c6f-a5e2-1d0b9c8a7f6e"},
		{name: "lowercase base64url token", input: ScanInput{Path: "/app/.env", Content: "API_TOKEN=\"a9f3k2m8x1q7z4w6v0b5n3c8j2h6g4d1s7_t9\"\n"}, want: "a9f3k2m8x1q7z4w6v0b5n3c8j2h6g4d1s7_t9"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireSingleValueMatch(t, set.Scan(tt.input), "keyword_entropy", tt.want)
		})
	}
}

func TestKeywordEntropyStillSuppressesSlugsAndPackageNames(t *testing.T) {
	set := Default()
	for _, content := range []string{
		"PASSWORD=base-passwd/user-change-gecos",
		"password=usr/share/doc/base-passwd/README",
		"token=linux-headers-5-15-0-generic",
		"secret=python3-oauthlib-3-2-2-amd64",
		"auth_backend=my-company-auth-service-v2",
		"token=user-change-gecos-helper_1",
	} {
		for _, match := range set.Scan(ScanInput{Content: content}) {
			if match.Detector == "keyword_entropy" {
				t.Fatalf("unexpected keyword_entropy match for %q: %#v", content, match)
			}
		}
	}
}

func TestIsLowercaseSeparatorCandidate(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{value: "base-passwd/user-change-gecos", want: true},
		{value: "linux-headers-5-15-0-generic", want: true},
		{value: "my-company-auth-service-v2", want: true},
		{value: "7f3c2a1e-9b8d-4c6f-a5e2-1d0b9c8a7f6e", want: false},
		{value: "key-3ax6xnjp29jd6fds4gc373sgvjxteol0", want: false},
		{value: "a9f3k2m8x1q7z4w6v0b5n3c8j2h6g4d1s7_t9", want: false},
		{value: "Mixed-Case-value-1", want: false},
		{value: "nosegments", want: false},
	}
	for _, tt := range tests {
		if got := isLowercaseSeparatorCandidate(tt.value); got != tt.want {
			t.Fatalf("isLowercaseSeparatorCandidate(%q) = %t, want %t", tt.value, got, tt.want)
		}
	}
}

// TestIsLowercaseSeparatorCandidateEdges covers the alphabet, letter, digit
// count and word-segment boundaries of the slug suppression.
func TestIsLowercaseSeparatorCandidateEdges(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{value: "", want: false},
		{value: "123-456", want: false},
		{value: "-_/", want: false},
		{value: "a-1", want: true},
		{value: "x9/y8", want: true},
		{value: "café-crème", want: true},
		{value: "abc def-x", want: false},
		{value: "abc.def-x", want: false},
		{value: "abc-d١٢٣", want: false},
		{value: "abc-def-12-34", want: true},
		{value: "abc-def-12-34-56", want: false},
		{value: "abc-def-ghi-12-34-56", want: true},
		{value: "abc-12-34-56", want: false},
		{value: "abc12-def34-5", want: true},
		{value: "abc123-def-1", want: false},
		{value: "--abc//def__12-3", want: true},
	}
	for _, tt := range tests {
		if got := isLowercaseSeparatorCandidate(tt.value); got != tt.want {
			t.Errorf("isLowercaseSeparatorCandidate(%q) = %t, want %t", tt.value, got, tt.want)
		}
	}
}

func TestEntropyThresholdIsAlphabetAware(t *testing.T) {
	for _, tt := range []struct {
		value string
		want  float64
	}{
		{value: "abcdefghijklmnopqrstuvwxyzabcdef", want: 3.75},
		{value: randomHex(newSeededRand(1), 32), want: 4 - 24.0/32},
		{value: strings.ToUpper(randomHex(newSeededRand(1), 40)), want: 4 - 24.0/40},
		{value: randomUUID(newSeededRand(1)), want: 4 - 24.0/36},
		{value: "q7Y8zX6wV4uT2sR0pN9mL7kJ5hG3fD1cB5", want: 3.75},
		{value: strings.Repeat("1234567890", 4), want: 3.75},
	} {
		if got := entropyThreshold(tt.value); fmt.Sprintf("%.4f", got) != fmt.Sprintf("%.4f", tt.want) {
			t.Fatalf("entropyThreshold(%q) = %.4f, want %.4f", tt.value, got, tt.want)
		}
	}
}
