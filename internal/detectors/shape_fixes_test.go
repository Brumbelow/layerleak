package detectors

import (
	"strings"
	"testing"
)

// DET-10: a closing quote between the key and the separator ("key": "value")
// is the normal JSON shape and must be accepted by every key-context rule.
func TestKeyContextRulesAcceptQuotedKeys(t *testing.T) {
	set := Default()
	awsSecret := testAWSSecret
	uuid := "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	hex32 := "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
	tests := []struct {
		name     string
		content  string
		detector string
		value    string
	}{
		{name: "aws secret json", content: `{"aws_secret_access_key": "` + awsSecret + `"}`, detector: "aws_secret_access_key", value: awsSecret},
		{name: "aws secret yaml quoted key", content: `"aws_secret_access_key": ` + awsSecret, detector: "aws_secret_access_key", value: awsSecret},
		{name: "aws secret uppercase key", content: `AWS_SECRET_ACCESS_KEY = "` + awsSecret + `"`, detector: "aws_secret_access_key", value: awsSecret},
		{name: "twilio json", content: `{"twilio_auth_token": "` + hex32 + `"}`, detector: "twilio_auth_token", value: hex32},
		{name: "snyk json", content: `{"snyk_token": "` + uuid + `"}`, detector: "snyk_api_token", value: uuid},
		{name: "heroku json", content: `{"heroku_api_key": "` + uuid + `"}`, detector: "heroku_api_key", value: uuid},
		{name: "heroku single quoted key", content: `'HEROKU_API_KEY' => '` + uuid + `'`, detector: "heroku_api_key", value: uuid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, ok := findDetectorMatch(set.Scan(ScanInput{Content: tt.content}), tt.detector)
			if !ok {
				t.Fatalf("expected %s in %#v", tt.detector, set.Scan(ScanInput{Content: tt.content}))
			}
			if match.Value != tt.value {
				t.Fatalf("match.Value = %q, want %q", match.Value, tt.value)
			}
		})
	}
}

func TestAWSSecretAccessKeyRequiresATrailingBoundary(t *testing.T) {
	content := "AWS_SECRET_ACCESS_KEY=" + testAWSSecret + "X"
	for _, match := range Default().Scan(ScanInput{Content: content}) {
		if match.Detector == "aws_secret_access_key" {
			t.Fatalf("41-character value matched as a 40-character secret: %#v", match)
		}
	}
}

// DET-11: PGP private key blocks and keys without an END marker.
func TestPEMPrivateKeyDetectorCoversPGPAndTruncatedKeys(t *testing.T) {
	set := Default()
	body := strings.Repeat("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n", 3)

	t.Run("pgp private key block", func(t *testing.T) {
		content := "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG v2\n\n" + body + "=abcd\n-----END PGP PRIVATE KEY BLOCK-----\n"
		match, ok := findDetectorMatch(set.Scan(ScanInput{Content: content}), "pem_private_key")
		if !ok {
			t.Fatal("expected pem_private_key for a PGP block")
		}
		if !strings.HasSuffix(match.Value, "-----END PGP PRIVATE KEY BLOCK-----") || match.Confidence != ConfidenceHigh {
			t.Fatalf("match = %#v", match)
		}
	})

	t.Run("truncated key without an END marker covers the body", func(t *testing.T) {
		content := "config:\n-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,ABCD\n\n" + body
		match, ok := findDetectorMatch(set.Scan(ScanInput{Content: content}), "pem_private_key")
		if !ok {
			t.Fatal("expected pem_private_key for a truncated key")
		}
		if !strings.HasPrefix(match.Value, "-----BEGIN RSA PRIVATE KEY-----") || !strings.Contains(match.Value, "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7") {
			t.Fatalf("match.Value does not cover the key body: %q", match.Value)
		}
		if match.Confidence != ConfidenceHigh {
			t.Fatalf("match.Confidence = %q", match.Confidence)
		}
	})

	t.Run("lone header is reported at medium confidence", func(t *testing.T) {
		content := "grep -q -- '-----BEGIN RSA PRIVATE KEY-----' \"$f\" && echo found\n"
		match, ok := findDetectorMatch(set.Scan(ScanInput{Content: content}), "pem_private_key")
		if !ok {
			t.Fatal("expected pem_private_key for a lone header")
		}
		if match.Value != "-----BEGIN RSA PRIVATE KEY-----" || match.Confidence != ConfidenceMedium {
			t.Fatalf("match = %#v", match)
		}
	})

	t.Run("json escaped key still spans to the END marker", func(t *testing.T) {
		content := `{"private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n-----END PRIVATE KEY-----\n"}`
		match, ok := findDetectorMatch(set.Scan(ScanInput{Content: content}), "pem_private_key")
		if !ok {
			t.Fatal("expected pem_private_key for a JSON-escaped key")
		}
		if !strings.HasSuffix(match.Value, "-----END PRIVATE KEY-----") {
			t.Fatalf("match.Value = %q", match.Value)
		}
	})

	t.Run("two keys in one file are two findings", func(t *testing.T) {
		one := "-----BEGIN EC PRIVATE KEY-----\n" + body + "-----END EC PRIVATE KEY-----\n"
		matches := set.Scan(ScanInput{Content: one + "\n" + one})
		count := 0
		for _, match := range matches {
			if match.Detector == "pem_private_key" {
				count++
			}
		}
		if count != 2 {
			t.Fatalf("pem_private_key count = %d: %#v", count, matches)
		}
	})
}

// DET-12: GitLab routable tokens carry a ".<version>.<length+crc>" tail that
// must be part of the value, or the fingerprint is of a prefix and the tail
// stays in plaintext.
func TestGitLabTokensIncludeTheRoutableTail(t *testing.T) {
	set := Default()
	tail := ".01.0w1bd93a1"
	tests := []struct {
		detector string
		token    string
	}{
		{detector: "gitlab_personal_access_token", token: "glpat-" + strings.Repeat("A", 27) + tail},
		{detector: "gitlab_deploy_token", token: "gl" + "dt-" + strings.Repeat("A", 27) + tail},
		{detector: "gitlab_runner_token", token: "gl" + "rt-" + strings.Repeat("A", 27) + tail},
	}
	for _, tt := range tests {
		t.Run(tt.detector, func(t *testing.T) {
			content := "GITLAB_TOKEN=" + tt.token + "\n"
			match, ok := findDetectorMatch(set.Scan(ScanInput{Content: content}), tt.detector)
			if !ok {
				t.Fatalf("expected %s", tt.detector)
			}
			if match.Value != tt.token {
				t.Fatalf("match.Value = %q, want %q", match.Value, tt.token)
			}
		})
	}
}

// DET-13: GitHub refresh tokens have a 76-character body.
func TestGitHubRefreshTokensAcceptLongBodies(t *testing.T) {
	set := Default()
	for _, length := range []int{36, 76} {
		token := "ghr_" + strings.Repeat("A", length)
		match, ok := findDetectorMatch(set.Scan(ScanInput{Content: "token=" + token}), "github_token")
		if !ok || match.Value != token {
			t.Fatalf("ghr_ with %d-character body: match = %#v", length, match)
		}
	}
	for _, match := range set.Scan(ScanInput{Content: "token=ghp_" + strings.Repeat("A", 40)}) {
		if match.Detector == "github_token" {
			t.Fatalf("ghp_ with a 40-character body matched: %#v", match)
		}
	}
}

// DET-20: capture boundaries.
func TestCaptureBoundaries(t *testing.T) {
	set := Default()

	t.Run("quoted npmrc token excludes the quotes and is one finding", func(t *testing.T) {
		token := "npm_" + strings.Repeat("1234567890", 3) + "abcdef"
		matches := set.Scan(ScanInput{Path: "/root/.npmrc", Content: "//registry.npmjs.org/:_authToken=\"" + token + "\"\n"})
		if len(matches) != 1 || matches[0].Value != token || matches[0].Detector != "npmrc_auth_token" {
			t.Fatalf("matches = %#v", matches)
		}
	})

	t.Run("databricks token keeps its version suffix", func(t *testing.T) {
		token := "dapi" + strings.Repeat("a1", 16) + "-3"
		match, ok := findDetectorMatch(set.Scan(ScanInput{Content: "DATABRICKS_TOKEN=" + token}), "databricks_token")
		if !ok || match.Value != token {
			t.Fatalf("match = %#v", match)
		}
	})

	t.Run("telegram token needs a trailing boundary", func(t *testing.T) {
		for _, match := range set.Scan(ScanInput{Content: "1234567890:" + strings.Repeat("A", 36)}) {
			if match.Detector == "telegram_bot_token" {
				t.Fatalf("36-character secret matched as a telegram token: %#v", match)
			}
		}
		token := "1234567890:" + strings.Repeat("A", 35)
		if _, ok := findDetectorMatch(set.Scan(ScanInput{Content: token + "\n"}), "telegram_bot_token"); !ok {
			t.Fatal("35-character token not detected")
		}
	})
}
