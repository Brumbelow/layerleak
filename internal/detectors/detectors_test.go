package detectors

import (
	"strings"
	"testing"
)

func TestDefaultSetScan(t *testing.T) {
	tests := []struct {
		name         string
		input        ScanInput
		wantDetector string
	}{
		{
			name: "github token",
			input: ScanInput{
				Content: "token=ghp_123456789012345678901234567890123456",
			},
			wantDetector: "github_token",
		},
		{
			name: "google api key",
			input: ScanInput{
				Content: "AIzaSyD3mWq9y7fH2Lk5nV8pR1sT4uX6zA0bCDe",
			},
			wantDetector: "google_api_key",
		},
		{
			name: "sendgrid api key",
			input: ScanInput{
				Content: "SG.qwertyuiopasdfghjklzxcvbnm.QWERTYUIOPASDFGHJKLZXCVBNMASDFGHJKLZXCV",
			},
			wantDetector: "sendgrid_api_key",
		},
		{
			name: "shopify access token",
			input: ScanInput{
				Content: "shpat_0123456789abcdef0123456789abcdef",
			},
			wantDetector: "shopify_access_token",
		},
		{
			name: "slack webhook",
			input: ScanInput{
				Content: "https://hooks.slack.com/services/T12345678/B12345678/abcdefghijklmnop",
			},
			wantDetector: "slack_webhook",
		},
		{
			name: "docker auth blob",
			input: ScanInput{
				Content: `{"auth":"dXNlcjpwYXNz"}`,
				Path:    "/root/.docker/config.json",
			},
			wantDetector: "docker_auth_blob",
		},
		{
			name: "aws secret access key",
			input: ScanInput{
				Content: "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			},
			wantDetector: "aws_secret_access_key",
		},
		{
			name: "npmrc auth token",
			input: ScanInput{
				Path:    "/root/.npmrc",
				Content: "//registry.npmjs.org/:_authToken=internalTokenValue1234567890",
			},
			wantDetector: "npmrc_auth_token",
		},
		{
			name: "npmrc auth",
			input: ScanInput{
				Path:    "/root/.npmrc",
				Content: "//registry.npmjs.org/:_auth=dXNlcjpwYXNz",
			},
			wantDetector: "npmrc_auth",
		},
		{
			name: "netrc password",
			input: ScanInput{
				Path:    "/root/.netrc",
				Content: "machine example.com login deploy password supersecretvalue",
			},
			wantDetector: "netrc_password",
		},
		{
			name: "pypirc password",
			input: ScanInput{
				Path:    "/root/.pypirc",
				Content: "[distutils]\npassword = pypiSecretValue123",
			},
			wantDetector: "pypirc_password",
		},
		{
			name: "jwt",
			input: ScanInput{
				Content: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.signaturetoken",
			},
			wantDetector: "jwt",
		},
		{
			name: "basic auth url",
			input: ScanInput{
				Content: "https://user:pass@example.com/config",
				Path:    "/root/.netrc",
			},
			wantDetector: "basic_auth_url",
		},
	}

	set := Default()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := set.Scan(tt.input)
			if len(matches) == 0 {
				t.Fatal("len(matches) = 0")
			}
			found := false
			for _, match := range matches {
				if match.Detector == tt.wantDetector {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected detector %q in %#v", tt.wantDetector, matches)
			}
		})
	}
}

func TestKeywordEntropyUsesPathWeighting(t *testing.T) {
	set := Default()
	matches := set.Scan(ScanInput{
		Path:    "/app/.env",
		Key:     "SECRET_VALUE",
		Content: "SECRET_VALUE=q7Y8zX6wV4uT2sR0pN9mL7kJ5hG3fD1cB5",
	})

	found := false
	for _, match := range matches {
		if match.Detector == "keyword_entropy" {
			found = true
			if match.Confidence == ConfidenceLow {
				t.Fatalf("match.Confidence = %q", match.Confidence)
			}
		}
	}

	if !found {
		t.Fatal("expected keyword_entropy match")
	}
}

func TestKeywordEntropyRequiresAssignmentContext(t *testing.T) {
	set := Default()
	matches := set.Scan(ScanInput{
		Content: "password base-passwd/user-change-gecos",
	})

	for _, match := range matches {
		if match.Detector == "keyword_entropy" {
			t.Fatalf("unexpected keyword_entropy match: %#v", match)
		}
	}
}

func TestKeywordEntropySuppressesWordyCandidates(t *testing.T) {
	tests := []ScanInput{
		{Content: "PASSWORD=base-passwd/user-change-gecos"},
		{Content: "secret: Extended_description-ca"},
		{Content: "token=ITM_deregisterTMCloneTable"},
		{Content: "password=pam_modutil_getpwnam"},
		{Content: "password=usr/share/doc/base-passwd/README"},
	}

	set := Default()
	for _, input := range tests {
		matches := set.Scan(input)
		for _, match := range matches {
			if match.Detector == "keyword_entropy" {
				t.Fatalf("unexpected keyword_entropy match for %q: %#v", input.Content, match)
			}
		}
	}
}

func TestBasicAuthURLRejectsNonPrintableMatches(t *testing.T) {
	set := Default()
	matches := set.Scan(ScanInput{
		Content: "https://user:\x00pass@example.com",
		Path:    "/usr/sbin/nologin",
	})

	for _, match := range matches {
		if match.Detector == "basic_auth_url" {
			t.Fatalf("unexpected basic_auth_url match: %#v", match)
		}
	}
}

func TestAWSSecretAccessKeyRequiresContext(t *testing.T) {
	set := Default()
	matches := set.Scan(ScanInput{
		Content: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	})

	for _, match := range matches {
		if match.Detector == "aws_secret_access_key" {
			t.Fatalf("unexpected aws_secret_access_key match: %#v", match)
		}
	}
}

func TestFileSpecificDetectorsRequireExpectedPath(t *testing.T) {
	tests := []struct {
		name         string
		input        ScanInput
		wantDetector string
	}{
		{
			name: "npmrc auth token on wrong path",
			input: ScanInput{
				Path:    "/tmp/config.txt",
				Content: "//registry.npmjs.org/:_authToken=internalTokenValue1234567890",
			},
			wantDetector: "npmrc_auth_token",
		},
		{
			name: "netrc password on wrong path",
			input: ScanInput{
				Path:    "/tmp/example.txt",
				Content: "machine example.com login deploy password supersecretvalue",
			},
			wantDetector: "netrc_password",
		},
	}

	set := Default()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := set.Scan(tt.input)
			for _, match := range matches {
				if match.Detector == tt.wantDetector {
					t.Fatalf("unexpected %s match: %#v", tt.wantDetector, match)
				}
			}
		})
	}
}

func TestDefaultSetIncludesTrufflehogAnthropicDetector(t *testing.T) {
	set := Default()
	matches := set.Scan(ScanInput{
		Content: `
System Log - Authentication Token Issued
Date: 2025-02-04 14:32:10 UTC
Service: Anthropic API Gateway
API Key: sk-ant-api03-abc123xyz-456def789ghij-klmnopqrstuvwx-3456yza789bcde-1234fghijklmnopby56aaaogaopaaaabc123xyzAA
`,
	})

	match, ok := findDetectorMatch(matches, "anthropic")
	if !ok {
		t.Fatalf("expected anthropic detector in %#v", matches)
	}
	if !strings.Contains(match.Value, "sk-ant-api03-") {
		t.Fatalf("match.Value = %q", match.Value)
	}
}

func TestDefaultSetIncludesTrufflehogMultipartDetector(t *testing.T) {
	set := Default()
	matches := set.Scan(ScanInput{
		Content: `
secret: "dapib8a799e452bf722cb28874cee50a7abf"
domain: "nonprod-test.cloud.databricks.com"
`,
	})

	match, ok := findDetectorMatch(matches, "databricks_token")
	if !ok {
		t.Fatalf("expected databricks_token detector in %#v", matches)
	}
	if !strings.Contains(match.Value, "dapib8a799e452bf722cb28874cee50a7abfnonprod-test.cloud.databricks.com") {
		t.Fatalf("match.Value = %q", match.Value)
	}
}

func TestDefaultSetDeduplicatesOverlappingGithubDetectors(t *testing.T) {
	set := Default()
	matches := set.Scan(ScanInput{
		Content: "token=ghp_123456789012345678901234567890123456",
	})

	count := 0
	for _, match := range matches {
		if match.Detector == "github_token" {
			count++
		}
	}

	if count != 1 {
		t.Fatalf("github_token count = %d, matches = %#v", count, matches)
	}
}

func findDetectorMatch(matches []Match, detectorName string) (Match, bool) {
	for _, match := range matches {
		if match.Detector == detectorName {
			return match, true
		}
	}

	return Match{}, false
}
