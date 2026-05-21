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
				Content: "https://deploy:supersecretvalue@registry.internal/config",
				Path:    "/root/.netrc",
			},
			wantDetector: "basic_auth_url",
		},
		{
			name: "huggingface token",
			input: ScanInput{
				Content: "HF_TOKEN=hf_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			wantDetector: "huggingface_token",
		},
		{
			name: "digitalocean pat",
			input: ScanInput{
				Content: "DO_TOKEN=dop_v1_" + strings.Repeat("0", 64),
			},
			wantDetector: "digitalocean_pat",
		},
		{
			name: "mailchimp api key",
			input: ScanInput{
				Content: "MC_API_KEY=" + strings.Repeat("0", 32) + "-us1",
			},
			wantDetector: "mailchimp_api_key",
		},
		{
			name: "hashicorp vault service token",
			input: ScanInput{
				Content: "VAULT_TOKEN=hvs." + strings.Repeat("a", 24),
			},
			wantDetector: "hashicorp_vault_token",
		},
		{
			name: "kubeconfig token",
			input: ScanInput{
				Path:    "/root/.kube/config",
				Content: "    token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.signaturetoken",
			},
			wantDetector: "kubeconfig_token",
		},
		{
			name: "vault token file hvs",
			input: ScanInput{
				Path:    "/root/.vault-token",
				Content: "hvs." + strings.Repeat("a", 24),
			},
			wantDetector: "vault_token_file",
		},
		{
			name: "openai project api key",
			input: ScanInput{
				Content: "OPENAI_API_KEY=sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl",
			},
			wantDetector: "openai_api_key",
		},
		{
			name: "linear api key",
			input: ScanInput{
				// Prefix split across adjacent literals so no contiguous lin_api_ literal
				// appears in source (avoids secret-scanner false positives in test files).
				Content: "LINEAR_API_KEY=" + "lin" + "_api_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCD",
			},
			wantDetector: "linear_api_key",
		},
		{
			name: "doppler service token",
			input: ScanInput{
				Content: "DOPPLER_TOKEN=dp.st.production.someservice.SomeLongSecretToken123456",
			},
			wantDetector: "doppler_token",
		},
		{
			name: "grafana service account token",
			input: ScanInput{
				Content: "GRAFANA_TOKEN=glsa_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef_12ab34cd",
			},
			wantDetector: "grafana_service_account_token",
		},
		{
			name: "twilio account sid",
			input: ScanInput{
				// Prefix split to avoid triggering secret-scanner false positives in test files.
				Content: "TWILIO_ACCOUNT_SID=" + "AC" + "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
			},
			wantDetector: "twilio_account_sid",
		},
		{
			name: "databricks token",
			input: ScanInput{
				// Prefix split to avoid triggering secret-scanner false positives in test files.
				Content: "DATABRICKS_TOKEN=" + "dapi" + "AbCdEf0123456789AbCdEf0123456789",
			},
			wantDetector: "databricks_token",
		},
		{
			name: "azure storage account key in connection string",
			input: ScanInput{
				Content: "DefaultEndpointsProtocol=https;AccountName=mystorageaccount;AccountKey=" + strings.Repeat("A", 86) + "==;EndpointSuffix=core.windows.net",
			},
			wantDetector: "azure_storage_account_key",
		},
		{
			name: "datadog api key",
			input: ScanInput{
				Key:     "DD_API_KEY",
				Content: "DD_API_KEY=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
			},
			wantDetector: "datadog_api_key",
		},
		{
			name: "notion integration token",
			input: ScanInput{
				// Prefix split to avoid triggering secret-scanner false positives in test files.
				Content: "NOTION_TOKEN=" + "secr" + "et_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop",
			},
			wantDetector: "notion_integration_token",
		},
		{
			name: "pulumi access token",
			input: ScanInput{
				// Prefix split to avoid triggering secret-scanner false positives in test files.
				Content: "PULUMI_ACCESS_TOKEN=" + "pu" + "l-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn",
			},
			wantDetector: "pulumi_access_token",
		},
		{
			name: "age secret key",
			input: ScanInput{
				// Prefix split to avoid triggering secret-scanner false positives in test files.
				// 58 lowercase alphanumeric chars after the bech32 separator '1'.
				Content: "AGE-" + "SECRET-KEY-1qpzry9x8gf2tvdw0s3jn54khce6mua7lqpzry9x8gf2tvdw0s3jn54khce",
			},
			wantDetector: "age_secret_key",
		},
		{
			name: "render api key",
			input: ScanInput{
				// Prefix split to avoid triggering secret-scanner false positives in test files.
				// 32 alphanumeric chars after 'rnd_'.
				Content: "RENDER_API_KEY=" + "rn" + "d_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef",
			},
			wantDetector: "render_api_key",
		},
		{
			name: "twilio auth token",
			input: ScanInput{
				Content: "TWILIO_AUTH_TOKEN=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
			},
			wantDetector: "twilio_auth_token",
		},
		{
			name: "new relic user api key",
			input: ScanInput{
				// Prefix split to avoid triggering secret-scanner false positives in test files.
				Content: "NEW_RELIC_API_KEY=" + "NR" + "AK-ABCDEFGHIJKLMNOPQRSTUVWXYZ1",
			},
			wantDetector: "new_relic_user_api_key",
		},
		{
			name: "okta api token",
			input: ScanInput{
				// Prefix split to avoid triggering secret-scanner false positives in test files.
				Content: "Authorization: " + "SS" + "WS ABCDEFGHIJKLMNOPQRSTUVWXYZ01",
			},
			wantDetector: "okta_api_token",
		},
		{
			name: "square application secret",
			input: ScanInput{
				// Prefix split to avoid triggering secret-scanner false positives in test files.
				Content: "SQUARE_APP_SECRET=" + "sq0c" + "sp-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq",
			},
			wantDetector: "square_application_secret",
		},
		{
			name: "square oauth token",
			input: ScanInput{
				// Prefix split to avoid triggering secret-scanner false positives in test files.
				Content: "SQUARE_ACCESS_TOKEN=" + "sq0a" + "tp-ABCDEFGHIJKLMNOPQRSTUV",
			},
			wantDetector: "square_oauth_token",
		},
		{
			name: "gitlab deploy token",
			input: ScanInput{
				// Prefix split to avoid triggering secret-scanner false positives in test files.
				Content: "CI_DEPLOY_PASSWORD=" + "gl" + "dt-ABCDEFGHIJKLMNOPQRSTUVWXYZ01",
			},
			wantDetector: "gitlab_deploy_token",
		},
		{
			name: "gitlab runner token",
			input: ScanInput{
				// Prefix split to avoid triggering secret-scanner false positives in test files.
				Content: "RUNNER_TOKEN=" + "gl" + "rt-ABCDEFGHIJKLMNOPQRSTUVWXYZ01",
			},
			wantDetector: "gitlab_runner_token",
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
		{
			name: "kubeconfig token on wrong path",
			input: ScanInput{
				Path:    "/tmp/config.txt",
				Content: "    token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.signaturetoken",
			},
			wantDetector: "kubeconfig_token",
		},
		{
			name: "vault token file on wrong path",
			input: ScanInput{
				Path:    "/tmp/token.txt",
				Content: "hvs." + strings.Repeat("a", 24),
			},
			wantDetector: "vault_token_file",
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

func TestDefaultSetDiscardsPlaceholderDockerAuthBlob(t *testing.T) {
	set := Default()
	matches := set.Scan(ScanInput{
		Path:    "/root/.docker/config.json",
		Content: `{"auth":"Zm9vOmJhcg=="}`,
	})

	for _, match := range matches {
		if match.Detector == "docker_auth_blob" {
			t.Fatalf("unexpected docker_auth_blob match: %#v", match)
		}
	}
}

func TestDefaultSetDiscardsPlaceholderBasicAuthURL(t *testing.T) {
	set := Default()
	matches := set.Scan(ScanInput{
		Content: "https://foo:bar@example.com/config",
	})

	for _, match := range matches {
		if match.Detector == "basic_auth_url" {
			t.Fatalf("unexpected basic_auth_url match: %#v", match)
		}
	}
}

func TestDefaultSetDiscardsPlaceholderNetrcPassword(t *testing.T) {
	set := Default()
	matches := set.Scan(ScanInput{
		Path:    "/root/.netrc",
		Content: "machine example.com login deploy password foobar",
	})

	for _, match := range matches {
		if match.Detector == "netrc_password" {
			t.Fatalf("unexpected netrc_password match: %#v", match)
		}
	}
}

func TestDefaultSetIncludesAnthropicDetector(t *testing.T) {
	set := Default()
	matches := set.Scan(ScanInput{
		Content: `
System Log - Authentication Token Issued
Date: 2025-02-04 14:32:10 UTC
Service: Anthropic API Gateway
API Key: sk-ant-api03-abc123xyz-456def789ghij-klmnopqrstuvwx-3456yza789bcde-1234fghijklmnopby56aaaogaopaaaabc123xyzAA
`,
	})

	match, ok := findDetectorMatch(matches, "anthropic_api_key")
	if !ok {
		t.Fatalf("expected anthropic_api_key detector in %#v", matches)
	}
	if !strings.Contains(match.Value, "sk-ant-api03-") {
		t.Fatalf("match.Value = %q", match.Value)
	}
	if match.Confidence != ConfidenceHigh {
		t.Fatalf("match.Confidence = %q", match.Confidence)
	}
}

func TestDefaultSetDatabricksTokenDetection(t *testing.T) {
	set := Default()
	matches := set.Scan(ScanInput{
		Content: `
secret: "dapib8a799e452bf722cb28874cee50a7abf"
domain: "nonprod-test.cloud.databricks.com"
`,
	})

	// The native databricks_token detector takes precedence over trufflehog.
	match, ok := findDetectorMatch(matches, "databricks_token")
	if !ok {
		t.Fatalf("expected databricks_token detector in %#v", matches)
	}
	if !strings.HasPrefix(match.Value, "dapi") {
		t.Fatalf("match.Value = %q", match.Value)
	}
}

func TestAWSSharedCredentialsDetectorPromotesPairedProfile(t *testing.T) {
	set := Default()
	matches := set.Scan(ScanInput{
		Path: "/root/.aws/credentials",
		Content: `[default]
aws_access_key_id = AKIA1234567890ABCDEF
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
`,
	})

	accessKeyMatch, ok := findDetectorMatch(matches, "aws_shared_credentials_access_key_id")
	if !ok {
		t.Fatalf("expected aws_shared_credentials_access_key_id in %#v", matches)
	}
	if accessKeyMatch.Confidence != ConfidenceHigh {
		t.Fatalf("accessKeyMatch.Confidence = %q", accessKeyMatch.Confidence)
	}

	secretMatch, ok := findDetectorMatch(matches, "aws_shared_credentials_secret_access_key")
	if !ok {
		t.Fatalf("expected aws_shared_credentials_secret_access_key in %#v", matches)
	}
	if secretMatch.Confidence != ConfidenceHigh {
		t.Fatalf("secretMatch.Confidence = %q", secretMatch.Confidence)
	}

	legacyCount := 0
	for _, match := range matches {
		if match.Value == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" {
			legacyCount++
		}
	}
	if legacyCount != 1 {
		t.Fatalf("secret value match count = %d, matches = %#v", legacyCount, matches)
	}
}

func TestAWSSharedCredentialsDetectorKeepsUnpairedAccessKeyMedium(t *testing.T) {
	set := Default()
	matches := set.Scan(ScanInput{
		Path: "/root/.aws/credentials",
		Content: `[default]
aws_access_key_id = AKIA1234567890ABCDEF
`,
	})

	match, ok := findDetectorMatch(matches, "aws_shared_credentials_access_key_id")
	if !ok {
		t.Fatalf("expected aws_shared_credentials_access_key_id in %#v", matches)
	}
	if match.Confidence != ConfidenceMedium {
		t.Fatalf("match.Confidence = %q", match.Confidence)
	}
}

func TestGitCredentialsDetectorExtractsPassword(t *testing.T) {
	set := Default()
	matches := set.Scan(ScanInput{
		Path:    "/root/.git-credentials",
		Content: "https://deploy:supersecretvalue@example.com/org/repo.git\n",
	})

	match, ok := findDetectorMatch(matches, "git_credentials_password")
	if !ok {
		t.Fatalf("expected git_credentials_password in %#v", matches)
	}
	if match.Value != "supersecretvalue" {
		t.Fatalf("match.Value = %q", match.Value)
	}
}

func TestTerraformCredentialsDetectorFindsToken(t *testing.T) {
	set := Default()
	matches := set.Scan(ScanInput{
		Path: "/root/.terraformrc",
		Content: `credentials "app.terraform.io" {
  token = "atlasv1.1234567890abcdefghijklmnopqrstuv"
}`,
	})

	match, ok := findDetectorMatch(matches, "terraform_cloud_token")
	if !ok {
		t.Fatalf("expected terraform_cloud_token in %#v", matches)
	}
	if !strings.Contains(match.Value, "atlasv1.") {
		t.Fatalf("match.Value = %q", match.Value)
	}
}

func TestDefaultSetUsesMediumBaseConfidenceForTrufflehogMatches(t *testing.T) {
	set := Default()
	matches := set.Scan(ScanInput{
		Content: `
secret: "dapib8a799e452bf722cb28874cee50a7abf"
domain: "nonprod-test.cloud.databricks.com"
`,
	})

	// Trufflehog emits its own databricks_token match with medium base confidence
	// alongside the native high-confidence match. Verify at least one medium match exists.
	foundMedium := false
	for _, m := range matches {
		if m.Detector == "databricks_token" && m.Confidence == ConfidenceMedium {
			foundMedium = true
			break
		}
	}
	if !foundMedium {
		t.Fatalf("expected a databricks_token match with ConfidenceMedium from trufflehog in %#v", matches)
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

func TestOpenAIProjectKeyDetector(t *testing.T) {
	set := Default()

	t.Run("legacy 48-char key still detected", func(t *testing.T) {
		matches := set.Scan(ScanInput{
			Content: "OPENAI_API_KEY=sk-" + strings.Repeat("A", 48),
		})
		match, ok := findDetectorMatch(matches, "openai_api_key")
		if !ok {
			t.Fatalf("expected openai_api_key in %#v", matches)
		}
		if match.Confidence != ConfidenceHigh {
			t.Fatalf("match.Confidence = %q", match.Confidence)
		}
	})

	t.Run("sk-proj key detected", func(t *testing.T) {
		projKey := "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl"
		matches := set.Scan(ScanInput{
			Content: "OPENAI_API_KEY=" + projKey,
		})
		match, ok := findDetectorMatch(matches, "openai_api_key")
		if !ok {
			t.Fatalf("expected openai_api_key in %#v", matches)
		}
		if !strings.HasPrefix(match.Value, "sk-proj-") {
			t.Fatalf("match.Value = %q", match.Value)
		}
	})

	t.Run("sk-admin key detected", func(t *testing.T) {
		adminKey := "sk-admin-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl"
		matches := set.Scan(ScanInput{
			Content: "OPENAI_API_KEY=" + adminKey,
		})
		match, ok := findDetectorMatch(matches, "openai_api_key")
		if !ok {
			t.Fatalf("expected openai_api_key in %#v", matches)
		}
		if !strings.HasPrefix(match.Value, "sk-admin-") {
			t.Fatalf("match.Value = %q", match.Value)
		}
	})

	t.Run("short sk-proj key not detected", func(t *testing.T) {
		matches := set.Scan(ScanInput{
			Content: "OPENAI_API_KEY=sk-proj-tooshort",
		})
		for _, m := range matches {
			if m.Detector == "openai_api_key" {
				t.Fatalf("unexpected openai_api_key match for short sk-proj: %#v", m)
			}
		}
	})
}

func TestLinearAPIKeyDetector(t *testing.T) {
	set := Default()

	// Prefix split so no contiguous lin_api_ literal appears in source.
	const linPrefix = "lin" + "_api_"

	t.Run("detects valid linear key", func(t *testing.T) {
		content := "LINEAR_API_KEY=" + linPrefix + "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCD"
		matches := set.Scan(ScanInput{Content: content})
		match, ok := findDetectorMatch(matches, "linear_api_key")
		if !ok {
			t.Fatalf("expected linear_api_key in %#v", matches)
		}
		wantValue := linPrefix + "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCD"
		if match.Value != wantValue {
			t.Fatalf("match.Value = %q", match.Value)
		}
	})

	t.Run("does not match short key", func(t *testing.T) {
		matches := set.Scan(ScanInput{
			Content: linPrefix + "tooshort",
		})
		for _, m := range matches {
			if m.Detector == "linear_api_key" {
				t.Fatalf("unexpected linear_api_key match: %#v", m)
			}
		}
	})
}

func TestDopplerTokenDetector(t *testing.T) {
	set := Default()

	t.Run("detects service token", func(t *testing.T) {
		matches := set.Scan(ScanInput{
			Content: "dp.st.production.someservice.SomeLongSecretToken123456",
		})
		match, ok := findDetectorMatch(matches, "doppler_token")
		if !ok {
			t.Fatalf("expected doppler_token in %#v", matches)
		}
		if !strings.HasPrefix(match.Value, "dp.st.") {
			t.Fatalf("match.Value = %q", match.Value)
		}
	})

	t.Run("detects project token", func(t *testing.T) {
		matches := set.Scan(ScanInput{
			Content: "TOKEN=dp.pt.dev.myapp.SecretValue1234567890abcdef",
		})
		_, ok := findDetectorMatch(matches, "doppler_token")
		if !ok {
			t.Fatalf("expected doppler_token in %#v", matches)
		}
	})

	t.Run("does not match unknown prefix", func(t *testing.T) {
		matches := set.Scan(ScanInput{
			Content: "dp.xx.production.someservice.SomeLongSecretToken123456",
		})
		for _, m := range matches {
			if m.Detector == "doppler_token" {
				t.Fatalf("unexpected doppler_token match: %#v", m)
			}
		}
	})
}

func TestGrafanaServiceAccountTokenDetector(t *testing.T) {
	set := Default()
	matches := set.Scan(ScanInput{
		Content: "GRAFANA_TOKEN=glsa_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef_12ab34cd",
	})
	match, ok := findDetectorMatch(matches, "grafana_service_account_token")
	if !ok {
		t.Fatalf("expected grafana_service_account_token in %#v", matches)
	}
	if match.Value != "glsa_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef_12ab34cd" {
		t.Fatalf("match.Value = %q", match.Value)
	}
	if match.Confidence != ConfidenceHigh {
		t.Fatalf("match.Confidence = %q", match.Confidence)
	}
}

func TestNewRelicUserAPIKeyDetector(t *testing.T) {
	set := Default()

	// Prefix split to avoid triggering secret-scanner false positives in test files.
	const nrPrefix = "NR" + "AK-"

	t.Run("detects valid key", func(t *testing.T) {
		matches := set.Scan(ScanInput{Content: "NEW_RELIC_API_KEY=" + nrPrefix + "ABCDEFGHIJKLMNOPQRSTUVWXYZ1"})
		match, ok := findDetectorMatch(matches, "new_relic_user_api_key")
		if !ok {
			t.Fatalf("expected new_relic_user_api_key in %#v", matches)
		}
		if !strings.HasPrefix(match.Value, "NRAK-") {
			t.Fatalf("match.Value = %q", match.Value)
		}
		if match.Confidence != ConfidenceHigh {
			t.Fatalf("match.Confidence = %q", match.Confidence)
		}
	})

	t.Run("does not match wrong length", func(t *testing.T) {
		matches := set.Scan(ScanInput{Content: nrPrefix + "TOOSHORT"})
		for _, m := range matches {
			if m.Detector == "new_relic_user_api_key" {
				t.Fatalf("unexpected new_relic_user_api_key match: %#v", m)
			}
		}
	})

	t.Run("does not match lowercase body", func(t *testing.T) {
		matches := set.Scan(ScanInput{Content: nrPrefix + "abcdefghijklmnopqrstuvwxyz1"})
		for _, m := range matches {
			if m.Detector == "new_relic_user_api_key" {
				t.Fatalf("unexpected new_relic_user_api_key match: %#v", m)
			}
		}
	})
}

func TestOktaAPITokenDetector(t *testing.T) {
	set := Default()

	// Prefix split to avoid triggering secret-scanner false positives in test files.
	const ssPrefix = "SS" + "WS "

	t.Run("detects token in authorization header", func(t *testing.T) {
		matches := set.Scan(ScanInput{Content: "Authorization: " + ssPrefix + "ABCDEFGHIJKLMNOPQRSTUVWXYZ01"})
		match, ok := findDetectorMatch(matches, "okta_api_token")
		if !ok {
			t.Fatalf("expected okta_api_token in %#v", matches)
		}
		if match.Confidence != ConfidenceHigh {
			t.Fatalf("match.Confidence = %q", match.Confidence)
		}
	})

	t.Run("detects token in config assignment", func(t *testing.T) {
		matches := set.Scan(ScanInput{Content: "OKTA_API_TOKEN=" + ssPrefix + "Abcdefghijklmnopqrstuvwxyz0123"})
		_, ok := findDetectorMatch(matches, "okta_api_token")
		if !ok {
			t.Fatalf("expected okta_api_token in %#v", matches)
		}
	})

	t.Run("does not match short token", func(t *testing.T) {
		matches := set.Scan(ScanInput{Content: ssPrefix + "tooshort"})
		for _, m := range matches {
			if m.Detector == "okta_api_token" {
				t.Fatalf("unexpected okta_api_token match: %#v", m)
			}
		}
	})
}

func TestSquareCredentialDetectors(t *testing.T) {
	set := Default()

	// Prefixes split to avoid triggering secret-scanner false positives in test files.
	const appSecretPrefix = "sq0c" + "sp-"
	const oauthTokenPrefix = "sq0a" + "tp-"

	t.Run("detects application secret", func(t *testing.T) {
		matches := set.Scan(ScanInput{Content: "SQUARE_APP_SECRET=" + appSecretPrefix + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"})
		match, ok := findDetectorMatch(matches, "square_application_secret")
		if !ok {
			t.Fatalf("expected square_application_secret in %#v", matches)
		}
		if !strings.HasPrefix(match.Value, "sq0csp-") {
			t.Fatalf("match.Value = %q", match.Value)
		}
		if match.Confidence != ConfidenceHigh {
			t.Fatalf("match.Confidence = %q", match.Confidence)
		}
	})

	t.Run("does not match short application secret", func(t *testing.T) {
		matches := set.Scan(ScanInput{Content: appSecretPrefix + "tooshort"})
		for _, m := range matches {
			if m.Detector == "square_application_secret" {
				t.Fatalf("unexpected square_application_secret match: %#v", m)
			}
		}
	})

	t.Run("detects oauth token", func(t *testing.T) {
		matches := set.Scan(ScanInput{Content: "SQUARE_ACCESS_TOKEN=" + oauthTokenPrefix + "ABCDEFGHIJKLMNOPQRSTUV"})
		match, ok := findDetectorMatch(matches, "square_oauth_token")
		if !ok {
			t.Fatalf("expected square_oauth_token in %#v", matches)
		}
		if !strings.HasPrefix(match.Value, "sq0atp-") {
			t.Fatalf("match.Value = %q", match.Value)
		}
		if match.Confidence != ConfidenceHigh {
			t.Fatalf("match.Confidence = %q", match.Confidence)
		}
	})

	t.Run("does not match wrong-length oauth token", func(t *testing.T) {
		matches := set.Scan(ScanInput{Content: oauthTokenPrefix + "TOOSHORT"})
		for _, m := range matches {
			if m.Detector == "square_oauth_token" {
				t.Fatalf("unexpected square_oauth_token match: %#v", m)
			}
		}
	})
}

func TestGitLabExtendedTokenDetectors(t *testing.T) {
	set := Default()

	// Prefixes split to avoid triggering secret-scanner false positives in test files.
	const deployPrefix = "gl" + "dt-"
	const runnerPrefix = "gl" + "rt-"

	t.Run("detects deploy token", func(t *testing.T) {
		matches := set.Scan(ScanInput{Content: "CI_DEPLOY_PASSWORD=" + deployPrefix + "ABCDEFGHIJKLMNOPQRSTUVWXYZ01"})
		match, ok := findDetectorMatch(matches, "gitlab_deploy_token")
		if !ok {
			t.Fatalf("expected gitlab_deploy_token in %#v", matches)
		}
		if !strings.HasPrefix(match.Value, "gldt-") {
			t.Fatalf("match.Value = %q", match.Value)
		}
		if match.Confidence != ConfidenceHigh {
			t.Fatalf("match.Confidence = %q", match.Confidence)
		}
	})

	t.Run("does not match short deploy token", func(t *testing.T) {
		matches := set.Scan(ScanInput{Content: deployPrefix + "tooshort"})
		for _, m := range matches {
			if m.Detector == "gitlab_deploy_token" {
				t.Fatalf("unexpected gitlab_deploy_token match: %#v", m)
			}
		}
	})

	t.Run("detects runner auth token", func(t *testing.T) {
		matches := set.Scan(ScanInput{Content: "RUNNER_TOKEN=" + runnerPrefix + "ABCDEFGHIJKLMNOPQRSTUVWXYZ01"})
		match, ok := findDetectorMatch(matches, "gitlab_runner_token")
		if !ok {
			t.Fatalf("expected gitlab_runner_token in %#v", matches)
		}
		if !strings.HasPrefix(match.Value, "glrt-") {
			t.Fatalf("match.Value = %q", match.Value)
		}
		if match.Confidence != ConfidenceHigh {
			t.Fatalf("match.Confidence = %q", match.Confidence)
		}
	})

	t.Run("does not match short runner token", func(t *testing.T) {
		matches := set.Scan(ScanInput{Content: runnerPrefix + "tooshort"})
		for _, m := range matches {
			if m.Detector == "gitlab_runner_token" {
				t.Fatalf("unexpected gitlab_runner_token match: %#v", m)
			}
		}
	})
}

func findDetectorMatch(matches []Match, detectorName string) (Match, bool) {
	for _, match := range matches {
		if match.Detector == detectorName {
			return match, true
		}
	}

	return Match{}, false
}
