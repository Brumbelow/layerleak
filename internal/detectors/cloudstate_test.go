package detectors

import (
	"encoding/base64"
	"strings"
	"testing"
)

// testPEMKey is a synthetic PEM private key with a short body; the base64 of
// the whole block is what kubeconfig and Secret manifests carry.
const testPEMKey = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n-----END RSA PRIVATE KEY-----\n"

func base64PEM(block string) string {
	return base64.StdEncoding.EncodeToString([]byte(block))
}

// DET-30: Kubernetes and cloud-CLI state files.
func TestCloudStateDetectors(t *testing.T) {
	set := Default()
	keyData := base64PEM(testPEMKey)
	refreshToken := "1//0" + "eXk9fL2mQ8vR4tY7wZ1aB3cD5eF6gH8jK0lM2nO4pQ6rS8tU0vW2xY4z"
	jwt := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.Xk9fL2mQ8vR4tY7wZ1aB3cD5eF6gH8jK0lM2"
	tests := []struct {
		name       string
		input      ScanInput
		detector   string
		value      string
		confidence Confidence
	}{
		{name: "kubeconfig client-key-data", input: ScanInput{Path: "/root/.kube/config", Content: "users:\n- name: admin\n  user:\n    client-certificate-data: " + base64PEM("-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n") + "\n    client-key-data: " + keyData + "\n"}, detector: "kubeconfig_client_key_data", value: keyData, confidence: ConfidenceHigh},
		{name: "kubeconfig named file", input: ScanInput{Path: "/ci/cluster.kubeconfig", Content: "    client-key-data: " + keyData + "\n"}, detector: "kubeconfig_client_key_data", value: keyData, confidence: ConfidenceHigh},
		{name: "kubeconfig password", input: ScanInput{Path: "/root/.kube/config", Content: "users:\n- name: admin\n  user:\n    username: admin\n    password: Sup3rS3cretPwXyz\n"}, detector: "kubeconfig_password", value: "Sup3rS3cretPwXyz", confidence: ConfidenceHigh},
		{name: "kubeconfig quoted token", input: ScanInput{Path: "/root/.kube/config", Content: "users:\n- name: sa\n  user:\n    token: \"" + jwt + "\"\n"}, detector: "kubeconfig_token", value: jwt, confidence: ConfidenceHigh},
		{name: "base64 pem in secret manifest", input: ScanInput{Path: "/app/manifests/tls.yaml", Content: "data:\n  tls.crt: " + base64PEM("-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n") + "\n  tls.key: " + keyData + "\n"}, detector: "base64_pem_private_key", value: keyData, confidence: ConfidenceHigh},
		{name: "base64 openssh key", input: ScanInput{Content: base64PEM("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n-----END OPENSSH PRIVATE KEY-----\n")}, detector: "base64_pem_private_key", value: base64PEM("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n-----END OPENSSH PRIVATE KEY-----\n"), confidence: ConfidenceHigh},
		{name: "gcloud adc refresh token", input: ScanInput{Path: "/root/.config/gcloud/application_default_credentials.json", Content: `{"client_id":"1234-abc.apps.googleusercontent.com","refresh_token":"` + refreshToken + `","type":"authorized_user"}`}, detector: "google_oauth_refresh_token", value: refreshToken, confidence: ConfidenceHigh},
		{name: "refresh token in env", input: ScanInput{Content: "GOOGLE_REFRESH_TOKEN=" + refreshToken}, detector: "google_oauth_refresh_token", value: refreshToken, confidence: ConfidenceHigh},
		{name: "azure legacy accessTokens.json", input: ScanInput{Path: "/root/.azure/accessTokens.json", Content: `[{"tokenType":"Bearer","accessToken":"` + jwt + `","refreshToken":"Xk9fL2mQ8vR4tY7wZ1aB3cD5eF6gH8jK0lM2nO4pQ6"}]`}, detector: "azure_cli_token_cache", value: jwt, confidence: ConfidenceHigh},
		{name: "azure msal token cache", input: ScanInput{Path: "/root/.azure/msal_token_cache.json", Content: `{"AccessToken":{"id-x":{"secret":"` + jwt + `","credential_type":"AccessToken"}}}`}, detector: "azure_cli_token_cache", value: jwt, confidence: ConfidenceHigh},
		{name: "azure service principal entries", input: ScanInput{Path: "/root/.azure/service_principal_entries.json", Content: `[{"client_id":"00000000-0000-0000-0000-000000000000","client_secret":"Xk9fL2mQ8vR4tY7wZ1aB3cD5eF6gH8jK0lM2nO4pQ6","tenant":"t"}]`}, detector: "azure_cli_token_cache", value: "Xk9fL2mQ8vR4tY7wZ1aB3cD5eF6gH8jK0lM2nO4pQ6", confidence: ConfidenceHigh},
		{name: "aws sso cache access token", input: ScanInput{Path: "/root/.aws/sso/cache/0123456789abcdef0123456789abcdef01234567.json", Content: `{"startUrl":"https://org.awsapps.com/start","region":"eu-west-1","accessToken":"` + jwt + `","expiresAt":"2026-01-01T00:00:00Z"}`}, detector: "aws_sso_cache_token", value: jwt, confidence: ConfidenceHigh},
		{name: "aws sso botocore client secret", input: ScanInput{Path: "/root/.aws/sso/cache/botocore-client-id-eu-west-1.json", Content: `{"clientId":"abc","clientSecret":"` + jwt + `"}`}, detector: "aws_sso_cache_token", value: jwt, confidence: ConfidenceHigh},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := set.Scan(tt.input)
			match, ok := findDetectorMatch(matches, tt.detector)
			if !ok {
				t.Fatalf("expected %s in %#v", tt.detector, matches)
			}
			if match.Value != tt.value {
				t.Fatalf("match.Value = %q, want %q", match.Value, tt.value)
			}
			if match.Confidence != tt.confidence {
				t.Fatalf("match.Confidence = %q, want %q", match.Confidence, tt.confidence)
			}
			if tt.input.Content[match.Start:match.End] != match.Value {
				t.Fatalf("span [%d:%d] does not address the value", match.Start, match.End)
			}
		})
	}
}

func TestCloudStateDetectorsRejectCertificatesAndReferences(t *testing.T) {
	set := Default()
	certificate := base64PEM("-----BEGIN CERTIFICATE-----\nMIICljCCAX4CCQCKz\n-----END CERTIFICATE-----\n")
	publicKey := base64PEM("-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf\n-----END PUBLIC KEY-----\n")
	tests := []struct {
		name     string
		input    ScanInput
		detector string
	}{
		{name: "client-certificate-data is not a key", input: ScanInput{Path: "/root/.kube/config", Content: "    client-certificate-data: " + certificate + "\n"}, detector: "kubeconfig_client_key_data"},
		{name: "base64 certificate anywhere", input: ScanInput{Content: certificate}, detector: "base64_pem_private_key"},
		{name: "base64 public key anywhere", input: ScanInput{Content: publicKey}, detector: "base64_pem_private_key"},
		{name: "kubeconfig password placeholder", input: ScanInput{Path: "/root/.kube/config", Content: "    password: ${KUBE_PASSWORD}\n"}, detector: "kubeconfig_password"},
		{name: "kubeconfig password outside the kubeconfig", input: ScanInput{Path: "/app/config.yaml", Content: "    password: Sup3rS3cretPwXyz\n"}, detector: "kubeconfig_password"},
		{name: "python floor division is not a refresh token", input: ScanInput{Content: "x = 1//0 if y else 2//0\n"}, detector: "google_oauth_refresh_token"},
		{name: "short refresh token", input: ScanInput{Content: "1//0" + strings.Repeat("a", 20)}, detector: "google_oauth_refresh_token"},
		{name: "azure profile without secrets", input: ScanInput{Path: "/root/.azure/azureProfile.json", Content: `{"subscriptions":[{"id":"00000000-0000-0000-0000-000000000000","name":"prod","state":"Enabled"}]}`}, detector: "azure_cli_token_cache"},
		{name: "aws sso cache outside the cache directory", input: ScanInput{Path: "/app/cache/token.json", Content: `{"accessToken":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.Xk9fL2mQ8vR4tY7wZ1aB3cD5eF6gH8jK0lM2"}`}, detector: "aws_sso_cache_token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, match := range set.Scan(tt.input) {
				if match.Detector == tt.detector {
					t.Fatalf("unexpected %s match: %#v", tt.detector, match)
				}
			}
		})
	}
}

// The refresh-token rule must keep a trailing '-' inside the value and stop
// at the first character outside the token alphabet.
func TestGoogleRefreshTokenBoundaries(t *testing.T) {
	token := "1//0" + strings.Repeat("Ab1-", 12) + "-"
	match, ok := findDetectorMatch(Default().Scan(ScanInput{Content: `{"refresh_token": "` + token + `"}`}), "google_oauth_refresh_token")
	if !ok || match.Value != token {
		t.Fatalf("match = %#v, want value %q", match, token)
	}
}
