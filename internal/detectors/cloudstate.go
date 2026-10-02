package detectors

import (
	"encoding/base64"
	"regexp"
	"strings"
)

// kubeconfigPathExpression matches the files kubectl and its tooling write:
// ~/.kube/config, a KUBECONFIG file named kubeconfig or *.kubeconfig, and the
// kubeconfig.yaml variants that CI jobs drop into build images.
var kubeconfigPathExpression = regexp.MustCompile(`(^|/)(?:\.kube/config|kubeconfig|kubeconfig\.ya?ml|[^/]+\.kubeconfig)$`)

// base64PEMPrefix is the base64 encoding of "-----BEGIN ", the first bytes of
// every PEM block; a certificate and a private key share it, so a candidate
// is decoded and checked for a private-key header before it is reported.
const base64PEMPrefix = "LS0tLS1CRUdJTi"

// cloudStateDetectors cover the credential caches that cloud CLIs and
// kubectl leave behind and that are routinely baked into CI and build images
// (DET-30): kubeconfig client keys, passwords and tokens, base64-encoded PEM
// private keys wherever they appear, gcloud application-default refresh
// tokens, the Azure CLI token caches and the AWS SSO/CLI caches.
func cloudStateDetectors() []Detector {
	return []Detector{
		// The file format is known, so a value in the documented field is the
		// credential itself: high confidence for every path-gated rule.
		newPathRegexDetector("kubeconfig_client_key_data", kubeconfigPathExpression, regexp.MustCompile(`(?im)^\s*client-key-data:\s*["']?(`+base64PEMPrefix+`[A-Za-z0-9+/=]{40,})`), 1, ConfidenceHigh, looksLikeBase64PEMPrivateKey),
		newPathRegexDetector("kubeconfig_password", kubeconfigPathExpression, regexp.MustCompile(`(?im)^\s+password:\s*["']?([^\s"'#]{4,})`), 1, ConfidenceHigh, looksLikeLiteralPassword),
		newPathRegexDetector("kubeconfig_token", kubeconfigPathExpression, regexp.MustCompile(`(?im)^\s+token:\s+["']?([^\s#"']+)["']?\s*$`), 1, ConfidenceHigh, hasMinPrintableLength(8)),
		// A base64 PEM private key anywhere (Kubernetes Secret manifests,
		// Helm values, kubeconfig files under another name). The prefix is the
		// literal the engine skips to and the decode check rejects
		// certificates and public keys, so the confidence is high.
		newRegexDetector("base64_pem_private_key", regexp.MustCompile(`\b`+base64PEMPrefix+`[A-Za-z0-9+/=]{40,}`), 0, ConfidenceHigh, looksLikeBase64PEMPrivateKey),
		// Google OAuth refresh tokens (gcloud application_default_credentials.json,
		// legacy_credentials/*/adc.json) all start with "1//0". The prefix plus
		// 40 base64url characters has no other common reading: high.
		newRegexDetector("google_oauth_refresh_token", regexp.MustCompile(`\b1//0[A-Za-z0-9_-]{40,}\b`), 0, ConfidenceHigh, nil),
		// ~/.azure/accessTokens.json (legacy, accessToken/refreshToken fields),
		// msal_token_cache.json ("secret" under AccessToken/RefreshToken) and
		// service_principal_entries.json (client_secret).
		newPathRegexDetector("azure_cli_token_cache", regexp.MustCompile(`(^|/)\.azure/[^/]+\.json$`), regexp.MustCompile(`(?i)"(?:accesstoken|refreshtoken|secret|client_secret)"\s*:\s*"([^"\s]{20,})"`), 1, ConfidenceHigh, looksLikeAssignedSensitiveValue),
		// ~/.aws/sso/cache/*.json (accessToken, refreshToken, the botocore
		// client registration's clientSecret) and ~/.aws/cli/cache/*.json
		// (assumed-role SessionToken; the secret key is matched by the AWS rules).
		newPathRegexDetector("aws_sso_cache_token", regexp.MustCompile(`(^|/)\.aws/(?:sso|cli)/cache/[^/]+\.json$`), regexp.MustCompile(`(?i)"(?:accesstoken|refreshtoken|clientsecret|sessiontoken)"\s*:\s*"([^"\s]{20,})"`), 1, ConfidenceHigh, looksLikeAssignedSensitiveValue),
	}
}

// looksLikeBase64PEMPrivateKey decodes the first base64 quantum of a
// candidate and accepts it when the plaintext starts with a PEM private-key
// header. Only a bounded prefix is decoded, so a truncated or very long value
// costs the same as a short one, and a "-----BEGIN CERTIFICATE-----" block
// (client-certificate-data, tls.crt) is rejected.
func looksLikeBase64PEMPrivateKey(value string) bool {
	const probe = 64 // 48 plaintext bytes: longer than any private-key header
	prefix := value
	if len(prefix) > probe {
		prefix = prefix[:probe]
	}
	prefix = prefix[:len(prefix)-len(prefix)%4]
	decoded, err := base64.StdEncoding.DecodeString(prefix)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(prefix, "="))
		if err != nil {
			return false
		}
	}
	return pemBeginExpression.Match(decoded)
}
