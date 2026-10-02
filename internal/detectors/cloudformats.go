package detectors

import (
	"encoding/base64"
	"regexp"
	"strings"
)

// cloudFormatDetectors cover the cloud-provider credential formats the rule
// set lagged behind (DET-32): Google OAuth client secrets, Azure AD client
// secrets, Azure storage SAS signatures, Service Bus / Event Hub / IoT Hub
// SharedAccessKey connection strings, Azure DevOps personal access tokens,
// AWS session tokens outside ~/.aws, Alibaba Cloud access key ids and
// Terraform Cloud tokens outside .terraformrc. Fly.io macaroons extend the
// existing fly_api_token rule in Default().
func cloudFormatDetectors() []Detector {
	const azureEntraValueClass = `[A-Za-z0-9_~.-]`
	return []Detector{
		// Google Cloud Console issues OAuth client secrets as GOCSPX- plus 28
		// base64url characters; nothing else carries the prefix: high.
		newRegexDetector("google_oauth_client_secret", regexp.MustCompile(`\bGOCSPX-[A-Za-z0-9_-]{28}\b`), 0, ConfidenceHigh, nil),
		// Azure AD application secrets are 37-40 characters whose fourth to
		// sixth characters are a digit followed by "Q~" (the gitleaks shape).
		// The bigram is the prefilter and an entropy check rejects padded
		// placeholders, so the shape alone is high; the key-context rule picks
		// up older secrets that predate the marker.
		newRegexDetector("azure_client_secret", regexp.MustCompile(`(?:^|[^A-Za-z0-9_~.-])([A-Za-z0-9_~.]{3}[0-9]Q~`+azureEntraValueClass+`{31,34})(?:[^A-Za-z0-9_~.-]|$)`), 1, ConfidenceHigh, looksLikeAzureClientSecret).requiring("Q~"),
		newKeyValueDetector("azure_client_secret", regexp.MustCompile(`(?i)(?:azure|arm|aad|entra)[_-]?client[_-]?secret`), regexp.MustCompile(azureEntraValueClass+`{32,44}`), ConfidenceHigh, looksLikeAssignedSensitiveValue),
		// A storage SAS is a query string whose signature field follows the
		// signed version (sv=) field; the sig value is the HMAC and the only
		// secret part. Runs on the lowered content so SharedAccessSignature=
		// connection strings and URLs match alike.
		newRegexDetector("azure_storage_sas_token", regexp.MustCompile(`sv=\d{4}-\d{2}-\d{2}[^\s"'<>]*?&sig=([a-z0-9%+/=]{40,})`), 1, ConfidenceHigh, nil).onLoweredContent().requiring("sig="),
		// Service Bus, Event Hubs and IoT Hub connection strings carry the
		// 32-byte key as SharedAccessKey=<base64>; the name field before it is
		// SharedAccessKeyName= and does not match. The key must decode: high.
		newRegexDetector("azure_shared_access_key", regexp.MustCompile(`sharedaccesskey=([a-z0-9+/]{32,}={0,2})`), 1, ConfidenceHigh, decodesAsBase64).onLoweredContent(),
		// Azure DevOps PATs are 84 alphanumerics with the fixed AZDO signature
		// near the end (Microsoft documents the format for secret detection);
		// legacy PATs are 52 lowercase base32 characters and need the key
		// context. Both are high: the signature or the explicit key names the
		// credential.
		newRegexDetector("azure_devops_personal_access_token", regexp.MustCompile(`\b[A-Za-z0-9]{70,78}AZDO[A-Za-z0-9]{2,10}\b`), 0, ConfidenceHigh, hasExactLength(84)).requiring("AZDO"),
		newKeyValueDetector("azure_devops_personal_access_token", regexp.MustCompile(`(?i)(?:azure[_-]?devops|azdo|vsts|tfs)[_-]?(?:ext[_-]?)?(?:pat|token|access[_-]?token)|ado[_-]?pat|system[_-]?accesstoken`), regexp.MustCompile(`\b[a-z0-9]{52}\b`), ConfidenceHigh, isLowercaseAlphanumeric),
		newRegexDetector("azure_devops_personal_access_token", regexp.MustCompile(assignedValuePattern(`(?:azure_devops(?:_ext)?_(?:pat|token)|azdo_(?:pat|token)|vsts_(?:pat|token)|ado_pat|system_accesstoken)`, `[a-z0-9]{52}`, `\b`)), 1, ConfidenceHigh, isLowercaseAlphanumeric).onLoweredContent().requiring("azure_devops", "azdo_", "vsts_", "ado_pat", "system_accesstoken"),
		// AWS session tokens are base64 whose plaintext starts with a protobuf
		// envelope: "IQoJ" decodes to the "origin_ec" marker and "FQoG"/"FwoG"
		// to "er/aws". The decode check makes the bare shape high; the key
		// context covers tokens assigned without the marker.
		newRegexDetector("aws_session_token", regexp.MustCompile(`\b(?:IQoJ|FQoG|FwoG)[A-Za-z0-9+/=]{100,}`), 0, ConfidenceHigh, looksLikeAWSSessionTokenBlob).requiring("IQoJ", "FQoG", "FwoG"),
		newKeyValueDetector("aws_session_token", regexp.MustCompile(`(?i)aws[_-]?session[_-]?token`), regexp.MustCompile(`[A-Za-z0-9+/=]{100,}`), ConfidenceHigh, looksLikeAWSSessionToken),
		newRegexDetector("aws_session_token", regexp.MustCompile(assignedValuePattern(`(?:aws_)?session_?token`, `[a-z0-9+/=]{100,}`, ``)), 1, ConfidenceHigh, looksLikeAWSSessionToken).onLoweredContent().requiring("session_token", "sessiontoken"),
		// Alibaba Cloud AccessKey ids are LTAI plus 12 (older) or 20 (current)
		// alphanumerics. Like aws_access_key_id it pairs with a secret and is
		// reported at the same confidence.
		newRegexDetector("alibaba_access_key_id", regexp.MustCompile(`\bLTAI[A-Za-z0-9]{12,20}\b`), 0, ConfidenceHigh, nil),
		// Terraform Cloud / Enterprise tokens: 14 characters, ".atlasv1.", then
		// 60-70 characters. Same id as the .terraformrc reader.
		newRegexDetector("terraform_cloud_token", regexp.MustCompile(`\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_=-]{60,70}\b`), 0, ConfidenceHigh, nil).requiring(".atlasv1."),
	}
}

// looksLikeAzureClientSecret checks the 37-40 character length of the marked
// shape and rejects padded or repeated placeholders by entropy.
func looksLikeAzureClientSecret(value string) bool {
	return len(value) >= 37 && len(value) <= 40 && passesEntropy(value)
}

// looksLikeAWSSessionTokenBlob decodes the first base64 quantum of a token
// and accepts it when the plaintext carries the AWS STS envelope marker.
func looksLikeAWSSessionTokenBlob(value string) bool {
	if len(value) < 16 {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(value[:16])
	if err != nil {
		return false
	}
	text := string(decoded)
	return strings.Contains(text, "origin_ec") || strings.Contains(text, "er/aws")
}

func decodesAsBase64(value string) bool {
	_, err := base64.StdEncoding.DecodeString(value)
	return err == nil
}

func hasExactLength(length int) func(string) bool {
	return func(value string) bool {
		return len(value) == length
	}
}

func isLowercaseAlphanumeric(value string) bool {
	if value == "" {
		return false
	}
	for index := 0; index < len(value); index++ {
		b := value[index]
		if (b < 'a' || b > 'z') && (b < '0' || b > '9') {
			return false
		}
	}
	return true
}
