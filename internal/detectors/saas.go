package detectors

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
)

// saasTokenDetectors cover the long tail of SaaS credential formats
// (DET-35): Atlassian API tokens, Mailgun keys, Facebook access tokens and app
// secrets, Supabase personal access tokens and service-role JWTs, Algolia
// admin keys, Duffel and Flutterwave keys, Twitch client secrets, Dropbox
// short-lived tokens, Asana personal access tokens, Bitbucket app passwords
// and Kafka SASL JAAS passwords. Shapes follow gitleaks and trufflehog where
// those projects have a rule and the vendor's documentation otherwise.
func saasTokenDetectors() []Detector {
	return []Detector{
		// ATATT3 plus base64url: the prefix is unique to Atlassian Cloud: high.
		newRegexDetector("atlassian_api_token", regexp.MustCompile(`\bATATT3[A-Za-z0-9_=-]{100,}\b`), 0, ConfidenceHigh, nil),
		// Mailgun private keys are "key-" plus 32 hex anywhere; the newer
		// 32-8-8 hex and 72-hex forms need the mailgun key context.
		newRegexDetector("mailgun_api_key", regexp.MustCompile(`\bkey-[0-9a-f]{32}\b`), 0, ConfidenceHigh, nil),
		newKeyValueDetector("mailgun_api_key", regexp.MustCompile(`(?i)mailgun`), regexp.MustCompile(`\b(?:key-[0-9a-f]{32}|[0-9a-f]{32}-[0-9a-f]{8}-[0-9a-f]{8}|[0-9a-f]{72})\b`), ConfidenceHigh, nil),
		newRegexDetector("mailgun_api_key", regexp.MustCompile(assignedValuePattern(`mailgun[a-z_-]{0,30}`, `[0-9a-f]{32}-[0-9a-f]{8}-[0-9a-f]{8}|[0-9a-f]{72}`, `\b`)), 1, ConfidenceHigh, nil).onLoweredContent(),
		// Facebook/Meta user and page tokens start with EAA and run to 100+
		// alphanumerics. The prefix is three letters any base64 blob can start
		// with, so the bare shape is medium (entropy-checked) and the usual
		// FACEBOOK_ACCESS_TOKEN key or path context promotes it.
		newRegexDetector("facebook_access_token", regexp.MustCompile(`\bEAA[A-Za-z0-9]{80,}\b`), 0, ConfidenceMedium, looksLikeFacebookAccessToken),
		newKeyValueDetector("facebook_app_secret", regexp.MustCompile(`(?i)(?:facebook|fb)[_-]?(?:app[_-]?)?secret`), regexp.MustCompile(`\b[a-f0-9]{32}\b`), ConfidenceHigh, nil),
		newRegexDetector("facebook_app_secret", regexp.MustCompile(assignedValuePattern(`(?:facebook|fb)_(?:app_)?secret`, `[a-f0-9]{32}`, `\b`)), 1, ConfidenceHigh, nil).onLoweredContent().requiring("facebook_secret", "facebook_app_secret", "fb_secret", "fb_app_secret"),
		// Supabase personal access tokens are sbp_ plus 40 hex (the dashboard
		// shows "sbp_bdd0...4f23"); a service-role key is a JWT whose payload
		// says so, which the validator decodes, so both are high.
		newRegexDetector("supabase_personal_access_token", regexp.MustCompile(`\bsbp_[a-f0-9]{40}\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("supabase_service_role_key", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`), 0, ConfidenceHigh, looksLikeSupabaseServiceRoleKey),
		// Algolia admin/write keys are 32 hex and only identifiable by their
		// key name (ALGOLIA_ADMIN_API_KEY, ALGOLIA_API_KEY, ALGOLIA_WRITE_API_KEY,
		// ALGOLIA_SECRET); search-only keys are public and their names
		// (ALGOLIA_SEARCH_*) do not match.
		newKeyValueDetector("algolia_admin_api_key", regexp.MustCompile(`(?i)algolia[_-]?(?:(?:admin|write)[_-]?)?(?:api[_-]?)?(?:key|secret)`), regexp.MustCompile(`\b[a-f0-9]{32}\b`), ConfidenceHigh, nil),
		newRegexDetector("algolia_admin_api_key", regexp.MustCompile(assignedValuePattern(`algolia_(?:(?:admin|write)_)?(?:api_)?(?:key|secret)`, `[a-f0-9]{32}`, `\b`)), 1, ConfidenceHigh, nil).onLoweredContent(),
		newRegexDetector("duffel_api_token", regexp.MustCompile(`\bduffel_(?:test|live)_[A-Za-z0-9_=-]{43}\b`), 0, ConfidenceHigh, nil).requiring("duffel_test_", "duffel_live_"),
		newRegexDetector("flutterwave_secret_key", regexp.MustCompile(`\bFLWSECK(?:_TEST)?-[0-9a-fA-F]{32}-X\b`), 0, ConfidenceHigh, nil),
		// Twitch client secrets and OAuth tokens are 30 lowercase alphanumerics
		// with no prefix, so a twitch key naming a secret, token, oauth value
		// or password is required: high. The public client id has the same
		// shape and sits next to the secret in every Twitch app's
		// configuration (TWITCH_CLIENT_ID), so the key must carry a credential
		// word after "twitch".
		newKeyValueDetector("twitch_api_token", regexp.MustCompile(`(?i)twitch[a-z0-9_-]*(?:secret|token|oauth|password)`), regexp.MustCompile(`\b[a-z0-9]{30}\b`), ConfidenceHigh, looksLikeTwitchToken),
		newRegexDetector("twitch_api_token", regexp.MustCompile(assignedValuePattern(`twitch[a-z0-9_-]{0,30}(?:secret|token|oauth|password)[a-z0-9_-]{0,10}`, `[a-z0-9]{30}`, `\b`)), 1, ConfidenceHigh, looksLikeTwitchToken).onLoweredContent(),
		// Dropbox short-lived tokens: "sl." plus 130+ base64url characters.
		newRegexDetector("dropbox_access_token", regexp.MustCompile(`\bsl\.[A-Za-z0-9_=-]{130,}\b`), 0, ConfidenceHigh, nil),
		// Asana PATs are "<version>/<16+ digit user id>:<32+ alphanumerics>"
		// (trufflehog); the digits-slash-colon shape has no literal to skip
		// to, so the word "asana" must appear in the content.
		newRegexDetector("asana_personal_access_token", regexp.MustCompile(`\b(?i)[0-9]{1,2}/[0-9]{16,}(?:/[0-9]{16,})?:[a-z0-9]{32,}\b`), 0, ConfidenceHigh, nil).requiring("asana"),
		// Bitbucket app passwords start with ATBB (trufflehog): high.
		newRegexDetector("bitbucket_app_password", regexp.MustCompile(`\bATBB[A-Za-z0-9_=-]{28,}\b`), 0, ConfidenceHigh, nil),
		// Kafka JAAS: `... PlainLoginModule required username="u" password="p";`
		// in sasl.jaas.config properties, KAFKA_SASL_JAAS_CONFIG values and
		// jaas.conf files. The password is a literal inside the quotes: high.
		newRegexDetector("kafka_sasl_jaas_password", regexp.MustCompile(`loginmodule\s+required[^;]*?password\s*=\s*["']([^"'\s;]{4,})["']`), 1, ConfidenceHigh, looksLikeLiteralPassword).onLoweredContent(),
	}
}

func looksLikeFacebookAccessToken(value string) bool {
	return hasStrongEntropyShape(value) && passesEntropy(value)
}

// looksLikeSupabaseServiceRoleKey accepts a JWT whose payload carries
// "role": "service_role", the privileged Supabase API key.
func looksLikeSupabaseServiceRoleKey(value string) bool {
	if !looksLikeJWT(value) {
		return false
	}
	parts := strings.Split(value, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		payload, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return false
		}
	}
	var claims struct {
		Role string `json:"role"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return false
	}
	return claims.Role == "service_role"
}

// looksLikeTwitchToken requires the lowercase alphanumeric alphabet with at
// least one digit and one letter, so a 30-letter word never matches.
func looksLikeTwitchToken(value string) bool {
	if !isLowercaseAlphanumeric(value) {
		return false
	}
	hasDigit, hasLetter := false, false
	for index := 0; index < len(value); index++ {
		if value[index] >= '0' && value[index] <= '9' {
			hasDigit = true
		} else {
			hasLetter = true
		}
	}
	return hasDigit && hasLetter
}
