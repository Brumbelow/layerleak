package detectors

import (
	"encoding/base64"
	"strings"
	"testing"
)

// Prefixed values are assembled at run time so no token-shaped literal sits
// in the source tree.
var (
	testAtlassianToken  = "ATATT3" + "xFfGF0" + strings.Repeat(testMixedToken, 2) + "=0A1B2C3D"
	testMailgunKey      = "key-" + "0123456789abcdef0123456789abcdef"
	testFacebookToken   = "EAA" + "G" + strings.Repeat(testMixedToken, 2)
	testSupabasePAT     = "sbp_" + "0123456789abcdef0123456789abcdef01234567"
	testDuffelToken     = "duffel_live_" + "Xk9fL2mQ8vR4tY7wZ1aB3cD5eF6gH8jK0lM2nO4pQ6r"
	testFlutterwaveKey  = "FLWSECK-" + "0123456789abcdef0123456789abcdef" + "-X"
	testDropboxToken    = "sl." + strings.Repeat(testMixedToken, 3)
	testAsanaToken      = "1/" + "1234567890123456" + ":" + "0123456789abcdef0123456789abcdef"
	testBitbucketAppPwd = "ATBB" + "Xk9fL2mQ8vR4tY7wZ1aB3cD5eF6gH8jK"
	testTwitchSecret    = "x7k2m9q4w1e8r5t3y6u0i2o5p7a3s9"
)

func supabaseJWT(role string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"supabase","ref":"abcdefghij","role":"` + role + `","iat":1,"exp":2}`))
	return header + "." + payload + ".Xk9fL2mQ8vR4tY7wZ1aB3cD5eF6gH8jK0lM2"
}

// DET-35: long-tail SaaS formats.
func TestSaaSTokenDetectors(t *testing.T) {
	set := Default()
	hex32 := "0123456789abcdef0123456789abcdef"
	tests := []struct {
		name       string
		input      ScanInput
		detector   string
		value      string
		confidence Confidence
	}{
		{name: "atlassian api token", input: ScanInput{Content: "JIRA_API_TOKEN=" + testAtlassianToken}, detector: "atlassian_api_token", value: testAtlassianToken, confidence: ConfidenceHigh},
		{name: "mailgun key prefix", input: ScanInput{Content: "api_key = \"" + testMailgunKey + "\""}, detector: "mailgun_api_key", value: testMailgunKey, confidence: ConfidenceHigh},
		{name: "mailgun signing key by context", input: ScanInput{Key: "MAILGUN_API_KEY", Content: "MAILGUN_API_KEY=" + hex32 + "-01234567-89abcdef"}, detector: "mailgun_api_key", value: hex32 + "-01234567-89abcdef", confidence: ConfidenceHigh},
		{name: "mailgun 72 hex in file", input: ScanInput{Path: "/app/.env", Content: "MAILGUN_API_KEY=" + hex32 + hex32 + "01234567\n"}, detector: "mailgun_api_key", value: hex32 + hex32 + "01234567", confidence: ConfidenceHigh},
		{name: "facebook access token bare", input: ScanInput{Content: "token=" + testFacebookToken}, detector: "facebook_access_token", value: testFacebookToken, confidence: ConfidenceMedium},
		{name: "facebook access token in context", input: ScanInput{Key: "FACEBOOK_ACCESS_TOKEN", Content: "FACEBOOK_ACCESS_TOKEN=" + testFacebookToken}, detector: "facebook_access_token", value: testFacebookToken, confidence: ConfidenceHigh},
		{name: "facebook app secret by key", input: ScanInput{Key: "FACEBOOK_APP_SECRET", Content: "FACEBOOK_APP_SECRET=" + hex32}, detector: "facebook_app_secret", value: hex32, confidence: ConfidenceHigh},
		{name: "facebook app secret in file", input: ScanInput{Path: "/app/config.py", Content: "FB_APP_SECRET = '" + hex32 + "'\n"}, detector: "facebook_app_secret", value: hex32, confidence: ConfidenceHigh},
		{name: "supabase personal access token", input: ScanInput{Content: "SUPABASE_ACCESS_TOKEN=" + testSupabasePAT}, detector: "supabase_personal_access_token", value: testSupabasePAT, confidence: ConfidenceHigh},
		{name: "supabase service role key", input: ScanInput{Content: "SUPABASE_SERVICE_ROLE_KEY=" + supabaseJWT("service_role")}, detector: "supabase_service_role_key", value: supabaseJWT("service_role"), confidence: ConfidenceHigh},
		{name: "algolia admin key by key", input: ScanInput{Key: "ALGOLIA_ADMIN_API_KEY", Content: "ALGOLIA_ADMIN_API_KEY=" + hex32}, detector: "algolia_admin_api_key", value: hex32, confidence: ConfidenceHigh},
		{name: "algolia api key in file", input: ScanInput{Path: "/app/.env", Content: "ALGOLIA_API_KEY=" + hex32 + "\n"}, detector: "algolia_admin_api_key", value: hex32, confidence: ConfidenceHigh},
		{name: "duffel live token", input: ScanInput{Content: "DUFFEL_TOKEN=" + testDuffelToken}, detector: "duffel_api_token", value: testDuffelToken, confidence: ConfidenceHigh},
		{name: "flutterwave secret key", input: ScanInput{Content: "FLW_SECRET_KEY=" + testFlutterwaveKey}, detector: "flutterwave_secret_key", value: testFlutterwaveKey, confidence: ConfidenceHigh},
		{name: "flutterwave test secret key", input: ScanInput{Content: "FLWSECK_TEST-" + hex32 + "-X"}, detector: "flutterwave_secret_key", value: "FLWSECK_TEST-" + hex32 + "-X", confidence: ConfidenceHigh},
		{name: "twitch client secret by key", input: ScanInput{Key: "TWITCH_CLIENT_SECRET", Content: "TWITCH_CLIENT_SECRET=" + testTwitchSecret}, detector: "twitch_api_token", value: testTwitchSecret, confidence: ConfidenceHigh},
		{name: "twitch access token by key", input: ScanInput{Key: "TWITCH_ACCESS_TOKEN", Content: "TWITCH_ACCESS_TOKEN=" + testTwitchSecret}, detector: "twitch_api_token", value: testTwitchSecret, confidence: ConfidenceHigh},
		{name: "twitch oauth token in file", input: ScanInput{Path: "/app/config.yaml", Content: "twitch_oauth_token: " + testTwitchSecret + "\n"}, detector: "twitch_api_token", value: testTwitchSecret, confidence: ConfidenceHigh},
		{name: "twitch client secret in file", input: ScanInput{Path: "/app/config.yaml", Content: "twitch_client_secret: " + testTwitchSecret + "\n"}, detector: "twitch_api_token", value: testTwitchSecret, confidence: ConfidenceHigh},
		{name: "dropbox short-lived token", input: ScanInput{Content: "DROPBOX_TOKEN=" + testDropboxToken}, detector: "dropbox_access_token", value: testDropboxToken, confidence: ConfidenceHigh},
		{name: "asana personal access token", input: ScanInput{Content: "ASANA_ACCESS_TOKEN=" + testAsanaToken}, detector: "asana_personal_access_token", value: testAsanaToken, confidence: ConfidenceHigh},
		{name: "asana token with workspace segment", input: ScanInput{Content: "asana: 2/1234567890123456/6543210987654321:" + strings.Repeat("Ab1cD2eF3g", 4)}, detector: "asana_personal_access_token", value: "2/1234567890123456/6543210987654321:" + strings.Repeat("Ab1cD2eF3g", 4), confidence: ConfidenceHigh},
		{name: "bitbucket app password", input: ScanInput{Content: "https://deploy:" + testBitbucketAppPwd + "@bitbucket.org/org/repo.git"}, detector: "bitbucket_app_password", value: testBitbucketAppPwd, confidence: ConfidenceHigh},
		{name: "kafka jaas config property", input: ScanInput{Path: "/app/kafka.properties", Content: "sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required username=\"app\" password=\"Sup3rS3cretPwXyz\";\n"}, detector: "kafka_sasl_jaas_password", value: "Sup3rS3cretPwXyz", confidence: ConfidenceHigh},
		{name: "kafka jaas conf file", input: ScanInput{Path: "/etc/kafka/jaas.conf", Content: "KafkaClient {\n  org.apache.kafka.common.security.scram.ScramLoginModule required\n  username=\"app\"\n  password=\"Sup3rS3cretPwXyz\";\n};\n"}, detector: "kafka_sasl_jaas_password", value: "Sup3rS3cretPwXyz", confidence: ConfidenceHigh},
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

func TestSaaSTokenDetectorsRejectNearMisses(t *testing.T) {
	set := Default()
	hex32 := "0123456789abcdef0123456789abcdef"
	tests := []struct {
		name     string
		input    ScanInput
		detector string
	}{
		{name: "short atlassian token", input: ScanInput{Content: "ATATT3" + strings.Repeat("a", 40)}, detector: "atlassian_api_token"},
		{name: "mailgun key with 31 hex", input: ScanInput{Content: "key-" + hex32[:31]}, detector: "mailgun_api_key"},
		{name: "mailgun shape without context", input: ScanInput{Content: "id=" + hex32 + "-01234567-89abcdef"}, detector: "mailgun_api_key"},
		{name: "facebook prefix on a padded blob", input: ScanInput{Content: "EAA" + strings.Repeat("A", 120)}, detector: "facebook_access_token"},
		{name: "facebook prefix too short", input: ScanInput{Content: "EAA" + testMixedToken[:40]}, detector: "facebook_access_token"},
		{name: "supabase token wrong length", input: ScanInput{Content: "sbp_" + hex32}, detector: "supabase_personal_access_token"},
		{name: "supabase anon key is not service role", input: ScanInput{Content: supabaseJWT("anon")}, detector: "supabase_service_role_key"},
		{name: "algolia search-only key is public", input: ScanInput{Key: "ALGOLIA_SEARCH_ONLY_API_KEY", Content: "ALGOLIA_SEARCH_ONLY_API_KEY=" + hex32}, detector: "algolia_admin_api_key"},
		{name: "algolia app id", input: ScanInput{Key: "ALGOLIA_APP_ID", Content: "ALGOLIA_APP_ID=" + hex32}, detector: "algolia_admin_api_key"},
		{name: "duffel token wrong length", input: ScanInput{Content: "duffel_live_" + strings.Repeat("a", 20)}, detector: "duffel_api_token"},
		{name: "twitch client id is public", input: ScanInput{Key: "TWITCH_CLIENT_ID", Content: "TWITCH_CLIENT_ID=" + testTwitchSecret}, detector: "twitch_api_token"},
		{name: "twitch client id in file", input: ScanInput{Path: "/app/.env", Content: "twitch_client_id=" + testTwitchSecret + "\n"}, detector: "twitch_api_token"},
		{name: "twitch channel name", input: ScanInput{Key: "TWITCH_CHANNEL", Content: "TWITCH_CHANNEL=" + testTwitchSecret}, detector: "twitch_api_token"},
		{name: "twitch value with uppercase", input: ScanInput{Key: "TWITCH_CLIENT_SECRET", Content: "TWITCH_CLIENT_SECRET=" + strings.ToUpper(testTwitchSecret)}, detector: "twitch_api_token"},
		{name: "twitch value without digits", input: ScanInput{Key: "TWITCH_CLIENT_SECRET", Content: "TWITCH_CLIENT_SECRET=" + strings.Repeat("abcde", 6)}, detector: "twitch_api_token"},
		{name: "dropbox token too short", input: ScanInput{Content: "sl." + strings.Repeat("a", 60)}, detector: "dropbox_access_token"},
		{name: "asana shape without the asana context", input: ScanInput{Content: "TOKEN=" + testAsanaToken}, detector: "asana_personal_access_token"},
		{name: "version path is not an asana token", input: ScanInput{Content: "asana https://app.asana.com/api/1.0/tasks/1234567890123456:subtasks"}, detector: "asana_personal_access_token"},
		{name: "bitbucket prefix too short", input: ScanInput{Content: "ATBB" + strings.Repeat("a", 10)}, detector: "bitbucket_app_password"},
		{name: "kafka jaas password reference", input: ScanInput{Content: "sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required username=\"app\" password=\"${KAFKA_PASSWORD}\";"}, detector: "kafka_sasl_jaas_password"},
		{name: "kafka kerberos module without a password", input: ScanInput{Content: "KafkaClient { com.sun.security.auth.module.Krb5LoginModule required useKeyTab=true keyTab=\"/etc/kafka.keytab\" principal=\"kafka/host@REALM\"; };"}, detector: "kafka_sasl_jaas_password"},
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

// A service-role JWT is reported once, under its own id rather than as a
// generic json_web_token; an anon key stays a json_web_token.
func TestSupabaseServiceRoleKeyOutranksGenericJWT(t *testing.T) {
	set := Default()
	matches := set.Scan(ScanInput{Content: supabaseJWT("service_role")})
	if len(matches) != 1 || matches[0].Detector != "supabase_service_role_key" {
		t.Fatalf("matches = %#v", matches)
	}
	matches = set.Scan(ScanInput{Content: supabaseJWT("anon")})
	if len(matches) != 1 || matches[0].Detector != "json_web_token" {
		t.Fatalf("matches = %#v", matches)
	}
}

// Trailing-dash case: an Atlassian or Dropbox token may end in '-' or '='.
func TestSaaSTokenBoundaries(t *testing.T) {
	set := Default()
	token := "ATATT3" + strings.Repeat(testMixedToken, 2) + "-"
	match, ok := findDetectorMatch(set.Scan(ScanInput{Content: "token: " + token + "\n"}), "atlassian_api_token")
	if !ok || match.Value != token {
		t.Fatalf("atlassian_api_token = %#v, want %q", match, token)
	}
	dropbox := "sl." + strings.Repeat(testMixedToken, 3) + "="
	match, ok = findDetectorMatch(set.Scan(ScanInput{Content: dropbox + " "}), "dropbox_access_token")
	if !ok || match.Value != dropbox {
		t.Fatalf("dropbox_access_token = %#v, want %q", match, dropbox)
	}
}
