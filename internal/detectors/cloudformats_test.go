package detectors

import (
	"strings"
	"testing"
)

// Vendor-prefixed values are assembled from two pieces at run time so that no
// token-shaped literal sits in the source tree (push protection).
var (
	testGoogleClientSecret = "GOCSPX-" + "Xk9fL2mQ8vR4tY7wZ1aB3cD5eF6g"
	testAzureClientSecret  = "aB3" + "8Q~" + "Xk9fL2mQ8vR4tY7wZ1aB3cD5eF6gH8jK0."
	testAzureDevOpsPAT     = strings.Repeat("Ab1cD2eF3g", 7) + "hIjklAZ" + "DOmN8pQ"
	testLegacyDevOpsPAT    = "x7k2m9q4w1e8r5t3y6u0i2o5p7a3s9d1f4g6h8j0k2l5z7x9c1" + "v3"
	testAWSSessionToken    = "IQoJ" + "b3JpZ2luX2VjEJz//////////wEaCWV1LXdlc3QtMSJHMEUCIQD" + strings.Repeat("Ab1cD2eF3g", 8) + "=="
	testAlibabaAccessKeyID = "LTAI" + "5tXk9fL2mQ8vR4tY7wZ1"
	testFlyMacaroon        = "fm2_" + "lJPECAAAAAAAAAFvxBB" + strings.Repeat("Ab1cD2eF3g", 10) + "="
	testTerraformToken     = "Xk9fL2mQ8vR4tY" + ".atlasv1." + strings.Repeat("Ab1cD2eF3g", 6) + "Hi"
	// testMixedToken is a 56-character mixed-alphabet value with enough
	// distinct symbols to clear the entropy floor when repeated.
	testMixedToken = "Xk9fL2mQ8vR4tY7wZ1aB3cD5eF6gH8jK0lM2nO4pQ6rS8tU0vW2xY4z"
)

// DET-32: cloud-provider credential formats.
func TestCloudFormatDetectors(t *testing.T) {
	set := Default()
	sasSignature := "Xk9fL2mQ8vR4tY7wZ1aB3cD5eF6gH8jK0lM2nO4pQ6rS8%3D"
	sasURL := "https://acct.blob.core.windows.net/c?sv=2022-11-02&ss=b&srt=sco&sp=rwdlac&se=2026-01-01T00:00:00Z&spr=https&sig=" + sasSignature
	sharedAccessKey := "Xk9fL2mQ8vR4tY7wZ1aB3cD5eF6gH8jK0lM2nO4pQ6r="
	tests := []struct {
		name     string
		input    ScanInput
		detector string
		value    string
	}{
		{name: "google oauth client secret", input: ScanInput{Content: "GOOGLE_CLIENT_SECRET=" + testGoogleClientSecret}, detector: "google_oauth_client_secret", value: testGoogleClientSecret},
		{name: "azure client secret shape", input: ScanInput{Content: `{"clientSecret": "` + testAzureClientSecret + `"}`}, detector: "azure_client_secret", value: testAzureClientSecret},
		{name: "azure client secret shape at line start", input: ScanInput{Content: testAzureClientSecret + "\n"}, detector: "azure_client_secret", value: testAzureClientSecret},
		{name: "azure client secret by key", input: ScanInput{Key: "AZURE_CLIENT_SECRET", Content: "AZURE_CLIENT_SECRET=Xk9fL2mQ8vR4tY7wZ1aB3cD5eF6gH8jK0lM2nO4p"}, detector: "azure_client_secret", value: "Xk9fL2mQ8vR4tY7wZ1aB3cD5eF6gH8jK0lM2nO4p"},
		{name: "azure sas url", input: ScanInput{Content: "AZURE_STORAGE_SAS_URL=" + sasURL}, detector: "azure_storage_sas_token", value: sasSignature},
		{name: "azure sas connection string", input: ScanInput{Path: "/app/appsettings.json", Content: `"Storage": "BlobEndpoint=https://acct.blob.core.windows.net/;SharedAccessSignature=sv=2022-11-02&ss=b&srt=sco&sp=rwdlac&se=2026-01-01T00:00:00Z&sig=` + sasSignature + `"`}, detector: "azure_storage_sas_token", value: sasSignature},
		{name: "service bus shared access key", input: ScanInput{Content: "Endpoint=sb://ns.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=" + sharedAccessKey}, detector: "azure_shared_access_key", value: sharedAccessKey},
		{name: "azure devops new pat", input: ScanInput{Content: "AZURE_DEVOPS_EXT_PAT=" + testAzureDevOpsPAT}, detector: "azure_devops_personal_access_token", value: testAzureDevOpsPAT},
		{name: "azure devops legacy pat by key", input: ScanInput{Key: "SYSTEM_ACCESSTOKEN", Content: "SYSTEM_ACCESSTOKEN=" + testLegacyDevOpsPAT}, detector: "azure_devops_personal_access_token", value: testLegacyDevOpsPAT},
		{name: "azure devops legacy pat in file", input: ScanInput{Path: "/app/.env", Content: "AZURE_DEVOPS_PAT=" + testLegacyDevOpsPAT + "\n"}, detector: "azure_devops_personal_access_token", value: testLegacyDevOpsPAT},
		{name: "aws session token shape", input: ScanInput{Content: "export AWS_SESSION_TOKEN=" + testAWSSessionToken}, detector: "aws_session_token", value: testAWSSessionToken},
		{name: "aws session token in cli cache json", input: ScanInput{Path: "/app/creds.json", Content: `{"SessionToken": "` + testAWSSessionToken + `"}`}, detector: "aws_session_token", value: testAWSSessionToken},
		{name: "aws session token by key without marker", input: ScanInput{Key: "AWS_SESSION_TOKEN", Content: "AWS_SESSION_TOKEN=" + strings.Repeat(testMixedToken, 2)}, detector: "aws_session_token", value: strings.Repeat(testMixedToken, 2)},
		{name: "alibaba access key id", input: ScanInput{Content: "ALIBABA_CLOUD_ACCESS_KEY_ID=" + testAlibabaAccessKeyID}, detector: "alibaba_access_key_id", value: testAlibabaAccessKeyID},
		{name: "alibaba older access key id", input: ScanInput{Content: "accessKeyId: " + "LTAI" + "Xk9fL2mQ8vR4"}, detector: "alibaba_access_key_id", value: "LTAI" + "Xk9fL2mQ8vR4"},
		{name: "fly macaroon", input: ScanInput{Content: "FLY_API_TOKEN=FlyV1 " + testFlyMacaroon}, detector: "fly_api_token", value: testFlyMacaroon},
		{name: "fly revocable macaroon", input: ScanInput{Content: "fm1r_" + strings.Repeat("Ab1cD2eF3g", 10)}, detector: "fly_api_token", value: "fm1r_" + strings.Repeat("Ab1cD2eF3g", 10)},
		{name: "terraform cloud token in env", input: ScanInput{Content: "TF_TOKEN_app_terraform_io=" + testTerraformToken}, detector: "terraform_cloud_token", value: testTerraformToken},
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
			if match.Confidence != ConfidenceHigh {
				t.Fatalf("match.Confidence = %q", match.Confidence)
			}
			if tt.input.Content[match.Start:match.End] != match.Value {
				t.Fatalf("span [%d:%d] does not address the value", match.Start, match.End)
			}
		})
	}
}

func TestCloudFormatDetectorsRejectNearMisses(t *testing.T) {
	set := Default()
	tests := []struct {
		name     string
		input    ScanInput
		detector string
	}{
		{name: "google client secret wrong length", input: ScanInput{Content: "GOCSPX-" + strings.Repeat("a", 20)}, detector: "google_oauth_client_secret"},
		{name: "azure client secret padded placeholder", input: ScanInput{Content: "aaa" + "8Q~" + strings.Repeat("a", 34)}, detector: "azure_client_secret"},
		{name: "azure client secret glued to a word", input: ScanInput{Content: "prefix" + testAzureClientSecret}, detector: "azure_client_secret"},
		{name: "sig without a signed version field", input: ScanInput{Content: "https://host/path?sig=" + strings.Repeat("Ab1cD2eF3g", 5)}, detector: "azure_storage_sas_token"},
		{name: "shared access key name is not a key", input: ScanInput{Content: "SharedAccessKeyName=RootManageSharedAccessKeyWithAVeryLongName0123"}, detector: "azure_shared_access_key"},
		{name: "shared access key that is not base64", input: ScanInput{Content: "SharedAccessKey=" + strings.Repeat("a", 45)}, detector: "azure_shared_access_key"},
		{name: "azdo marker at the wrong length", input: ScanInput{Content: strings.Repeat("Ab1cD2eF3g", 7) + "AZDO" + "abcdefgh"}, detector: "azure_devops_personal_access_token"},
		{name: "legacy devops pat without context", input: ScanInput{Content: "value=" + testLegacyDevOpsPAT}, detector: "azure_devops_personal_access_token"},
		{name: "legacy devops pat with uppercase", input: ScanInput{Key: "AZURE_DEVOPS_PAT", Content: "AZURE_DEVOPS_PAT=" + strings.ToUpper(testLegacyDevOpsPAT)}, detector: "azure_devops_personal_access_token"},
		{name: "session token shape without the envelope", input: ScanInput{Content: "IQoJ" + strings.Repeat("Ab1cD2eF3g", 11)}, detector: "aws_session_token"},
		{name: "alibaba id too long", input: ScanInput{Content: "LTAI" + strings.Repeat("a", 24)}, detector: "alibaba_access_key_id"},
		{name: "terraform token too short", input: ScanInput{Content: "Xk9fL2mQ8vR4tY.atlasv1." + strings.Repeat("a", 30)}, detector: "terraform_cloud_token"},
		{name: "fly macaroon too short", input: ScanInput{Content: "fm2_" + strings.Repeat("a", 40)}, detector: "fly_api_token"},
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

// Trailing-dash and terminator cases: a client secret may end in '-', a
// Terraform token in '=', and the SAS signature stops at the next '&'.
func TestCloudFormatDetectorBoundaries(t *testing.T) {
	set := Default()
	secret := "aB3" + "8Q~" + "Xk9fL2mQ8vR4tY7wZ1aB3cD5eF6gH8jK0-"
	match, ok := findDetectorMatch(set.Scan(ScanInput{Content: "secret: " + secret + "\n"}), "azure_client_secret")
	if !ok || match.Value != secret {
		t.Fatalf("azure_client_secret = %#v, want %q", match, secret)
	}
	token := "Xk9fL2mQ8vR4tY" + ".atlasv1." + strings.Repeat("Ab1cD2eF3g", 6) + "=="
	match, ok = findDetectorMatch(set.Scan(ScanInput{Content: "credentials \"app.terraform.io\" { token = \"" + token + "\" }"}), "terraform_cloud_token")
	if !ok || match.Value != token {
		t.Fatalf("terraform_cloud_token = %#v, want %q", match, token)
	}
	signature := "Xk9fL2mQ8vR4tY7wZ1aB3cD5eF6gH8jK0lM2nO4pQ6rS8%3D"
	match, ok = findDetectorMatch(set.Scan(ScanInput{Content: "?sv=2022-11-02&sp=r&sig=" + signature + "&sr=b"}), "azure_storage_sas_token")
	if !ok || match.Value != signature {
		t.Fatalf("azure_storage_sas_token = %#v, want %q", match, signature)
	}
}

// A CamelCase policy name such as RootManageSharedAccessKey sits right after
// an "AccessKeyName=" assignment in every Service Bus connection string and
// must not be reported as an entropy candidate.
func TestKeywordEntropySuppressesCamelCaseWordCompounds(t *testing.T) {
	content := "Endpoint=sb://ns.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=Xk9fL2mQ8vR4tY7wZ1aB3cD5eF6gH8jK0lM2nO4pQ6r="
	for _, match := range Default().Scan(ScanInput{Content: content}) {
		if match.Detector == "keyword_entropy" {
			t.Fatalf("unexpected keyword_entropy match: %#v", match)
		}
	}
	if !looksLikeWordCompound("RootManageSharedAccessKey") || !looksLikeWordCompound("defaultServiceAccount") {
		t.Fatal("CamelCase compounds are not recognised")
	}
	for _, value := range []string{"qWeRtYuIoPaSdFgHjKlZxCvB", "Xk9fL2mQ8vR4tY7wZ1aB3cD5", "ROOTMANAGESHAREDACCESSKEY"} {
		if looksLikeWordCompound(value) {
			t.Fatalf("%q treated as a word compound", value)
		}
	}
}
