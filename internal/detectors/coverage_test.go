package detectors

import (
	"encoding/base64"
	"strings"
	"testing"
)

// Coverage additions (DET-29, DET-31, DET-33), one synthetic fixture per rule
// in the vendor shape the ledger verified.
func TestCoverageDetectors(t *testing.T) {
	set := Default()
	hex40 := strings.Repeat("0123456789abcdef", 3)[:40]
	dockerAuth := base64.StdEncoding.EncodeToString([]byte("deploy:Sup3rS3cretPwXyz"))
	dockerConfig := base64.StdEncoding.EncodeToString([]byte(`{"auths":{"registry.internal":{"auth":"` + dockerAuth + `"}}}`))
	tests := []struct {
		name     string
		input    ScanInput
		detector string
		value    string
	}{
		// DET-33
		{name: "slack app token", input: ScanInput{Content: "SLACK_APP_TOKEN=xapp-1-A0123456789-1234567890123-" + strings.Repeat("a1", 32)}, detector: "slack_token", value: "xapp-1-A0123456789-1234567890123-" + strings.Repeat("a1", 32)},
		{name: "slack config refresh token", input: ScanInput{Content: "xoxe-1-" + strings.Repeat("A", 146)}, detector: "slack_token", value: "xoxe-1-" + strings.Repeat("A", 146)},
		{name: "slack config access token", input: ScanInput{Content: "xoxe.xoxp-1-" + strings.Repeat("B", 164)}, detector: "slack_token", value: "xoxe.xoxp-1-" + strings.Repeat("B", 164)},
		{name: "gitlab pipeline trigger token", input: ScanInput{Content: "glptt-" + hex40}, detector: "gitlab_pipeline_trigger_token", value: "glptt-" + hex40},
		{name: "gitlab oauth application secret", input: ScanInput{Content: "gloas-" + strings.Repeat("A", 64)}, detector: "gitlab_oauth_application_secret", value: "gloas-" + strings.Repeat("A", 64)},
		{name: "gitlab agent token", input: ScanInput{Content: "glagent-" + strings.Repeat("A", 50)}, detector: "gitlab_agent_token", value: "glagent-" + strings.Repeat("A", 50)},
		{name: "gitlab scim token", input: ScanInput{Content: "glsoat-" + strings.Repeat("A", 20)}, detector: "gitlab_scim_token", value: "glsoat-" + strings.Repeat("A", 20)},
		{name: "gitlab feature flag client token", input: ScanInput{Content: "glffct-" + strings.Repeat("A", 20)}, detector: "gitlab_feature_flag_client_token", value: "glffct-" + strings.Repeat("A", 20)},
		{name: "gitlab incoming mail token", input: ScanInput{Content: "glimt-" + strings.Repeat("A", 25)}, detector: "gitlab_incoming_mail_token", value: "glimt-" + strings.Repeat("A", 25)},
		{name: "gitlab ci job token", input: ScanInput{Content: "CI_JOB_TOKEN=glcbt-1a_" + strings.Repeat("A", 20)}, detector: "gitlab_ci_job_token", value: "glcbt-1a_" + strings.Repeat("A", 20)},
		{name: "gitlab feed token", input: ScanInput{Content: "glft-" + strings.Repeat("A", 20)}, detector: "gitlab_feed_token", value: "glft-" + strings.Repeat("A", 20)},
		{name: "gitlab runner registration token", input: ScanInput{Content: "GR1348941" + strings.Repeat("A", 20)}, detector: "gitlab_runner_registration_token", value: "GR1348941" + strings.Repeat("A", 20)},
		{name: "openai service account key", input: ScanInput{Content: "OPENAI_API_KEY=sk-svcacct-" + strings.Repeat("A", 100)}, detector: "openai_api_key", value: "sk-svcacct-" + strings.Repeat("A", 100)},
		{name: "openai key with marker", input: ScanInput{Content: "sk-" + strings.Repeat("a", 24) + "T3BlbkFJ" + strings.Repeat("b", 30)}, detector: "openai_api_key", value: "sk-" + strings.Repeat("a", 24) + "T3BlbkFJ" + strings.Repeat("b", 30)},
		{name: "notion ntn token", input: ScanInput{Content: "NOTION_TOKEN=ntn_12345678901" + strings.Repeat("A", 35)}, detector: "notion_integration_token", value: "ntn_12345678901" + strings.Repeat("A", 35)},
		{name: "sonarqube user token", input: ScanInput{Content: "SONAR_TOKEN=squ_" + hex40}, detector: "sonarqube_token", value: "squ_" + hex40},
		{name: "sonarqube project token", input: ScanInput{Content: "sqp_" + hex40}, detector: "sonarqube_token", value: "sqp_" + hex40},
		{name: "grafana cloud token", input: ScanInput{Content: "GRAFANA_CLOUD_TOKEN=glc_" + strings.Repeat("A", 40) + "=="}, detector: "grafana_cloud_api_token", value: "glc_" + strings.Repeat("A", 40) + "=="},
		{name: "sentry organization token", input: ScanInput{Content: "sntrys_eyJ" + strings.Repeat("a", 40) + "_" + strings.Repeat("b", 40)}, detector: "sentry_organization_token", value: "sntrys_eyJ" + strings.Repeat("a", 40) + "_" + strings.Repeat("b", 40)},
		{name: "new relic insert key", input: ScanInput{Content: "NRII-" + strings.Repeat("A", 32)}, detector: "new_relic_insights_key", value: "NRII-" + strings.Repeat("A", 32)},
		{name: "new relic license key", input: ScanInput{Content: "NEW_RELIC_LICENSE_KEY=" + strings.Repeat("a1", 18) + "NRAL"}, detector: "new_relic_license_key", value: strings.Repeat("a1", 18) + "NRAL"},
		{name: "planetscale password", input: ScanInput{Content: "pscale_pw_" + strings.Repeat("A", 32)}, detector: "planetscale_password", value: "pscale_pw_" + strings.Repeat("A", 32)},
		{name: "planetscale oauth token", input: ScanInput{Content: "pscale_oauth_" + strings.Repeat("A", 32)}, detector: "planetscale_oauth_token", value: "pscale_oauth_" + strings.Repeat("A", 32)},
		{name: "circleci project token", input: ScanInput{Content: "CCIPRJ_" + strings.Repeat("A", 22) + "_" + hex40}, detector: "circleci_project_api_token", value: "CCIPRJ_" + strings.Repeat("A", 22) + "_" + hex40},
		{name: "twilio api key", input: ScanInput{Content: "TWILIO_API_KEY=SK" + strings.Repeat("a1", 16)}, detector: "twilio_api_key", value: "SK" + strings.Repeat("a1", 16)},
		{name: "datadog application key", input: ScanInput{Key: "DD_APP_KEY", Content: "DD_APP_KEY=" + hex40}, detector: "datadog_application_key", value: hex40},
		// DET-29
		{name: "docker hub pat", input: ScanInput{Content: "DOCKER_TOKEN=dckr_pat_" + strings.Repeat("A", 27)}, detector: "docker_hub_personal_access_token", value: "dckr_pat_" + strings.Repeat("A", 27)},
		{name: "docker hub org token", input: ScanInput{Content: "dckr_oat_" + strings.Repeat("A", 32)}, detector: "docker_hub_organization_access_token", value: "dckr_oat_" + strings.Repeat("A", 32)},
		{name: "kubernetes dockerconfigjson", input: ScanInput{Path: "/app/manifests/regcred.yaml", Content: "data:\n  .dockerconfigjson: " + dockerConfig + "\n"}, detector: "docker_config_json_blob", value: dockerConfig},
		{name: "docker registrytoken", input: ScanInput{Path: "/root/.docker/config.json", Content: `{"auths":{"r.internal":{"registrytoken":"Xk9fL2mQ8vR4tY7wZ1aB3cD5eF6gH8jK0"}}}`}, detector: "docker_config_registry_token", value: "Xk9fL2mQ8vR4tY7wZ1aB3cD5eF6gH8jK0"},
		{name: "artifactory reference token", input: ScanInput{Content: "cmVmdGtuOjAx" + strings.Repeat("A", 44)}, detector: "artifactory_reference_token", value: "cmVmdGtuOjAx" + strings.Repeat("A", 44)},
		{name: "artifactory api key", input: ScanInput{Content: "AKCp" + strings.Repeat("A", 69)}, detector: "artifactory_api_key", value: "AKCp" + strings.Repeat("A", 69)},
		{name: "rubygems api key", input: ScanInput{Path: "/root/.gem/credentials", Content: ":rubygems_api_key: rubygems_" + strings.Repeat("0123456789abcdef", 3)}, detector: "rubygems_api_key", value: "rubygems_" + strings.Repeat("0123456789abcdef", 3)},
		{name: "nuget api key", input: ScanInput{Content: "oy2" + strings.Repeat("a", 43)}, detector: "nuget_api_key", value: "oy2" + strings.Repeat("a", 43)},
		{name: "crates io token", input: ScanInput{Path: "/root/.cargo/credentials.toml", Content: "[registry]\ntoken = \"cio" + strings.Repeat("A", 32) + "\"\n"}, detector: "crates_io_token", value: "cio" + strings.Repeat("A", 32)},
		{name: "maven settings password", input: ScanInput{Path: "/root/.m2/settings.xml", Content: "<servers><server><id>nexus</id><username>deploy</username><password>Sup3rS3cretPw</password></server></servers>"}, detector: "maven_settings_password", value: "Sup3rS3cretPw"},
		{name: "my.cnf password", input: ScanInput{Path: "/root/.my.cnf", Content: "[client]\nuser=root\npassword=Sup3rS3cretPw\n"}, detector: "mysql_client_password", value: "Sup3rS3cretPw"},
		{name: "pgpass password", input: ScanInput{Path: "/root/.pgpass", Content: "# comment\ndb.internal:5432:app:deploy:Sup3rS3cretPw\n"}, detector: "pgpass_password", value: "Sup3rS3cretPw"},
		{name: "pgpass password with escaped colon in user", input: ScanInput{Path: "/root/.pgpass", Content: "db.internal:5432:app:de\\:ploy:Sup3r\\:S3cretPw\n"}, detector: "pgpass_password", value: "Sup3r\\:S3cretPw"},
		{name: "npmrc password", input: ScanInput{Path: "/root/.npmrc", Content: "//registry.internal/:_password=" + base64.StdEncoding.EncodeToString([]byte("Sup3rS3cretPw")) + "\n//registry.internal/:username=deploy\n"}, detector: "npmrc_password", value: base64.StdEncoding.EncodeToString([]byte("Sup3rS3cretPw"))},
		{name: "composer auth password", input: ScanInput{Path: "/root/.composer/auth.json", Content: `{"http-basic":{"repo.internal":{"username":"deploy","password":"Sup3rS3cretPw"}}}`}, detector: "composer_auth_password", value: "Sup3rS3cretPw"},
		{name: "bundler credentials", input: ScanInput{Path: "/root/.bundle/config", Content: "---\nBUNDLE_GEMS__INTERNAL: \"deploy:Sup3rS3cretPw\"\n"}, detector: "bundler_credentials", value: "deploy:Sup3rS3cretPw"},
		// DET-31
		{name: "authorization basic header", input: ScanInput{Path: "/etc/nginx/conf.d/upstream.conf", Content: "proxy_set_header Authorization \"Basic " + dockerAuth + "\";"}, detector: "http_basic_authorization_header", value: dockerAuth},
		{name: "authorization bearer in curl history", input: ScanInput{Key: "history[2].created_by", Content: "RUN curl -H 'Authorization: Bearer Xk9fL2mQ8vR4tY7wZ1aB3cD5eF6gH8' https://api.internal/v1/x"}, detector: "http_bearer_authorization_header", value: "Xk9fL2mQ8vR4tY7wZ1aB3cD5eF6gH8"},
		{name: "authorization bearer json", input: ScanInput{Content: `{"Authorization": "Bearer Xk9fL2mQ8vR4tY7wZ1aB3cD5eF6gH8"}`}, detector: "http_bearer_authorization_header", value: "Xk9fL2mQ8vR4tY7wZ1aB3cD5eF6gH8"},
		{name: "x-api-key header", input: ScanInput{Path: "/root/.curlrc", Content: "header = \"X-Api-Key: Xk9fL2mQ8vR4tY7wZ1aB3cD5\""}, detector: "http_api_key_header", value: "Xk9fL2mQ8vR4tY7wZ1aB3cD5"},
		{name: "private-token header", input: ScanInput{Content: "curl --header \"PRIVATE-TOKEN: Xk9fL2mQ8vR4tY7wZ1aB3cD5\" https://gitlab.internal/api/v4/projects"}, detector: "gitlab_private_token_header", value: "Xk9fL2mQ8vR4tY7wZ1aB3cD5"},
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
		})
	}
}

func TestCoverageDetectorsRejectReferencesAndPlaceholders(t *testing.T) {
	set := Default()
	tests := []struct {
		name     string
		input    ScanInput
		detector string
	}{
		{name: "short docker hub pat", input: ScanInput{Content: "dckr_pat_" + strings.Repeat("A", 20)}, detector: "docker_hub_personal_access_token"},
		{name: "maven property reference", input: ScanInput{Path: "/root/.m2/settings.xml", Content: "<password>${env.NEXUS_PASSWORD}</password>"}, detector: "maven_settings_password"},
		{name: "bearer shell variable", input: ScanInput{Content: "curl -H \"Authorization: Bearer $TOKEN\" https://api.internal/"}, detector: "http_bearer_authorization_header"},
		{name: "bearer braces placeholder", input: ScanInput{Content: "Authorization: Bearer ${ACCESS_TOKEN}"}, detector: "http_bearer_authorization_header"},
		{name: "bearer angle placeholder", input: ScanInput{Content: "Authorization: Bearer <your-token-here-please>"}, detector: "http_bearer_authorization_header"},
		{name: "basic header that is not base64 user:pass", input: ScanInput{Content: "Authorization: Basic notbase64atall"}, detector: "http_basic_authorization_header"},
		{name: "pgpass wildcard password", input: ScanInput{Path: "/root/.pgpass", Content: "*:*:*:deploy:*\n"}, detector: "pgpass_password"},
		{name: "my.cnf without password", input: ScanInput{Path: "/root/.my.cnf", Content: "[client]\nuser=root\nhost=db.internal\n"}, detector: "mysql_client_password"},
		{name: "dockerconfigjson without auth", input: ScanInput{Content: base64.StdEncoding.EncodeToString([]byte(`{"auths":{"registry.internal":{}}}`))}, detector: "docker_config_json_blob"},
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

// DET-21: an Account SID and a Sentry DSN are identifiers, not credentials;
// they are reported at medium confidence.
func TestIdentifierOnlyDetectorsAreMediumConfidence(t *testing.T) {
	set := Default()
	sid, ok := findDetectorMatch(set.Scan(ScanInput{Content: "TWILIO_ACCOUNT_SID=" + "AC" + strings.Repeat("a1", 16)}), "twilio_account_sid")
	if !ok || sid.Confidence != ConfidenceMedium {
		t.Fatalf("twilio_account_sid = %#v, want medium", sid)
	}
	dsn, ok := findDetectorMatch(set.Scan(ScanInput{Content: "SENTRY_DSN=https://" + strings.Repeat("a", 32) + "@o1234567.ingest.sentry.io/4567890"}), "sentry_dsn")
	if !ok || dsn.Confidence != ConfidenceMedium {
		t.Fatalf("sentry_dsn = %#v, want medium", dsn)
	}
}
