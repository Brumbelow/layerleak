package detectors

import (
	"encoding/base64"
	"regexp"
	"strings"
)

var (
	dockerConfigPathExpression = regexp.MustCompile(`(^|/)\.docker/config\.json$`)
	npmrcPathExpression        = regexp.MustCompile(`(^|/)\.npmrc$`)
	pgpassPathExpression       = regexp.MustCompile(`(^|/)\.pgpass$`)
	dockerAuthFieldExpression  = regexp.MustCompile(`"auth"\s*:\s*"([A-Za-z0-9+/=]{8,})"`)
)

// vendorTokenDetectors are the vendor formats the original rule set lagged
// behind (DET-33): GitLab's token families, SonarQube on-prem tokens, Grafana
// Cloud, Sentry organization tokens, New Relic insert/query/license keys,
// PlanetScale passwords, CircleCI project tokens, Twilio API keys and Datadog
// application keys.
func vendorTokenDetectors() []Detector {
	return []Detector{
		newRegexDetector("gitlab_pipeline_trigger_token", regexp.MustCompile(`\bglptt-[0-9a-f]{40}\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("gitlab_oauth_application_secret", regexp.MustCompile(`\bgloas-[A-Za-z0-9_-]{64}\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("gitlab_agent_token", regexp.MustCompile(`\bglagent-[A-Za-z0-9_-]{50,}\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("gitlab_scim_token", regexp.MustCompile(`\bglsoat-[A-Za-z0-9_-]{20,300}`+gitlabRoutableTail+`\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("gitlab_feature_flag_client_token", regexp.MustCompile(`\bglffct-[A-Za-z0-9_-]{20,300}`+gitlabRoutableTail+`\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("gitlab_incoming_mail_token", regexp.MustCompile(`\bglimt-[A-Za-z0-9_-]{25,300}`+gitlabRoutableTail+`\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("gitlab_ci_job_token", regexp.MustCompile(`\bglcbt-[A-Za-z0-9]{1,5}_[A-Za-z0-9_-]{20,300}`+gitlabRoutableTail+`\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("gitlab_feed_token", regexp.MustCompile(`\bglft-[A-Za-z0-9_-]{20,300}`+gitlabRoutableTail+`\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("gitlab_runner_registration_token", regexp.MustCompile(`\b(?:glrtr-[A-Za-z0-9_-]{20,300}|GR1348941[A-Za-z0-9_-]{20,300})\b`), 0, ConfidenceHigh, nil).requiring("glrtr-", "GR1348941"),
		newRegexDetector("sonarqube_token", regexp.MustCompile(`\bsq[upa]_[0-9a-f]{40}\b`), 0, ConfidenceHigh, nil).requiring("squ_", "sqp_", "sqa_"),
		newRegexDetector("grafana_cloud_api_token", regexp.MustCompile(`\bglc_[A-Za-z0-9+/]{32,400}={0,2}`), 0, ConfidenceHigh, nil),
		newRegexDetector("sentry_organization_token", regexp.MustCompile(`\bsntrys_eyJ[A-Za-z0-9+/=_-]{20,}_[A-Za-z0-9+/=_-]{20,}`), 0, ConfidenceHigh, nil),
		newRegexDetector("new_relic_insights_key", regexp.MustCompile(`\bNRI[IQ]-[A-Za-z0-9_-]{32}\b`), 0, ConfidenceHigh, nil).requiring("NRII-", "NRIQ-"),
		newRegexDetector("new_relic_license_key", regexp.MustCompile(`\b[a-f0-9]{36}NRAL\b`), 0, ConfidenceHigh, nil).requiring("NRAL"),
		newRegexDetector("planetscale_password", regexp.MustCompile(`\bpscale_pw_[A-Za-z0-9._-]{32,}`), 0, ConfidenceHigh, nil),
		newRegexDetector("planetscale_oauth_token", regexp.MustCompile(`\bpscale_oauth_[A-Za-z0-9._-]{32,}`), 0, ConfidenceHigh, nil),
		newRegexDetector("circleci_project_api_token", regexp.MustCompile(`\bCCIPRJ_[A-Za-z0-9]{22}_[a-f0-9]{40}\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("twilio_api_key", regexp.MustCompile(`\bSK[0-9a-f]{32}\b`), 0, ConfidenceHigh, nil),
		newKeyValueDetector("datadog_application_key",
			regexp.MustCompile(`(?i)(?:dd|datadog)[_-]?app(?:lication)?[_-]?key`),
			regexp.MustCompile(`\b[a-f0-9]{40}\b`),
			ConfidenceHigh, nil),
	}
}

// registryCredentialDetectors cover registry and package-manager credentials
// (DET-29): Docker Hub tokens, Kubernetes .dockerconfigjson blobs, Docker
// registry tokens, JFrog Artifactory, RubyGems, NuGet, crates.io, Maven
// settings.xml, .pgpass, .my.cnf, .npmrc _password, Composer auth.json and
// Bundler config.
func registryCredentialDetectors() []Detector {
	return []Detector{
		newRegexDetector("docker_hub_personal_access_token", regexp.MustCompile(`\bdckr_pat_[A-Za-z0-9_-]{27}\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("docker_hub_organization_access_token", regexp.MustCompile(`\bdckr_oat_[A-Za-z0-9_-]{32}\b`), 0, ConfidenceHigh, nil),
		// base64 of `{"auths":`, the start of every encoded Docker config.
		newRegexDetector("docker_config_json_blob", regexp.MustCompile(`\beyJhdXRocyI6[A-Za-z0-9+/=]{20,}`), 0, ConfidenceHigh, looksLikeDockerConfigJSONBlob),
		newPathRegexDetector("docker_config_registry_token", dockerConfigPathExpression, regexp.MustCompile(`(?i)"registrytoken"\s*:\s*"([^"\s]{16,})"`), 1, ConfidenceHigh, looksLikeAssignedSensitiveValue),
		// base64 of "reftkn:01", the prefix of JFrog reference tokens.
		newRegexDetector("artifactory_reference_token", regexp.MustCompile(`\bcmVmdGtuOjAx[A-Za-z0-9+/=]{40,}`), 0, ConfidenceHigh, nil),
		newRegexDetector("artifactory_api_key", regexp.MustCompile(`\bAKCp[A-Za-z0-9]{69}\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("rubygems_api_key", regexp.MustCompile(`\brubygems_[0-9a-f]{48}\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("nuget_api_key", regexp.MustCompile(`\boy2[a-z0-9]{43}\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("crates_io_token", regexp.MustCompile(`\bcio[A-Za-z0-9]{32}\b`), 0, ConfidenceHigh, nil),
		newPathRegexDetector("maven_settings_password", regexp.MustCompile(`(^|/)settings\.xml$`), regexp.MustCompile(`(?is)<password>\s*([^<\s]{6,})\s*</password>`), 1, ConfidenceHigh, looksLikeLiteralPassword),
		newPathRegexDetector("mysql_client_password", regexp.MustCompile(`(^|/)(?:\.my\.cnf|my\.cnf|\.mylogin\.cnf)$`), regexp.MustCompile(`(?im)^\s*password\s*=\s*["']?([^\s"'#;]{4,})`), 1, ConfidenceHigh, looksLikeLiteralPassword),
		newPathRegexDetector("npmrc_password", npmrcPathExpression, regexp.MustCompile(`(?im)^\s*//[^\s=]+:_password\s*=\s*["']?([A-Za-z0-9+/=]{8,})`), 1, ConfidenceHigh, looksLikeBase64Text),
		newPathRegexDetector("composer_auth_password", regexp.MustCompile(`(^|/)auth\.json$`), regexp.MustCompile(`(?i)"password"\s*:\s*"([^"\s]{6,})"`), 1, ConfidenceHigh, looksLikeLiteralPassword),
		newPathRegexDetector("bundler_credentials", regexp.MustCompile(`(^|/)\.bundle/config$`), regexp.MustCompile(`(?m)^\s*BUNDLE_[A-Z0-9_]+:\s*["']?([^\s"':]+:[^\s"']{4,})`), 1, ConfidenceHigh, nil),
		pgpassDetector{},
	}
}

// httpHeaderCredentialDetectors cover credentials sent as HTTP headers in
// configs, curl history lines, .curlrc/.wgetrc and ingress annotations
// (DET-31). The rules are lowercase and run over the lowered content so the
// header name keeps a literal prefix; values come from the original.
func httpHeaderCredentialDetectors() []Detector {
	const headerSeparator = `["']?\s*[:=]?\s*["']?`
	const headerValueClass = `[a-z0-9._~+/=_-]`
	return []Detector{
		newRegexDetector("http_basic_authorization_header", regexp.MustCompile(`authorization`+headerSeparator+`basic\s+([a-z0-9+/=]{8,})`), 1, ConfidenceHigh, looksLikeBase64Credential).onLoweredContent(),
		newRegexDetector("http_bearer_authorization_header", regexp.MustCompile(`authorization`+headerSeparator+`bearer\s+(`+headerValueClass+`{20,})`), 1, ConfidenceHigh, looksLikeAssignedSensitiveValue).onLoweredContent(),
		newRegexDetector("http_api_key_header", regexp.MustCompile(`x-api-key`+headerSeparator+`(`+headerValueClass+`{16,})`), 1, ConfidenceHigh, looksLikeAssignedSensitiveValue).onLoweredContent(),
		newRegexDetector("gitlab_private_token_header", regexp.MustCompile(`private-token`+headerSeparator+`(`+headerValueClass+`{16,})`), 1, ConfidenceHigh, looksLikeAssignedSensitiveValue).onLoweredContent(),
	}
}

// looksLikeDockerConfigJSONBlob decodes a base64 Docker config and accepts it
// when it carries an "auth" field that itself decodes to user:password.
func looksLikeDockerConfigJSONBlob(value string) bool {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(value, "="))
		if err != nil {
			return false
		}
	}
	if !isPrintableText(string(decoded)) {
		return false
	}
	for _, auth := range dockerAuthFieldExpression.FindAllStringSubmatch(string(decoded), -1) {
		if looksLikeDockerAuth(auth[1]) {
			return true
		}
	}
	return false
}

// looksLikeBase64Text accepts base64 that decodes to printable text, the
// shape of an .npmrc _password (the base64 of the plain password).
func looksLikeBase64Text(value string) bool {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return false
	}
	return len(decoded) >= 4 && isPrintableText(string(decoded))
}

// looksLikeLiteralPassword rejects configuration references (${env.X},
// {{ var }}, %VAR%, $VAR, <placeholder>) so only literal passwords match.
func looksLikeLiteralPassword(value string) bool {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) < 4 || !isPrintableText(trimmed) {
		return false
	}
	for _, marker := range []string{"${", "{{", "}}", "%", "<", ">"} {
		if strings.Contains(trimmed, marker) {
			return false
		}
	}
	return !strings.HasPrefix(trimmed, "$")
}

// pgpassDetector reads libpq password files: one "host:port:db:user:password"
// entry per line, with ':' and '\' escaped by a backslash in any field.
type pgpassDetector struct{}

func (pgpassDetector) Name() string {
	return "pgpass_password"
}

func (d pgpassDetector) IDs() []string {
	return singleID(d.Name())
}

func (d pgpassDetector) Scan(input ScanInput) []Match {
	pathValue := strings.ToLower(strings.TrimSpace(input.Path))
	if pathValue == "" || !pgpassPathExpression.MatchString(pathValue) {
		return nil
	}
	matches := make([]Match, 0)
	for _, line := range splitLinesWithOffsets(input.Content) {
		start, end, ok := pgpassLinePasswordSpan(line.Value)
		if !ok {
			continue
		}
		password := line.Value[start:end]
		matches = append(matches, Match{
			Detector:   d.Name(),
			Value:      password,
			Start:      line.Offset + start,
			End:        line.Offset + end,
			Confidence: adjustConfidence(ConfidenceHigh, input.Path, "password", password),
			Priority:   priorityStructured,
		})
	}
	return matches
}

// pgpassLinePasswordSpan returns the password span within one pgpass line. It
// skips blank lines and comments, the '*' wildcard and values too short or
// not printable to be a literal password.
func pgpassLinePasswordSpan(line string) (int, int, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return 0, 0, false
	}
	start, ok := pgpassPasswordStart(line)
	if !ok {
		return 0, 0, false
	}
	end := len(strings.TrimRightFunc(line, isPgpassTrailingSpace))
	if end <= start {
		return 0, 0, false
	}
	password := line[start:end]
	if password == "*" || len(password) < 4 || !isPrintableText(password) {
		return 0, 0, false
	}
	return start, end, true
}

// isPgpassTrailingSpace is the trailing whitespace trimmed from a password.
func isPgpassTrailingSpace(r rune) bool {
	return r == ' ' || r == '\t' || r == '\r'
}

// pgpassPasswordStart returns the offset of the fifth field, honouring
// backslash escapes in the first four.
func pgpassPasswordStart(line string) (int, bool) {
	separators := 0
	for index := 0; index < len(line); index++ {
		switch line[index] {
		case '\\':
			index++
		case ':':
			separators++
			if separators == 4 {
				return index + 1, true
			}
		}
	}
	return 0, false
}
