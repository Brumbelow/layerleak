package detectors

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/brumbelow/layerleak/v3/internal/detectionpolicy"
)

type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

type ScanInput struct {
	Content string
	Path    string
	Key     string

	// lowered caches the ASCII-lowercased content for the case-insensitive
	// literal prefilters; Set.Scan fills it once for every detector.
	lowered string
}

type Match struct {
	Detector   string
	Value      string
	Start      int
	End        int
	Confidence Confidence
	Priority   int
}

// Detector is one detection strategy. Name identifies the strategy; IDs lists
// every identifier its matches can carry in Match.Detector, which is the
// public contract (finding.detector_name, the API detectors array, SARIF rule
// ids). For most strategies IDs is just the name; the structured AWS and git
// credential readers emit per-field sub-identifiers.
type Detector interface {
	Name() string
	IDs() []string
	Scan(input ScanInput) []Match
}

// singleID is the IDs() of a strategy that reports under its own name.
func singleID(name string) []string {
	return []string{name}
}

type Set struct {
	detectors []Detector
}

const (
	priorityEntropy = 1
	// priorityAssigned ranks the generic assigned_sensitive_value rule above
	// keyword_entropy but below every self-identifying rule, so an identical
	// span is labelled github_token rather than by the generic name.
	priorityAssigned   = 2
	priorityLocal      = 3
	priorityStructured = 4
)

func Default() Set {
	rules := []Detector{
		awsSharedCredentialsDetector{},
		gitCredentialsDetector{},
		newTerraformCredentialsDetector(),
		newPathRegexDetector("docker_auth_blob", regexp.MustCompile(`(^|/)\.docker/config\.json$`), regexp.MustCompile(`(?i)"auth"\s*:\s*"([A-Za-z0-9+/=]{8,})"`), 1, ConfidenceHigh, looksLikeDockerAuth),
		newPathRegexDetector("docker_config_identity_token", regexp.MustCompile(`(^|/)\.docker/config\.json$`), regexp.MustCompile(`(?i)"identitytoken"\s*:\s*"([^"\s]{16,})"`), 1, ConfidenceHigh, looksLikeAssignedSensitiveValue),
		// The key regex always satisfies sensitiveKey, so every match would be
		// promoted to high anyway; declare high so the catalog is truthful.
		newKeyValueDetector("assigned_sensitive_value", regexp.MustCompile(`(?i)client[_-]?secret|access[_-]?token|refresh[_-]?token|auth[_-]?token`), regexp.MustCompile(`[A-Za-z0-9][A-Za-z0-9+/_.:-]{15,}={0,2}`), ConfidenceHigh, looksLikeAssignedSensitiveValue),
		newHerokuTokenDetector(),
		newSnykTokenDetector(),
		pemPrivateKeyDetector{},
		newRegexDetector("github_token", regexp.MustCompile(`\b(?:ghr_[A-Za-z0-9]{36,76}|gh[pous]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b`), 0, ConfidenceHigh, nil).requiring("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"),
		newRegexDetector("gitlab_personal_access_token", regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,300}`+gitlabRoutableTail+`\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("slack_token", regexp.MustCompile(`\b(?:xox[abeprs]-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9-]{16,}|xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+|xoxe\.xox[bp]-\d-[A-Z0-9]{100,}|xoxe-\d-[A-Z0-9]{100,})\b`), 0, ConfidenceHigh, nil).requiring("xox", "xapp-"),
		newRegexDetector("slack_webhook", regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{16,}`), 0, ConfidenceHigh, nil),
		newRegexDetector("stripe_api_key", regexp.MustCompile(`\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b`), 0, ConfidenceHigh, nil).requiring("sk_live_", "sk_test_", "rk_live_", "rk_test_"),
		newRegexDetector("aws_access_key_id", regexp.MustCompile(`\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b`), 0, ConfidenceHigh, nil).requiring("AKIA", "ASIA", "ABIA", "ACCA"),
		// Matched on the lowercased content: the optional aws[_-]? prefix only moved
		// the match start, never the captured value, so it is left out to keep a
		// literal prefix.
		newRegexDetector("aws_secret_access_key", regexp.MustCompile(assignedValuePattern(`secret[_-]?access[_-]?key`, `[a-z0-9/+=]{40}`, `(?:[^a-z0-9/+=]|$)`)), 1, ConfidenceHigh, looksLikeAWSSecretAccessKey).onLoweredContent(),
		newKeyValueDetector("aws_secret_access_key", regexp.MustCompile(`aws[_-]?secret[_-]?access[_-]?key|secret[_-]?access[_-]?key`), regexp.MustCompile(`[A-Za-z0-9/+=]{40}`), ConfidenceHigh, looksLikeAWSSecretAccessKey),
		newRegexDetector("google_api_key", regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("sendgrid_api_key", regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{16,64}\.[A-Za-z0-9_-]{16,64}\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("shopify_access_token", regexp.MustCompile(`\bshpat_[a-fA-F0-9]{32}\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("npm_token", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`), 0, ConfidenceHigh, nil),
		newPathRegexDetector("npmrc_auth_token", regexp.MustCompile(`(^|/)\.npmrc$`), regexp.MustCompile(`(?im)^\s*(?:\/\/[^\s=]+:)?_authToken\s*=\s*["']?([^\s#;"']+)["']?\s*$`), 1, ConfidenceHigh, hasMinPrintableLength(8)),
		newPathRegexDetector("npmrc_basic_auth", regexp.MustCompile(`(^|/)\.npmrc$`), regexp.MustCompile(`(?im)^\s*(?:\/\/[^\s=]+:)?_auth\s*=\s*([A-Za-z0-9+/=]{8,})\s*$`), 1, ConfidenceHigh, looksLikeBase64Credential),
		newRegexDetector("docker_auth_blob", regexp.MustCompile(`"auth"\s*:\s*"([a-z0-9+/=]{8,})"`), 1, ConfidenceHigh, looksLikeDockerAuth).onLoweredContent(),
		newRegexDetector("json_web_token", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`), 0, ConfidenceMedium, looksLikeJWT),
		// A netrc password token must start its line or follow whitespace on a
		// line with no comment marker before it, so prose in comments is ignored.
		newPathRegexDetector("netrc_password", regexp.MustCompile(`(^|/)\.netrc$`), regexp.MustCompile(`(?im)^(?:[^#\n]*\s)?password\s+([^\s#]+)`), 1, ConfidenceMedium, hasMinPrintableLength(4)),
		newPathRegexDetector("pypirc_password", regexp.MustCompile(`(^|/)\.pypirc$`), regexp.MustCompile(`(?im)^\s*password\s*=\s*([^\s#;]+)\s*$`), 1, ConfidenceMedium, hasMinPrintableLength(4)),
		newCredentialedURLDetector("basic_auth_url", basicAuthURLSchemes, urlHostClass),
		newCredentialedURLDetector("connection_url_credentials", connectionURLSchemes, urlHostListClass),
		newRegexDetector("huggingface_token", regexp.MustCompile(`\b(?:hf_|api_org_)[A-Za-z0-9]{34,}\b`), 0, ConfidenceHigh, nil).requiring("hf_", "api_org_"),
		newRegexDetector("digitalocean_personal_access_token", regexp.MustCompile(`\b(?:dop|doo|dor)_v1_[a-f0-9]{64}\b`), 0, ConfidenceHigh, nil).requiring("dop_v1_", "doo_v1_", "dor_v1_"),
		newRegexDetector("mailchimp_api_key", regexp.MustCompile(`\b[0-9a-f]{32}-us[0-9]{1,2}\b`), 0, ConfidenceHigh, nil).requiring("-us"),
		newRegexDetector("vault_token", regexp.MustCompile(`\b(?:hvs|hvb|hvr)\.[A-Za-z0-9_-]{24,}\b`), 0, ConfidenceHigh, nil).requiring("hvs.", "hvb.", "hvr."),
		newRegexDetector("anthropic_api_key", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{30,}\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("openai_api_key", regexp.MustCompile(`\bsk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_-]{100,}|[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}|[A-Za-z0-9]{48}\b)`), 0, ConfidenceHigh, nil),
		newRegexDetector("pypi_api_token", regexp.MustCompile(`\bpypi-[A-Za-z0-9_-]{32,}\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("linear_api_key", regexp.MustCompile(`\blin_api_[A-Za-z0-9]{40}\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("doppler_token", regexp.MustCompile(`\bdp\.(?:st|pt|sa|ct)\.[A-Za-z0-9._-]{20,}`), 0, ConfidenceHigh, nil),
		newRegexDetector("grafana_service_account_token", regexp.MustCompile(`\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}\b`), 0, ConfidenceHigh, nil),
		newPathRegexDetector("kubeconfig_token", regexp.MustCompile(`(^|/)\.kube/config$`), regexp.MustCompile(`(?im)^\s+token:\s+([^\s#]+)\s*$`), 1, ConfidenceHigh, hasMinPrintableLength(8)),
		newPathRegexDetector("vault_token_file", regexp.MustCompile(`(^|/)\.vault-token$`), regexp.MustCompile(`((?:hvs|hvb|hvr)\.[A-Za-z0-9_-]{24,}|s\.[A-Za-z0-9]{24,})`), 0, ConfidenceHigh, hasMinPrintableLength(24)),
		// An Account SID is a public identifier, not a credential (DET-21).
		newRegexDetector("twilio_account_sid", regexp.MustCompile(`\bAC[a-f0-9]{32}\b`), 0, ConfidenceMedium, nil),
		newRegexDetector("databricks_token", regexp.MustCompile(`\bdapi[A-Za-z0-9]{32}(?:-\d)?\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("azure_storage_account_key", regexp.MustCompile(`accountkey=([a-z0-9+/]{86}==)`), 1, ConfidenceHigh, nil).onLoweredContent(),
		newKeyValueDetector("datadog_api_key",
			regexp.MustCompile(`(?i)(?:dd[_-]?api[_-]?key|datadog[_-]?api[_-]?key)`),
			regexp.MustCompile(`\b[a-f0-9]{32}\b`),
			ConfidenceHigh, nil),
		newRegexDetector("notion_integration_token", regexp.MustCompile(`\b(?:secret_[A-Za-z0-9]{40,60}|ntn_[0-9]{11}[A-Za-z0-9]{35})\b`), 0, ConfidenceHigh, nil).requiring("secret_", "ntn_"),
		newRegexDetector("pulumi_access_token", regexp.MustCompile(`\bpul-[A-Za-z0-9]{40}\b`), 0, ConfidenceHigh, nil),
		// age identities are Bech32 with HRP AGE-SECRET-KEY-; age-keygen and SOPS
		// write them uppercase, and Bech32 also permits an all-lowercase form.
		newRegexDetector("age_secret_key", regexp.MustCompile(`\bAGE-SECRET-KEY-1(?:[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}|[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58})\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("render_api_key", regexp.MustCompile(`\brnd_[A-Za-z0-9]{32}\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("twilio_auth_token", regexp.MustCompile(assignedValuePattern(`twilio[_-]?auth[_-]?token`, `[a-f0-9]{32}`, `\b`)), 1, ConfidenceHigh, nil).onLoweredContent(),
		newRegexDetector("new_relic_user_api_key", regexp.MustCompile(`\bNRAK-[A-Z0-9]{27}\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("okta_api_token", regexp.MustCompile(`\bSSWS[ \t]+([A-Za-z0-9_-]{20,})`), 1, ConfidenceHigh, nil),
		newRegexDetector("square_application_secret", regexp.MustCompile(`\bsq0csp-[0-9A-Za-z_-]{43}\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("square_oauth_token", regexp.MustCompile(`\bsq0atp-[0-9A-Za-z_-]{22}\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("gitlab_deploy_token", regexp.MustCompile(`\bgldt-[A-Za-z0-9_-]{20,300}`+gitlabRoutableTail+`\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("gitlab_runner_token", regexp.MustCompile(`\bglrt-[A-Za-z0-9_-]{20,300}`+gitlabRoutableTail+`\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("discord_webhook", regexp.MustCompile(`(?:^|[^A-Za-z0-9+.-])(https://discord(?:app)?\.com/api/webhooks/\d{17,20}/[A-Za-z0-9_-]{68})(?:$|[^A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-])`), 1, ConfidenceHigh, nil).requiring("https://discord"),
		discordBotTokenDetector{},
		// A DSN is designed to ship in client applications; identifier, not credential (DET-21).
		newRegexDetector("sentry_dsn", regexp.MustCompile(`https://[0-9a-f]{16,32}(?::[0-9a-f]{16,32})?@(?:o\d+\.ingest(?:\.us|\.de)?\.sentry\.io|(?:[a-z0-9-]+\.)?sentry\.io)/\d+`), 0, ConfidenceMedium, nil).requiring("sentry.io"),
		newRegexDetector("shopify_shared_secret", regexp.MustCompile(`\bshpss_[a-fA-F0-9]{32}\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("shopify_partner_key", regexp.MustCompile(`\bshppa_[a-fA-F0-9]{32}\b`), 0, ConfidenceHigh, nil),
		telegramBotTokenDetector{},
		newRegexDetector("postman_api_key", regexp.MustCompile(`\bPMAK-[0-9a-fA-F]{24}-[0-9a-fA-F]{34}\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("stripe_webhook_secret", regexp.MustCompile(`\bwhsec_[A-Za-z0-9]{32,}\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("mapbox_secret_token", regexp.MustCompile(`\bsk\.eyJ[A-Za-z0-9_-]{3,}\.[A-Za-z0-9_-]{3,}\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("airtable_personal_access_token", regexp.MustCompile(`\bpat[A-Za-z0-9]{14}\.[0-9a-f]{64}\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("planetscale_service_token", regexp.MustCompile(`\bpscale_tkn_[A-Za-z0-9_]{43,}\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("fly_api_token", regexp.MustCompile(`\bfo1_[A-Za-z0-9._-]{43,}\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("circleci_personal_api_token", regexp.MustCompile(`\bCCIPAT_[A-Za-z0-9]{22}_[A-Fa-f0-9]{40}\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("openrouter_api_key", regexp.MustCompile(`\bsk-or-v1-[a-f0-9]{64}\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("sentry_user_token", regexp.MustCompile(`\bsntryu_[a-f0-9]{64}\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("cloudflare_api_token", regexp.MustCompile(`\bcf[ua]t_[A-Za-z0-9]{40}[a-f0-9]{8}\b`), 0, ConfidenceHigh, nil).requiring("cfut_", "cfat_"),
		newRegexDetector("sonarcloud_token", regexp.MustCompile(`\bsqco_[A-Za-z0-9]{59}\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("google_oauth_access_token", regexp.MustCompile(`\b(ya29\.(?i:[a-z0-9_-]{10,}))(?:[^A-Za-z0-9_-]|$)`), 1, ConfidenceHigh, nil),
		newRegexDetector("netlify_personal_access_token", regexp.MustCompile(`\bnfp_[A-Za-z0-9_]{36}\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("prefect_api_key", regexp.MustCompile(`\bpnu_[A-Za-z0-9]{36}\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("nightfall_api_key", regexp.MustCompile(`\bNF-[A-Za-z0-9]{32}\b`), 0, ConfidenceHigh, nil),
		newRegexDetector("tailscale_key", regexp.MustCompile(`\btskey-[a-z]+-[A-Za-z0-9_]+-[A-Za-z0-9_]+\b`), 0, ConfidenceHigh, nil),
		newKeyValueDetector("cloudflare_api_token",
			regexp.MustCompile(`(?i)(?:cf[_-]?api[_-]?(?:token|key)|cloudflare[_-]?(?:api[_-]?(?:token|key)|token))`),
			regexp.MustCompile(`(?:cf[ua]t_[A-Za-z0-9]{40}[a-f0-9]{8}|\b[A-Za-z0-9_-]{37,45}\b)`),
			ConfidenceHigh, looksLikeAssignedSensitiveValue),
		newKeyValueDetector("vercel_access_token",
			regexp.MustCompile(`(?i)(?:vercel|zeit)[_-]?(?:api[_-]?)?token`),
			regexp.MustCompile(`[A-Za-z0-9]{24,}`),
			ConfidenceMedium, looksLikeAssignedSensitiveValue),
	}
	rules = append(rules, vendorTokenDetectors()...)
	rules = append(rules, registryCredentialDetectors()...)
	rules = append(rules, httpHeaderCredentialDetectors()...)
	rules = append(rules, contextEntropyDetector{})
	return Set{detectors: rules}
}

func (s Set) Len() int {
	return len(s.detectors)
}

// Catalog returns the sorted, de-duplicated detector identifiers this set can
// report in Match.Detector, built from every strategy's IDs. Several strategies
// may share one identifier (docker_auth_blob is matched by path and by shape)
// and one strategy may emit several (aws_shared_credentials_*), so the catalog
// is the public identifier list rather than the strategy list.
func (s Set) Catalog() []string {
	seen := make(map[string]struct{}, len(s.detectors))
	catalog := make([]string, 0, len(s.detectors))
	for _, detector := range s.detectors {
		for _, id := range detector.IDs() {
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			catalog = append(catalog, id)
		}
	}
	sort.Strings(catalog)
	return catalog
}

func (s Set) Scan(input ScanInput) []Match {
	input.lowered = asciiLower(input.Content)
	matches := make([]Match, 0)
	for _, detector := range s.detectors {
		matches = append(matches, detector.Scan(input)...)
	}

	filtered := matches[:0]
	for _, match := range matches {
		if detectionpolicy.DiscardReason(match.Value) != detectionpolicy.ReasonNone {
			continue
		}
		filtered = append(filtered, match)
	}
	matches = filtered

	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Start == matches[j].Start {
			if matches[i].End == matches[j].End {
				if matches[i].Priority != matches[j].Priority {
					return matches[i].Priority > matches[j].Priority
				}
				if confidenceRank(matches[i].Confidence) != confidenceRank(matches[j].Confidence) {
					return confidenceRank(matches[i].Confidence) > confidenceRank(matches[j].Confidence)
				}
				if matches[i].Value != matches[j].Value {
					return matches[i].Value < matches[j].Value
				}
				return matches[i].Detector < matches[j].Detector
			}
			return matches[i].End < matches[j].End
		}
		return matches[i].Start < matches[j].Start
	})

	deduped := make([]Match, 0, len(matches))
	seenExact := make(map[string]struct{})
	seenSpanValue := make(map[string]struct{})
	for _, match := range matches {
		key := strings.Join([]string{
			match.Detector,
			match.Value,
			strconv.Itoa(match.Start),
			strconv.Itoa(match.End),
			string(match.Confidence),
			strconv.Itoa(match.Priority),
		}, "|")
		if _, ok := seenExact[key]; ok {
			continue
		}
		seenExact[key] = struct{}{}

		spanValueKey := strings.Join([]string{
			match.Value,
			strconv.Itoa(match.Start),
			strconv.Itoa(match.End),
		}, "|")
		if _, ok := seenSpanValue[spanValueKey]; ok {
			continue
		}
		seenSpanValue[spanValueKey] = struct{}{}
		deduped = append(deduped, match)
	}

	return dropNestedLowerPriorityMatches(deduped)
}

// dropNestedLowerPriorityMatches removes a match that lies strictly inside a
// match of higher priority: keyword_entropy on the password inside a
// basic_auth_url match is the same credential reported twice with two
// fingerprints. A higher-priority inner match (git_credentials_password inside
// basic_auth_url) is intentional nesting and is kept. The input order is
// preserved.
func dropNestedLowerPriorityMatches(matches []Match) []Match {
	if len(matches) < 2 {
		return matches
	}
	order := make([]int, len(matches))
	for index := range order {
		order[index] = index
	}
	// Outer spans first: by start, then by the longest end, then by priority.
	sort.SliceStable(order, func(i, j int) bool {
		left, right := matches[order[i]], matches[order[j]]
		if left.Start != right.Start {
			return left.Start < right.Start
		}
		if left.End != right.End {
			return left.End > right.End
		}
		return left.Priority > right.Priority
	})

	dropped := make([]bool, len(matches))
	active := make([]int, 0, 4)
	for _, index := range order {
		match := matches[index]
		kept := active[:0]
		for _, candidate := range active {
			if matches[candidate].End > match.Start {
				kept = append(kept, candidate)
			}
		}
		active = kept
		for _, candidate := range active {
			outer := matches[candidate]
			if outer.Priority > match.Priority && outer.Start <= match.Start && outer.End >= match.End {
				dropped[index] = true
				break
			}
		}
		if !dropped[index] {
			active = append(active, index)
		}
	}

	result := make([]Match, 0, len(matches))
	for index, match := range matches {
		if !dropped[index] {
			result = append(result, match)
		}
	}
	return result
}

type regexDetector struct {
	name      string
	rule      compiledRule
	group     int
	base      Confidence
	validator func(string) bool
	// lowered runs the rule over the ASCII-lowercased content; the rule must
	// then be written in lowercase without (?i), which keeps a literal prefix.
	lowered bool
}

func newRegexDetector(name string, expression *regexp.Regexp, group int, base Confidence, validator func(string) bool) regexDetector {
	return regexDetector{
		name:      name,
		rule:      compileRule(expression),
		group:     group,
		base:      base,
		validator: validator,
	}
}

// requiring declares literals one of which must occur in the content before
// the rule's regular expression runs; use it for rules whose pattern has no
// literal prefix of its own (alternations, character classes, (?i) flags).
func (d regexDetector) requiring(literals ...string) regexDetector {
	d.rule = d.rule.withLiterals(literals...)
	return d
}

// onLoweredContent makes the rule case-insensitive by matching the lowercased
// content instead of carrying a (?i) flag, which has no literal prefix.
func (d regexDetector) onLoweredContent() regexDetector {
	d.lowered = true
	return d
}

func (d regexDetector) Name() string {
	return d.name
}

func (d regexDetector) IDs() []string {
	return singleID(d.name)
}

func (d regexDetector) Scan(input ScanInput) []Match {
	haystack := input
	if d.lowered {
		haystack = input.loweredView()
	}
	return scanRegexMatches(d.name, d.rule, d.group, d.base, priorityLocal, d.validator, input, haystack)
}

type pathRegexDetector struct {
	name           string
	pathExpression *regexp.Regexp
	rule           compiledRule
	group          int
	base           Confidence
	validator      func(string) bool
}

func newPathRegexDetector(name string, pathExpression, expression *regexp.Regexp, group int, base Confidence, validator func(string) bool) pathRegexDetector {
	return pathRegexDetector{
		name:           name,
		pathExpression: pathExpression,
		rule:           compileRule(expression),
		group:          group,
		base:           base,
		validator:      validator,
	}
}

func (d pathRegexDetector) Name() string {
	return d.name
}

func (d pathRegexDetector) IDs() []string {
	return singleID(d.name)
}

func (d pathRegexDetector) Scan(input ScanInput) []Match {
	pathValue := strings.ToLower(strings.TrimSpace(input.Path))
	if pathValue == "" || !d.pathExpression.MatchString(pathValue) {
		return nil
	}
	// A rule gated on a file format knows what it is reading, so it outranks
	// the shape-only rules on the same span.
	return scanRegexMatches(d.name, d.rule, d.group, d.base, priorityStructured, d.validator, input, input)
}

type keyValueDetector struct {
	name            string
	keyExpression   *regexp.Regexp
	valueExpression *regexp.Regexp
	base            Confidence
	validator       func(string) bool
}

func newKeyValueDetector(name string, keyExpression, valueExpression *regexp.Regexp, base Confidence, validator func(string) bool) keyValueDetector {
	return keyValueDetector{
		name:            name,
		keyExpression:   keyExpression,
		valueExpression: valueExpression,
		base:            base,
		validator:       validator,
	}
}

func (d keyValueDetector) Name() string {
	return d.name
}

func (d keyValueDetector) IDs() []string {
	return singleID(d.name)
}

func (d keyValueDetector) Scan(input ScanInput) []Match {
	keyValue := strings.ToLower(strings.TrimSpace(input.Key))
	if keyValue == "" || !d.keyExpression.MatchString(keyValue) {
		return nil
	}

	lines := splitLinesWithOffsets(input.Content)
	matches := make([]Match, 0)
	for _, line := range lines {
		indexes := d.valueExpression.FindAllStringIndex(line.Value, -1)
		for _, index := range indexes {
			start := index[0]
			end := index[1]
			if start < 0 || end <= start || end > len(line.Value) {
				continue
			}
			value := line.Value[start:end]
			prefix := line.Value[:start]
			if !hasAssignedValuePrefix(prefix) && !isStandaloneValue(line.Value, start, end) {
				continue
			}
			if d.validator != nil && !d.validator(value) {
				continue
			}
			matches = append(matches, Match{
				Detector:   d.name,
				Value:      value,
				Start:      line.Offset + start,
				End:        line.Offset + end,
				Confidence: adjustConfidence(d.base, input.Path, input.Key, value),
				Priority:   priorityForKeyValueDetector(d.name),
			})
		}
	}

	return matches
}

// scanRegexMatches runs rule over haystack (the input itself, or its lowered
// view) and reports values from input at the matched offsets.
func scanRegexMatches(name string, rule compiledRule, group int, base Confidence, priority int, validator func(string) bool, input, haystack ScanInput) []Match {
	indexes := rule.findAll(haystack)
	matches := make([]Match, 0, len(indexes))
	for _, index := range indexes {
		start := index[0]
		end := index[1]
		if group > 0 && len(index) >= (group+1)*2 {
			start = index[group*2]
			end = index[group*2+1]
		}
		if start < 0 || end <= start || end > len(input.Content) {
			continue
		}
		value := input.Content[start:end]
		if validator != nil && !validator(value) {
			continue
		}
		matches = append(matches, Match{
			Detector:   name,
			Value:      value,
			Start:      start,
			End:        end,
			Confidence: adjustConfidence(base, input.Path, input.Key, value),
			Priority:   priority,
		})
	}

	return matches
}

type contextEntropyDetector struct{}

func (contextEntropyDetector) Name() string {
	return "keyword_entropy"
}

func (d contextEntropyDetector) IDs() []string {
	return singleID(d.Name())
}

func (contextEntropyDetector) Scan(input ScanInput) []Match {
	lowered := input.loweredContent()
	keyIsSensitive := sensitiveKey(input.Key)
	if !keyIsSensitive && !containsSecretKeyword(lowered) {
		return nil
	}
	lines := splitLinesWithOffsets(input.Content)
	matches := make([]Match, 0)
	for _, line := range lines {
		trimmed := strings.TrimSpace(line.Value)
		if trimmed == "" {
			continue
		}
		// asciiLower preserves byte offsets, so the lowered line is a slice.
		if !keyIsSensitive && !containsSecretKeyword(lowered[line.Offset:line.Offset+len(line.Value)]) {
			continue
		}
		candidates := entropyCandidateExpression.FindAllStringIndex(line.Value, -1)
		for _, candidate := range candidates {
			value := line.Value[candidate[0]:candidate[1]]
			if !hasEntropyContext(line.Value, input.Key, candidate[0], candidate[1]) {
				continue
			}
			if shouldSuppressEntropyCandidate(value) {
				continue
			}
			if looksLikeContentDigest(line.Value[:candidate[0]], value, input.Path) {
				continue
			}
			if !passesEntropy(value) {
				continue
			}
			matches = append(matches, Match{
				Detector:   "keyword_entropy",
				Value:      value,
				Start:      line.Offset + candidate[0],
				End:        line.Offset + candidate[1],
				Confidence: adjustConfidence(ConfidenceLow, input.Path, input.Key, value),
				Priority:   priorityEntropy,
			})
		}
	}

	return matches
}

type lineWithOffset struct {
	Value  string
	Offset int
}

var (
	secretKeywordExpression = regexp.MustCompile(`secret|token|password|passwd|pwd|api[_-]?key|auth|authorization|credential|private[_-]?key|access[_-]?key|client[_-]?secret`)
	// entropyCandidateExpression keeps '=' out of the repeating class so an
	// unquoted KEY=VALUE line yields the value as its own candidate instead of
	// one KEY=VALUE token whose prefix is empty; base64 padding is still
	// allowed at the end of a value.
	entropyCandidateExpression = regexp.MustCompile(`[A-Za-z0-9][A-Za-z0-9+/_-]{19,}={0,2}`)
	wordyCandidateExpression   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*$`)
	// dockerfileSpaceAssignmentExpression matches the legacy Dockerfile
	// `ENV KEY value` form, whose separator is whitespace rather than '='.
	dockerfileSpaceAssignmentExpression = regexp.MustCompile(`(?i)(?:^|\s)(?:ENV|ARG)\s+[A-Za-z_][A-Za-z0-9_.]*\s+$`)
)

func splitLinesWithOffsets(value string) []lineWithOffset {
	lines := strings.SplitAfter(value, "\n")
	results := make([]lineWithOffset, 0, len(lines))
	offset := 0
	for _, line := range lines {
		trimmed := strings.TrimRight(line, "\n")
		results = append(results, lineWithOffset{
			Value:  trimmed,
			Offset: offset,
		})
		offset += len(line)
	}
	if len(lines) == 0 && value != "" {
		results = append(results, lineWithOffset{Value: value})
	}
	return results
}

func adjustConfidence(base Confidence, pathValue, key, value string) Confidence {
	score := 0
	if sensitivePath(pathValue) {
		score++
	}
	if sensitiveKey(key) {
		score++
	}
	if sensitiveValue(value) {
		score++
	}

	switch base {
	case ConfidenceLow:
		if score >= 2 {
			return ConfidenceHigh
		}
		if score >= 1 {
			return ConfidenceMedium
		}
	case ConfidenceMedium:
		if score >= 1 {
			return ConfidenceHigh
		}
	}

	return base
}

func sensitivePath(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return false
	}
	base := path.Base(value)
	switch base {
	case ".env", ".env.local", ".npmrc", ".netrc", ".pypirc", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "config.json":
		return true
	}
	// Match whole words of the path, so keycloak, keyrings, tokenizer and
	// monkey do not promote unrelated findings.
	for _, segment := range strings.Split(value, "/") {
		if segment == ".docker" {
			return true
		}
		for _, word := range strings.FieldsFunc(segment, func(r rune) bool { return !unicode.IsLetter(r) }) {
			switch word {
			case "secret", "secrets", "token", "tokens", "credential", "credentials", "key", "keys", "apikey", "password", "passwd":
				return true
			}
		}
	}
	return false
}

func sensitiveKey(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return false
	}
	for _, token := range []string{"secret", "token", "password", "apikey", "api_key", "auth", "credential", "access_key"} {
		if strings.Contains(value, token) {
			return true
		}
	}
	return false
}

func sensitiveValue(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	for _, token := range []string{"-----begin", "xox", "ghp_", "glpat-", "sk_live_", "akia"} {
		if strings.Contains(value, token) {
			return true
		}
	}
	return false
}

func looksLikeDockerAuth(value string) bool {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return false
	}
	return strings.Contains(string(decoded), ":")
}

func looksLikeBase64Credential(value string) bool {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return false
	}
	if !isPrintableText(string(decoded)) {
		return false
	}
	return strings.Contains(string(decoded), ":")
}

func looksLikeJWT(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		header, err = base64.URLEncoding.DecodeString(parts[0])
		if err != nil {
			return false
		}
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(header, &payload); err != nil {
		return false
	}
	_, hasAlg := payload["alg"]
	_, hasTyp := payload["typ"]
	return hasAlg || hasTyp
}

func looksLikeAWSSecretAccessKey(value string) bool {
	if len(value) != 40 || !isPrintableText(value) {
		return false
	}
	hasLower := false
	hasUpper := false
	for _, r := range value {
		switch {
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsDigit(r), r == '/', r == '+', r == '=':
		default:
			return false
		}
	}
	return hasLower && hasUpper
}

func hasMinPrintableLength(minLength int) func(string) bool {
	return func(value string) bool {
		trimmed := strings.TrimSpace(value)
		return len(trimmed) >= minLength && isPrintableText(trimmed)
	}
}

func hasEntropyContext(line, key string, start, end int) bool {
	if start < 0 || end <= start || end > len(line) {
		return false
	}

	prefix := line[:start]
	if sensitiveKey(key) && (hasAssignedValuePrefix(prefix) || isStandaloneValue(line, start, end)) {
		return true
	}
	if !hasAssignedValuePrefix(prefix) {
		return false
	}

	lowerPrefix := strings.ToLower(prefix)
	if len(lowerPrefix) > 96 {
		lowerPrefix = lowerPrefix[len(lowerPrefix)-96:]
	}
	return secretKeywordExpression.MatchString(lowerPrefix)
}

// hasAssignedValuePrefix reports whether the text before a candidate ends in
// an assignment operator, ignoring any run of whitespace and opening quotes
// between the operator and the value (`"key": "value"`, `key = "value"`,
// `key => 'value'`), or in a legacy Dockerfile `ENV KEY ` separator.
func hasAssignedValuePrefix(prefix string) bool {
	trimmed := strings.TrimRightFunc(prefix, func(r rune) bool {
		return unicode.IsSpace(r) || r == '"' || r == '\'' || r == '`'
	})
	if trimmed != prefix && dockerfileSpaceAssignmentExpression.MatchString(prefix) {
		return true
	}
	switch {
	case strings.HasSuffix(trimmed, ":="):
		return true
	case strings.HasSuffix(trimmed, "=>"):
		return true
	case strings.HasSuffix(trimmed, "="):
		return true
	case strings.HasSuffix(trimmed, ":"):
		return true
	default:
		return false
	}
}

func isStandaloneValue(line string, start, end int) bool {
	before := strings.TrimSpace(line[:start])
	after := strings.TrimSpace(line[end:])
	before = strings.Trim(before, "\"'`")
	after = strings.Trim(after, "\"'`")
	return before == "" && after == ""
}

func shouldSuppressEntropyCandidate(value string) bool {
	if !isPrintableText(value) {
		return true
	}
	if isLowercaseSeparatorCandidate(value) {
		return true
	}
	if looksPathLikeCandidate(value) {
		return true
	}
	if looksLikeWordCompound(value) {
		return true
	}
	if !hasStrongEntropyShape(value) {
		return true
	}
	return false
}

// lowercaseWordExpression matches a segment that reads as a word (python3,
// amd64, headers) rather than as random material.
var lowercaseWordExpression = regexp.MustCompile(`^[a-z]{3,}[0-9]{0,2}$`)

// isLowercaseSeparatorCandidate suppresses slugs and package names such as
// base-passwd/user-change-gecos or linux-headers-5-15-0-generic: lowercase
// letters, digits and separators with few digits or mostly word-like
// segments. Random lowercase secrets (UUIDs, Mailgun key-... values,
// base64url tokens) carry many digits and few words, so they pass through to
// the entropy check instead of being discarded regardless of context.
func isLowercaseSeparatorCandidate(value string) bool {
	if value == "" || !strings.ContainsAny(value, "-_/") {
		return false
	}
	hasLetter := false
	for _, r := range value {
		switch {
		case unicode.IsLower(r):
			hasLetter = true
		case unicode.IsDigit(r), r == '-', r == '_', r == '/':
		default:
			return false
		}
	}
	if !hasLetter {
		return false
	}
	if digitCount(value) <= 2 {
		return true
	}
	segments := strings.FieldsFunc(value, func(r rune) bool {
		return r == '-' || r == '_' || r == '/'
	})
	wordy := 0
	for _, segment := range segments {
		if lowercaseWordExpression.MatchString(segment) {
			wordy++
		}
	}
	return wordy >= 2 && wordy*2 >= len(segments)
}

func looksPathLikeCandidate(value string) bool {
	if strings.HasPrefix(value, "/") {
		return true
	}
	if strings.Contains(value, "../") || strings.Contains(value, "./") {
		return true
	}
	if strings.Count(value, "/") >= 2 && !strings.ContainsAny(value, "+=") && digitCount(value) <= 2 {
		return true
	}
	return false
}

func looksLikeWordCompound(value string) bool {
	if strings.ContainsAny(value, "+=") || digitCount(value) > 2 {
		return false
	}
	segments := strings.FieldsFunc(value, func(r rune) bool {
		switch r {
		case '-', '_', '/', '.', ':':
			return true
		default:
			return false
		}
	})
	if len(segments) < 2 {
		return false
	}
	for _, segment := range segments {
		if segment == "" || !wordyCandidateExpression.MatchString(segment) {
			return false
		}
	}
	return true
}

func hasStrongEntropyShape(value string) bool {
	hasLower := false
	hasUpper := false
	hasDigit := false
	hasBase64Punct := false
	hasSeparator := false

	for _, r := range value {
		switch {
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsDigit(r):
			hasDigit = true
		case r == '+' || r == '=':
			hasBase64Punct = true
		case r == '-' || r == '_' || r == '/' || r == '.' || r == ':':
			hasSeparator = true
		}
	}

	classCount := 0
	for _, present := range []bool{hasLower, hasUpper, hasDigit, hasBase64Punct} {
		if present {
			classCount++
		}
	}

	switch {
	case classCount >= 3:
		return true
	case classCount == 2 && (hasDigit || hasBase64Punct):
		return true
	case classCount == 2 && !hasSeparator:
		return len(value) >= 24
	case classCount == 1 && !hasSeparator:
		return len(value) >= 32
	default:
		return false
	}
}

func digitCount(value string) int {
	count := 0
	for _, r := range value {
		if unicode.IsDigit(r) {
			count++
		}
	}
	return count
}

func isPrintableText(value string) bool {
	for _, r := range value {
		if unicode.IsSpace(r) {
			continue
		}
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func looksLikeDiscordBotToken(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	if len(decoded) < 8 {
		return false
	}
	for _, r := range string(decoded) {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

// genericEntropyThreshold is the Shannon-entropy floor (bits per symbol) for
// values drawn from a mixed alphabet; a random 20-character alphanumeric value
// clears it about 96% of the time.
const genericEntropyThreshold = 3.75

func passesEntropy(value string) bool {
	if len(value) < 20 {
		return false
	}
	var total float64
	counts := make(map[rune]float64)
	for _, r := range value {
		if unicode.IsSpace(r) {
			return false
		}
		total++
		counts[r]++
	}
	if total == 0 {
		return false
	}
	var entropy float64
	for _, count := range counts {
		probability := count / total
		entropy += -probability * math.Log2(probability)
	}
	return entropy >= entropyThreshold(value)
}

// entropyThreshold returns the entropy floor for a value's alphabet. A hex
// string cannot exceed 4 bits per symbol and its plug-in entropy for n symbols
// is well below that (about 3.6 bits at 32 characters), so the fixed generic
// floor rejected most 32- and 40-hex API keys and UUIDs. For single-case hex,
// optionally dashed (UUIDs), the floor is 4 - 24/n, which sits at the first
// percentile of genuinely random hex at every length from 20 to 64. Digit-only
// values keep the generic floor and so never pass.
func entropyThreshold(value string) float64 {
	if isHexAlphabet(value) {
		return 4 - 24/float64(len(value))
	}
	return genericEntropyThreshold
}

// isHexAlphabet reports whether value is single-case hexadecimal, allowing the
// dashes of a UUID, with at least one hex letter so digit-only strings are
// excluded.
func isHexAlphabet(value string) bool {
	hasLetter := false
	hasLower := false
	hasUpper := false
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9', r == '-':
		case r >= 'a' && r <= 'f':
			hasLetter = true
			hasLower = true
		case r >= 'A' && r <= 'F':
			hasLetter = true
			hasUpper = true
		default:
			return false
		}
	}
	return hasLetter && (!hasLower || !hasUpper)
}

var (
	// contentDigestPrefixExpression matches text that introduces a content
	// digest or revision rather than a credential: an algorithm label
	// (sha256:, md5=), or a digest/checksum/commit/etag key, ending with the
	// assignment operator and any opening quote.
	contentDigestPrefixExpression = regexp.MustCompile(`(?i)(?:sha-?(?:1|224|256|384|512)|md5|blake2[bs]?|digest|checksum|integrity|etag|commit|revision|hash)(?:_?sha)?(?:sum)?\s*(?:[:=]|=>|:=)?\s*["'` + "`" + `]*$`)
	// lockFileNameExpression matches dependency lock files, whose hex is
	// package digests and never a credential.
	lockFileNameExpression = regexp.MustCompile(`(?i)(?:^|/)(?:go\.sum|package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|pipfile\.lock|poetry\.lock|pdm\.lock|uv\.lock|cargo\.lock|composer\.lock|gemfile\.lock|packages\.lock\.json|flake\.lock|mix\.lock|pubspec\.lock|podfile\.lock|[^/]+\.lockfile|[^/]+\.lock)$`)
)

// looksLikeContentDigest reports whether a candidate is a content digest
// rather than a secret: any candidate in a dependency lock file (package
// digests, go.sum h1: hashes, yarn.lock #sha1 fragments), or hex that follows
// a digest marker (sha256:, md5=, a checksum/commit/etag key).
func looksLikeContentDigest(prefix, value, pathValue string) bool {
	if lockFileNameExpression.MatchString(strings.ToLower(strings.TrimSpace(pathValue))) {
		return true
	}
	return isHexAlphabet(value) && contentDigestPrefixExpression.MatchString(prefix)
}

func confidenceRank(value Confidence) int {
	switch value {
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	case ConfidenceLow:
		return 1
	default:
		return 0
	}
}

func priorityForKeyValueDetector(name string) int {
	switch name {
	case "assigned_sensitive_value":
		return priorityAssigned
	default:
		return priorityLocal
	}
}
