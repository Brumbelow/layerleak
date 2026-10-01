package detectors

import (
	"math/rand"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// DET-14: every self-identifying rule must give Go's engine a literal to skip
// ahead with, or declare required literals, so a secret-free file is not an
// NFA pass per rule. The two exceptions have no literal in their shape.
func TestRegexRulesKeepALiteralFastPath(t *testing.T) {
	allowed := map[string]bool{"discord_bot_token": true, "telegram_bot_token": true}
	for _, detector := range Default().detectors {
		rule, ok := detector.(regexDetector)
		if !ok {
			continue
		}
		prefix, _ := rule.rule.expression.LiteralPrefix()
		if len(prefix) >= 2 || len(rule.rule.literals) > 0 || allowed[rule.name] {
			continue
		}
		t.Errorf("%s: literal prefix %q and no required literals; the rule walks the NFA over every byte", rule.name, prefix)
	}
}

func TestCompileRuleMovesBoundariesOutOfTheExpression(t *testing.T) {
	rule := compileRule(regexp.MustCompile(`\bglpat-[A-Za-z0-9\-_]{20,}\b`))
	if !rule.boundaryBefore || !rule.boundaryAfter {
		t.Fatalf("boundaries not derived: %+v", rule)
	}
	if prefix, _ := rule.expression.LiteralPrefix(); prefix != "glpat-" {
		t.Fatalf("LiteralPrefix() = %q, want glpat-", prefix)
	}

	folded := compileRule(regexp.MustCompile(`(?i)AccountKey=([A-Za-z0-9+/]{86}==)`), "AccountKey=")
	if !folded.foldLiterals || folded.literals[0] != "accountkey=" {
		t.Fatalf("case-insensitive literals not folded: %+v", folded)
	}
	if !folded.mayMatch(ScanInput{Content: "ACCOUNTKEY=abc"}) || folded.mayMatch(ScanInput{Content: "nothing here"}) {
		t.Fatal("literal prefilter disagrees with the content")
	}

	escaped := compileRule(regexp.MustCompile(`token\\b`))
	if escaped.boundaryAfter {
		t.Fatal("an escaped backslash before b is not a boundary")
	}
}

// For rules whose token class holds only word characters, the post-match
// boundary checks must be indistinguishable from \b inside the expression.
func TestCompileRuleMatchesWordBoundarySemantics(t *testing.T) {
	patterns := []string{
		`\bAC[a-f0-9]{32}\b`,
		`\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b`,
		`\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}\b`,
		`\bnpm_[A-Za-z0-9]{36}\b`,
		`\b\d{8,10}:[A-Za-z0-9_]{35}\b`,
	}
	tokens := []string{
		"AC" + strings.Repeat("a1", 16),
		"ghp_" + strings.Repeat("Z", 36),
		"glsa_" + strings.Repeat("x", 32) + "_12ab34cd",
		"npm_" + strings.Repeat("9", 36),
		"1234567890:" + strings.Repeat("A", 35),
	}
	glue := []string{" ", "\"", "x", "_", "-", "=", "\n", "", "9", ":", "/"}
	rng := rand.New(rand.NewSource(3)) //nolint:gosec // deterministic test data
	for _, pattern := range patterns {
		reference := regexp.MustCompile(pattern)
		rule := compileRule(reference)
		for trial := 0; trial < 300; trial++ {
			var builder strings.Builder
			for piece := 0; piece < 6; piece++ {
				builder.WriteString(glue[rng.Intn(len(glue))])
				if rng.Intn(2) == 0 {
					builder.WriteString(tokens[rng.Intn(len(tokens))])
				}
			}
			content := builder.String()
			want := reference.FindAllStringSubmatchIndex(content, -1)
			got := rule.findAll(ScanInput{Content: content})
			if len(want) == 0 && len(got) == 0 {
				continue
			}
			if !reflect.DeepEqual(want, got) {
				t.Fatalf("pattern %s on %q: findAll = %v, reference = %v", pattern, content, got, want)
			}
		}
	}
}

// DET-36: a token whose last character is '-' followed by a quote, space or
// end of input has no \b there, so fixed-length rules missed it outright and
// variable-length rules dropped the final character. Every prefix rule whose
// class contains '-' gets a trailing-dash fixture.
func TestPrefixRulesAcceptTokensEndingInDash(t *testing.T) {
	jwtHeader := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	tests := []struct {
		detector string
		token    string
	}{
		{detector: "google_api_key", token: "AIza" + strings.Repeat("A", 34) + "-"},
		{detector: "square_application_secret", token: "sq0c" + "sp-" + strings.Repeat("A", 42) + "-"},
		{detector: "square_oauth_token", token: "sq0a" + "tp-" + strings.Repeat("A", 21) + "-"},
		{detector: "json_web_token", token: jwtHeader + ".eyJzdWIiOiIxMjM0In0." + strings.Repeat("s", 20) + "-"},
		{detector: "anthropic_api_key", token: "sk-ant-" + strings.Repeat("a", 30) + "-"},
		{detector: "gitlab_personal_access_token", token: "glpat-" + strings.Repeat("A", 20) + "-"},
		{detector: "gitlab_deploy_token", token: "gl" + "dt-" + strings.Repeat("A", 20) + "-"},
		{detector: "gitlab_runner_token", token: "gl" + "rt-" + strings.Repeat("A", 20) + "-"},
		{detector: "vault_token", token: "hvs." + strings.Repeat("a", 24) + "-"},
		{detector: "sendgrid_api_key", token: "SG." + strings.Repeat("a", 20) + "." + strings.Repeat("b", 20) + "-"},
		{detector: "pypi_api_token", token: "pypi-" + strings.Repeat("A", 32) + "-"},
		{detector: "fly_api_token", token: "fo" + "1_" + strings.Repeat("A", 43) + "-"},
		{detector: "mapbox_secret_token", token: "s" + "k.eyJhbGciOiJSUzI1NiJ9." + strings.Repeat("A", 20) + "-"},
		{detector: "slack_token", token: "xoxb-1234567890-1234567890-" + strings.Repeat("a", 16) + "-"},
		{detector: "okta_api_token", token: "SS" + "WS " + strings.Repeat("a", 20) + "-"},
		{detector: "heroku_api_key", token: "HRKU-" + strings.Repeat("a", 20) + "-"},
	}

	set := Default()
	for _, tt := range tests {
		for _, terminator := range []string{"\"", " next", ""} {
			t.Run(tt.detector+" "+terminator, func(t *testing.T) {
				content := "value=" + tt.token + terminator
				match, ok := findDetectorMatch(set.Scan(ScanInput{Content: content}), tt.detector)
				if !ok {
					t.Fatalf("expected %s in %#v", tt.detector, set.Scan(ScanInput{Content: content}))
				}
				want := tt.token
				if tt.detector == "okta_api_token" {
					want = strings.TrimPrefix(tt.token, "SS"+"WS ")
				}
				if match.Value != want {
					t.Fatalf("match.Value = %q, want the full token %q", match.Value, want)
				}
			})
		}
	}
}

func TestAsciiLowerPreservesOffsets(t *testing.T) {
	value := "TOKEN=Ünïcödé-ÀBC\tX"
	lowered := asciiLower(value)
	if len(lowered) != len(value) {
		t.Fatalf("len changed: %d != %d", len(lowered), len(value))
	}
	if lowered != "token=Ünïcödé-Àbc\tx" {
		t.Fatalf("asciiLower() = %q", lowered)
	}
	if asciiLower("already lower") != "already lower" {
		t.Fatal("asciiLower changed an already lowercase value")
	}
}

func TestContainsSecretKeywordMatchesTheKeywordExpression(t *testing.T) {
	rng := rand.New(rand.NewSource(11)) //nolint:gosec // deterministic test data
	fragments := []string{"secret", "token", "password", "passwd", "pwd", "api_key", "api-key", "apikey", "auth", "authorization",
		"credential", "private_key", "private-key", "privatekey", "access_key", "access-key", "accesskey", "client_secret",
		"image", "version", "name", "value", "sec", "tok", "key", "_", "-", " ", "=", "x9"}
	for trial := 0; trial < 2000; trial++ {
		var builder strings.Builder
		for piece := 0; piece < 1+rng.Intn(5); piece++ {
			builder.WriteString(fragments[rng.Intn(len(fragments))])
		}
		line := builder.String()
		if got, want := containsSecretKeyword(line), secretKeywordExpression.MatchString(line); got != want {
			t.Fatalf("containsSecretKeyword(%q) = %t, regex = %t", line, got, want)
		}
	}
}
