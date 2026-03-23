package detectors

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
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
}

type Match struct {
	Detector   string
	Value      string
	Start      int
	End        int
	Confidence Confidence
	Priority   int
}

type Detector interface {
	Name() string
	Scan(input ScanInput) []Match
}

type Set struct {
	detectors []Detector
}

const (
	priorityEntropy    = 1
	priorityTrufflehog = 2
	priorityLocal      = 3
	priorityStructured = 4
)

func Default() Set {
	return Set{
		detectors: []Detector{
			awsSharedCredentialsDetector{},
			gitCredentialsDetector{},
			newTerraformCredentialsDetector(),
			newPathRegexDetector("docker_auth_blob", regexp.MustCompile(`(^|/)\.docker/config\.json$`), regexp.MustCompile(`(?i)"auth"\s*:\s*"([A-Za-z0-9+/=]{8,})"`), 1, ConfidenceHigh, looksLikeDockerAuth),
			newPathRegexDetector("docker_config_identitytoken", regexp.MustCompile(`(^|/)\.docker/config\.json$`), regexp.MustCompile(`(?i)"identitytoken"\s*:\s*"([^"\s]{16,})"`), 1, ConfidenceHigh, looksLikeAssignedSensitiveValue),
			newKeyValueDetector("assigned_sensitive_value", regexp.MustCompile(`(?i)client[_-]?secret|access[_-]?token|refresh[_-]?token|auth[_-]?token`), regexp.MustCompile(`[A-Za-z0-9][A-Za-z0-9+/=_.:-]{15,}`), ConfidenceMedium, looksLikeAssignedSensitiveValue),
			newTrufflehogDetector(),
			newRegexDetector("pem_private_key", regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`), 0, ConfidenceHigh, nil),
			newRegexDetector("github_token", regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b`), 0, ConfidenceHigh, nil),
			newRegexDetector("gitlab_token", regexp.MustCompile(`\bglpat-[A-Za-z0-9\-_]{20,}\b`), 0, ConfidenceHigh, nil),
			newRegexDetector("slack_token", regexp.MustCompile(`\bxox(?:a|b|p|r|s)-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9-]{16,}\b`), 0, ConfidenceHigh, nil),
			newRegexDetector("slack_webhook", regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{16,}`), 0, ConfidenceHigh, nil),
			newRegexDetector("stripe_key", regexp.MustCompile(`\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b`), 0, ConfidenceHigh, nil),
			newRegexDetector("aws_access_key_id", regexp.MustCompile(`\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b`), 0, ConfidenceHigh, nil),
			newRegexDetector("aws_secret_access_key", regexp.MustCompile(`(?i)(?:aws[_-]?secret[_-]?access[_-]?key|secret[_-]?access[_-]?key)\s*(?:=|:|=>)\s*["']?([A-Za-z0-9/+=]{40})`), 1, ConfidenceHigh, looksLikeAWSSecretAccessKey),
			newKeyValueDetector("aws_secret_access_key", regexp.MustCompile(`aws[_-]?secret[_-]?access[_-]?key|secret[_-]?access[_-]?key`), regexp.MustCompile(`[A-Za-z0-9/+=]{40}`), ConfidenceHigh, looksLikeAWSSecretAccessKey),
			newRegexDetector("google_api_key", regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`), 0, ConfidenceHigh, nil),
			newRegexDetector("sendgrid_api_key", regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{16,64}\.[A-Za-z0-9_-]{16,64}\b`), 0, ConfidenceHigh, nil),
			newRegexDetector("shopify_access_token", regexp.MustCompile(`\bshpat_[a-fA-F0-9]{32}\b`), 0, ConfidenceHigh, nil),
			newRegexDetector("npm_token", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`), 0, ConfidenceHigh, nil),
			newPathRegexDetector("npmrc_auth_token", regexp.MustCompile(`(^|/)\.npmrc$`), regexp.MustCompile(`(?im)^\s*(?:\/\/[^\s=]+:)?_authToken\s*=\s*([^\s#;]+)\s*$`), 1, ConfidenceHigh, hasMinPrintableLength(8)),
			newPathRegexDetector("npmrc_auth", regexp.MustCompile(`(^|/)\.npmrc$`), regexp.MustCompile(`(?im)^\s*(?:\/\/[^\s=]+:)?_auth\s*=\s*([A-Za-z0-9+/=]{8,})\s*$`), 1, ConfidenceHigh, looksLikeBase64Credential),
			newRegexDetector("docker_auth_blob", regexp.MustCompile(`(?i)"auth"\s*:\s*"([A-Za-z0-9+/=]{8,})"`), 1, ConfidenceHigh, looksLikeDockerAuth),
			newRegexDetector("jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`), 0, ConfidenceMedium, looksLikeJWT),
			newPathRegexDetector("netrc_password", regexp.MustCompile(`(^|/)\.netrc$`), regexp.MustCompile(`(?im)\bpassword\s+([^\s#]+)`), 1, ConfidenceMedium, hasMinPrintableLength(4)),
			newPathRegexDetector("pypirc_password", regexp.MustCompile(`(^|/)\.pypirc$`), regexp.MustCompile(`(?im)^\s*password\s*=\s*([^\s#;]+)\s*$`), 1, ConfidenceMedium, hasMinPrintableLength(4)),
			newRegexDetector("basic_auth_url", regexp.MustCompile(`https?://[^/\s:@]+:[^/\s@]+@[^/\s]+`), 0, ConfidenceHigh, looksLikeBasicAuthURL),
			contextEntropyDetector{},
		},
	}
}

func (s Set) Len() int {
	return len(s.detectors)
}

func (s Set) Scan(input ScanInput) []Match {
	matches := make([]Match, 0)
	for _, detector := range s.detectors {
		matches = append(matches, detector.Scan(input)...)
	}

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

	return deduped
}

type regexDetector struct {
	name       string
	expression *regexp.Regexp
	group      int
	base       Confidence
	validator  func(string) bool
}

func newRegexDetector(name string, expression *regexp.Regexp, group int, base Confidence, validator func(string) bool) regexDetector {
	return regexDetector{
		name:       name,
		expression: expression,
		group:      group,
		base:       base,
		validator:  validator,
	}
}

func (d regexDetector) Name() string {
	return d.name
}

func (d regexDetector) Scan(input ScanInput) []Match {
	return scanRegexMatches(d.name, d.expression, d.group, d.base, priorityLocal, d.validator, input)
}

type pathRegexDetector struct {
	name           string
	pathExpression *regexp.Regexp
	expression     *regexp.Regexp
	group          int
	base           Confidence
	validator      func(string) bool
}

func newPathRegexDetector(name string, pathExpression, expression *regexp.Regexp, group int, base Confidence, validator func(string) bool) pathRegexDetector {
	return pathRegexDetector{
		name:           name,
		pathExpression: pathExpression,
		expression:     expression,
		group:          group,
		base:           base,
		validator:      validator,
	}
}

func (d pathRegexDetector) Name() string {
	return d.name
}

func (d pathRegexDetector) Scan(input ScanInput) []Match {
	pathValue := strings.ToLower(strings.TrimSpace(input.Path))
	if pathValue == "" || !d.pathExpression.MatchString(pathValue) {
		return nil
	}
	priority := priorityLocal
	if d.name == "docker_auth_blob" || strings.HasPrefix(d.name, "docker_config_") || d.name == "terraform_cloud_token" {
		priority = priorityStructured
	}
	return scanRegexMatches(d.name, d.expression, d.group, d.base, priority, d.validator, input)
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

func scanRegexMatches(name string, expression *regexp.Regexp, group int, base Confidence, priority int, validator func(string) bool, input ScanInput) []Match {
	indexes := expression.FindAllStringSubmatchIndex(input.Content, -1)
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

func (contextEntropyDetector) Scan(input ScanInput) []Match {
	lines := splitLinesWithOffsets(input.Content)
	matches := make([]Match, 0)
	for _, line := range lines {
		trimmed := strings.TrimSpace(line.Value)
		if trimmed == "" {
			continue
		}
		lowerLine := strings.ToLower(line.Value)
		if !secretKeywordExpression.MatchString(lowerLine) && !sensitiveKey(input.Key) {
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
	secretKeywordExpression    = regexp.MustCompile(`secret|token|password|passwd|pwd|api[_-]?key|auth|authorization|credential|private[_-]?key|access[_-]?key|client[_-]?secret`)
	entropyCandidateExpression = regexp.MustCompile(`[A-Za-z0-9][A-Za-z0-9+/=_-]{19,}`)
	wordyCandidateExpression   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*$`)
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
	for _, token := range []string{"secret", "token", "credential", "key", ".docker"} {
		if strings.Contains(value, token) {
			return true
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

func looksLikeBasicAuthURL(value string) bool {
	if !isPrintableText(value) {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}
	if parsed.User == nil {
		return false
	}
	username := parsed.User.Username()
	password, ok := parsed.User.Password()
	if !ok || username == "" || password == "" {
		return false
	}
	if parsed.Hostname() == "" {
		return false
	}
	return isPrintableText(username) && isPrintableText(password) && isPrintableText(parsed.Hostname())
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

func hasMinPrintableLength(min int) func(string) bool {
	return func(value string) bool {
		trimmed := strings.TrimSpace(value)
		return len(trimmed) >= min && isPrintableText(trimmed)
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

func hasAssignedValuePrefix(prefix string) bool {
	trimmed := strings.TrimRightFunc(prefix, unicode.IsSpace)
	trimmed = strings.TrimRight(trimmed, "\"'`")
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
	return hasLetter
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
	return entropy >= 3.75
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
		return priorityStructured
	default:
		return priorityLocal
	}
}
