package detectors

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// uuidPattern is the lowercase RFC 4122 text form.
const uuidPattern = `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`

var (
	awsSharedCredentialsPathExpression = regexp.MustCompile(`(^|/)\.aws/(credentials|config)$`)
	gitCredentialsPathExpression       = regexp.MustCompile(`(^|/)\.git-credentials$`)
	uuidTokenExpression                = regexp.MustCompile(`(?i)^` + uuidPattern + `$`)
	uuidTokenCandidateExpression       = regexp.MustCompile(`(?i)\b` + uuidPattern + `\b`)
)

type contextualTokenDetector struct {
	name               string
	keyExpression      *regexp.Regexp
	assignedExpression compiledRule
	prefixedExpression compiledRule
}

func newHerokuTokenDetector() Detector {
	return contextualTokenDetector{
		name:          "heroku_api_key",
		keyExpression: regexp.MustCompile(`(?i)^heroku(?:[_-]?api)?[_-]?(?:key|token)$`),
		// The assigned expression is lowercase and runs over the lowered content
		// so Go keeps the "heroku" literal prefix instead of a (?i) flag.
		assignedExpression: compileRule(regexp.MustCompile(`\b` + assignedValuePattern(`heroku(?:[_-]?api)?[_-]?(?:key|token)\b`, uuidPattern, `\b`))),
		prefixedExpression: compileRule(regexp.MustCompile(`\bHRKU-[A-Za-z0-9_-]{20,}\b`)),
	}
}

func newSnykTokenDetector() Detector {
	return contextualTokenDetector{
		name:               "snyk_api_token",
		keyExpression:      regexp.MustCompile(`(?i)^snyk(?:[_-]?api)?[_-]?(?:key|token)$`),
		assignedExpression: compileRule(regexp.MustCompile(`\b` + assignedValuePattern(`snyk(?:[_-]?api)?[_-]?(?:key|token)\b`, uuidPattern, `\b`))),
	}
}

func (d contextualTokenDetector) Name() string {
	return d.name
}

func (d contextualTokenDetector) IDs() []string {
	return singleID(d.name)
}

func (d contextualTokenDetector) Scan(input ScanInput) []Match {
	matches := make([]Match, 0, 2)
	appendIndexes := func(rule compiledRule, haystack ScanInput, group int) {
		if rule.expression == nil {
			return
		}
		for _, indexes := range rule.findAll(haystack) {
			start, end := indexes[0], indexes[1]
			if group > 0 && len(indexes) >= (group+1)*2 {
				start, end = indexes[group*2], indexes[group*2+1]
			}
			if start < 0 || end <= start || end > len(input.Content) {
				continue
			}
			matches = append(matches, Match{
				Detector:   d.name,
				Value:      input.Content[start:end],
				Start:      start,
				End:        end,
				Confidence: adjustConfidence(ConfidenceHigh, input.Path, input.Key, input.Content[start:end]),
				Priority:   priorityLocal,
			})
		}
	}

	appendIndexes(d.assignedExpression, input.loweredView(), 1)
	appendIndexes(d.prefixedExpression, input, 0)

	if d.keyExpression.MatchString(strings.TrimSpace(input.Key)) {
		for _, indexes := range uuidTokenCandidateExpression.FindAllStringIndex(input.Content, -1) {
			value := input.Content[indexes[0]:indexes[1]]
			if !uuidTokenExpression.MatchString(value) {
				continue
			}
			matches = append(matches, Match{
				Detector:   d.name,
				Value:      value,
				Start:      indexes[0],
				End:        indexes[1],
				Confidence: ConfidenceHigh,
				Priority:   priorityLocal,
			})
		}
	}

	return matches
}

func newTerraformCredentialsDetector() Detector {
	return newPathRegexDetector(
		"terraform_cloud_token",
		regexp.MustCompile(`(^|/)(?:\.terraformrc|(?:terraform\.d/)?credentials\.tfrc\.json)$`),
		regexp.MustCompile(`(?im)(?:^\s*token\s*=\s*["']?|\"token\"\s*:\s*\")([A-Za-z0-9][A-Za-z0-9+/=_.:-]{15,})`),
		1,
		ConfidenceHigh,
		looksLikeAssignedSensitiveValue,
	)
}

type awsSharedCredentialsDetector struct{}

func (awsSharedCredentialsDetector) Name() string {
	return "aws_shared_credentials"
}

// IDs are the per-field identifiers the reader emits; the strategy name
// itself never appears in a finding.
func (awsSharedCredentialsDetector) IDs() []string {
	return []string{"aws_shared_credentials_access_key_id", "aws_shared_credentials_secret_access_key", "aws_shared_credentials_session_token"}
}

func (awsSharedCredentialsDetector) Scan(input ScanInput) []Match {
	pathValue := strings.ToLower(strings.TrimSpace(input.Path))
	if pathValue == "" || !awsSharedCredentialsPathExpression.MatchString(pathValue) {
		return nil
	}

	entries := parseAWSSharedCredentialsEntries(input.Content)
	if len(entries) == 0 {
		return nil
	}

	profilesWithSecrets := make(map[string]bool)
	for _, entry := range entries {
		switch entry.key {
		case "aws_secret_access_key", "aws_session_token":
			profilesWithSecrets[entry.section] = true
		}
	}

	matches := make([]Match, 0, len(entries))
	for _, entry := range entries {
		switch entry.key {
		case "aws_access_key_id":
			if !looksLikeAWSAccessKeyID(entry.value) {
				continue
			}
			confidence := ConfidenceMedium
			if profilesWithSecrets[entry.section] {
				confidence = adjustConfidence(ConfidenceHigh, input.Path, entry.key, entry.value)
			}
			matches = append(matches, Match{
				Detector:   "aws_shared_credentials_access_key_id",
				Value:      entry.value,
				Start:      entry.start,
				End:        entry.end,
				Confidence: confidence,
				Priority:   priorityStructured,
			})
		case "aws_secret_access_key":
			if !looksLikeAWSSecretAccessKey(entry.value) {
				continue
			}
			matches = append(matches, Match{
				Detector:   "aws_shared_credentials_secret_access_key",
				Value:      entry.value,
				Start:      entry.start,
				End:        entry.end,
				Confidence: adjustConfidence(ConfidenceHigh, input.Path, entry.key, entry.value),
				Priority:   priorityStructured,
			})
		case "aws_session_token":
			if !looksLikeAWSSessionToken(entry.value) {
				continue
			}
			confidence := ConfidenceMedium
			if profilesWithSecrets[entry.section] {
				confidence = adjustConfidence(ConfidenceHigh, input.Path, entry.key, entry.value)
			}
			matches = append(matches, Match{
				Detector:   "aws_shared_credentials_session_token",
				Value:      entry.value,
				Start:      entry.start,
				End:        entry.end,
				Confidence: confidence,
				Priority:   priorityStructured,
			})
		}
	}

	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Start == matches[j].Start {
			if matches[i].End == matches[j].End {
				return matches[i].Detector < matches[j].Detector
			}
			return matches[i].End < matches[j].End
		}
		return matches[i].Start < matches[j].Start
	})

	return matches
}

type awsSharedCredentialsEntry struct {
	section string
	key     string
	value   string
	start   int
	end     int
}

func parseAWSSharedCredentialsEntries(content string) []awsSharedCredentialsEntry {
	lines := splitLinesWithOffsets(content)
	entries := make([]awsSharedCredentialsEntry, 0)
	currentSection := "default"

	for _, line := range lines {
		// A UTF-8 BOM is not White_Space, so TrimSpace leaves it in front of
		// the first section header and that profile would merge into default.
		lineValue, bomOffset := strings.CutPrefix(line.Value, "\uFEFF")
		offset := line.Offset
		if bomOffset {
			offset += len("\uFEFF")
		}
		trimmed := strings.TrimSpace(lineValue)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}

		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			currentSection = normalizeAWSSection(trimmed[1 : len(trimmed)-1])
			continue
		}

		key, value, start, end, ok := parseINIKeyValue(lineValue)
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		switch key {
		case "aws_access_key_id", "aws_secret_access_key", "aws_session_token":
			entries = append(entries, awsSharedCredentialsEntry{
				section: currentSection,
				key:     key,
				value:   value,
				start:   offset + start,
				end:     offset + end,
			})
		}
	}

	return entries
}

func normalizeAWSSection(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "profile ")
	if value == "" {
		return "default"
	}
	return value
}

func parseINIKeyValue(line string) (key, value string, start, end int, ok bool) {
	separator := strings.IndexAny(line, "=:")
	if separator <= 0 {
		return "", "", 0, 0, false
	}

	key = strings.TrimSpace(line[:separator])
	if key == "" {
		return "", "", 0, 0, false
	}

	valuePart := line[separator+1:]
	trimmedLeft := strings.TrimLeft(valuePart, " \t")
	if trimmedLeft == "" {
		return "", "", 0, 0, false
	}
	start = separator + 1 + len(valuePart) - len(trimmedLeft)
	// Trim every trailing space, including the '\r' of CRLF files, before the
	// surrounding-quote check or `"..."\r` keeps its quotes.
	value = strings.TrimRightFunc(trimmedLeft, unicode.IsSpace)

	if len(value) >= 2 && value[0] == value[len(value)-1] && (value[0] == '"' || value[0] == '\'') {
		value = value[1 : len(value)-1]
		start++
	}

	start += len(value) - len(strings.TrimLeftFunc(value, unicode.IsSpace))
	value = strings.TrimSpace(value)
	end = start + len(value)
	if value == "" {
		return "", "", 0, 0, false
	}

	return key, value, start, end, true
}

type gitCredentialsDetector struct{}

func (gitCredentialsDetector) Name() string {
	return "git_credentials"
}

func (gitCredentialsDetector) IDs() []string {
	return []string{"git_credentials_password"}
}

func (gitCredentialsDetector) Scan(input ScanInput) []Match {
	pathValue := strings.ToLower(strings.TrimSpace(input.Path))
	if pathValue == "" || !gitCredentialsPathExpression.MatchString(pathValue) {
		return nil
	}

	lines := splitLinesWithOffsets(input.Content)
	matches := make([]Match, 0)
	for _, line := range lines {
		trimmed := strings.TrimSpace(line.Value)
		if trimmed == "" {
			continue
		}

		parsed, err := url.Parse(trimmed)
		if err != nil || parsed.User == nil {
			continue
		}
		username := parsed.User.Username()
		if _, ok := parsed.User.Password(); !ok || username == "" || !looksLikeBasicAuthURL(trimmed) {
			continue
		}

		// Report the raw bytes of the password as stored: git credential-store
		// percent-encodes reserved characters, and url.Parse decodes them, so a
		// decoded needle would not be found in the line.
		start, end, ok := rawURLPasswordSpan(line.Value)
		if !ok {
			continue
		}
		password := line.Value[start:end]

		matches = append(matches, Match{
			Detector:   "git_credentials_password",
			Value:      password,
			Start:      line.Offset + start,
			End:        line.Offset + end,
			Confidence: adjustConfidence(ConfidenceHigh, input.Path, "password", password),
			Priority:   priorityStructured,
		})
	}

	return matches
}

// rawURLPasswordSpan returns the span of the password inside the userinfo of
// the URL in line, as written (not decoded).
func rawURLPasswordSpan(line string) (int, int, bool) {
	schemeEnd := strings.Index(line, "://")
	if schemeEnd < 0 {
		return 0, 0, false
	}
	authorityStart := schemeEnd + 3
	authority := line[authorityStart:]
	if slash := strings.IndexByte(authority, '/'); slash >= 0 {
		authority = authority[:slash]
	}
	at := strings.LastIndexByte(authority, '@')
	if at < 0 {
		return 0, 0, false
	}
	userinfo := authority[:at]
	colon := strings.IndexByte(userinfo, ':')
	if colon < 0 || colon+1 >= len(userinfo) {
		return 0, 0, false
	}
	return authorityStart + colon + 1, authorityStart + at, true
}

var awsAccessKeyIDExpression = regexp.MustCompile(`^(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}$`)

func looksLikeAWSAccessKeyID(value string) bool {
	return awsAccessKeyIDExpression.MatchString(strings.TrimSpace(value))
}

func looksLikeAWSSessionToken(value string) bool {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) < 16 || !isPrintableText(trimmed) || strings.Contains(trimmed, " ") {
		return false
	}
	if sensitiveValue(trimmed) {
		return true
	}
	if !hasStrongEntropyShape(trimmed) {
		return false
	}
	return passesEntropy(trimmed)
}

func looksLikeAssignedSensitiveValue(value string) bool {
	trimmed := strings.Trim(strings.TrimSpace(value), "\"'`")
	if len(trimmed) < 16 || !isPrintableText(trimmed) || strings.Contains(trimmed, " ") {
		return false
	}
	if looksLikeJWT(trimmed) || sensitiveValue(trimmed) {
		return true
	}
	if !hasStrongEntropyShape(trimmed) {
		return false
	}
	return passesEntropy(trimmed)
}
