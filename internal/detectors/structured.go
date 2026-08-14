package detectors

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
)

var (
	awsSharedCredentialsPathExpression = regexp.MustCompile(`(^|/)\.aws/(credentials|config)$`)
	gitCredentialsPathExpression       = regexp.MustCompile(`(^|/)\.git-credentials$`)
	uuidTokenExpression                = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	uuidTokenCandidateExpression       = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
)

type contextualTokenDetector struct {
	name               string
	keyExpression      *regexp.Regexp
	assignedExpression *regexp.Regexp
	prefixedExpression *regexp.Regexp
}

func newHerokuTokenDetector() Detector {
	return contextualTokenDetector{
		name:               "heroku_api_key",
		keyExpression:      regexp.MustCompile(`(?i)^heroku(?:[_-]?api)?[_-]?(?:key|token)$`),
		assignedExpression: regexp.MustCompile(`(?im)\bheroku(?:[_-]?api)?[_-]?(?:key|token)\b\s*(?:=|:|=>)\s*["']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`),
		prefixedExpression: regexp.MustCompile(`\bHRKU-[A-Za-z0-9_-]{20,}\b`),
	}
}

func newSnykTokenDetector() Detector {
	return contextualTokenDetector{
		name:               "snyk_api_token",
		keyExpression:      regexp.MustCompile(`(?i)^snyk(?:[_-]?api)?[_-]?(?:key|token)$`),
		assignedExpression: regexp.MustCompile(`(?im)\bsnyk(?:[_-]?api)?[_-]?(?:key|token)\b\s*(?:=|:|=>)\s*["']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`),
	}
}

func (d contextualTokenDetector) Name() string {
	return d.name
}

func (d contextualTokenDetector) Scan(input ScanInput) []Match {
	matches := make([]Match, 0, 2)
	appendIndexes := func(expression *regexp.Regexp, group int) {
		if expression == nil {
			return
		}
		for _, indexes := range expression.FindAllStringSubmatchIndex(input.Content, -1) {
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

	appendIndexes(d.assignedExpression, 1)
	appendIndexes(d.prefixedExpression, 0)

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
		trimmed := strings.TrimSpace(line.Value)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}

		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			currentSection = normalizeAWSSection(trimmed[1 : len(trimmed)-1])
			continue
		}

		key, value, start, end, ok := parseINIKeyValue(line.Value)
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
				start:   line.Offset + start,
				end:     line.Offset + end,
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
	end = len(line)

	trimmedRight := strings.TrimRight(trimmedLeft, " \t")
	end -= len(trimmedLeft) - len(trimmedRight)
	value = trimmedRight

	if len(value) >= 2 {
		switch {
		case strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\""):
			value = value[1 : len(value)-1]
			start++
			end--
		case strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'"):
			value = value[1 : len(value)-1]
			start++
			end--
		}
	}

	value = strings.TrimSpace(value)
	if value == "" || end <= start {
		return "", "", 0, 0, false
	}

	return key, value, start, end, true
}

type gitCredentialsDetector struct{}

func (gitCredentialsDetector) Name() string {
	return "git_credentials"
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
		password, ok := parsed.User.Password()
		if !ok || username == "" || !looksLikeBasicAuthURL(trimmed) {
			continue
		}

		needle := ":" + password + "@"
		index := strings.Index(line.Value, needle)
		if index < 0 {
			continue
		}

		matches = append(matches, Match{
			Detector:   "git_credentials_password",
			Value:      password,
			Start:      line.Offset + index + 1,
			End:        line.Offset + index + 1 + len(password),
			Confidence: adjustConfidence(ConfidenceHigh, input.Path, "password", password),
			Priority:   priorityStructured,
		})
	}

	return matches
}

func looksLikeAWSAccessKeyID(value string) bool {
	return regexp.MustCompile(`^(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}$`).MatchString(strings.TrimSpace(value))
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
