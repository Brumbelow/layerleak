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
}

type Detector interface {
	Name() string
	Scan(input ScanInput) []Match
}

type Set struct {
	detectors []Detector
}

func Default() Set {
	return Set{
		detectors: []Detector{
			newRegexDetector("pem_private_key", regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`), 0, ConfidenceHigh, nil),
			newRegexDetector("github_token", regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b`), 0, ConfidenceHigh, nil),
			newRegexDetector("gitlab_token", regexp.MustCompile(`\bglpat-[A-Za-z0-9\-_]{20,}\b`), 0, ConfidenceHigh, nil),
			newRegexDetector("slack_token", regexp.MustCompile(`\bxox(?:a|b|p|r|s)-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9-]{16,}\b`), 0, ConfidenceHigh, nil),
			newRegexDetector("stripe_key", regexp.MustCompile(`\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b`), 0, ConfidenceHigh, nil),
			newRegexDetector("aws_access_key_id", regexp.MustCompile(`\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b`), 0, ConfidenceHigh, nil),
			newRegexDetector("npm_token", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`), 0, ConfidenceHigh, nil),
			newRegexDetector("docker_auth_blob", regexp.MustCompile(`(?i)"auth"\s*:\s*"([A-Za-z0-9+/=]{8,})"`), 1, ConfidenceHigh, looksLikeDockerAuth),
			newRegexDetector("jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`), 0, ConfidenceMedium, looksLikeJWT),
			newRegexDetector("basic_auth_url", regexp.MustCompile(`https?://[^/\s:@]+:[^/\s@]+@[^/\s]+`), 0, ConfidenceHigh, nil),
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
				return matches[i].Detector < matches[j].Detector
			}
			return matches[i].End < matches[j].End
		}
		return matches[i].Start < matches[j].Start
	})

	deduped := make([]Match, 0, len(matches))
	seen := make(map[string]struct{})
	for _, match := range matches {
		key := strings.Join([]string{
			match.Detector,
			match.Value,
			strconv.Itoa(match.Start),
			strconv.Itoa(match.End),
			string(match.Confidence),
		}, "|")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
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
	indexes := d.expression.FindAllStringSubmatchIndex(input.Content, -1)
	matches := make([]Match, 0, len(indexes))
	for _, index := range indexes {
		start := index[0]
		end := index[1]
		if d.group > 0 && len(index) >= (d.group+1)*2 {
			start = index[d.group*2]
			end = index[d.group*2+1]
		}
		if start < 0 || end <= start || end > len(input.Content) {
			continue
		}
		value := input.Content[start:end]
		if d.validator != nil && !d.validator(value) {
			continue
		}
		matches = append(matches, Match{
			Detector:   d.name,
			Value:      value,
			Start:      start,
			End:        end,
			Confidence: adjustConfidence(d.base, input.Path, input.Key, value),
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
		if !secretKeywordExpression.MatchString(strings.ToLower(line.Value)) {
			continue
		}
		candidates := entropyCandidateExpression.FindAllStringIndex(line.Value, -1)
		for _, candidate := range candidates {
			value := line.Value[candidate[0]:candidate[1]]
			if !passesEntropy(value) {
				continue
			}
			matches = append(matches, Match{
				Detector:   "keyword_entropy",
				Value:      value,
				Start:      line.Offset + candidate[0],
				End:        line.Offset + candidate[1],
				Confidence: adjustConfidence(ConfidenceLow, input.Path, input.Key, value),
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
	return entropy >= 3.25
}
