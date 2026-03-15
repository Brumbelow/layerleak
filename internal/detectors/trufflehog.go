package detectors

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"unicode"

	thdetectors "github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	thac "github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	thdefaults "github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
)

type trufflehogDetector struct{}

type trufflehogState struct {
	core       *thac.Core
	noKeywords []thdetectors.Detector
}

type matchLocator struct {
	content string
	next    map[string]int
}

var (
	trufflehogOnce  sync.Once
	trufflehogCache trufflehogState
)

func newTrufflehogDetector() Detector {
	return trufflehogDetector{}
}

func (trufflehogDetector) Name() string {
	return "trufflehog_defaults"
}

func (trufflehogDetector) Scan(input ScanInput) []Match {
	if strings.TrimSpace(input.Content) == "" {
		return nil
	}

	state := loadTrufflehogState()
	detectorsToRun := state.detectorsForContent(input.Content)
	if len(detectorsToRun) == 0 {
		return nil
	}

	ctx := context.Background()
	data := []byte(input.Content)
	locator := matchLocator{
		content: input.Content,
		next:    make(map[string]int),
	}
	matches := make([]Match, 0)
	for _, detector := range detectorsToRun {
		results, ok := runTrufflehogDetector(ctx, detector, data)
		if !ok {
			continue
		}
		for _, result := range results {
			match, ok := locator.matchFromResult(input, detector, result)
			if !ok {
				continue
			}
			matches = append(matches, match)
		}
	}

	return matches
}

func loadTrufflehogState() trufflehogState {
	trufflehogOnce.Do(func() {
		all := thdefaults.DefaultDetectors()
		keyworded := make([]thdetectors.Detector, 0, len(all))
		noKeywords := make([]thdetectors.Detector, 0)
		for _, detector := range all {
			if len(detector.Keywords()) == 0 {
				noKeywords = append(noKeywords, detector)
				continue
			}
			keyworded = append(keyworded, detector)
		}

		trufflehogCache = trufflehogState{
			core:       thac.NewAhoCorasickCore(keyworded),
			noKeywords: noKeywords,
		}
	})

	return trufflehogCache
}

func (s trufflehogState) detectorsForContent(content string) []thdetectors.Detector {
	detectorsToRun := make([]thdetectors.Detector, 0, len(s.noKeywords))
	seen := make(map[string]struct{})

	for _, detector := range s.noKeywords {
		key := trufflehogDetectorIdentity(detector)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		detectorsToRun = append(detectorsToRun, detector)
	}

	for _, match := range s.core.FindDetectorMatches([]byte(content)) {
		key := fmt.Sprintf("%v", match.Key)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		detectorsToRun = append(detectorsToRun, match.Detector)
	}

	return detectorsToRun
}

func runTrufflehogDetector(ctx context.Context, detector thdetectors.Detector, data []byte) (results []thdetectors.Result, ok bool) {
	defer func() {
		if recover() != nil {
			results = nil
			ok = false
		}
	}()

	results, err := detector.FromData(ctx, false, data)
	if err != nil {
		return nil, false
	}

	return results, true
}

func (l *matchLocator) matchFromResult(input ScanInput, detector thdetectors.Detector, result thdetectors.Result) (Match, bool) {
	fullValue := trufflehogFullValue(result)
	searchValues := trufflehogSearchValues(result)
	start, end, ok := l.find(searchValues...)
	if !ok {
		return Match{}, false
	}
	if fullValue == "" {
		fullValue = l.content[start:end]
	}

	return Match{
		Detector:   trufflehogDetectorName(detector, result),
		Value:      fullValue,
		Start:      start,
		End:        end,
		Confidence: adjustConfidence(ConfidenceHigh, input.Path, input.Key, fullValue),
	}, true
}

func (l *matchLocator) find(values ...string) (int, int, bool) {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		startOffset := l.next[trimmed]
		if index := strings.Index(l.content[startOffset:], trimmed); index >= 0 {
			start := startOffset + index
			end := start + len(trimmed)
			l.next[trimmed] = end
			return start, end, true
		}
		if startOffset == 0 {
			continue
		}
		if index := strings.Index(l.content, trimmed); index >= 0 {
			start := index
			end := start + len(trimmed)
			l.next[trimmed] = end
			return start, end, true
		}
	}

	return 0, 0, false
}

func trufflehogFullValue(result thdetectors.Result) string {
	for _, value := range []string{
		string(result.RawV2),
		string(result.Raw),
		result.GetPrimarySecretValue(),
	} {
		if trimmed := trimMatchValue(value); trimmed != "" {
			return trimmed
		}
	}

	return ""
}

func trufflehogSearchValues(result thdetectors.Result) []string {
	values := make([]string, 0, 8)
	seen := make(map[string]struct{})
	add := func(value string) {
		trimmed := trimMatchValue(value)
		if trimmed == "" {
			return
		}
		if _, ok := seen[trimmed]; ok {
			return
		}
		seen[trimmed] = struct{}{}
		values = append(values, trimmed)
	}

	add(result.GetPrimarySecretValue())
	add(string(result.Raw))
	add(string(result.RawV2))

	for _, value := range []string{string(result.Raw), string(result.RawV2)} {
		trimmed := trimMatchValue(value)
		if trimmed == "" {
			continue
		}
		for _, fragment := range splitMatchValue(trimmed) {
			add(fragment)
		}
	}

	return values
}

func trimMatchValue(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	if !isPrintableText(trimmed) {
		return ""
	}
	return trimmed
}

func splitMatchValue(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool {
		switch r {
		case ':', ';', ',', '\n', '\r', '\t', ' ':
			return true
		default:
			return false
		}
	})

	fragments := make([]string, 0, len(parts))
	for _, part := range parts {
		part = trimMatchValue(part)
		if part == "" || len(part) < 8 {
			continue
		}
		fragments = append(fragments, part)
	}

	return fragments
}

func trufflehogDetectorName(detector thdetectors.Detector, result thdetectors.Result) string {
	name := result.DetectorName
	if name == "" {
		name = result.DetectorType.String()
	}
	if name == "" || name == "UNKNOWN" {
		name = detector.Type().String()
	}
	if normalized, ok := trufflehogNameOverrides[name]; ok {
		return normalized
	}
	return camelToSnake(name)
}

func trufflehogDetectorIdentity(detector thdetectors.Detector) string {
	version := 0
	if versioned, ok := detector.(interface{ Version() int }); ok {
		version = versioned.Version()
	}
	return fmt.Sprintf("%s@%d", detector.Type().String(), version)
}

var trufflehogNameOverrides = map[string]string{
	"AWS":          "aws",
	"Github":       "github_token",
	"Gitlab":       "gitlab_token",
	"GoogleApiKey": "google_api_key",
	"NpmToken":     "npm_token",
	"SendGrid":     "sendgrid_api_key",
	"Shopify":      "shopify_access_token",
	"Slack":        "slack_token",
	"SlackWebhook": "slack_webhook",
	"Stripe":       "stripe_key",
}

func camelToSnake(value string) string {
	if value == "" {
		return ""
	}

	runes := []rune(value)
	var builder strings.Builder
	for index, r := range runes {
		if r == '-' || r == ' ' {
			builder.WriteByte('_')
			continue
		}
		if unicode.IsUpper(r) {
			if index > 0 && (unicode.IsLower(runes[index-1]) || unicode.IsDigit(runes[index-1])) {
				builder.WriteByte('_')
			}
			if index > 0 && index+1 < len(runes) && unicode.IsUpper(runes[index-1]) && unicode.IsLower(runes[index+1]) {
				builder.WriteByte('_')
			}
			builder.WriteRune(unicode.ToLower(r))
		} else {
			builder.WriteRune(unicode.ToLower(r))
		}
	}

	return builder.String()
}
