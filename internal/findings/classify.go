package findings

import (
	"path"
	"strings"

	"github.com/brumbelow/layerleak/internal/detectors"
)

func Classify(input Input, match detectors.Match) (Disposition, DispositionReason) {
	if hasTestPathSignal(input.FilePath) {
		return DispositionExample, DispositionReasonTestPath
	}

	if hasExampleFilenameSignal(input.FilePath) {
		return DispositionExample, DispositionReasonExamplePath
	}

	line := matchLine(input.Content, match.Start, match.End)
	if hasKnownDummyValueSignal(match.Value) {
		return DispositionExample, DispositionReasonKnownDummyValue
	}

	if hasPlaceholderMarkerSignal(input, line, match.Value) {
		return DispositionExample, DispositionReasonPlaceholderMarker
	}

	weakSignals := 0
	reason := DispositionReasonNone
	if hasWeakExamplePathSignal(input.FilePath) {
		weakSignals++
		reason = firstReason(reason, DispositionReasonExamplePath)
	}
	if hasReservedHostSignal(line) || hasReservedHostSignal(match.Value) {
		weakSignals++
		reason = firstReason(reason, DispositionReasonReservedHost)
	}
	if hasWeakExampleKeySignal(input.Key) {
		weakSignals++
		reason = firstReason(reason, DispositionReasonPlaceholderMarker)
	}

	if weakSignals >= 2 {
		return DispositionExample, reason
	}

	return DispositionActionable, DispositionReasonNone
}

func hasTestPathSignal(filePath string) bool {
	for _, part := range normalizedPathParts(filePath) {
		switch part {
		case "test", "tests", "__tests__", "fixture", "fixtures", "mock", "mocks":
			return true
		}
	}
	return false
}

func hasExampleFilenameSignal(filePath string) bool {
	base := strings.ToLower(strings.TrimSpace(path.Base(strings.ReplaceAll(filePath, "\\", "/"))))
	if base == "" || base == "." || base == "/" {
		return false
	}

	for _, marker := range []string{".example", ".sample", ".template"} {
		if strings.Contains(base, marker+".") || strings.HasSuffix(base, marker) {
			return true
		}
	}

	return false
}

func hasWeakExamplePathSignal(filePath string) bool {
	for _, part := range normalizedPathParts(filePath) {
		switch part {
		case "example", "examples", "sample", "samples", "demo", "demos", "doc", "docs":
			return true
		}
	}
	return false
}

func hasWeakExampleKeySignal(key string) bool {
	lower := strings.ToLower(strings.TrimSpace(key))
	return strings.Contains(lower, "example") || strings.Contains(lower, "sample") || strings.Contains(lower, "demo")
}

func normalizedPathParts(filePath string) []string {
	value := strings.TrimSpace(filePath)
	if value == "" {
		return nil
	}

	value = strings.ReplaceAll(value, "\\", "/")
	value = path.Clean(value)
	if value == "." || value == "/" {
		return nil
	}

	parts := strings.Split(value, "/")
	normalized := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.ToLower(strings.TrimSpace(part))
		if part == "" || part == "." {
			continue
		}
		normalized = append(normalized, part)
	}

	return normalized
}

func hasPlaceholderMarkerSignal(input Input, line, value string) bool {
	for _, source := range []string{input.FilePath, input.Key, line, value} {
		lower := strings.ToLower(source)
		for _, marker := range []string{
			"placeholder",
			"dummy",
			"fake",
			"changeme",
			"change_me",
			"replace_me",
			"replace-me",
			"replace this",
			"your_token_here",
			"your-token-here",
			"your_secret_here",
			"your-secret-here",
			"example token",
			"sample token",
		} {
			if strings.Contains(lower, marker) {
				return true
			}
		}
	}

	return false
}

func hasKnownDummyValueSignal(value string) bool {
	trimmed := strings.Trim(strings.TrimSpace(value), "\"'`")
	if trimmed == "" {
		return false
	}

	lower := strings.ToLower(trimmed)
	upper := strings.ToUpper(trimmed)
	if strings.Contains(upper, "EXAMPLE") {
		return true
	}

	switch lower {
	case "changeme", "replace_me", "replace-me", "dummy", "fake", "your_token_here", "your_secret_here":
		return true
	default:
		return false
	}
}

func hasReservedHostSignal(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{
		"example.com",
		"example.org",
		"example.net",
		"localhost",
		"127.0.0.1",
		"0.0.0.0",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func matchLine(content string, start, end int) string {
	if start < 0 {
		start = 0
	}
	if end < start {
		end = start
	}
	if end > len(content) {
		end = len(content)
	}

	lineStart := strings.LastIndex(content[:start], "\n")
	if lineStart < 0 {
		lineStart = 0
	} else {
		lineStart++
	}
	lineEnd := strings.Index(content[end:], "\n")
	if lineEnd < 0 {
		lineEnd = len(content)
	} else {
		lineEnd = end + lineEnd
	}

	return content[lineStart:lineEnd]
}

func firstReason(current, next DispositionReason) DispositionReason {
	if current != DispositionReasonNone {
		return current
	}
	return next
}
