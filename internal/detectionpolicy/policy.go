package detectionpolicy

import (
	"encoding/base64"
	"net/url"
	"path"
	"strings"
	"unicode"
)

const (
	ReasonNone               = ""
	ReasonDiscardEmpty       = "empty_value"
	ReasonDiscardPlaceholder = "discard_placeholder"
	ReasonTestPath           = "test_path"
	ReasonExamplePath        = "example_path"
	ReasonPlaceholderMarker  = "placeholder_marker"
	ReasonReservedHost       = "reserved_host"
	ReasonKnownDummyValue    = "known_dummy_value"
)

func DiscardReason(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ReasonDiscardEmpty
	}

	for _, candidate := range discardValueCandidates(trimmed) {
		if containsDiscardPlaceholder(candidate) {
			return ReasonDiscardPlaceholder
		}
	}

	parsed, err := url.Parse(trimmed)
	if err == nil && shouldDiscardPlaceholderURL(parsed) {
		return ReasonDiscardPlaceholder
	}

	return ReasonNone
}

func ExampleReason(filePath, key, line, value string) string {
	if TestPathReason(filePath) != ReasonNone {
		return ReasonTestPath
	}

	if ExampleFilenameReason(filePath) != ReasonNone {
		return ReasonExamplePath
	}

	if hasKnownDummyValueSignal(value) {
		return ReasonKnownDummyValue
	}

	if hasPlaceholderMarkerSignal(filePath, key, line, value) {
		return ReasonPlaceholderMarker
	}

	weakSignals := 0
	reason := ReasonNone
	if hasWeakExamplePathSignal(filePath) {
		weakSignals++
		reason = firstReason(reason, ReasonExamplePath)
	}
	if hasReservedHostSignal(line) || hasReservedHostSignal(value) {
		weakSignals++
		reason = firstReason(reason, ReasonReservedHost)
	}
	if hasWeakExampleKeySignal(key) {
		weakSignals++
		reason = firstReason(reason, ReasonPlaceholderMarker)
	}

	if weakSignals >= 2 {
		return reason
	}

	return ReasonNone
}

func TestPathReason(filePath string) string {
	for _, part := range normalizedPathParts(filePath) {
		switch part {
		case "test", "tests", "__tests__", "fixture", "fixtures", "mock", "mocks":
			return ReasonTestPath
		}
	}

	return ReasonNone
}

func ExampleFilenameReason(filePath string) string {
	base := strings.ToLower(strings.TrimSpace(path.Base(strings.ReplaceAll(filePath, "\\", "/"))))
	if base == "" || base == "." || base == "/" {
		return ReasonNone
	}

	for _, marker := range []string{".example", ".sample", ".template"} {
		if strings.Contains(base, marker+".") || strings.HasSuffix(base, marker) {
			return ReasonExamplePath
		}
	}

	return ReasonNone
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

func hasPlaceholderMarkerSignal(values ...string) bool {
	for _, source := range values {
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

func firstReason(current, next string) string {
	if current != ReasonNone {
		return current
	}

	return next
}

func discardValueCandidates(value string) []string {
	candidates := []string{strings.ToLower(strings.TrimSpace(value))}
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		decoded, err := encoding.DecodeString(strings.TrimSpace(value))
		if err != nil {
			continue
		}
		text := strings.ToLower(strings.TrimSpace(string(decoded)))
		if text == "" || !isPrintableText(text) {
			continue
		}
		candidates = append(candidates, text)
	}

	return candidates
}

func containsDiscardPlaceholder(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	for _, marker := range []string{
		"foobar",
		"foo:bar",
		"user@example.com",
		"admin@example.com",
		"test@example.com",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}

	return false
}

func shouldDiscardPlaceholderURL(parsed *url.URL) bool {
	if parsed == nil || parsed.User == nil {
		return false
	}

	username := strings.ToLower(strings.TrimSpace(parsed.User.Username()))
	password, _ := parsed.User.Password()
	password = strings.ToLower(strings.TrimSpace(password))
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))

	if containsDiscardPlaceholder(username + ":" + password) {
		return true
	}
	if containsDiscardPlaceholder(username + "@" + host) {
		return true
	}

	return false
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
