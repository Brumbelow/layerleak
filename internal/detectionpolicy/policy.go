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
	// ReasonDefaultCredentials marks a URL whose userinfo is a well-known
	// default pair (admin:admin, postgres:postgres). It is a finding worth
	// seeing (CWE-1392), so it is suppressed with this reason rather than
	// discarded.
	ReasonDefaultCredentials = "default_credentials"
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
	if reason := strongExampleReason(filePath, key, line, value); reason != ReasonNone {
		return reason
	}
	return weakExampleReason(filePath, key, line, value)
}

// strongExampleReason returns the reason of the first signal that alone
// marks a value as example material, or ReasonNone.
func strongExampleReason(filePath, key, line, value string) string {
	if TestPathReason(filePath) != ReasonNone {
		return ReasonTestPath
	}

	if ExampleFilenameReason(filePath) != ReasonNone {
		return ReasonExamplePath
	}

	if hasKnownDummyValueSignal(value) {
		return ReasonKnownDummyValue
	}

	// Markers are decisive in the key, the value and the assignment itself,
	// but not in a trailing comment ("# TODO replace this with vault lookup")
	// and not in the file path, which only counts as a weak signal below.
	if hasPlaceholderMarkerSignal(key, stripTrailingComment(line), value) {
		return ReasonPlaceholderMarker
	}

	return credentialPairReason(value)
}

// weakExampleReason counts the signals that only suggest example material
// and returns the first one's reason when at least two are present.
func weakExampleReason(filePath, key, line, value string) string {
	weakSignals := 0
	reason := ReasonNone
	if hasWeakExamplePathSignal(filePath) {
		weakSignals++
		reason = firstReason(reason, ReasonExamplePath)
	}
	if hasWeakExampleFilenameSignal(filePath) {
		weakSignals++
		reason = firstReason(reason, ReasonExamplePath)
	}
	if hasPlaceholderMarkerSignal(filePath) {
		weakSignals++
		reason = firstReason(reason, ReasonPlaceholderMarker)
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

// TestPathReason reports the segments that only ever hold test material.
// OpenAPI spec/ directories, RPM SPECS/, e2e and acceptance configs, stubs and
// mocks ship in production images, so those segments are weak signals instead
// (see hasWeakExamplePathSignal).
func TestPathReason(filePath string) string {
	for _, part := range normalizedPathParts(filePath) {
		switch part {
		case "test", "tests", "__tests__", "testdata", "fixtures", "__mocks__":
			return ReasonTestPath
		}
	}

	return ReasonNone
}

func ExampleFilenameReason(filePath string) string {
	base := strings.ToLower(path.Base(strings.ReplaceAll(filePath, "\\", "/")))
	if base == "" || base == "." || base == "/" {
		return ReasonNone
	}

	for _, marker := range []string{".example", ".sample"} {
		if strings.Contains(base, marker+".") || strings.HasSuffix(base, marker) {
			return ReasonExamplePath
		}
	}

	return ReasonNone
}

// hasWeakExampleFilenameSignal reports *.template names. envsubst templates
// (nginx.conf.template) are shipped in production images, so the suffix alone
// does not suppress a finding.
func hasWeakExampleFilenameSignal(filePath string) bool {
	base := strings.ToLower(path.Base(strings.ReplaceAll(filePath, "\\", "/")))
	return strings.Contains(base, ".template.") || strings.HasSuffix(base, ".template")
}

// stripTrailingComment removes a shell/YAML '#' or C-style '//' comment that
// follows the assignment, so a note such as "# replace this with a vault
// lookup" does not turn the real secret before it into an example. A line
// that is entirely a comment yields "".
func stripTrailingComment(line string) string {
	for _, marker := range []string{" #", "\t#", " //", "\t//"} {
		if index := strings.Index(line, marker); index >= 0 {
			line = line[:index]
		}
	}
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
		return ""
	}
	return line
}

// credentialPairReason classifies the userinfo of a URL value: a well-known
// default pair is a suppressed default_credentials finding and the foobar
// placeholder user a known dummy. Pairs on reserved hosts never reach here;
// DiscardReason drops them.
func credentialPairReason(value string) string {
	trimmed := strings.Trim(strings.TrimSpace(value), "\"'`")
	if !strings.Contains(trimmed, "://") {
		return ReasonNone
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.User == nil {
		return ReasonNone
	}
	username := strings.ToLower(parsed.User.Username())
	password, _ := parsed.User.Password()
	if isPlaceholderCredentialPair(username, strings.ToLower(password)) {
		return ReasonDefaultCredentials
	}
	if username == "foobar" {
		return ReasonKnownDummyValue
	}
	return ReasonNone
}

func normalizedPathParts(filePath string) []string {
	value := filePath
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
		part = strings.ToLower(part)
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
		case "example", "examples", "sample", "samples", "demo", "demos", "doc", "docs",
			"spec", "specs", "e2e", "acceptance", "stubs", "mock", "mocks", "fixture":
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
			"your_api_key_here",
			"your-api-key-here",
			"your_api_key",
			"api_key_here",
			"insert_token",
			"token_goes_here",
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

	// A URL is judged by its credentials, not by its host: "example" in
	// git.examplecorp.internal says nothing about the password before it.
	if strings.Contains(trimmed, "://") {
		if parsed, err := url.Parse(trimmed); err == nil && parsed.User != nil {
			trimmed = parsed.User.String()
		}
	}

	lower := strings.ToLower(trimmed)
	upper := strings.ToUpper(trimmed)
	if strings.Contains(upper, "EXAMPLE") {
		return true
	}
	if strings.Contains(upper, "PLACEHOLDER") {
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
	lower := strings.ToLower(strings.Trim(strings.TrimSpace(value), "\"'`"))
	for _, marker := range []string{
		"foobar",
		"foo:bar",
		"user@example.com",
		"admin@example.com",
		"test@example.com",
		"admin:admin",
		"admin:password",
		"root:password",
		"test:test",
		"user:user",
	} {
		if lower == marker || lower == "user="+marker || lower == "username="+marker || lower == "credentials="+marker {
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

	// Only a placeholder on a reserved or example host is documentation. The
	// same pair on a real host is a default credential and stays a finding
	// (suppressed with ReasonDefaultCredentials by ExampleReason).
	if !hasReservedHostSignal(host) {
		return false
	}
	if isPlaceholderCredentialPair(username, password) || username == "foobar" {
		return true
	}
	return username == "user" || username == "admin" || username == "test"
}

// isPlaceholderCredentialPair reports the documentation placeholders and the
// factory-default pairs of common services.
func isPlaceholderCredentialPair(username, password string) bool {
	switch username + ":" + password {
	case "foo:bar", "admin:admin", "admin:password", "admin:admin123", "root:password", "root:root", "root:toor",
		"test:test", "user:user", "user:password", "guest:guest", "postgres:postgres", "mysql:mysql",
		"minioadmin:minioadmin", "elastic:changeme", "neo4j:neo4j", "rabbitmq:rabbitmq", "redis:redis":
		return true
	default:
		return false
	}
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
