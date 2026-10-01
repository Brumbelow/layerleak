package detectors

import (
	"net/url"
	"regexp"
	"strings"
)

// URL userinfo and host character classes shared by the credentialed-URL
// rules. Quotes, angle brackets and backticks end the userinfo so JSON, YAML,
// Python and JavaScript quoting never leaks into the matched value, and the
// host is limited to characters url.Parse accepts in a host so the match ends
// before a closing brace or quote instead of swallowing it (which made Go's
// parser reject the whole compact-JSON value).
const (
	urlUserinfoNameClass  = "[^/\\s:@\"'<>`]*"
	urlUserinfoValueClass = "[^/\\s@\"'<>`]+"
	urlHostClass          = "[A-Za-z0-9.\\-_~%\\[\\]:]+"
	// urlHostListClass also allows the comma-separated host lists MongoDB and
	// AMQP connection strings carry.
	urlHostListClass = "[A-Za-z0-9.\\-_~%\\[\\]:,]+"
)

var (
	basicAuthURLSchemes = []string{"http", "https"}

	// connectionURLSchemes are the database, cache, queue and service URL
	// schemes whose userinfo carries a password in container ENV and .env
	// files.
	connectionURLSchemes = []string{
		"postgres", "postgresql", "mysql", "mariadb", "mssql", "sqlserver",
		"mongodb", "mongodb+srv", "redis", "rediss", "amqp", "amqps",
		"cloudinary", "nats", "ftp", "ftps", "sftp", "smtp", "smtps", "ldap", "ldaps",
	}
)

// credentialedURLDetector finds scheme://user:password@host for a fixed list
// of schemes. Each scheme compiles to its own pattern whose literal prefix
// lets Go's engine skip ahead with strings.Index, and the patterns run over
// the ASCII-lowercased content (whose byte offsets equal the original's) so an
// uppercase scheme still matches without a case-insensitive alternation, which
// has no literal prefix and cost more than every other rule combined. Values
// are taken from the original content at the matched offsets.
type credentialedURLDetector struct {
	name      string
	rules     []compiledRule
	schemes   map[string]struct{}
	validator func(string) bool
}

func newCredentialedURLDetector(name string, schemes []string, hostClass string) credentialedURLDetector {
	detector := credentialedURLDetector{
		name:    name,
		rules:   make([]compiledRule, 0, len(schemes)),
		schemes: make(map[string]struct{}, len(schemes)),
	}
	for _, scheme := range schemes {
		pattern := `\b` + regexp.QuoteMeta(scheme) + "://" + urlUserinfoNameClass + ":" + urlUserinfoValueClass + "@" + hostClass
		detector.rules = append(detector.rules, compileRule(regexp.MustCompile(pattern), scheme+"://"))
		detector.schemes[scheme] = struct{}{}
	}
	detector.validator = func(value string) bool {
		return looksLikeCredentialedURL(value, func(scheme string) bool {
			_, ok := detector.schemes[scheme]
			return ok
		})
	}
	return detector
}

func (d credentialedURLDetector) Name() string {
	return d.name
}

func (d credentialedURLDetector) IDs() []string {
	return singleID(d.Name())
}

func (d credentialedURLDetector) Scan(input ScanInput) []Match {
	lowered := input.loweredContent()
	loweredInput := ScanInput{Content: lowered, Path: input.Path, Key: input.Key, lowered: lowered}
	matches := make([]Match, 0)
	for _, rule := range d.rules {
		for _, index := range rule.findAll(loweredInput) {
			start, end := index[0], index[1]
			if start < 0 || end <= start || end > len(input.Content) {
				continue
			}
			value := input.Content[start:end]
			if !d.validator(value) {
				continue
			}
			matches = append(matches, Match{
				Detector:   d.name,
				Value:      value,
				Start:      start,
				End:        end,
				Confidence: adjustConfidence(ConfidenceHigh, input.Path, input.Key, value),
				Priority:   priorityLocal,
			})
		}
	}
	return matches
}

// looksLikeBasicAuthURL is the http(s) validator, shared with the
// .git-credentials detector.
func looksLikeBasicAuthURL(value string) bool {
	return looksLikeCredentialedURL(value, func(scheme string) bool {
		return scheme == "http" || scheme == "https"
	})
}

// looksLikeCredentialedURL accepts a URL whose userinfo carries a non-empty
// password for an allowed scheme. The username may be empty (redis://:pw@host,
// https://:token@registry) because the password alone is the credential.
func looksLikeCredentialedURL(value string, schemeAllowed func(string) bool) bool {
	if !isPrintableText(value) {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return false
	}
	if !schemeAllowed(strings.ToLower(parsed.Scheme)) {
		return false
	}
	if parsed.User == nil {
		return false
	}
	password, ok := parsed.User.Password()
	if !ok || password == "" {
		return false
	}
	if parsed.Hostname() == "" {
		return false
	}
	return isPrintableText(parsed.User.Username()) && isPrintableText(password) && isPrintableText(parsed.Hostname())
}
