package detectors

import (
	"regexp"
	"strings"
)

// compiledRule wraps a rule's regular expression with the cheap checks that
// let Go's regexp engine keep its literal-prefix fast path.
//
// Go's engine skips ahead with strings.Index only when the compiled program
// starts with literal runes. A leading \b (most token rules) or a leading
// (?i) (key-context rules) disables that, so every one of ~80 rules walked
// the NFA over every byte of every file and a scan ran at about 0.5 MB/s.
//
// A rule written with a leading \b is compiled without it and the boundary is
// enforced after the match with the same ASCII word-character semantics; a
// rejected candidate is re-searched from the next byte, exactly as the engine
// would have done. A trailing \b becomes "not followed by a word character",
// which is what \b meant for every rule whose token ends in a word character
// and additionally accepts tokens that end in '-' (one in 64 base64url
// positions), which \b never could (DET-36).
//
// Rules without a usable literal prefix declare required literals: the regex
// runs only when one of them occurs in the content (case-folded for (?i)
// rules), which is a few SIMD string searches instead of an NFA pass.
type compiledRule struct {
	expression     *regexp.Regexp
	literals       []string
	foldLiterals   bool
	boundaryBefore bool
	boundaryAfter  bool
}

func compileRule(expression *regexp.Regexp, literals ...string) compiledRule {
	source := expression.String()
	rule := compiledRule{}
	if strings.HasPrefix(source, `\b`) {
		source = source[2:]
		rule.boundaryBefore = true
	}
	if strings.HasSuffix(source, `\b`) && !strings.HasSuffix(source, `\\b`) {
		source = source[:len(source)-2]
		rule.boundaryAfter = true
	}
	rule.expression = expression
	if rule.boundaryBefore || rule.boundaryAfter {
		rule.expression = regexp.MustCompile(source)
	}
	rule.foldLiterals = strings.HasPrefix(source, "(?i")
	return rule.withLiterals(literals...)
}

// withLiterals returns the rule with the given required literals, folded to
// lowercase for a case-insensitive rule.
func (r compiledRule) withLiterals(literals ...string) compiledRule {
	r.literals = make([]string, 0, len(literals))
	for _, literal := range literals {
		if r.foldLiterals {
			literal = strings.ToLower(literal)
		}
		r.literals = append(r.literals, literal)
	}
	return r
}

// mayMatch reports whether the content contains one of the rule's required
// literals; a rule without literals may always match.
func (r compiledRule) mayMatch(input ScanInput) bool {
	if len(r.literals) == 0 {
		return true
	}
	haystack := input.Content
	if r.foldLiterals {
		haystack = input.loweredContent()
	}
	for _, literal := range r.literals {
		if strings.Contains(haystack, literal) {
			return true
		}
	}
	return false
}

// findAll returns the submatch index slices of every non-overlapping match
// that satisfies the rule's boundary checks, in the same order and with the
// same semantics as FindAllStringSubmatchIndex on the rule as written.
func (r compiledRule) findAll(input ScanInput) [][]int {
	if !r.mayMatch(input) {
		return nil
	}
	content := input.Content
	if !r.boundaryBefore && !r.boundaryAfter {
		return r.expression.FindAllStringSubmatchIndex(content, -1)
	}

	var results [][]int
	position := 0
	for position <= len(content) {
		indexes := r.expression.FindStringSubmatchIndex(content[position:])
		if indexes == nil {
			break
		}
		for index := range indexes {
			if indexes[index] >= 0 {
				indexes[index] += position
			}
		}
		start, end := indexes[0], indexes[1]
		if r.satisfiesBoundaries(content, start, end) {
			results = append(results, indexes)
			if end > start {
				position = end
			} else {
				position = end + 1
			}
			continue
		}
		position = start + 1
	}
	return results
}

func (r compiledRule) satisfiesBoundaries(content string, start, end int) bool {
	if r.boundaryBefore && start > 0 && isWordByte(content[start-1]) {
		return false
	}
	if r.boundaryAfter && end < len(content) && isWordByte(content[end]) {
		return false
	}
	return true
}

// isWordByte mirrors RE2's ASCII \b word class.
func isWordByte(b byte) bool {
	return b == '_' || (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

// asciiLower lowercases ASCII letters only, so byte offsets into the result
// line up with the original content (full Unicode lowering can change byte
// lengths).
func asciiLower(value string) string {
	if !strings.ContainsFunc(value, func(r rune) bool { return r >= 'A' && r <= 'Z' }) {
		return value
	}
	buffer := []byte(value)
	for index, b := range buffer {
		if b >= 'A' && b <= 'Z' {
			buffer[index] = b + ('a' - 'A')
		}
	}
	return string(buffer)
}

// loweredContent returns the ASCII-lowercased content, computed once per
// Set.Scan and recomputed only when a detector is driven outside a Set.
func (input ScanInput) loweredContent() string {
	if input.lowered != "" || input.Content == "" {
		return input.lowered
	}
	return asciiLower(input.Content)
}

// loweredView returns the input with its content replaced by the lowered copy.
// Byte offsets are identical, so a rule written in lowercase can run over the
// view (keeping Go's literal-prefix fast path instead of a (?i) flag) while
// values are still taken from the original content.
func (input ScanInput) loweredView() ScanInput {
	lowered := input.loweredContent()
	return ScanInput{Content: lowered, Path: input.Path, Key: input.Key, lowered: lowered}
}

// assignedValuePattern builds the one shape every key-context rule shares:
// the key, an optional closing quote (JSON's "key": "value"), the separator,
// an optional opening quote, the captured value and a terminator, so the four
// rules stay consistent and none of them misses the quoted-key form.
func assignedValuePattern(key, value, terminator string) string {
	return key + `["']?\s*(?:=|:|=>)\s*["']?(` + value + `)` + terminator
}

// gitlabRoutableTail is the ".<2 base36 version>.<2 base36 length + 7 base36
// CRC>" suffix GitLab 17.7+ appends to routable tokens; it is part of the
// token and must be part of the value.
const gitlabRoutableTail = `(?:\.[0-9a-z]{2}\.[0-9a-z]{9})?`

// secretKeywords are the literal forms of secretKeywordExpression; checking
// them with strings.Contains on a lowercased line is far cheaper than running
// the alternation regex, which has no literal prefix, over every line.
var secretKeywords = []string{
	"secret", "token", "password", "passwd", "pwd",
	"apikey", "api_key", "api-key",
	"auth", "credential",
	"privatekey", "private_key", "private-key",
	"accesskey", "access_key", "access-key",
}

func containsSecretKeyword(lowered string) bool {
	for _, keyword := range secretKeywords {
		if strings.Contains(lowered, keyword) {
			return true
		}
	}
	return false
}
