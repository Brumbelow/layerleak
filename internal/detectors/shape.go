package detectors

import "strings"

// Two token shapes carry no literal at all, so their regular expressions make
// Go's engine walk the NFA over every byte of every file (about 120 ms per
// mebibyte together). Each is implemented here as a linear scan anchored on
// the one punctuation byte the shape requires, with exactly the semantics of
// the expression it replaces; shape_test.go checks the equivalence against the
// original expressions on random inputs.

// discordBotTokenDetector implements
//
//	\b([A-Za-z0-9]{23,28})\.([A-Za-z0-9_-]{6,8})\.([A-Za-z0-9_-]{27,38})
//
// anchored on the first '.'.
type discordBotTokenDetector struct{}

func (discordBotTokenDetector) Name() string {
	return "discord_bot_token"
}

func (d discordBotTokenDetector) IDs() []string {
	return singleID(d.Name())
}

func (d discordBotTokenDetector) Scan(input ScanInput) []Match {
	content := input.Content
	matches := make([]Match, 0)
	position := 0
	for position < len(content) {
		offset := strings.IndexByte(content[position:], '.')
		if offset < 0 {
			break
		}
		dot := position + offset
		start, end, ok := discordBotTokenAt(content, position, dot)
		if !ok {
			position = dot + 1
			continue
		}
		// A regex match consumes its span whether or not the validator keeps it.
		position = end
		value := content[start:end]
		if !looksLikeDiscordBotToken(value) {
			continue
		}
		matches = append(matches, Match{
			Detector:   d.Name(),
			Value:      value,
			Start:      start,
			End:        end,
			Confidence: adjustConfidence(ConfidenceHigh, input.Path, input.Key, value),
			Priority:   priorityLocal,
		})
	}
	return matches
}

// discordBotTokenAt reports the span of a token whose first '.' is at dot and
// whose start is not before searchStart.
func discordBotTokenAt(content string, searchStart, dot int) (int, int, bool) {
	// First segment: 23-28 alphanumerics ending at the dot, starting at a word
	// boundary. A longer run cannot match because \b only holds at its start.
	start := dot
	for start > 0 && isAlphanumericByte(content[start-1]) {
		start--
	}
	if length := dot - start; length < 23 || length > 28 {
		return 0, 0, false
	}
	if start < searchStart || (start > 0 && isWordByte(content[start-1])) {
		return 0, 0, false
	}

	// Second segment: exactly 6-8 token bytes between the two dots.
	middle := dot + 1
	middleEnd := middle
	for middleEnd < len(content) && isTokenByte(content[middleEnd]) {
		middleEnd++
	}
	if length := middleEnd - middle; length < 6 || length > 8 || middleEnd >= len(content) || content[middleEnd] != '.' {
		return 0, 0, false
	}

	// Third segment: at least 27 token bytes, greedy up to 38.
	third := middleEnd + 1
	end := third
	for end < len(content) && end-third < 38 && isTokenByte(content[end]) {
		end++
	}
	if end-third < 27 {
		return 0, 0, false
	}
	return start, end, true
}

// telegramBotTokenDetector implements
//
//	\b\d{8,10}:[A-Za-z0-9_-]{35}(?:[^A-Za-z0-9_-]|$)
//
// anchored on the ':'. The trailing boundary is enforced so a longer secret
// is not cut at 35 characters with the remainder left in plaintext.
type telegramBotTokenDetector struct{}

func (telegramBotTokenDetector) Name() string {
	return "telegram_bot_token"
}

func (d telegramBotTokenDetector) IDs() []string {
	return singleID(d.Name())
}

func (d telegramBotTokenDetector) Scan(input ScanInput) []Match {
	content := input.Content
	matches := make([]Match, 0)
	position := 0
	for position < len(content) {
		offset := strings.IndexByte(content[position:], ':')
		if offset < 0 {
			break
		}
		colon := position + offset
		start, end, ok := telegramBotTokenAt(content, position, colon)
		if !ok {
			position = colon + 1
			continue
		}
		position = end
		value := content[start:end]
		matches = append(matches, Match{
			Detector:   d.Name(),
			Value:      value,
			Start:      start,
			End:        end,
			Confidence: adjustConfidence(ConfidenceHigh, input.Path, input.Key, value),
			Priority:   priorityLocal,
		})
	}
	return matches
}

func telegramBotTokenAt(content string, searchStart, colon int) (int, int, bool) {
	start := colon
	for start > 0 && isDigitByte(content[start-1]) {
		start--
	}
	if length := colon - start; length < 8 || length > 10 {
		return 0, 0, false
	}
	if start < searchStart || (start > 0 && isWordByte(content[start-1])) {
		return 0, 0, false
	}
	end := colon + 1
	for end < len(content) && end-(colon+1) < 35 && isTokenByte(content[end]) {
		end++
	}
	if end-(colon+1) < 35 || (end < len(content) && isTokenByte(content[end])) {
		return 0, 0, false
	}
	return start, end, true
}

func isDigitByte(b byte) bool {
	return b >= '0' && b <= '9'
}

func isAlphanumericByte(b byte) bool {
	return isDigitByte(b) || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

// isTokenByte is the [A-Za-z0-9_-] class.
func isTokenByte(b byte) bool {
	return isAlphanumericByte(b) || b == '_' || b == '-'
}
