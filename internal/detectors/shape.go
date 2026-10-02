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
	start, ok := discordFirstSegmentStart(content, searchStart, dot)
	if !ok {
		return 0, 0, false
	}
	middleEnd, ok := discordMiddleSegmentEnd(content, dot+1)
	if !ok {
		return 0, 0, false
	}
	end, ok := discordThirdSegmentEnd(content, middleEnd+1)
	if !ok {
		return 0, 0, false
	}
	return start, end, true
}

// discordFirstSegmentStart finds the first segment: 23-28 alphanumerics ending
// at the dot, starting at a word boundary. A longer run cannot match because
// \b only holds at its start.
func discordFirstSegmentStart(content string, searchStart, dot int) (int, bool) {
	start := dot
	for start > 0 && isAlphanumericByte(content[start-1]) {
		start--
	}
	if length := dot - start; length < 23 || length > 28 {
		return 0, false
	}
	return start, startsAtWordBoundary(content, searchStart, start)
}

// discordMiddleSegmentEnd finds the second segment: exactly 6-8 token bytes
// between the two dots. It returns the index of the second dot.
func discordMiddleSegmentEnd(content string, middle int) (int, bool) {
	middleEnd := middle
	for middleEnd < len(content) && isTokenByte(content[middleEnd]) {
		middleEnd++
	}
	if length := middleEnd - middle; length < 6 || length > 8 || middleEnd >= len(content) || content[middleEnd] != '.' {
		return 0, false
	}
	return middleEnd, true
}

// discordThirdSegmentEnd finds the third segment: at least 27 token bytes,
// greedy up to 38.
func discordThirdSegmentEnd(content string, third int) (int, bool) {
	end := third
	for end < len(content) && end-third < 38 && isTokenByte(content[end]) {
		end++
	}
	if end-third < 27 {
		return 0, false
	}
	return end, true
}

// startsAtWordBoundary reports whether a match starting at start lies inside
// the search window and begins at a \b word boundary.
func startsAtWordBoundary(content string, searchStart, start int) bool {
	return start >= searchStart && (start == 0 || !isWordByte(content[start-1]))
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
	start, ok := telegramBotIDStart(content, searchStart, colon)
	if !ok {
		return 0, 0, false
	}
	end, ok := telegramSecretEnd(content, colon+1)
	if !ok {
		return 0, 0, false
	}
	return start, end, true
}

// telegramBotIDStart finds the 8-10 digit bot id ending at the colon, starting
// at a word boundary.
func telegramBotIDStart(content string, searchStart, colon int) (int, bool) {
	start := colon
	for start > 0 && isDigitByte(content[start-1]) {
		start--
	}
	if length := colon - start; length < 8 || length > 10 {
		return 0, false
	}
	return start, startsAtWordBoundary(content, searchStart, start)
}

// telegramSecretEnd finds the 35 token bytes after the colon and requires the
// trailing boundary, so a longer secret is not cut at 35 characters.
func telegramSecretEnd(content string, secret int) (int, bool) {
	end := secret
	for end < len(content) && end-secret < 35 && isTokenByte(content[end]) {
		end++
	}
	if end-secret < 35 || (end < len(content) && isTokenByte(content[end])) {
		return 0, false
	}
	return end, true
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
