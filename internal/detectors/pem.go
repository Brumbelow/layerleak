package detectors

import (
	"regexp"
	"strings"
)

var (
	pemBeginExpression = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----`)
	pemEndExpression   = regexp.MustCompile(`-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----`)
	// pemBodyLineExpression matches the lines a PEM body is made of: base64,
	// the "Proc-Type:"/"DEK-Info:" headers of encrypted keys, or blanks.
	pemBodyLineExpression = regexp.MustCompile(`^(?:[A-Za-z0-9+/=]+|[A-Za-z-]+: .*)?\s*$`)
)

// pemPrivateKeyDetector reports PEM-armoured private keys, including PGP
// "PRIVATE KEY BLOCK" armour. A key whose END marker is missing (truncated by
// the file-size limit, partially written) is still reported over its header
// and body at high confidence; a header with no body at all (a grep in a
// script, a log line) is reported at medium confidence.
type pemPrivateKeyDetector struct{}

func (pemPrivateKeyDetector) Name() string {
	return "pem_private_key"
}

func (d pemPrivateKeyDetector) IDs() []string {
	return singleID(d.Name())
}

func (d pemPrivateKeyDetector) Scan(input ScanInput) []Match {
	content := input.Content
	matches := make([]Match, 0)
	position := 0
	for position < len(content) {
		begin := pemBeginExpression.FindStringIndex(content[position:])
		if begin == nil {
			break
		}
		start, headerEnd := position+begin[0], position+begin[1]
		end, hasKeyMaterial := d.extent(content, headerEnd)
		value := content[start:end]
		// A bare header carries no key material, so it stays medium rather than
		// being promoted by its own "-----BEGIN" marker.
		confidence := ConfidenceMedium
		if hasKeyMaterial {
			confidence = adjustConfidence(ConfidenceHigh, input.Path, input.Key, value)
		}
		matches = append(matches, Match{
			Detector:   d.Name(),
			Value:      value,
			Start:      start,
			End:        end,
			Confidence: confidence,
			Priority:   priorityLocal,
		})
		position = end
	}
	return matches
}

// extent returns where a key starting with a header that ends at headerEnd
// stops, and whether any key material (an END marker or body lines) follows.
func (pemPrivateKeyDetector) extent(content string, headerEnd int) (int, bool) {
	rest := content[headerEnd:]
	if end := pemEndExpression.FindStringIndex(rest); end != nil {
		return headerEnd + end[1], true
	}

	// No END marker: take the base64 body lines that follow the header.
	end := headerEnd
	bodyLines := 0
	for cursor := headerEnd; cursor < len(content); {
		lineEnd := strings.IndexByte(content[cursor:], '\n')
		var line string
		next := len(content)
		if lineEnd >= 0 {
			line = content[cursor : cursor+lineEnd]
			next = cursor + lineEnd + 1
		} else {
			line = content[cursor:]
		}
		if cursor == headerEnd {
			// The remainder of the header line must be blank.
			if strings.TrimSpace(line) != "" {
				break
			}
		} else {
			if !pemBodyLineExpression.MatchString(line) {
				break
			}
			if strings.TrimSpace(line) != "" {
				bodyLines++
				end = cursor + len(line)
			}
		}
		cursor = next
	}
	if bodyLines == 0 {
		return headerEnd, false
	}
	return end, true
}
