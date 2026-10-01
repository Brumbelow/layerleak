package layers

import (
	"unicode/utf16"
	"unicode/utf8"
)

// TextEncoding names the on-disk encoding of a scannable file whose content
// was transcoded to UTF-8 before classification and detection. It is empty for
// files scanned as stored.
type TextEncoding string

const (
	TextEncodingUTF16LE TextEncoding = "utf-16le"
	TextEncodingUTF16BE TextEncoding = "utf-16be"

	// utf16ProbeBytes bounds the prefix inspected for the alternating-NUL
	// pattern of BOM-less UTF-16 text (PowerShell scripts, web.config and .env
	// files written by Windows tools). Four code units are the minimum that can
	// be judged; a shorter file is classified as stored.
	utf16ProbeBytes    = 64
	utf16MinProbeUnits = 4

	// utf16PrintableRatio is the share of printable ASCII the non-NUL half of
	// the probe must reach. It matches the text classifier's own threshold so a
	// binary with a few zero bytes does not pass as text.
	utf16PrintableRatio = 0.85
)

// detectUTF16 reports the UTF-16 byte order of content and the length of its
// byte-order mark, or an empty encoding when the prefix is not UTF-16. A BOM
// decides immediately; without one the first code units must all be printable
// ASCII in the same byte order (a NUL in the other half of every unit).
func detectUTF16(content []byte) (TextEncoding, int) {
	if len(content) >= 2 {
		switch {
		case content[0] == 0xFF && content[1] == 0xFE:
			return TextEncodingUTF16LE, 2
		case content[0] == 0xFE && content[1] == 0xFF:
			return TextEncodingUTF16BE, 2
		}
	}
	probe := content
	if len(probe) > utf16ProbeBytes {
		probe = probe[:utf16ProbeBytes]
	}
	probe = probe[:len(probe)&^1]
	if len(probe) < 2*utf16MinProbeUnits {
		return "", 0
	}
	if matchesUTF16Pattern(probe, 1, 0) {
		return TextEncodingUTF16LE, 0
	}
	if matchesUTF16Pattern(probe, 0, 1) {
		return TextEncodingUTF16BE, 0
	}
	return "", 0
}

// matchesUTF16Pattern checks that every code unit of probe has a NUL at
// nulOffset and a predominantly printable ASCII byte at charOffset.
func matchesUTF16Pattern(probe []byte, nulOffset, charOffset int) bool {
	units := len(probe) / 2
	printable := 0
	for index := 0; index < len(probe); index += 2 {
		if probe[index+nulOffset] != 0 {
			return false
		}
		character := probe[index+charOffset]
		if character == 0 {
			// A NUL code unit is not text in either byte order.
			return false
		}
		if isPrintableByte(character) {
			printable++
		}
	}
	return float64(printable)/float64(units) >= utf16PrintableRatio
}

// transcodeUTF16 decodes content (after bomLength bytes) from the given byte
// order to UTF-8. The decoded size is bounded by maxBytes: the result is nil
// and ok is false when the UTF-8 form would exceed it, so a transcoded file is
// subject to the same per-file limit as one stored as UTF-8. Unpaired
// surrogates and a trailing odd byte become U+FFFD, as every tolerant decoder
// does, so detection sees the text that a reader would.
func transcodeUTF16(content []byte, encoding TextEncoding, bomLength int, maxBytes int64) ([]byte, bool) {
	body := content[bomLength:]
	units := make([]uint16, 0, len(body)/2+1)
	for index := 0; index+1 < len(body); index += 2 {
		if encoding == TextEncodingUTF16LE {
			units = append(units, uint16(body[index])|uint16(body[index+1])<<8)
		} else {
			units = append(units, uint16(body[index])<<8|uint16(body[index+1]))
		}
	}
	if len(body)%2 == 1 {
		units = append(units, utf8.RuneError)
	}
	decoded := make([]byte, 0, len(units))
	for _, r := range utf16.Decode(units) {
		decoded = utf8.AppendRune(decoded, r)
		if int64(len(decoded)) > maxBytes {
			return nil, false
		}
	}
	return decoded, true
}
