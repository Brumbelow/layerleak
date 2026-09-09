package detectors

import "testing"

func TestParseINIKeyValuePreservesValueSpan(t *testing.T) {
	tests := []struct {
		name, line, key, value string
	}{
		{"unquoted", " color = blue \t", "color", "blue"},
		{"double quoted padding", "color = \" \tblue \t\"", "color", "blue"},
		{"single quoted padding", "color: '  blue  '", "color", "blue"},
		{"unicode padding", "color = \u2003blå\u00a0", "color", "blå"},
		{"quoted unicode padding", "color = '\u2003blå\u00a0'", "color", "blå"},
		{"unicode key and value", "色 = \" 藍 色 \"", "色", "藍 色"},
		{"internal whitespace", "color = blue sky", "color", "blue sky"},
		{"quoted markers", "color = 'blue # sky ; sea'", "color", "blue # sky ; sea"},
		{"unquoted markers", "color = blue # sky ; sea", "color", "blue # sky ; sea"},
		{"trailing comment unchanged", "color = 'blue' # sky", "color", "'blue' # sky"},
		{"mismatched quotes", "color = \"blue'", "color", "\"blue'"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, value, start, end, ok := parseINIKeyValue(tt.line)
			if !ok || key != tt.key || value != tt.value {
				t.Fatalf("parseINIKeyValue() = (%q, %q, %d, %d, %t), want (%q, %q)", key, value, start, end, ok, tt.key, tt.value)
			}
			if start < 0 || end > len(tt.line) || start >= end {
				t.Fatalf("invalid span [%d:%d] for %q", start, end, tt.line)
			}
			if got := tt.line[start:end]; got != value {
				t.Fatalf("line[%d:%d] = %q, want value %q", start, end, got, value)
			}
		})
	}
}

func TestParseINIKeyValueRejectsEmptyEntries(t *testing.T) {
	for _, line := range []string{"", "color", "= blue", "  : blue", "color =", "color = \t", "color = ''", "color = \" \t\"", "color = \u2003\u00a0"} {
		t.Run(line, func(t *testing.T) {
			key, value, start, end, ok := parseINIKeyValue(line)
			if ok || key != "" || value != "" || start != 0 || end != 0 {
				t.Fatalf("parseINIKeyValue(%q) = (%q, %q, %d, %d, %t), want empty rejected entry", line, key, value, start, end, ok)
			}
		})
	}
}
