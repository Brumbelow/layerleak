package api

import (
	"errors"
	"strings"
	"testing"
)

// TestDecodeCursorRequiresExactKeyParts pins the per-kind key check: a
// repository cursor carries a repository and registry and no ID, every other
// kind an ID and neither name.
func TestDecodeCursorRequiresExactKeyParts(t *testing.T) {
	tests := []struct {
		name    string
		payload cursorPayload
		kind    string
		valid   bool
	}{
		{name: "repository ok", payload: cursorPayload{Kind: cursorKindRepository, Micros: 1, Repository: "r", Registry: "g"}, kind: cursorKindRepository, valid: true},
		{name: "repository with id", payload: cursorPayload{Kind: cursorKindRepository, Micros: 1, ID: 1, Repository: "r", Registry: "g"}, kind: cursorKindRepository},
		{name: "repository without repository", payload: cursorPayload{Kind: cursorKindRepository, Micros: 1, Registry: "g"}, kind: cursorKindRepository},
		{name: "finding ok", payload: cursorPayload{Kind: cursorKindFinding, Micros: 1, ID: 1}, kind: cursorKindFinding, valid: true},
		{name: "finding with registry", payload: cursorPayload{Kind: cursorKindFinding, Micros: 1, ID: 1, Registry: "g"}, kind: cursorKindFinding},
		{name: "scan negative time", payload: cursorPayload{Kind: cursorKindScan, Micros: -1, ID: 1}, kind: cursorKindScan},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := decodeCursor(encodeCursor(test.payload), test.kind)
			if test.valid && err != nil {
				t.Fatalf("decodeCursor rejected a valid cursor: %v", err)
			}
			if !test.valid && !errors.Is(err, errCursorInvalid) {
				t.Fatalf("decodeCursor = %v, want errCursorInvalid", err)
			}
		})
	}
}

// TestValidateRegistryHostEdges pins the registry filter grammar at its
// boundaries: label and host lengths, empty labels and hosts, hyphen
// placement, port range and the bracketed IPv6 form.
func TestValidateRegistryHostEdges(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	host253 := strings.Repeat(label63+".", 3) + strings.Repeat("b", 61)
	tests := []struct {
		value string
		valid bool
	}{
		{value: "ghcr.io", valid: true},
		{value: "a", valid: true},
		{value: "my-registry.example", valid: true},
		{value: "10.0.0.5", valid: true},
		{value: "10.0.0.5:1", valid: true},
		{value: "registry:65535", valid: true},
		{value: "[::1]:5000", valid: true},
		{value: "[2001:db8::1]:443", valid: true},
		{value: label63 + ".example", valid: true},
		{value: host253, valid: true},
		{value: host253 + "c", valid: false},
		{value: strings.Repeat("a", 64) + ".example", valid: false},
		{value: "", valid: false},
		{value: ":5000", valid: false},
		{value: "registry:", valid: false},
		{value: "registry:0", valid: false},
		{value: "registry:65536", valid: false},
		{value: "registry:50:00", valid: false},
		{value: "a..b", valid: false},
		{value: ".example", valid: false},
		{value: "example.", valid: false},
		{value: "bad-.example", valid: false},
		{value: "-bad.example", valid: false},
		{value: "UPPER.example", valid: false},
		{value: "under_score.example", valid: false},
		{value: "café.example", valid: false},
		{value: "[::1]", valid: false},
		{value: "[::1]:0", valid: false},
		{value: "[not-an-ip]:5000", valid: false},
		{value: "[::1:5000", valid: false},
		{value: "::1", valid: false},
	}
	for _, test := range tests {
		err := validateRegistryHost(test.value)
		if test.valid && err != nil {
			t.Errorf("validateRegistryHost(%q) = %v, want nil", test.value, err)
		}
		if !test.valid && !errors.Is(err, errInvalidRegistryFilter) {
			t.Errorf("validateRegistryHost(%q) = %v, want errInvalidRegistryFilter", test.value, err)
		}
	}
}
