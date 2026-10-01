package limits

import (
	"errors"
	"fmt"
	"math"
	"testing"
)

func TestOverflowProbeLimit(t *testing.T) {
	tests := []struct {
		name  string
		limit int64
		want  int64
	}{
		{name: "zero", limit: 0, want: 1},
		{name: "small", limit: 10, want: 11},
		{name: "one below max", limit: math.MaxInt64 - 1, want: math.MaxInt64},
		{name: "max", limit: math.MaxInt64, want: math.MaxInt64},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := OverflowProbeLimit(tc.limit); got != tc.want {
				t.Fatalf("OverflowProbeLimit(%d) = %d, want %d", tc.limit, got, tc.want)
			}
			// The probe limit must never wrap around to a negative value.
			if got := OverflowProbeLimit(tc.limit); got < tc.limit {
				t.Fatalf("OverflowProbeLimit(%d) = %d is below the limit", tc.limit, got)
			}
		})
	}
}

func TestExceededErrorMessages(t *testing.T) {
	tests := []struct {
		name    string
		kind    Kind
		limit   int64
		subject string
		want    string
	}{
		{name: "layer bytes", kind: KindLayerBytes, limit: 512, subject: "layer sha256:abc", want: "layer sha256:abc exceeded max layer bytes limit of 512"},
		{name: "layer entries", kind: KindLayerEntries, limit: 7, subject: "layer", want: "layer exceeded max layer entries limit of 7"},
		{name: "manifest bytes", kind: KindManifestBytes, limit: 1024, subject: "manifest", want: "manifest exceeded max manifest bytes limit of 1024"},
		{name: "config bytes", kind: KindConfigBytes, limit: 2048, subject: "config blob", want: "config blob exceeded max config bytes limit of 2048"},
		{name: "tag response bytes", kind: KindTagResponseBytes, limit: 4096, subject: "tag list", want: "tag list exceeded max tag response bytes limit of 4096"},
		{name: "repository tags", kind: KindRepositoryTags, limit: 3, subject: "repository", want: "repository exceeded max repository tags limit of 3"},
		{name: "repository targets", kind: KindRepositoryTargets, limit: 2, subject: "repository", want: "repository exceeded max repository targets limit of 2"},
		{name: "unknown kind", kind: Kind("something_else"), limit: 9, subject: "thing", want: "thing exceeded configured limit of 9"},
		{name: "empty subject", kind: KindLayerBytes, limit: 1, subject: "", want: "resource exceeded max layer bytes limit of 1"},
		{name: "whitespace subject", kind: KindConfigBytes, limit: 1, subject: "  \t", want: "resource exceeded max config bytes limit of 1"},
		{name: "subject is trimmed", kind: KindRepositoryTags, limit: 5, subject: "  repo  ", want: "repo exceeded max repository tags limit of 5"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := NewExceeded(tc.kind, tc.limit, tc.subject)
			if got := err.Error(); got != tc.want {
				t.Fatalf("Error() = %q, want %q", got, tc.want)
			}
			exceeded, ok := AsExceeded(err)
			if !ok {
				t.Fatalf("AsExceeded() = false for a freshly constructed error")
			}
			if exceeded.Kind != tc.kind || exceeded.Limit != tc.limit || exceeded.Subject != tc.subject {
				t.Fatalf("AsExceeded() = %+v, want kind %q limit %d subject %q", exceeded, tc.kind, tc.limit, tc.subject)
			}
		})
	}
}

func TestIsExceededAndAsExceeded(t *testing.T) {
	base := NewExceeded(KindLayerBytes, 10, "layer")
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "plain error", err: errors.New("exceeded max layer bytes limit of 10"), want: false},
		{name: "direct", err: base, want: true},
		{name: "wrapped once", err: fmt.Errorf("read layer: %w", base), want: true},
		{name: "wrapped twice", err: fmt.Errorf("scan manifest: %w", fmt.Errorf("read layer: %w", base)), want: true},
		{name: "joined", err: errors.Join(errors.New("other"), base), want: true},
		{name: "joined without exceeded", err: errors.Join(errors.New("a"), errors.New("b")), want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsExceeded(tc.err); got != tc.want {
				t.Fatalf("IsExceeded() = %v, want %v", got, tc.want)
			}
			exceeded, ok := AsExceeded(tc.err)
			if ok != tc.want {
				t.Fatalf("AsExceeded() ok = %v, want %v", ok, tc.want)
			}
			if !ok {
				if exceeded != nil {
					t.Fatalf("AsExceeded() returned %+v for a non-exceeded error", exceeded)
				}
				return
			}
			if exceeded.Kind != KindLayerBytes || exceeded.Limit != 10 || exceeded.Subject != "layer" {
				t.Fatalf("AsExceeded() = %+v, want the original layer-bytes error", exceeded)
			}
		})
	}
}
