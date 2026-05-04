package limits

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestExceededErrorMessage(t *testing.T) {
	tests := []struct {
		name    string
		err     *ExceededError
		wantSub string
	}{
		{
			name:    "layer bytes",
			err:     &ExceededError{Kind: KindLayerBytes, Limit: 1024, Subject: "layer sha256:abc"},
			wantSub: "layer sha256:abc exceeded max layer bytes limit of 1024",
		},
		{
			name:    "layer entries",
			err:     &ExceededError{Kind: KindLayerEntries, Limit: 50000, Subject: "layer sha256:abc"},
			wantSub: "exceeded max layer entries limit of 50000",
		},
		{
			name:    "manifest bytes",
			err:     &ExceededError{Kind: KindManifestBytes, Limit: 1048576, Subject: "manifest"},
			wantSub: "exceeded max manifest bytes limit of 1048576",
		},
		{
			name:    "config bytes",
			err:     &ExceededError{Kind: KindConfigBytes, Limit: 2048, Subject: "config"},
			wantSub: "exceeded max config bytes limit of 2048",
		},
		{
			name:    "tag response bytes",
			err:     &ExceededError{Kind: KindTagResponseBytes, Limit: 8388608, Subject: "tag list"},
			wantSub: "exceeded max tag response bytes limit of 8388608",
		},
		{
			name:    "repository tags",
			err:     &ExceededError{Kind: KindRepositoryTags, Limit: 1000, Subject: "library/app"},
			wantSub: "exceeded max repository tags limit of 1000",
		},
		{
			name:    "repository targets",
			err:     &ExceededError{Kind: KindRepositoryTargets, Limit: 50, Subject: "library/app"},
			wantSub: "exceeded max repository targets limit of 50",
		},
		{
			name:    "unknown kind falls back to generic message",
			err:     &ExceededError{Kind: "unknown_kind", Limit: 7, Subject: "thing"},
			wantSub: "thing exceeded configured limit of 7",
		},
		{
			name:    "empty subject defaults to resource",
			err:     &ExceededError{Kind: KindLayerBytes, Limit: 1, Subject: ""},
			wantSub: "resource exceeded max layer bytes limit of 1",
		},
		{
			name:    "whitespace subject defaults to resource",
			err:     &ExceededError{Kind: KindLayerBytes, Limit: 2, Subject: "   "},
			wantSub: "resource exceeded max layer bytes limit of 2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if !strings.Contains(got, tt.wantSub) {
				t.Fatalf("Error() = %q, want substring %q", got, tt.wantSub)
			}
		})
	}
}

func TestNewExceededReturnsExceededError(t *testing.T) {
	err := NewExceeded(KindLayerBytes, 4096, "layer sha256:abc")

	target, ok := err.(*ExceededError)
	if !ok {
		t.Fatalf("NewExceeded() = %T, want *ExceededError", err)
	}
	if target.Kind != KindLayerBytes {
		t.Errorf("Kind = %q, want %q", target.Kind, KindLayerBytes)
	}
	if target.Limit != 4096 {
		t.Errorf("Limit = %d, want %d", target.Limit, 4096)
	}
	if target.Subject != "layer sha256:abc" {
		t.Errorf("Subject = %q, want %q", target.Subject, "layer sha256:abc")
	}
}

func TestIsExceededAndAsExceeded(t *testing.T) {
	direct := NewExceeded(KindManifestBytes, 1024, "manifest")
	wrapped := fmt.Errorf("save scan: %w", direct)
	doubleWrapped := fmt.Errorf("upper: %w", wrapped)
	plain := errors.New("not a limit error")

	if !IsExceeded(direct) {
		t.Error("IsExceeded(direct) = false, want true")
	}
	if !IsExceeded(wrapped) {
		t.Error("IsExceeded(wrapped) = false, want true")
	}
	if !IsExceeded(doubleWrapped) {
		t.Error("IsExceeded(doubleWrapped) = false, want true")
	}
	if IsExceeded(plain) {
		t.Error("IsExceeded(plain) = true, want false")
	}
	if IsExceeded(nil) {
		t.Error("IsExceeded(nil) = true, want false")
	}

	target, ok := AsExceeded(wrapped)
	if !ok {
		t.Fatal("AsExceeded(wrapped) ok = false, want true")
	}
	if target.Kind != KindManifestBytes || target.Limit != 1024 || target.Subject != "manifest" {
		t.Errorf("AsExceeded(wrapped) = %+v, want manifest-bytes/1024/manifest", target)
	}

	if _, ok := AsExceeded(plain); ok {
		t.Error("AsExceeded(plain) ok = true, want false")
	}
	if _, ok := AsExceeded(nil); ok {
		t.Error("AsExceeded(nil) ok = true, want false")
	}
}
