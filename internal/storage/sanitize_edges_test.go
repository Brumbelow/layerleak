package storage

import (
	"testing"

	"github.com/brumbelow/layerleak/v3/internal/manifest"
)

// TestSanitizeScanRecordCopiesNestedSlicesAndKeepsNil pins that the nested
// manifest slices are copied before they are cleaned and that absent slices
// stay nil rather than becoming empty.
func TestSanitizeScanRecordCopiesNestedSlicesAndKeepsNil(t *testing.T) {
	original := ScanRecord{
		Targets: []TargetRecord{{
			ResolvedReference: "ref\x00",
			RequestedDigest:   "sha256:\x01",
			Manifests: []ManifestRecord{{
				Digest:     "sha256:\x02",
				RootDigest: "sha256:\x03",
				Status:     "fail\x04ed",
				Platform:   manifest.Platform{Architecture: "arm\x0564"},
			}},
		}},
	}
	got, err := sanitizeScanRecord(original)
	if err != nil {
		t.Fatal(err)
	}
	target := got.Targets[0]
	if target.ResolvedReference != "ref�" || target.RequestedDigest != "sha256:�" || target.Tags != nil {
		t.Errorf("Targets[0] = %+v", target)
	}
	item := target.Manifests[0]
	if item.Digest != "sha256:�" || item.RootDigest != "sha256:�" || item.Status != "fail�ed" || item.Platform.Architecture != "arm�64" {
		t.Errorf("Targets[0].Manifests[0] = %+v", item)
	}
	if original.Targets[0].Manifests[0].Digest != "sha256:\x02" || original.Targets[0].ResolvedReference != "ref\x00" {
		t.Error("sanitizeScanRecord mutated the caller's target or manifest slices")
	}
	if got.Tags != nil || got.DetailedFindings != nil {
		t.Errorf("nil slices became %#v and %#v", got.Tags, got.DetailedFindings)
	}
}
