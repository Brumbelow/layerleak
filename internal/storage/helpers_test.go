package storage

import (
	"slices"
	"testing"

	"github.com/brumbelow/layerleak/internal/findings"
	"github.com/brumbelow/layerleak/internal/manifest"
)

func TestNormalizeRegistryFilter(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty defaults to docker hub", in: "", want: manifest.DockerHubRegistry},
		{name: "whitespace defaults to docker hub", in: "   ", want: manifest.DockerHubRegistry},
		{name: "docker.io canonical", in: "docker.io", want: manifest.DockerHubRegistry},
		{name: "index.docker.io alias", in: "index.docker.io", want: manifest.DockerHubRegistry},
		{name: "registry-1.docker.io alias", in: "registry-1.docker.io", want: manifest.DockerHubRegistry},
		{name: "ghcr.io is preserved", in: "ghcr.io", want: "ghcr.io"},
		{name: "uppercase normalised", in: "GHCR.IO", want: "ghcr.io"},
		{name: "self-hosted preserved", in: "registry.internal.example", want: "registry.internal.example"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeRegistryFilter(tt.in); got != tt.want {
				t.Fatalf("normalizeRegistryFilter(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestNormalizeFindingDispositionFilter(t *testing.T) {
	tests := []struct {
		name string
		in   FindingDispositionFilter
		want FindingDispositionFilter
	}{
		{name: "all", in: FindingDispositionAll, want: FindingDispositionAll},
		{name: "actionable", in: FindingDispositionActionable, want: FindingDispositionActionable},
		{name: "suppressed", in: FindingDispositionSuppressed, want: FindingDispositionSuppressed},
		{name: "actionable with whitespace", in: " actionable ", want: FindingDispositionActionable},
		{name: "empty defaults to all", in: "", want: FindingDispositionAll},
		{name: "unrecognized defaults to all", in: "garbage", want: FindingDispositionAll},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeFindingDispositionFilter(tt.in); got != tt.want {
				t.Fatalf("normalizeFindingDispositionFilter(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if got := firstNonEmpty("", "  ", "second"); got != "second" {
		t.Fatalf("firstNonEmpty = %q, want %q", got, "second")
	}
	if got := firstNonEmpty("first", "second"); got != "first" {
		t.Fatalf("firstNonEmpty = %q, want %q", got, "first")
	}
	if got := firstNonEmpty("  trimmed  "); got != "trimmed" {
		t.Fatalf("firstNonEmpty = %q, want %q", got, "trimmed")
	}
	if got := firstNonEmpty(); got != "" {
		t.Fatalf("firstNonEmpty() = %q, want empty", got)
	}
	if got := firstNonEmpty("", "   ", ""); got != "" {
		t.Fatalf("firstNonEmpty(blanks) = %q, want empty", got)
	}
}

func TestMergePlatform(t *testing.T) {
	current := manifest.Platform{OS: "linux", Architecture: "", Variant: ""}
	incoming := manifest.Platform{OS: "windows", Architecture: "amd64", Variant: "v8"}

	got := mergePlatform(current, incoming)
	if got.OS != "linux" {
		t.Errorf("OS = %q, want preserved %q", got.OS, "linux")
	}
	if got.Architecture != "amd64" {
		t.Errorf("Architecture = %q, want backfilled %q", got.Architecture, "amd64")
	}
	if got.Variant != "v8" {
		t.Errorf("Variant = %q, want backfilled %q", got.Variant, "v8")
	}

	got = mergePlatform(manifest.Platform{}, manifest.Platform{OS: "  linux  "})
	if got.OS != "linux" {
		t.Errorf("trim-on-backfill OS = %q, want %q", got.OS, "linux")
	}
}

func TestNormalizeManifestRecord(t *testing.T) {
	in := ManifestRecord{
		Digest:     "  sha256:abc  ",
		RootDigest: "",
		Status:     "",
		Error:      "  oops  ",
		Platform:   manifest.Platform{OS: "  linux ", Architecture: " amd64", Variant: ""},
	}

	got := normalizeManifestRecord(in)
	if got.Digest != "sha256:abc" {
		t.Errorf("Digest = %q, want %q", got.Digest, "sha256:abc")
	}
	if got.RootDigest != "sha256:abc" {
		t.Errorf("RootDigest fallback = %q, want %q", got.RootDigest, "sha256:abc")
	}
	if got.Status != "scanned" {
		t.Errorf("Status default = %q, want %q", got.Status, "scanned")
	}
	if got.Error != "oops" {
		t.Errorf("Error trim = %q, want %q", got.Error, "oops")
	}
	if got.Platform.OS != "linux" || got.Platform.Architecture != "amd64" {
		t.Errorf("Platform = %+v, want trimmed", got.Platform)
	}
}

func TestUniqueTagNames(t *testing.T) {
	got := uniqueTagNames([]TagRecord{
		{Name: "latest"},
		{Name: " latest "},
		{Name: "v1.0"},
		{Name: ""},
		{Name: "   "},
		{Name: "v1.0"},
		{Name: "alpine"},
	})

	want := []string{"alpine", "latest", "v1.0"}
	if !slices.Equal(got, want) {
		t.Fatalf("uniqueTagNames = %v, want %v", got, want)
	}
}

func TestNormalizeTagRecords(t *testing.T) {
	in := []TagRecord{
		{Name: "latest", Status: "scanned", ManifestDigest: "sha256:bbb", RootDigest: "sha256:aaa"},
		{Name: " latest ", Status: "scanned", ManifestDigest: "sha256:bbb", RootDigest: "sha256:aaa"},
		{Name: "v1", Status: "", ManifestDigest: "sha256:ccc"},      // dropped: status empty
		{Name: "", Status: "scanned", ManifestDigest: "sha256:ddd"}, // dropped: empty name
		{Name: "alpine", Status: "scanned", ManifestDigest: "sha256:eee"},
	}

	got := normalizeTagRecords(in)

	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2 (alpine, latest)", len(got))
	}
	if got[0].Name != "alpine" {
		t.Errorf("got[0].Name = %q, want %q (sorted)", got[0].Name, "alpine")
	}
	if got[1].Name != "latest" {
		t.Errorf("got[1].Name = %q, want %q", got[1].Name, "latest")
	}
}

func TestPersistedValueRespectsFlag(t *testing.T) {
	finding := findings.DetailedFinding{
		Value:      "raw-secret",
		RawSnippet: "context with raw-secret here",
	}

	if got := persistedValue(finding, false); got != "" {
		t.Errorf("persistedValue(false) = %q, want empty", got)
	}
	if got := persistedValue(finding, true); got != "raw-secret" {
		t.Errorf("persistedValue(true) = %q, want %q", got, "raw-secret")
	}
	if got := persistedRawSnippet(finding, false); got != "" {
		t.Errorf("persistedRawSnippet(false) = %q, want empty", got)
	}
	if got := persistedRawSnippet(finding, true); got != finding.RawSnippet {
		t.Errorf("persistedRawSnippet(true) = %q, want %q", got, finding.RawSnippet)
	}
}

func TestUpsertManifestRecordPrefersScannedOverFailed(t *testing.T) {
	items := make(map[string]ManifestRecord)
	upsertManifestRecord(items, ManifestRecord{Digest: "sha256:abc", Status: "failed", Error: "nope"})
	upsertManifestRecord(items, ManifestRecord{Digest: "sha256:abc", Status: "scanned"})

	got, ok := items["sha256:abc"]
	if !ok {
		t.Fatal("missing sha256:abc")
	}
	if got.Status != "scanned" {
		t.Errorf("Status = %q, want scanned (scanned should win)", got.Status)
	}
	if got.Error != "" {
		t.Errorf("Error = %q, want cleared when scanned wins", got.Error)
	}
}

func TestUpsertManifestRecordKeepsScannedWhenFailedArrives(t *testing.T) {
	items := make(map[string]ManifestRecord)
	upsertManifestRecord(items, ManifestRecord{Digest: "sha256:abc", Status: "scanned"})
	upsertManifestRecord(items, ManifestRecord{Digest: "sha256:abc", Status: "failed", Error: "nope"})

	got := items["sha256:abc"]
	if got.Status != "scanned" {
		t.Errorf("Status = %q, want scanned (existing scanned must be sticky)", got.Status)
	}
}

func TestUpsertManifestRecordSkipsEmptyDigest(t *testing.T) {
	items := make(map[string]ManifestRecord)
	upsertManifestRecord(items, ManifestRecord{Digest: "", Status: "scanned"})

	if len(items) != 0 {
		t.Fatalf("items = %v, want empty", items)
	}
}

func TestUpsertManifestRecordMergesPlatformAndRoot(t *testing.T) {
	items := make(map[string]ManifestRecord)
	upsertManifestRecord(items, ManifestRecord{
		Digest:     "sha256:abc",
		RootDigest: "sha256:root",
		Status:     "scanned",
		Platform:   manifest.Platform{OS: "linux"},
	})
	upsertManifestRecord(items, ManifestRecord{
		Digest:   "sha256:abc",
		Status:   "scanned",
		Platform: manifest.Platform{Architecture: "amd64"},
	})

	got := items["sha256:abc"]
	if got.RootDigest != "sha256:root" {
		t.Errorf("RootDigest = %q, want preserved %q", got.RootDigest, "sha256:root")
	}
	if got.Platform.OS != "linux" || got.Platform.Architecture != "amd64" {
		t.Errorf("Platform = %+v, want merged linux/amd64", got.Platform)
	}
}

func TestCollectManifestRecordsMergesTargetsAndFindings(t *testing.T) {
	record := ScanRecord{
		Targets: []TargetRecord{
			{
				Reference:       "docker.io/library/app@sha256:aaa",
				RequestedDigest: "sha256:aaa",
				Manifests: []ManifestRecord{
					{Digest: "sha256:bbb", Platform: manifest.Platform{OS: "linux"}, Status: "scanned"},
				},
			},
			{
				// Failed target with no manifests should produce a synthetic failure record.
				Reference:       "docker.io/library/app@sha256:ccc",
				RequestedDigest: "sha256:ccc",
				Error:           "registry: not found",
			},
		},
		DetailedFindings: []findings.DetailedFinding{
			{
				Finding: findings.Finding{
					ManifestDigest: "sha256:bbb",
					Fingerprint:    "fp1",
					Platform:       manifest.Platform{Architecture: "amd64"},
				},
			},
		},
	}

	got := collectManifestRecords(record)

	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2; got=%+v", len(got), got)
	}
	// Sorted by digest ascending.
	if got[0].Digest != "sha256:bbb" {
		t.Errorf("got[0].Digest = %q, want sha256:bbb", got[0].Digest)
	}
	if got[0].Platform.OS != "linux" || got[0].Platform.Architecture != "amd64" {
		t.Errorf("got[0].Platform = %+v, want linux/amd64 merged from finding", got[0].Platform)
	}
	if got[0].Status != "scanned" {
		t.Errorf("got[0].Status = %q, want scanned", got[0].Status)
	}
	if got[1].Digest != "sha256:ccc" {
		t.Errorf("got[1].Digest = %q, want sha256:ccc", got[1].Digest)
	}
	if got[1].Status != "failed" {
		t.Errorf("got[1].Status = %q, want failed", got[1].Status)
	}
	if got[1].Error != "registry: not found" {
		t.Errorf("got[1].Error = %q, want registry: not found", got[1].Error)
	}
}

func TestCollectManifestRecordsDerivesRootFromReferenceWhenDigestMissing(t *testing.T) {
	record := ScanRecord{
		Targets: []TargetRecord{
			{
				Reference: "docker.io/library/app@sha256:0000000000000000000000000000000000000000000000000000000000000001",
				Manifests: []ManifestRecord{
					{Digest: "sha256:bbb", Status: "scanned"},
				},
			},
		},
	}

	got := collectManifestRecords(record)
	if len(got) != 1 {
		t.Fatalf("len(got) = %d, want 1", len(got))
	}
	if got[0].RootDigest != "sha256:0000000000000000000000000000000000000000000000000000000000000001" {
		t.Errorf("RootDigest = %q, want digest from reference", got[0].RootDigest)
	}
}

func TestDigestFromReference(t *testing.T) {
	digest := "sha256:0000000000000000000000000000000000000000000000000000000000000001"
	if got := digestFromReference("docker.io/library/app@" + digest); got != digest {
		t.Errorf("digestFromReference(with digest) = %q, want %q", got, digest)
	}
	if got := digestFromReference("docker.io/library/app:latest"); got != "" {
		t.Errorf("digestFromReference(no digest) = %q, want empty", got)
	}
	if got := digestFromReference("not a valid reference!!!"); got != "" {
		t.Errorf("digestFromReference(invalid) = %q, want empty", got)
	}
}
