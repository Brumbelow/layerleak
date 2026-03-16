package main

import (
	"testing"
	"time"

	"github.com/brumbelow/layerleak/internal/config"
	"github.com/brumbelow/layerleak/internal/findings"
	"github.com/brumbelow/layerleak/internal/jobs"
	"github.com/brumbelow/layerleak/internal/manifest"
	"github.com/brumbelow/layerleak/internal/scanner"
)

func TestNewStoreUsesNoopWithoutDatabaseURL(t *testing.T) {
	store, err := newStore(config.Config{})
	if err != nil {
		t.Fatalf("newStore() error = %v", err)
	}
	if store.Name() != "noop" {
		t.Fatalf("store.Name() = %q", store.Name())
	}
}

func TestNewStoreRejectsInvalidDatabaseURL(t *testing.T) {
	if _, err := newStore(config.Config{
		DatabaseURL: "mysql://root@localhost:3306/layerleak",
	}); err == nil {
		t.Fatal("newStore() error = nil")
	}
}

func TestBuildScanRecordMapsMultiArchTagToPlatformManifests(t *testing.T) {
	scannedAt := time.Date(2026, time.March, 15, 12, 0, 0, 0, time.UTC)
	rootDigest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	amd64Digest := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	arm64Digest := "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

	record := buildScanRecord(manifest.Reference{
		Registry:    "docker.io",
		Repository:  "library/app",
		Original:    "library/app:latest",
		Tag:         "latest",
		TagExplicit: true,
	}, jobs.Result{
		RequestedReference: "library/app:latest",
		Repository:         "library/app",
		Mode:               "reference",
		ResolvedReference:  "docker.io/library/app@" + rootDigest,
		RequestedDigest:    rootDigest,
		TagResults: []jobs.TagResult{
			{Tag: "latest", RootDigest: rootDigest, Status: "scanned"},
		},
		Targets: []jobs.TargetResult{
			{
				Reference:         "docker.io/library/app@" + rootDigest,
				ResolvedReference: "docker.io/library/app@" + rootDigest,
				RequestedDigest:   rootDigest,
				Tags:              []string{"latest"},
				PlatformResults: []scanner.PlatformResult{
					{Platform: manifest.Platform{OS: "linux", Architecture: "amd64"}, ManifestDigest: amd64Digest, FindingsCount: 1},
					{Platform: manifest.Platform{OS: "linux", Architecture: "arm64"}, ManifestDigest: arm64Digest, FindingsCount: 1},
				},
			},
		},
		DetailedFindings: []findings.DetailedFinding{
			testDetailedFindingForManifest(amd64Digest, manifest.Platform{OS: "linux", Architecture: "amd64"}),
			testDetailedFindingForManifest(arm64Digest, manifest.Platform{OS: "linux", Architecture: "arm64"}),
		},
	}, scannedAt)

	if record.ScannedAt != scannedAt {
		t.Fatalf("record.ScannedAt = %s", record.ScannedAt)
	}
	if len(record.Targets) != 1 {
		t.Fatalf("len(record.Targets) = %d", len(record.Targets))
	}
	if len(record.Targets[0].Manifests) != 2 {
		t.Fatalf("len(record.Targets[0].Manifests) = %d", len(record.Targets[0].Manifests))
	}
	if len(record.Tags) != 2 {
		t.Fatalf("len(record.Tags) = %d", len(record.Tags))
	}
	for _, item := range record.Tags {
		if item.Name != "latest" {
			t.Fatalf("item.Name = %q", item.Name)
		}
		if item.RootDigest != rootDigest {
			t.Fatalf("item.RootDigest = %q", item.RootDigest)
		}
		if item.ManifestDigest != amd64Digest && item.ManifestDigest != arm64Digest {
			t.Fatalf("item.ManifestDigest = %q", item.ManifestDigest)
		}
	}
}

func TestBuildScanRecordMapsRepositoryTagGroups(t *testing.T) {
	digestOne := "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	digestTwo := "sha256:2222222222222222222222222222222222222222222222222222222222222222"

	record := buildScanRecord(manifest.Reference{
		Registry:   "docker.io",
		Repository: "library/app",
		Original:   "library/app",
	}, jobs.Result{
		RequestedReference: "library/app",
		Repository:         "library/app",
		Mode:               "repository",
		TagResults: []jobs.TagResult{
			{Tag: "latest", RootDigest: digestOne, Status: "resolved"},
			{Tag: "2.0", RootDigest: digestOne, Status: "resolved"},
			{Tag: "1.0", RootDigest: digestTwo, Status: "resolved"},
		},
		Targets: []jobs.TargetResult{
			{
				Reference:         "docker.io/library/app@" + digestOne,
				ResolvedReference: "docker.io/library/app@" + digestOne,
				RequestedDigest:   digestOne,
				Tags:              []string{"2.0", "latest"},
				PlatformResults: []scanner.PlatformResult{
					{Platform: manifest.Platform{OS: "linux", Architecture: "amd64"}, ManifestDigest: digestOne, FindingsCount: 1},
				},
			},
			{
				Reference:         "docker.io/library/app@" + digestTwo,
				ResolvedReference: "docker.io/library/app@" + digestTwo,
				RequestedDigest:   digestTwo,
				Tags:              []string{"1.0"},
				PlatformResults: []scanner.PlatformResult{
					{Platform: manifest.Platform{OS: "linux", Architecture: "amd64"}, ManifestDigest: digestTwo, FindingsCount: 1},
				},
			},
		},
	}, time.Now().UTC())

	if len(record.Targets) != 2 {
		t.Fatalf("len(record.Targets) = %d", len(record.Targets))
	}
	if len(record.Tags) != 3 {
		t.Fatalf("len(record.Tags) = %d", len(record.Tags))
	}
	if record.Tags[0].Name != "1.0" {
		t.Fatalf("record.Tags[0].Name = %q", record.Tags[0].Name)
	}
	if record.Tags[1].Name != "2.0" {
		t.Fatalf("record.Tags[1].Name = %q", record.Tags[1].Name)
	}
	if record.Tags[2].Name != "latest" {
		t.Fatalf("record.Tags[2].Name = %q", record.Tags[2].Name)
	}
}

func TestBuildScanRecordCreatesFailedManifestForFailedTarget(t *testing.T) {
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	record := buildScanRecord(manifest.Reference{
		Registry:   "docker.io",
		Repository: "library/app",
		Original:   "library/app",
	}, jobs.Result{
		RequestedReference: "library/app",
		Repository:         "library/app",
		Mode:               "repository",
		TagResults: []jobs.TagResult{
			{Tag: "latest", RootDigest: digest, Status: "resolved"},
		},
		Targets: []jobs.TargetResult{
			{
				Reference: "docker.io/library/app@" + digest,
				Tags:      []string{"latest"},
				Error:     "fetch config blob: status=404",
			},
		},
	}, time.Now().UTC())

	if len(record.Targets) != 1 {
		t.Fatalf("len(record.Targets) = %d", len(record.Targets))
	}
	if len(record.Targets[0].Manifests) != 1 {
		t.Fatalf("len(record.Targets[0].Manifests) = %d", len(record.Targets[0].Manifests))
	}
	if record.Targets[0].Manifests[0].Digest != digest {
		t.Fatalf("record.Targets[0].Manifests[0].Digest = %q", record.Targets[0].Manifests[0].Digest)
	}
	if record.Targets[0].Manifests[0].Status != "failed" {
		t.Fatalf("record.Targets[0].Manifests[0].Status = %q", record.Targets[0].Manifests[0].Status)
	}
	if len(record.Tags) != 1 {
		t.Fatalf("len(record.Tags) = %d", len(record.Tags))
	}
	if record.Tags[0].Status != "failed" {
		t.Fatalf("record.Tags[0].Status = %q", record.Tags[0].Status)
	}
}

func TestBuildScanRecordDeduplicatesIdenticalRawSnippets(t *testing.T) {
	record := buildScanRecord(manifest.Reference{
		Registry:   "docker.io",
		Repository: "library/app",
		Original:   "library/app:latest",
		Tag:        "latest",
	}, jobs.Result{
		RequestedReference: "library/app:latest",
		Repository:         "library/app",
		Mode:               "reference",
		DetailedFindings: []findings.DetailedFinding{
			{
				Finding: findings.Finding{
					DetectorName:   "github_token",
					Confidence:     "high",
					SourceType:     findings.SourceTypeFileFinal,
					ManifestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					Platform:       manifest.Platform{OS: "linux", Architecture: "amd64"},
					FilePath:       "z.env",
					RedactedValue:  "ghp********************************56",
					Fingerprint:    "fingerprint",
					ContextSnippet: "TOKEN=ghp********************************56",
				},
				Value:          "ghp_123456789012345678901234567890123456",
				RawSnippet:     "TOKEN=ghp_123456789012345678901234567890123456",
				SourceLocation: "file:z.env",
				MatchStart:     6,
				MatchEnd:       46,
			},
			{
				Finding: findings.Finding{
					DetectorName:   "github_token",
					Confidence:     "high",
					SourceType:     findings.SourceTypeFileFinal,
					ManifestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					Platform:       manifest.Platform{OS: "linux", Architecture: "amd64"},
					FilePath:       "a.env",
					RedactedValue:  "ghp********************************56",
					Fingerprint:    "fingerprint",
					ContextSnippet: "TOKEN=ghp********************************56",
				},
				Value:          "ghp_123456789012345678901234567890123456",
				RawSnippet:     "TOKEN=ghp_123456789012345678901234567890123456",
				SourceLocation: "file:a.env",
				MatchStart:     6,
				MatchEnd:       46,
			},
		},
	}, time.Now().UTC())

	if len(record.DetailedFindings) != 1 {
		t.Fatalf("len(record.DetailedFindings) = %d", len(record.DetailedFindings))
	}
	if record.DetailedFindings[0].FilePath != "a.env" {
		t.Fatalf("record.DetailedFindings[0].FilePath = %q", record.DetailedFindings[0].FilePath)
	}
}

func testDetailedFindingForManifest(manifestDigest string, platform manifest.Platform) findings.DetailedFinding {
	return findings.DetailedFinding{
		Finding: findings.Finding{
			DetectorName:        "github_token",
			Confidence:          "high",
			SourceType:          findings.SourceTypeEnv,
			ManifestDigest:      manifestDigest,
			Platform:            platform,
			Key:                 "GH_TOKEN",
			RedactedValue:       "ghp********************************56",
			Fingerprint:         manifestDigest,
			ContextSnippet:      "GH_TOKEN=ghp********************************56",
			PresentInFinalImage: true,
		},
		Value:          "ghp_123456789012345678901234567890123456",
		RawSnippet:     "GH_TOKEN=ghp_123456789012345678901234567890123456",
		SourceLocation: "env:GH_TOKEN",
		MatchStart:     9,
		MatchEnd:       49,
	}
}
