package scanner

import (
	"strings"
	"testing"

	"github.com/brumbelow/layerleak/v3/internal/detectors"
	"github.com/brumbelow/layerleak/v3/internal/findings"
	"github.com/brumbelow/layerleak/v3/internal/layers"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
)

// TestMetadataFindingsCoverOnlyTheValue guards DET-01/DET-03 at the scanner
// level. scanMetadataWithBudget hands detectors the whole `KEY=value` text of
// an image-config Env entry or label (`key=value`), so value-only spans rely
// on no detector candidate class admitting '='. For a vendor pattern and for
// the generic keyword/entropy detector, the env and label findings must have
// exactly the span, redacted value and fingerprint the same `key=value` line
// gets in a file, and no second finding may cover the key. A detector class
// that re-admits '=' fails here.
func TestMetadataFindingsCoverOnlyTheValue(t *testing.T) {
	const manifestDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	platform := manifest.Platform{OS: "linux", Architecture: "amd64"}
	cases := []struct {
		name     string
		detector string
		secret   string
		envKey   string
		labelKey string
	}{
		{
			name:     "vendor pattern",
			detector: "github_token",
			secret:   "ghp_123456789012345678901234567890123456",
			envKey:   "GH_TOKEN",
			labelKey: "token",
		},
		{
			name:     "generic keyword entropy",
			detector: "keyword_entropy",
			// Synthetic high-entropy value with no vendor prefix.
			secret:   "q7Y8zX6wV4uT2sR0pN9mL7kJ5hG3fD1cB5",
			envKey:   "DB_PASSWORD",
			labelKey: "db_password",
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			set := detectors.Default()
			metadata := scanMetadataWithBudget(&detectionBudget{retainRaw: true}, set, manifestDigest, platform, manifest.ImageConfig{
				Config: manifest.ImageConfigPayload{
					Env:    []string{item.envKey + "=" + item.secret},
					Labels: map[string]string{item.labelKey: item.secret},
				},
			})
			files := scanArtifacts(set, manifestDigest, platform, findings.SourceTypeFileFinal, true, []layers.Artifact{
				{Path: "app/env.env", Type: layers.ArtifactTypeRegularFile, Scannable: true, Content: []byte(item.envKey + "=" + item.secret + "\n"), ContentLength: int64(len(item.envKey) + 1 + len(item.secret) + 1)},
				{Path: "app/label.env", Type: layers.ArtifactTypeRegularFile, Scannable: true, Content: []byte(item.labelKey + "=" + item.secret + "\n"), ContentLength: int64(len(item.labelKey) + 1 + len(item.secret) + 1)},
			})

			for _, pair := range []struct {
				source   findings.SourceType
				key      string
				filePath string
			}{
				{findings.SourceTypeEnv, item.envKey, "app/env.env"},
				{findings.SourceTypeLabel, item.labelKey, "app/label.env"},
			} {
				metadataFinding := onlyFinding(t, metadata, func(finding findings.DetailedFinding) bool { return finding.SourceType == pair.source })
				fileFinding := onlyFinding(t, files, func(finding findings.DetailedFinding) bool { return finding.FilePath == pair.filePath })
				for label, finding := range map[string]findings.DetailedFinding{string(pair.source): metadataFinding, pair.filePath: fileFinding} {
					if finding.DetectorName != item.detector || finding.Value != item.secret {
						t.Fatalf("%s finding = %s %q, want %s over the value alone", label, finding.DetectorName, finding.Value, item.detector)
					}
					if finding.MatchStart != len(pair.key)+1 || finding.MatchEnd != len(pair.key)+1+len(item.secret) {
						t.Fatalf("%s span = [%d:%d], want the value span [%d:%d]", label, finding.MatchStart, finding.MatchEnd, len(pair.key)+1, len(pair.key)+1+len(item.secret))
					}
				}
				if metadataFinding.MatchStart != fileFinding.MatchStart || metadataFinding.MatchEnd != fileFinding.MatchEnd {
					t.Fatalf("%s span [%d:%d] differs from the file span [%d:%d]", pair.source, metadataFinding.MatchStart, metadataFinding.MatchEnd, fileFinding.MatchStart, fileFinding.MatchEnd)
				}
				if metadataFinding.RedactedValue != fileFinding.RedactedValue || strings.Contains(metadataFinding.RedactedValue, pair.key) {
					t.Fatalf("%s redacted_value %q, file %q", pair.source, metadataFinding.RedactedValue, fileFinding.RedactedValue)
				}
				if metadataFinding.Fingerprint != fileFinding.Fingerprint || metadataFinding.Fingerprint != findings.Fingerprint(item.secret) {
					t.Fatalf("%s fingerprint %q, file %q, want the fingerprint of the value alone", pair.source, metadataFinding.Fingerprint, fileFinding.Fingerprint)
				}
			}
		})
	}
}

// onlyFinding returns the single finding selected by keep and fails when the
// source produced none or more than one (a second, whole-line finding).
func onlyFinding(t *testing.T, items []findings.DetailedFinding, keep func(findings.DetailedFinding) bool) findings.DetailedFinding {
	t.Helper()
	var selected []findings.DetailedFinding
	for _, item := range items {
		if keep(item) {
			selected = append(selected, item)
		}
	}
	if len(selected) != 1 {
		described := make([]string, 0, len(selected))
		for _, item := range selected {
			described = append(described, item.DetectorName+" "+item.SourceLocation)
		}
		t.Fatalf("want exactly one finding, got %d: %v", len(selected), described)
	}
	return selected[0]
}
