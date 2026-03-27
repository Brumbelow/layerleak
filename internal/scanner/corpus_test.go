package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/brumbelow/layerleak/internal/detectors"
	"github.com/brumbelow/layerleak/internal/findings"
	"github.com/brumbelow/layerleak/internal/layers"
	"github.com/brumbelow/layerleak/internal/manifest"
)

const (
	corpusOutcomeActionable = "actionable"
	corpusOutcomeSuppressed = "suppressed"
	corpusOutcomeDiscarded  = "discarded"
)

var (
	corpusManifestDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	corpusLayerDigest    = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	corpusPlatform       = manifest.Platform{OS: "linux", Architecture: "amd64"}
)

type corpusCase struct {
	Name                    string               `json:"name"`
	SourceType              findings.SourceType  `json:"source_type"`
	Path                    string               `json:"path"`
	Key                     string               `json:"key"`
	Content                 string               `json:"content"`
	ExpectedOutcome         string               `json:"expected_outcome"`
	ExpectedDetectors       []string             `json:"expected_detectors"`
	ExpectedConfidenceFloor detectors.Confidence `json:"expected_confidence_floor"`
	ExpectedReason          string               `json:"expected_reason"`
}

type corpusExecution struct {
	all        []findings.DetailedFinding
	actionable []findings.DetailedFinding
	suppressed []findings.DetailedFinding
	survivors  []findings.DetailedFinding
	outcome    string
}

func TestCorpusFixtures(t *testing.T) {
	cases := loadCorpusCases(t)
	detectorSet := detectors.Default()

	for _, fixture := range cases {
		t.Run(fixture.Name, func(t *testing.T) {
			result := runCorpusCase(t, detectorSet, fixture)

			if result.outcome != fixture.ExpectedOutcome {
				t.Fatalf("outcome = %q, want %q", result.outcome, fixture.ExpectedOutcome)
			}

			gotDetectors := detectorNames(result.survivors)
			wantDetectors := slices.Clone(fixture.ExpectedDetectors)
			slices.Sort(gotDetectors)
			slices.Sort(wantDetectors)
			if !slices.Equal(gotDetectors, wantDetectors) {
				t.Fatalf("detectors = %v, want %v", gotDetectors, wantDetectors)
			}

			if fixture.ExpectedOutcome == corpusOutcomeSuppressed {
				if strings.TrimSpace(fixture.ExpectedReason) == "" {
					t.Fatal("expected_reason must be set for suppressed fixtures")
				}
				for _, item := range result.suppressed {
					if string(item.DispositionReason) != fixture.ExpectedReason {
						t.Fatalf("disposition_reason = %q, want %q", item.DispositionReason, fixture.ExpectedReason)
					}
				}
			}

			if fixture.ExpectedConfidenceFloor == "" {
				return
			}
			for _, item := range result.survivors {
				if confidenceRank(detectors.Confidence(item.Confidence)) < confidenceRank(fixture.ExpectedConfidenceFloor) {
					t.Fatalf("confidence = %q, want at least %q", item.Confidence, fixture.ExpectedConfidenceFloor)
				}
			}
		})
	}
}

func TestCorpusProvenancePreservesDistinctSourceLocations(t *testing.T) {
	cases := loadCorpusCaseMap(t)
	detectorSet := detectors.Default()

	left, ok := cases["provenance_env_shared_secret"]
	if !ok {
		t.Fatal("missing provenance_env_shared_secret fixture")
	}
	right, ok := cases["provenance_deleted_layer_shared_secret"]
	if !ok {
		t.Fatal("missing provenance_deleted_layer_shared_secret fixture")
	}

	leftResult := runCorpusCase(t, detectorSet, left)
	rightResult := runCorpusCase(t, detectorSet, right)
	leftFinding := requireFindingByDetector(t, leftResult.actionable, "github_token")
	rightFinding := requireFindingByDetector(t, rightResult.actionable, "github_token")

	combined := []findings.DetailedFinding{leftFinding, rightFinding}
	deduped := findings.DeduplicateDetailed(combined)
	if len(deduped) != 2 {
		t.Fatalf("len(deduped) = %d", len(deduped))
	}
	if deduped[0].Fingerprint != deduped[1].Fingerprint {
		t.Fatalf("fingerprints differ: %q != %q", deduped[0].Fingerprint, deduped[1].Fingerprint)
	}
	if deduped[0].SourceLocation == deduped[1].SourceLocation {
		t.Fatalf("source locations collapsed: %q", deduped[0].SourceLocation)
	}
}

func runCorpusCase(t *testing.T, detectorSet detectors.Set, fixture corpusCase) corpusExecution {
	t.Helper()

	all := executeCorpusInput(t, detectorSet, fixture)
	actionable, suppressed := splitDetailedFindings(all)

	result := corpusExecution{
		all:        all,
		actionable: actionable,
		suppressed: suppressed,
	}

	switch {
	case len(actionable) == 0 && len(suppressed) == 0:
		result.outcome = corpusOutcomeDiscarded
		result.survivors = nil
	case len(actionable) > 0 && len(suppressed) == 0:
		result.outcome = corpusOutcomeActionable
		result.survivors = actionable
	case len(actionable) == 0 && len(suppressed) > 0:
		result.outcome = corpusOutcomeSuppressed
		result.survivors = suppressed
	default:
		result.outcome = "mixed"
		result.survivors = append([]findings.DetailedFinding{}, actionable...)
		result.survivors = append(result.survivors, suppressed...)
	}

	return result
}

func executeCorpusInput(t *testing.T, detectorSet detectors.Set, fixture corpusCase) []findings.DetailedFinding {
	t.Helper()

	switch fixture.SourceType {
	case findings.SourceTypeFileFinal, findings.SourceTypeFileDeletedLayer:
		return scanArtifacts(
			detectorSet,
			corpusManifestDigest,
			corpusPlatform,
			fixture.SourceType,
			fixture.SourceType == findings.SourceTypeFileFinal,
			[]layers.Artifact{
				{
					Path:         fixture.Path,
					LayerDigest:  corpusLayerDigest,
					ContentClass: layers.ContentClassText,
					Scannable:    true,
					Content:      []byte(fixture.Content),
				},
			},
		)
	case findings.SourceTypeEnv, findings.SourceTypeLabel, findings.SourceTypeHistory, findings.SourceTypeConfig:
		return scanString(detectorSet, findings.Input{
			ManifestDigest: corpusManifestDigest,
			Platform:       corpusPlatform,
			SourceType:     fixture.SourceType,
			FilePath:       fixture.Path,
			Key:            fixture.Key,
			Content:        fixture.Content,
		}, detectors.ScanInput{
			Content: fixture.Content,
			Path:    fixture.Path,
			Key:     fixture.Key,
		})
	default:
		t.Fatalf("unsupported source_type %q", fixture.SourceType)
		return nil
	}
}

func loadCorpusCases(t *testing.T) []corpusCase {
	t.Helper()

	root := filepath.Join("testdata", "corpus")
	paths := make([]string, 0)
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}
		paths = append(paths, path)
		return nil
	}); err != nil {
		t.Fatalf("WalkDir(%q) error = %v", root, err)
	}
	slices.Sort(paths)

	cases := make([]corpusCase, 0, len(paths))
	seenNames := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%q) error = %v", path, err)
		}

		var fixture corpusCase
		if err := json.Unmarshal(body, &fixture); err != nil {
			t.Fatalf("Unmarshal(%q) error = %v", path, err)
		}
		validateCorpusCase(t, path, fixture)
		if _, ok := seenNames[fixture.Name]; ok {
			t.Fatalf("duplicate corpus fixture name %q", fixture.Name)
		}
		seenNames[fixture.Name] = struct{}{}
		cases = append(cases, fixture)
	}

	return cases
}

func loadCorpusCaseMap(t *testing.T) map[string]corpusCase {
	t.Helper()

	fixtures := loadCorpusCases(t)
	indexed := make(map[string]corpusCase, len(fixtures))
	for _, fixture := range fixtures {
		indexed[fixture.Name] = fixture
	}

	return indexed
}

func validateCorpusCase(t *testing.T, path string, fixture corpusCase) {
	t.Helper()

	if strings.TrimSpace(fixture.Name) == "" {
		t.Fatalf("%s: name is required", path)
	}
	if fixture.SourceType == "" {
		t.Fatalf("%s: source_type is required", path)
	}
	switch fixture.ExpectedOutcome {
	case corpusOutcomeActionable, corpusOutcomeSuppressed, corpusOutcomeDiscarded:
	default:
		t.Fatalf("%s: unexpected expected_outcome %q", path, fixture.ExpectedOutcome)
	}
}

func detectorNames(items []findings.DetailedFinding) []string {
	names := make([]string, 0, len(items))
	for _, item := range items {
		names = append(names, item.DetectorName)
	}

	return names
}

func confidenceRank(value detectors.Confidence) int {
	switch value {
	case detectors.ConfidenceHigh:
		return 3
	case detectors.ConfidenceMedium:
		return 2
	case detectors.ConfidenceLow:
		return 1
	default:
		return 0
	}
}

func requireFindingByDetector(t *testing.T, items []findings.DetailedFinding, detectorName string) findings.DetailedFinding {
	t.Helper()

	for _, item := range items {
		if item.DetectorName == detectorName {
			return item
		}
	}

	t.Fatalf("missing detector %q in %#v", detectorName, items)
	return findings.DetailedFinding{}
}
