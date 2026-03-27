package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/brumbelow/layerleak/internal/detectionpolicy"
	"github.com/brumbelow/layerleak/internal/detectors"
	"github.com/brumbelow/layerleak/internal/manifest"
)

type SourceType string

type Disposition string

type DispositionReason string

const (
	SourceTypeFileFinal        SourceType = "file_final"
	SourceTypeFileDeletedLayer SourceType = "file_deleted_layer"
	SourceTypeEnv              SourceType = "env"
	SourceTypeLabel            SourceType = "label"
	SourceTypeHistory          SourceType = "history"
	SourceTypeConfig           SourceType = "config"

	DispositionActionable Disposition = "actionable"
	DispositionExample    Disposition = "example"

	DispositionReasonNone              DispositionReason = ""
	DispositionReasonTestPath          DispositionReason = "test_path"
	DispositionReasonExamplePath       DispositionReason = "example_path"
	DispositionReasonPlaceholderMarker DispositionReason = "placeholder_marker"
	DispositionReasonReservedHost      DispositionReason = "reserved_host"
	DispositionReasonKnownDummyValue   DispositionReason = "known_dummy_value"
)

type Input struct {
	ManifestDigest      string
	Platform            manifest.Platform
	SourceType          SourceType
	FilePath            string
	LayerDigest         string
	Key                 string
	PresentInFinalImage bool
	Content             string
}

type Finding struct {
	DetectorName        string            `json:"detector_name"`
	Confidence          string            `json:"confidence"`
	Disposition         Disposition       `json:"disposition"`
	DispositionReason   DispositionReason `json:"disposition_reason,omitempty"`
	SourceType          SourceType        `json:"source_type"`
	ManifestDigest      string            `json:"manifest_digest"`
	Platform            manifest.Platform `json:"platform,omitempty"`
	FilePath            string            `json:"file_path,omitempty"`
	LayerDigest         string            `json:"layer_digest,omitempty"`
	Key                 string            `json:"key,omitempty"`
	LineNumber          int               `json:"line_number,omitempty"`
	RedactedValue       string            `json:"redacted_value"`
	Fingerprint         string            `json:"fingerprint"`
	ContextSnippet      string            `json:"context_snippet"`
	PresentInFinalImage bool              `json:"present_in_final_image"`
}

type DetailedFinding struct {
	Finding
	Value          string `json:"-"`
	RawSnippet     string `json:"-"`
	SourceLocation string `json:"-"`
	MatchStart     int    `json:"-"`
	MatchEnd       int    `json:"-"`
}

func Deduplicate(items []Finding) []Finding {
	sorted := slices.Clone(items)
	slices.SortFunc(sorted, compareFindings)

	deduped := make([]Finding, 0, len(sorted))
	seen := make(map[string]struct{})
	for _, item := range sorted {
		key := findingSnippetDedupKey(item)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		deduped = append(deduped, item)
	}

	return deduped
}

func UniqueFingerprintCount(items []Finding) int {
	seen := make(map[string]struct{})
	for _, item := range items {
		if item.Fingerprint == "" {
			continue
		}
		seen[item.Fingerprint] = struct{}{}
	}
	return len(seen)
}

func Normalize(input Input, match detectors.Match) (Finding, error) {
	detailed, err := NormalizeDetailed(input, match)
	if err != nil {
		return Finding{}, err
	}

	return detailed.PublicFinding(), nil
}

func NormalizeDetailed(input Input, match detectors.Match) (DetailedFinding, error) {
	if strings.TrimSpace(input.ManifestDigest) == "" {
		return DetailedFinding{}, fmt.Errorf("manifest digest is required")
	}

	if !isValidSourceType(input.SourceType) {
		return DetailedFinding{}, fmt.Errorf("source type is invalid: %s", input.SourceType)
	}

	if match.Value == "" {
		return DetailedFinding{}, fmt.Errorf("match value is required")
	}

	disposition, reason := Classify(input, match)

	return DetailedFinding{
		Finding: Finding{
			DetectorName:        match.Detector,
			Confidence:          string(match.Confidence),
			Disposition:         disposition,
			DispositionReason:   reason,
			SourceType:          input.SourceType,
			ManifestDigest:      input.ManifestDigest,
			Platform:            input.Platform,
			FilePath:            input.FilePath,
			LayerDigest:         input.LayerDigest,
			Key:                 input.Key,
			LineNumber:          lineNumberForOffset(input.Content, match.Start),
			RedactedValue:       Redact(match.Value),
			Fingerprint:         Fingerprint(match.Value),
			ContextSnippet:      buildContextSnippet(input.Content, match),
			PresentInFinalImage: input.PresentInFinalImage,
		},
		Value:          match.Value,
		RawSnippet:     buildRawContextSnippet(input.Content, match),
		SourceLocation: buildSourceLocation(input),
		MatchStart:     match.Start,
		MatchEnd:       match.End,
	}, nil
}

func (d DetailedFinding) PublicFinding() Finding {
	return d.Finding
}

func DeduplicateDetailed(items []DetailedFinding) []DetailedFinding {
	sorted := slices.Clone(items)
	slices.SortFunc(sorted, compareDetailedFindings)

	deduped := make([]DetailedFinding, 0, len(sorted))
	seen := make(map[string]struct{})
	for _, item := range sorted {
		key := detailedFindingSnippetDedupKey(item)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		deduped = append(deduped, item)
	}

	return deduped
}

func Redact(value string) string {
	if value == "" {
		return ""
	}

	if strings.Contains(value, "\n") {
		firstLine := strings.SplitN(value, "\n", 2)[0]
		return firstLine + "...redacted..."
	}

	runes := []rune(value)
	if len(runes) <= 6 {
		return strings.Repeat("*", len(runes))
	}

	return string(runes[:3]) + strings.Repeat("*", len(runes)-5) + string(runes[len(runes)-2:])
}

func Fingerprint(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func ShouldSuppressFilePath(filePath string) bool {
	return detectionpolicy.TestPathReason(filePath) == detectionpolicy.ReasonTestPath
}

func buildContextSnippet(content string, match detectors.Match) string {
	return buildSnippet(content, match, true)
}

func buildRawContextSnippet(content string, match detectors.Match) string {
	return buildSnippet(content, match, false)
}

func buildSnippet(content string, match detectors.Match, redact bool) string {
	if content == "" || match.Start < 0 || match.End > len(content) || match.Start >= match.End {
		if redact {
			return Redact(match.Value)
		}
		return match.Value
	}

	start := match.Start - 24
	if start < 0 {
		start = 0
	}

	end := match.End + 24
	if end > len(content) {
		end = len(content)
	}

	before := strings.TrimSpace(content[start:match.Start])
	after := strings.TrimSpace(content[match.End:end])
	value := match.Value
	if redact {
		value = Redact(match.Value)
	}

	parts := make([]string, 0, 3)
	if before != "" {
		parts = append(parts, before)
	}
	parts = append(parts, value)
	if after != "" {
		parts = append(parts, after)
	}

	return strings.Join(parts, " ")
}

func buildSourceLocation(input Input) string {
	location := ""
	switch {
	case strings.TrimSpace(input.FilePath) != "":
		location = input.FilePath
	case strings.TrimSpace(input.Key) != "":
		location = input.Key
	default:
		location = string(input.SourceType)
	}

	return string(input.SourceType) + ":" + location
}

func findingSnippetDedupKey(item Finding) string {
	return strings.Join([]string{
		item.ManifestDigest,
		string(item.Disposition),
		publicSourceLocation(item),
		strconv.Itoa(item.LineNumber),
		firstNonEmpty(item.ContextSnippet, item.Fingerprint),
	}, "|")
}

func detailedFindingSnippetDedupKey(item DetailedFinding) string {
	return strings.Join([]string{
		item.ManifestDigest,
		string(item.Disposition),
		item.SourceLocation,
		strconv.Itoa(item.LineNumber),
		strconv.Itoa(item.MatchStart),
		strconv.Itoa(item.MatchEnd),
		firstNonEmpty(item.RawSnippet, item.ContextSnippet, item.Fingerprint),
	}, "|")
}

func compareFindings(left, right Finding) int {
	if value := strings.Compare(left.ManifestDigest, right.ManifestDigest); value != 0 {
		return value
	}
	if value := strings.Compare(left.Platform.String(), right.Platform.String()); value != 0 {
		return value
	}
	if value := strings.Compare(string(left.SourceType), string(right.SourceType)); value != 0 {
		return value
	}
	if value := strings.Compare(string(left.Disposition), string(right.Disposition)); value != 0 {
		return value
	}
	if value := strings.Compare(left.FilePath, right.FilePath); value != 0 {
		return value
	}
	if value := strings.Compare(left.LayerDigest, right.LayerDigest); value != 0 {
		return value
	}
	if value := strings.Compare(left.DetectorName, right.DetectorName); value != 0 {
		return value
	}
	if left.LineNumber != right.LineNumber {
		return left.LineNumber - right.LineNumber
	}
	if value := strings.Compare(left.Fingerprint, right.Fingerprint); value != 0 {
		return value
	}
	return strings.Compare(left.Key, right.Key)
}

func compareDetailedFindings(left, right DetailedFinding) int {
	if value := compareFindings(left.Finding, right.Finding); value != 0 {
		return value
	}
	if left.MatchStart != right.MatchStart {
		return left.MatchStart - right.MatchStart
	}
	if left.MatchEnd != right.MatchEnd {
		return left.MatchEnd - right.MatchEnd
	}
	return strings.Compare(left.SourceLocation, right.SourceLocation)
}

func lineNumberForOffset(content string, offset int) int {
	if offset <= 0 {
		return 1
	}
	if offset > len(content) {
		offset = len(content)
	}
	return 1 + strings.Count(content[:offset], "\n")
}

func publicSourceLocation(item Finding) string {
	location := ""
	switch {
	case strings.TrimSpace(item.FilePath) != "":
		location = item.FilePath
	case strings.TrimSpace(item.Key) != "":
		location = item.Key
	default:
		location = string(item.SourceType)
	}

	return string(item.SourceType) + ":" + location
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func isValidSourceType(value SourceType) bool {
	switch value {
	case SourceTypeFileFinal, SourceTypeFileDeletedLayer, SourceTypeEnv, SourceTypeLabel, SourceTypeHistory, SourceTypeConfig:
		return true
	default:
		return false
	}
}
