package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/brumbelow/layerleak/internal/detectors"
	"github.com/brumbelow/layerleak/internal/manifest"
)

type SourceType string

const (
	SourceTypeFileFinal        SourceType = "file_final"
	SourceTypeFileDeletedLayer SourceType = "file_deleted_layer"
	SourceTypeEnv              SourceType = "env"
	SourceTypeLabel            SourceType = "label"
	SourceTypeHistory          SourceType = "history"
	SourceTypeConfig           SourceType = "config"
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
	SourceType          SourceType        `json:"source_type"`
	ManifestDigest      string            `json:"manifest_digest"`
	Platform            manifest.Platform `json:"platform,omitempty"`
	FilePath            string            `json:"file_path,omitempty"`
	LayerDigest         string            `json:"layer_digest,omitempty"`
	Key                 string            `json:"key,omitempty"`
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

	return DetailedFinding{
		Finding: Finding{
			DetectorName:        match.Detector,
			Confidence:          string(match.Confidence),
			SourceType:          input.SourceType,
			ManifestDigest:      input.ManifestDigest,
			Platform:            input.Platform,
			FilePath:            input.FilePath,
			LayerDigest:         input.LayerDigest,
			Key:                 input.Key,
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
	value := strings.TrimSpace(filePath)
	if value == "" {
		return false
	}

	value = strings.ReplaceAll(value, "\\", "/")
	value = path.Clean(value)
	if value == "." || value == "/" {
		return false
	}

	parts := strings.Split(value, "/")
	normalized := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || part == "." {
			continue
		}
		normalized = append(normalized, part)
	}
	if len(normalized) <= 1 {
		return false
	}

	for _, part := range normalized[:len(normalized)-1] {
		switch strings.ToLower(part) {
		case "test", "tests":
			return true
		}
	}

	return false
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
		firstNonEmpty(item.ContextSnippet, item.Fingerprint),
	}, "|")
}

func detailedFindingSnippetDedupKey(item DetailedFinding) string {
	return strings.Join([]string{
		item.ManifestDigest,
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
	if value := strings.Compare(left.FilePath, right.FilePath); value != 0 {
		return value
	}
	if value := strings.Compare(left.LayerDigest, right.LayerDigest); value != 0 {
		return value
	}
	if value := strings.Compare(left.DetectorName, right.DetectorName); value != 0 {
		return value
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
	return strings.Compare(left.SourceLocation, right.SourceLocation)
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
