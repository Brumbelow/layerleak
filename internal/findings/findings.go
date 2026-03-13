package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"git.tools.cloudfor.ge/andrew/layerleak/internal/detectors"
	"git.tools.cloudfor.ge/andrew/layerleak/internal/manifest"
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

func Deduplicate(items []Finding) []Finding {
	deduped := make([]Finding, 0, len(items))
	seen := make(map[string]struct{})
	for _, item := range items {
		key := strings.Join([]string{
			item.DetectorName,
			item.Confidence,
			string(item.SourceType),
			item.ManifestDigest,
			item.Platform.String(),
			item.FilePath,
			item.LayerDigest,
			item.Key,
			item.RedactedValue,
			item.Fingerprint,
			item.ContextSnippet,
			boolString(item.PresentInFinalImage),
		}, "|")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		deduped = append(deduped, item)
	}

	slices.SortFunc(deduped, func(left, right Finding) int {
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
	})

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
	if strings.TrimSpace(input.ManifestDigest) == "" {
		return Finding{}, fmt.Errorf("manifest digest is required")
	}

	if !isValidSourceType(input.SourceType) {
		return Finding{}, fmt.Errorf("source type is invalid: %s", input.SourceType)
	}

	if match.Value == "" {
		return Finding{}, fmt.Errorf("match value is required")
	}

	return Finding{
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
	}, nil
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

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func buildContextSnippet(content string, match detectors.Match) string {
	if content == "" || match.Start < 0 || match.End > len(content) || match.Start >= match.End {
		return Redact(match.Value)
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
	parts := make([]string, 0, 3)
	if before != "" {
		parts = append(parts, before)
	}
	parts = append(parts, Redact(match.Value))
	if after != "" {
		parts = append(parts, after)
	}

	return strings.Join(parts, " ")
}

func isValidSourceType(value SourceType) bool {
	switch value {
	case SourceTypeFileFinal, SourceTypeFileDeletedLayer, SourceTypeEnv, SourceTypeLabel, SourceTypeHistory, SourceTypeConfig:
		return true
	default:
		return false
	}
}
