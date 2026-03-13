package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"git.tools.cloudfor.ge/andrew/layerleak/internal/findings"
	"git.tools.cloudfor.ge/andrew/layerleak/internal/manifest"
	"git.tools.cloudfor.ge/andrew/layerleak/internal/scanner"
)

type persistedResult struct {
	RequestedReference     string                   `json:"requested_reference"`
	ResolvedReference      string                   `json:"resolved_reference"`
	RequestedDigest        string                   `json:"requested_digest"`
	ManifestCount          int                      `json:"manifest_count"`
	CompletedManifestCount int                      `json:"completed_manifest_count"`
	FailedManifestCount    int                      `json:"failed_manifest_count"`
	PlatformResults        []scanner.PlatformResult `json:"platform_results"`
	Findings               []persistedFinding       `json:"findings"`
	TotalFindings          int                      `json:"total_findings"`
	UniqueFingerprints     int                      `json:"unique_fingerprints"`
}

type persistedFinding struct {
	DetectorName        string              `json:"detector_name"`
	Confidence          string              `json:"confidence"`
	SourceType          findings.SourceType `json:"source_type"`
	ManifestDigest      string              `json:"manifest_digest"`
	Platform            manifest.Platform   `json:"platform,omitempty"`
	FilePath            string              `json:"file_path,omitempty"`
	LayerDigest         string              `json:"layer_digest,omitempty"`
	Key                 string              `json:"key,omitempty"`
	Value               string              `json:"value"`
	Fingerprint         string              `json:"fingerprint"`
	ContextSnippet      string              `json:"context_snippet"`
	SourceLocation      string              `json:"source_location"`
	MatchStart          int                 `json:"match_start"`
	MatchEnd            int                 `json:"match_end"`
	PresentInFinalImage bool                `json:"present_in_final_image"`
	OccurrenceCount     int                 `json:"occurrence_count,omitempty"`
	SuppressedCount     int                 `json:"suppressed_occurrence_count,omitempty"`
}

const persistedLowConfidenceGroupCap = 3

func writeResultFile(configuredDir string, result scanner.Result) (string, error) {
	findingsDir, err := resolveFindingsDir(configuredDir)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(findingsDir, 0o755); err != nil {
		return "", fmt.Errorf("create findings directory: %w", err)
	}

	filePath := filepath.Join(findingsDir, buildResultFileName(result))
	file, err := os.Create(filePath)
	if err != nil {
		return "", fmt.Errorf("create findings result file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(buildPersistedResult(result)); err != nil {
		return "", fmt.Errorf("write findings result file: %w", err)
	}

	return filePath, nil
}

func buildPersistedResult(result scanner.Result) persistedResult {
	items := make([]persistedFinding, 0, len(result.DetailedFindings))
	for _, item := range result.DetailedFindings {
		items = append(items, persistedFinding{
			DetectorName:        item.DetectorName,
			Confidence:          item.Confidence,
			SourceType:          item.SourceType,
			ManifestDigest:      item.ManifestDigest,
			Platform:            item.Platform,
			FilePath:            item.FilePath,
			LayerDigest:         item.LayerDigest,
			Key:                 item.Key,
			Value:               item.Value,
			Fingerprint:         item.Fingerprint,
			ContextSnippet:      item.RawSnippet,
			SourceLocation:      item.SourceLocation,
			MatchStart:          item.MatchStart,
			MatchEnd:            item.MatchEnd,
			PresentInFinalImage: item.PresentInFinalImage,
		})
	}
	items = capPersistedLowConfidenceFindings(items)

	return persistedResult{
		RequestedReference:     result.RequestedReference,
		ResolvedReference:      result.ResolvedReference,
		RequestedDigest:        result.RequestedDigest,
		ManifestCount:          result.ManifestCount,
		CompletedManifestCount: result.CompletedManifestCount,
		FailedManifestCount:    result.FailedManifestCount,
		PlatformResults:        result.PlatformResults,
		Findings:               items,
		TotalFindings:          result.TotalFindings,
		UniqueFingerprints:     result.UniqueFingerprints,
	}
}

func capPersistedLowConfidenceFindings(items []persistedFinding) []persistedFinding {
	groupCounts := make(map[string]int)
	output := make([]persistedFinding, 0, len(items))
	firstIndexByGroup := make(map[string]int)

	for _, item := range items {
		groupKey, limited := persistedFindingGroupKey(item)
		if !limited {
			output = append(output, item)
			continue
		}

		groupCounts[groupKey]++
		if firstIndex, ok := firstIndexByGroup[groupKey]; ok {
			output[firstIndex].OccurrenceCount++
			if groupCounts[groupKey] > persistedLowConfidenceGroupCap {
				output[firstIndex].SuppressedCount++
				continue
			}
		} else {
			item.OccurrenceCount = 1
			firstIndexByGroup[groupKey] = len(output)
		}

		output = append(output, item)
	}

	return output
}

func persistedFindingGroupKey(item persistedFinding) (string, bool) {
	if item.Confidence != "low" || item.FilePath == "" {
		return "", false
	}

	return strings.Join([]string{
		item.DetectorName,
		item.Confidence,
		string(item.SourceType),
		item.ManifestDigest,
		item.Platform.String(),
		item.FilePath,
		item.LayerDigest,
		item.Key,
		item.Value,
		item.Fingerprint,
		boolString(item.PresentInFinalImage),
	}, "|"), true
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func resolveFindingsDir(configuredDir string) (string, error) {
	value := strings.TrimSpace(configuredDir)
	if value != "" {
		if filepath.IsAbs(value) {
			return value, nil
		}
		root, err := repoRoot()
		if err != nil {
			cwd, cwdErr := os.Getwd()
			if cwdErr != nil {
				return "", fmt.Errorf("resolve current working directory: %w", cwdErr)
			}
			return filepath.Clean(filepath.Join(cwd, value)), nil
		}
		return filepath.Clean(filepath.Join(root, value)), nil
	}

	root, err := repoRoot()
	if err != nil {
		cwd, cwdErr := os.Getwd()
		if cwdErr != nil {
			return "", fmt.Errorf("resolve current working directory: %w", cwdErr)
		}
		root = cwd
	}

	return filepath.Join(root, "findings"), nil
}

func repoRoot() (string, error) {
	current, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("resolve working directory: %w", err)
	}

	for {
		if _, err := os.Stat(filepath.Join(current, "go.mod")); err == nil {
			return current, nil
		}

		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("repo root not found")
		}
		current = parent
	}
}

func buildResultFileName(result scanner.Result) string {
	timestamp := time.Now().UTC().Format("20060102T150405Z")
	digest := sanitizePathToken(result.RequestedDigest)
	if digest == "" {
		digest = "unknown-digest"
	}

	return fmt.Sprintf("%s-%s.json", timestamp, digest)
}

func sanitizePathToken(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	var builder strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			builder.WriteRune(r)
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
		case r == '-', r == '_':
			builder.WriteRune(r)
		case r == ':', r == '/', r == '.', r == ' ':
			builder.WriteRune('-')
		}
	}

	return strings.Trim(builder.String(), "-")
}
