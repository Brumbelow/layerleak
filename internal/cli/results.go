package cli

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/brumbelow/layerleak/internal/findings"
	"github.com/brumbelow/layerleak/internal/jobs"
	"github.com/brumbelow/layerleak/internal/manifest"
	"github.com/brumbelow/layerleak/internal/scanservice"
)

type persistedFinding struct {
	DetectorName        string                     `json:"detector_name"`
	Confidence          string                     `json:"confidence"`
	Disposition         findings.Disposition       `json:"disposition"`
	DispositionReason   findings.DispositionReason `json:"disposition_reason,omitempty"`
	SourceType          findings.SourceType        `json:"source_type"`
	ManifestDigest      string                     `json:"manifest_digest"`
	Platform            manifest.Platform          `json:"platform,omitempty"`
	FilePath            string                     `json:"file_path,omitempty"`
	LayerDigest         string                     `json:"layer_digest,omitempty"`
	Key                 string                     `json:"key,omitempty"`
	LineNumber          int                        `json:"line_number,omitempty"`
	RedactedValue       string                     `json:"redacted_value"`
	Value               string                     `json:"value,omitempty"`
	Fingerprint         string                     `json:"fingerprint"`
	ContextSnippet      string                     `json:"context_snippet"`
	RawContextSnippet   string                     `json:"raw_context_snippet,omitempty"`
	SourceLocation      string                     `json:"source_location"`
	MatchStart          int                        `json:"match_start"`
	MatchEnd            int                        `json:"match_end"`
	PresentInFinalImage bool                       `json:"present_in_final_image"`
	OccurrenceCount     int                        `json:"occurrence_count,omitempty"`
	SuppressedCount     int                        `json:"suppressed_occurrence_count,omitempty"`
}

const persistedLowConfidenceGroupCap = 3

func uniqueResultFileName(result jobs.Result) string {
	return strings.TrimSuffix(buildResultFileName(result), ".json") + "-" + rand.Text() + ".json"
}

func publishResultJSON(dir, name string, value any) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create result directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", fmt.Errorf("secure result directory: %w", err)
	}
	file, err := os.CreateTemp(dir, ".layerleak-result-*")
	if err != nil {
		return "", fmt.Errorf("create result file: %w", err)
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		_ = file.Close()
		return "", fmt.Errorf("write result file: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return "", fmt.Errorf("sync result file: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close result file: %w", err)
	}
	path := filepath.Join(dir, name)
	if err := os.Link(temporary, path); err != nil {
		return "", fmt.Errorf("publish result file: %w", err)
	}
	if err := os.Remove(temporary); err != nil {
		return path, fmt.Errorf("remove temporary result file: %w", err)
	}
	return path, nil
}

func buildPersistedFindings(result jobs.Result, persistRawSecrets bool) []persistedFinding {
	allDetailedFindings := append([]findings.DetailedFinding{}, result.DetailedFindings...)
	allDetailedFindings = append(allDetailedFindings, result.SuppressedDetailedFindings...)

	items := make([]persistedFinding, 0, len(allDetailedFindings))
	for _, item := range allDetailedFindings {
		persisted := persistedFinding{
			DetectorName:        item.DetectorName,
			Confidence:          item.Confidence,
			Disposition:         item.Disposition,
			DispositionReason:   item.DispositionReason,
			SourceType:          item.SourceType,
			ManifestDigest:      item.ManifestDigest,
			Platform:            item.Platform,
			FilePath:            item.FilePath,
			LayerDigest:         item.LayerDigest,
			Key:                 item.Key,
			LineNumber:          item.LineNumber,
			RedactedValue:       item.RedactedValue,
			Fingerprint:         item.Fingerprint,
			ContextSnippet:      item.ContextSnippet,
			SourceLocation:      item.SourceLocation,
			MatchStart:          item.MatchStart,
			MatchEnd:            item.MatchEnd,
			PresentInFinalImage: item.PresentInFinalImage,
		}
		if persistRawSecrets {
			persisted.Value = item.Value
			persisted.RawContextSnippet = item.RawSnippet
		}
		items = append(items, persisted)
	}

	return capPersistedLowConfidenceFindings(items)
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
		string(item.Disposition),
		string(item.SourceType),
		item.ManifestDigest,
		item.Platform.String(),
		item.FilePath,
		item.LayerDigest,
		item.Key,
		strconv.Itoa(item.LineNumber),
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

func buildResultFileName(result jobs.Result) string {
	timestamp := time.Now().UTC().Format("20060102T150405Z")
	token := sanitizePathToken(result.RequestedDigest)
	if token == "" {
		token = sanitizePathToken(result.Repository)
	}
	if token == "" {
		token = "scan-result"
	}

	return fmt.Sprintf("%s-%s.json", timestamp, token)
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

type resultArtifactPaths struct {
	Findings string
	Scan     string
}

type localScanRecord struct {
	RecordSchemaVersion int                `json:"record_schema_version"`
	CreatedAt           time.Time          `json:"created_at"`
	Result              jobs.Result        `json:"result"`
	Persistence         persistenceOutcome `json:"persistence"`
}

type persistenceOutcome struct {
	Status       string `json:"status"`
	ScanRunID    int64  `json:"scan_run_id,omitempty"`
	ErrorCode    string `json:"error_code,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
}

func writeResultArtifacts(configuredDir string, persistRawSecrets bool, outcome scanservice.Outcome, storeName string) (resultArtifactPaths, error) {
	dir, err := resolveFindingsDir(configuredDir)
	if err != nil {
		return resultArtifactPaths{}, err
	}
	name := uniqueResultFileName(outcome.Result)
	persistence := persistenceOutcome{Status: "disabled"}
	if outcome.SaveError != nil {
		persistence = persistenceOutcome{Status: "failed", ErrorCode: "storage_unavailable", ErrorMessage: "the scan result could not be stored"}
	} else if storeName != "noop" {
		persistence = persistenceOutcome{Status: "saved", ScanRunID: outcome.ScanRunID}
	}
	record := localScanRecord{RecordSchemaVersion: 1, CreatedAt: time.Now().UTC(), Result: scanservice.RedactedResult(outcome.Result), Persistence: persistence}
	return publishResultArtifacts(dir, name, buildPersistedFindings(outcome.Result, persistRawSecrets), record)
}

func publishResultArtifacts(dir, name string, legacy []persistedFinding, record localScanRecord) (resultArtifactPaths, error) {
	findingsPath, findingsErr := publishResultJSON(dir, name, legacy)
	scanPath, scanErr := publishResultJSON(filepath.Join(dir, "scans"), name, record)
	return resultArtifactPaths{Findings: findingsPath, Scan: scanPath}, errors.Join(findingsErr, scanErr)
}
