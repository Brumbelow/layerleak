package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/findings"
	"github.com/brumbelow/layerleak/v3/internal/jobs"
)

// baselineSchemaVersion is the baseline_schema_version this build reads and
// writes. Entries are keyed on the stable finding fingerprint (sha256 of the
// raw value, identical across installs), never on raw values.
const baselineSchemaVersion = 1

// maxBaselineBytes bounds the baseline file read: a baseline is a list of
// fingerprints, so even a very large one is far below this.
const maxBaselineBytes = 16 << 20

// maxBaselineSourceBytes bounds the result or scan record `baseline create`
// reads; results are bounded by LAYERLEAK_MAX_FINDINGS_PER_SCAN upstream.
const maxBaselineSourceBytes = 256 << 20

// maxBaselineReasonBytes bounds one entry's reason, which reaches SARIF
// justifications and the summary.
const maxBaselineReasonBytes = 1024

// fingerprintPrefixLength is how much of a fingerprint warnings show: enough
// to find the entry, not enough to serve as an offline oracle.
const fingerprintPrefixLength = 12

var (
	fingerprintPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	detectorIDPattern  = regexp.MustCompile(`^[a-z0-9_]+$`)
)

// baselineDocument is the on-disk baseline file.
type baselineDocument struct {
	BaselineSchemaVersion int             `json:"baseline_schema_version"`
	Entries               []baselineEntry `json:"entries"`
}

// baselineEntry accepts one finding by fingerprint. An empty Detector matches
// the fingerprint under any detector; a set Detector matches only findings of
// that detector, so the same value matched by a second detector stays
// actionable. Expires is an optional RFC 3339 timestamp after which the entry
// is ignored with a warning.
type baselineEntry struct {
	Fingerprint string `json:"fingerprint"`
	Detector    string `json:"detector,omitempty"`
	Reason      string `json:"reason,omitempty"`
	Expires     string `json:"expires,omitempty"`
}

// baseline is a loaded, validated baseline file.
type baseline struct {
	path    string
	entries map[string][]baselineEntry
	// Warnings describe ignored (expired) entries, naming a fingerprint
	// prefix only.
	Warnings []string
}

// loadBaseline reads and validates a baseline file. Any structural problem is
// an error (exit 1 before the scan starts); expired entries are skipped with a
// warning. now decides expiry.
func loadBaseline(path string, now time.Time) (*baseline, error) {
	file, err := os.Open(path) //nolint:gosec // the operator-chosen --baseline path
	if err != nil {
		return nil, fmt.Errorf("open baseline file: %w", err)
	}
	defer func() { _ = file.Close() }()
	document, err := decodeBaseline(io.LimitReader(file, maxBaselineBytes+1))
	if err != nil {
		return nil, fmt.Errorf("baseline file %q: %w", path, err)
	}
	loaded := &baseline{path: path, entries: make(map[string][]baselineEntry, len(document.Entries))}
	for index, entry := range document.Entries {
		normalized, err := normalizeBaselineEntry(entry)
		if err != nil {
			return nil, fmt.Errorf("baseline file %q: entry %d: %w", path, index, err)
		}
		if normalized.Expires != "" {
			expires, err := time.Parse(time.RFC3339, normalized.Expires)
			if err != nil {
				return nil, fmt.Errorf("baseline file %q: entry %d: expires must be an RFC 3339 timestamp: %w", path, index, err)
			}
			if !now.Before(expires) {
				loaded.Warnings = append(loaded.Warnings, fmt.Sprintf("warning: baseline entry %s... expired at %s and is ignored", normalized.Fingerprint[:fingerprintPrefixLength], expires.UTC().Format(time.RFC3339)))
				continue
			}
		}
		loaded.entries[normalized.Fingerprint] = append(loaded.entries[normalized.Fingerprint], normalized)
	}
	return loaded, nil
}

// decodeBaseline parses exactly one JSON document with no unknown fields and
// no trailing content, and checks the schema version before anything else.
func decodeBaseline(reader io.Reader) (baselineDocument, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return baselineDocument{}, fmt.Errorf("read: %w", err)
	}
	if len(data) > maxBaselineBytes {
		return baselineDocument{}, fmt.Errorf("exceeds %d bytes", maxBaselineBytes)
	}
	var version struct {
		BaselineSchemaVersion *int `json:"baseline_schema_version"`
	}
	probe := json.NewDecoder(bytes.NewReader(data))
	if err := probe.Decode(&version); err != nil {
		return baselineDocument{}, fmt.Errorf("not a JSON object: %w", err)
	}
	// Decoder.More reports false before a stray '}' or ']', so check the bytes
	// after the first value directly: only JSON whitespace may follow it.
	if len(bytes.Trim(data[probe.InputOffset():], " \t\r\n")) != 0 {
		return baselineDocument{}, errors.New("malformed: trailing content after the document")
	}
	if version.BaselineSchemaVersion == nil {
		return baselineDocument{}, errors.New("baseline_schema_version is missing")
	}
	if *version.BaselineSchemaVersion != baselineSchemaVersion {
		return baselineDocument{}, fmt.Errorf("unsupported baseline_schema_version %d (this build reads version %d)", *version.BaselineSchemaVersion, baselineSchemaVersion)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var document baselineDocument
	if err := decoder.Decode(&document); err != nil {
		return baselineDocument{}, fmt.Errorf("malformed: %w", err)
	}
	if document.Entries == nil {
		return baselineDocument{}, errors.New("entries is missing")
	}
	return document, nil
}

func normalizeBaselineEntry(entry baselineEntry) (baselineEntry, error) {
	entry.Fingerprint = strings.ToLower(strings.TrimSpace(entry.Fingerprint))
	if !fingerprintPattern.MatchString(entry.Fingerprint) {
		return entry, errors.New("fingerprint must be the 64 hexadecimal characters of a finding fingerprint")
	}
	entry.Detector = strings.TrimSpace(entry.Detector)
	if entry.Detector != "" && !detectorIDPattern.MatchString(entry.Detector) {
		return entry, fmt.Errorf("detector %q is not a detector identifier", sanitizeProgressValue(entry.Detector))
	}
	entry.Reason = strings.TrimSpace(entry.Reason)
	if len(entry.Reason) > maxBaselineReasonBytes {
		return entry, fmt.Errorf("reason exceeds %d bytes", maxBaselineReasonBytes)
	}
	entry.Expires = strings.TrimSpace(entry.Expires)
	return entry, nil
}

// match reports the entry that accepts item: a fingerprint match whose
// detector is empty or equal to the finding's detector. Findings without a
// fingerprint are never matched.
func (b *baseline) match(item findings.Finding) (baselineEntry, bool) {
	if b == nil || item.Fingerprint == "" {
		return baselineEntry{}, false
	}
	for _, entry := range b.entries[item.Fingerprint] {
		if entry.Detector == "" || entry.Detector == item.DetectorName {
			return entry, true
		}
	}
	return baselineEntry{}, false
}

// Len is the number of live (non-expired) entries.
func (b *baseline) Len() int {
	if b == nil {
		return 0
	}
	count := 0
	for _, entries := range b.entries {
		count += len(entries)
	}
	return count
}

// justification is the SARIF suppression text for a baselined finding: the
// entry's reason when it has one.
func (b *baseline) justification(item findings.Finding) string {
	if item.Disposition != findings.DispositionBaselined {
		return ""
	}
	entry, ok := b.match(item)
	if !ok || entry.Reason == "" {
		return ""
	}
	return "accepted by the caller's baseline file: " + sanitizeProgressValue(entry.Reason)
}

// applyBaseline returns a copy of result in which every actionable finding
// the baseline accepts carries disposition baselined and is listed among the
// suppressed findings, with the top-level counters recomputed. Findings the
// scanner already suppressed (example) are left as they are. Per-target and
// per-platform findings_count keep the scanner's values: the baseline is a
// view over the published result, not a re-scan. The input is not modified,
// so the unmodified result can still be persisted.
func applyBaseline(result jobs.Result, b *baseline) (jobs.Result, int) {
	if b == nil {
		return result, 0
	}
	actionable := make([]findings.Finding, 0, len(result.Findings))
	suppressed := slices.Clone(result.SuppressedFindings)
	baselined := 0
	for _, item := range result.Findings {
		if _, ok := b.match(item); ok {
			item.Disposition = findings.DispositionBaselined
			item.DispositionReason = findings.DispositionReasonNone
			suppressed = append(suppressed, item)
			baselined++
			continue
		}
		actionable = append(actionable, item)
	}
	detailed := make([]findings.DetailedFinding, 0, len(result.DetailedFindings))
	suppressedDetailed := slices.Clone(result.SuppressedDetailedFindings)
	for _, item := range result.DetailedFindings {
		if _, ok := b.match(item.Finding); ok {
			item.Disposition = findings.DispositionBaselined
			item.DispositionReason = findings.DispositionReasonNone
			suppressedDetailed = append(suppressedDetailed, item)
			continue
		}
		detailed = append(detailed, item)
	}
	result.Findings = actionable
	result.DetailedFindings = detailed
	result.SuppressedFindings = suppressed
	result.SuppressedDetailedFindings = suppressedDetailed
	result.TotalFindings = len(result.Findings)
	result.UniqueFingerprints = findings.UniqueFingerprintCount(result.Findings)
	result.SuppressedFindingsCount = len(result.SuppressedFindings)
	result.SuppressedUniqueFingerprints = findings.UniqueFingerprintCount(result.SuppressedFindings)
	return result, baselined
}

// countBaselined counts the suppressed findings the baseline accepted. The
// switch is exhaustive over findings.Disposition so a new value cannot be
// miscounted silently.
func countBaselined(items []findings.Finding) int {
	count := 0
	for _, item := range items {
		switch item.Disposition {
		case findings.DispositionBaselined:
			count++
		case findings.DispositionActionable, findings.DispositionExample:
		default:
		}
	}
	return count
}

// baselineSource is the shape `baseline create --from` reads: a result-v2
// document or a scan record (record_schema_version 2) embedding one.
type baselineSource struct {
	ResultSchemaVersion int                `json:"result_schema_version"`
	RecordSchemaVersion int                `json:"record_schema_version"`
	Findings            []findings.Finding `json:"findings"`
	Result              *struct {
		ResultSchemaVersion int                `json:"result_schema_version"`
		Findings            []findings.Finding `json:"findings"`
	} `json:"result"`
}

// baselineFromSource builds the entries for every actionable finding of a
// result or scan record: fingerprint plus detector, de-duplicated and sorted.
// Only the fingerprint and the detector name are taken from the source; no
// redacted value, path or snippet is copied.
func baselineFromSource(reader io.Reader, reason string) (baselineDocument, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxBaselineSourceBytes+1))
	if err != nil {
		return baselineDocument{}, fmt.Errorf("read: %w", err)
	}
	if len(data) > maxBaselineSourceBytes {
		return baselineDocument{}, fmt.Errorf("exceeds %d bytes", maxBaselineSourceBytes)
	}
	var source baselineSource
	if err := json.Unmarshal(data, &source); err != nil {
		return baselineDocument{}, fmt.Errorf("not a JSON result: %w", err)
	}
	items := source.Findings
	switch {
	case source.RecordSchemaVersion != 0:
		if source.RecordSchemaVersion != recordSchemaVersion || source.Result == nil {
			return baselineDocument{}, fmt.Errorf("unsupported record_schema_version %d (this build reads version %d)", source.RecordSchemaVersion, recordSchemaVersion)
		}
		if source.Result.ResultSchemaVersion != jobs.ResultSchemaVersion {
			return baselineDocument{}, fmt.Errorf("unsupported result_schema_version %d (this build reads version %d)", source.Result.ResultSchemaVersion, jobs.ResultSchemaVersion)
		}
		items = source.Result.Findings
	case source.ResultSchemaVersion != jobs.ResultSchemaVersion:
		return baselineDocument{}, fmt.Errorf("unsupported result_schema_version %d (this build reads version %d)", source.ResultSchemaVersion, jobs.ResultSchemaVersion)
	}
	document := baselineDocument{BaselineSchemaVersion: baselineSchemaVersion, Entries: make([]baselineEntry, 0, len(items))}
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		if item.Disposition != findings.DispositionActionable && item.Disposition != "" {
			continue
		}
		fingerprint := strings.ToLower(strings.TrimSpace(item.Fingerprint))
		detector := strings.TrimSpace(item.DetectorName)
		if !fingerprintPattern.MatchString(fingerprint) || !detectorIDPattern.MatchString(detector) {
			continue
		}
		key := detector + "\x00" + fingerprint
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		document.Entries = append(document.Entries, baselineEntry{Fingerprint: fingerprint, Detector: detector, Reason: reason})
	}
	slices.SortFunc(document.Entries, func(left, right baselineEntry) int {
		if value := strings.Compare(left.Fingerprint, right.Fingerprint); value != 0 {
			return value
		}
		return strings.Compare(left.Detector, right.Detector)
	})
	return document, nil
}

// writeBaselineFile writes the document with mode 0600, refusing to replace
// an existing file unless force is set.
func writeBaselineFile(path string, document baselineDocument, force bool) error {
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	file, err := os.OpenFile(path, flags, 0o600) //nolint:gosec // the operator-chosen --output path
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("baseline file %q already exists; pass --force to replace it", path)
	}
	if err != nil {
		return fmt.Errorf("create baseline file: %w", err)
	}
	if err := encodeBaseline(file, document); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close baseline file: %w", err)
	}
	return nil
}

func encodeBaseline(writer io.Writer, document baselineDocument) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(document); err != nil {
		return fmt.Errorf("write baseline file: %w", err)
	}
	return nil
}
