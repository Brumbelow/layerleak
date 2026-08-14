package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

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

	// DispositionActionable marks findings that count toward total_findings and
	// drive the non-zero scan exit status.
	DispositionActionable Disposition = "actionable"
	// DispositionExample marks placeholder/test/demo detections that are
	// emitted as suppressed findings. The HTTP API exposes these through the
	// `?disposition=suppressed` filter and the `suppressed_findings` JSON
	// payload; the on-disk and DB value remains the literal string "example"
	// to preserve schema compatibility with existing scan_runs and
	// finding_occurrences rows.
	DispositionExample Disposition = "example"

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

type sensitiveSpan struct {
	start     int
	end       int
	multiline bool
}

const MaxPublicProvenanceBytes = 512

// DetailedNormalizer prepares the shared redaction and line indexes for every
// detector match in one input. Reusing it keeps normalization linearithmic in
// the match count instead of rescanning every match for every finding.
type DetailedNormalizer struct {
	input          Input
	spans          []sensitiveSpan
	lineBreaks     []int
	filePath       string
	metadataKey    string
	sourceLocation string
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
	MatchStart          int               `json:"match_start"`
	MatchEnd            int               `json:"match_end"`
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
	seen := make(map[snippetDedupKey]struct{})
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
	return NormalizeDetailedWithMatches(input, match, []detectors.Match{match})
}

// NormalizeDetailedWithMatches normalizes one detector match while redacting every
// sensitive span that intersects its public context window.
func NormalizeDetailedWithMatches(input Input, match detectors.Match, matches []detectors.Match) (DetailedFinding, error) {
	normalizer, err := NewDetailedNormalizer(input, matches)
	if err != nil {
		return DetailedFinding{}, err
	}
	return normalizer.Normalize(match)
}

// NewDetailedNormalizer prepares shared indexes for a set of matches from one
// detector input.
func NewDetailedNormalizer(input Input, matches []detectors.Match) (*DetailedNormalizer, error) {
	return NewDetailedNormalizerWithProvenance(input, matches, nil, nil)
}

// NewDetailedNormalizerWithProvenance prepares shared indexes and uses matches
// found in provenance fields only to redact those fields. Provenance-only
// matches never become findings.
func NewDetailedNormalizerWithProvenance(input Input, matches, filePathMatches, metadataKeyMatches []detectors.Match) (*DetailedNormalizer, error) {
	if strings.TrimSpace(input.ManifestDigest) == "" {
		return nil, fmt.Errorf("manifest digest is required")
	}

	if !isValidSourceType(input.SourceType) {
		return nil, fmt.Errorf("source type is invalid: %s", input.SourceType)
	}

	lineBreaks := make([]int, 0, strings.Count(input.Content, "\n"))
	for index := 0; index < len(input.Content); index++ {
		if input.Content[index] == '\n' {
			lineBreaks = append(lineBreaks, index)
		}
	}

	filePath := sanitizedProvenance(input.FilePath, filePathMatches, matches)
	metadataKey := sanitizedProvenance(input.Key, metadataKeyMatches, matches)
	normalizer := &DetailedNormalizer{
		input:       input,
		spans:       mergeSensitiveSpans(input.Content, matches),
		lineBreaks:  lineBreaks,
		filePath:    filePath,
		metadataKey: metadataKey,
	}
	normalizer.sourceLocation = boundedSanitizedProvenance(buildSourceLocation(Finding{
		SourceType: input.SourceType,
		FilePath:   filePath,
		Key:        metadataKey,
	}))
	return normalizer, nil
}

// Normalize converts one match from the prepared detector input.
func (n *DetailedNormalizer) Normalize(match detectors.Match) (DetailedFinding, error) {
	return n.NormalizeWithRaw(match, true)
}

// NormalizeWithRaw converts one match and optionally retains its raw value and
// context snippet.
func (n *DetailedNormalizer) NormalizeWithRaw(match detectors.Match, retainRaw bool) (DetailedFinding, error) {
	if n == nil {
		return DetailedFinding{}, fmt.Errorf("detailed normalizer is required")
	}
	input := n.input

	if match.Value == "" {
		return DetailedFinding{}, fmt.Errorf("match value is required")
	}
	if match.Start < 0 || match.End <= match.Start || match.End > len(input.Content) {
		return DetailedFinding{}, fmt.Errorf("match span is invalid")
	}
	if input.Content[match.Start:match.End] != match.Value {
		return DetailedFinding{}, fmt.Errorf("match value does not match its content span")
	}

	disposition, reason := Classify(input, match)

	result := DetailedFinding{
		Finding: Finding{
			DetectorName:        match.Detector,
			Confidence:          string(match.Confidence),
			Disposition:         disposition,
			DispositionReason:   reason,
			SourceType:          input.SourceType,
			ManifestDigest:      input.ManifestDigest,
			Platform:            input.Platform,
			FilePath:            n.filePath,
			LayerDigest:         input.LayerDigest,
			Key:                 n.metadataKey,
			LineNumber:          n.lineNumber(match.Start),
			RedactedValue:       Redact(match.Value),
			Fingerprint:         Fingerprint(match.Value),
			ContextSnippet:      n.contextSnippet(match),
			MatchStart:          match.Start,
			MatchEnd:            match.End,
			PresentInFinalImage: input.PresentInFinalImage,
		},
		MatchStart: match.Start,
		MatchEnd:   match.End,
	}
	if retainRaw {
		result.Value = strings.Clone(match.Value)
		result.RawSnippet = strings.Clone(buildRawContextSnippet(input.Content, match))
	}
	result.SourceLocation = n.sourceLocation
	return result, nil
}

// RawByteSize reports the raw value and context bytes that NormalizeWithRaw
// would retain for one match.
func (n *DetailedNormalizer) RawByteSize(match detectors.Match) (int64, error) {
	if n == nil {
		return 0, fmt.Errorf("detailed normalizer is required")
	}
	if match.Value == "" || match.Start < 0 || match.End <= match.Start || match.End > len(n.input.Content) || n.input.Content[match.Start:match.End] != match.Value {
		return 0, fmt.Errorf("match span is invalid")
	}
	start, end := snippetBounds(n.input.Content, match)
	return int64(len(match.Value)) + int64(len(strings.TrimSpace(n.input.Content[start:end]))), nil
}

func (d DetailedFinding) PublicFinding() Finding {
	return d.Finding
}

// WithoutRawSecrets returns a copy suitable for callers that do not persist
// raw secret material.
func (d DetailedFinding) WithoutRawSecrets() DetailedFinding {
	d.Value = ""
	d.RawSnippet = ""
	return d
}

// StripRawSecrets clears raw values and snippets in place.
func StripRawSecrets(items []DetailedFinding) {
	for index := range items {
		items[index].Value = ""
		items[index].RawSnippet = ""
	}
}

func DeduplicateDetailed(items []DetailedFinding) []DetailedFinding {
	sorted := slices.Clone(items)
	slices.SortFunc(sorted, compareDetailedFindings)

	deduped := make([]DetailedFinding, 0, len(sorted))
	seen := make(map[snippetDedupKey]struct{})
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
		return "[REDACTED MULTILINE]"
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

func mergeSensitiveSpans(content string, matches []detectors.Match) []sensitiveSpan {
	spans := make([]sensitiveSpan, 0, len(matches))
	for _, candidate := range matches {
		if candidate.Start < 0 || candidate.End <= candidate.Start || candidate.End > len(content) {
			continue
		}
		spans = append(spans, sensitiveSpan{
			start:     candidate.Start,
			end:       candidate.End,
			multiline: strings.Contains(content[candidate.Start:candidate.End], "\n"),
		})
	}
	slices.SortFunc(spans, compareSensitiveSpans)
	return mergeSortedSensitiveSpans(spans)
}

func compareSensitiveSpans(left, right sensitiveSpan) int {
	if left.start != right.start {
		return left.start - right.start
	}
	return left.end - right.end
}

func mergeSortedSensitiveSpans(spans []sensitiveSpan) []sensitiveSpan {
	merged := make([]sensitiveSpan, 0, len(spans))
	for _, span := range spans {
		if len(merged) == 0 || span.start > merged[len(merged)-1].end {
			merged = append(merged, span)
			continue
		}
		last := &merged[len(merged)-1]
		last.end = max(last.end, span.end)
		last.multiline = last.multiline || span.multiline
	}
	return merged
}

func (n *DetailedNormalizer) contextSnippet(match detectors.Match) string {
	content := n.input.Content
	if content == "" || match.Start < 0 || match.End > len(content) || match.Start >= match.End {
		return "[REDACTED]"
	}

	start, end := snippetBounds(content, match)
	first := sort.Search(len(n.spans), func(index int) bool {
		return n.spans[index].end > start
	})
	spans := make([]sensitiveSpan, 0, 4)
	for index := first; index < len(n.spans) && n.spans[index].start < end; index++ {
		candidate := n.spans[index]
		spans = append(spans, sensitiveSpan{
			start:     max(candidate.start, start),
			end:       min(candidate.end, end),
			multiline: candidate.multiline,
		})
	}
	spans = append(spans, sensitiveSpan{
		start:     max(match.Start, start),
		end:       min(match.End, end),
		multiline: strings.Contains(content[match.Start:match.End], "\n"),
	})
	slices.SortFunc(spans, compareSensitiveSpans)
	spans = mergeSortedSensitiveSpans(spans)

	var builder strings.Builder
	cursor := start
	for _, span := range spans {
		builder.WriteString(content[cursor:span.start])
		if span.multiline {
			builder.WriteString("[REDACTED MULTILINE]")
		} else {
			builder.WriteString("[REDACTED]")
		}
		cursor = span.end
	}
	builder.WriteString(content[cursor:end])
	return strings.TrimSpace(builder.String())
}

func (n *DetailedNormalizer) lineNumber(offset int) int {
	if offset <= 0 {
		return 1
	}
	return 1 + sort.SearchInts(n.lineBreaks, offset)
}

func buildRawContextSnippet(content string, match detectors.Match) string {
	if content == "" || match.Start < 0 || match.End > len(content) || match.Start >= match.End {
		return match.Value
	}
	start, end := snippetBounds(content, match)
	return strings.TrimSpace(content[start:end])
}

func snippetBounds(content string, match detectors.Match) (int, int) {

	start := match.Start - 24
	if start < 0 {
		start = 0
	}

	end := match.End + 24
	if end > len(content) {
		end = len(content)
	}
	for start > 0 && !utf8.RuneStart(content[start]) {
		start--
	}
	for end < len(content) && !utf8.RuneStart(content[end]) {
		end++
	}
	return start, end
}

func buildSourceLocation(item Finding) string {
	location := ""
	switch {
	case item.FilePath != "":
		location = item.FilePath
	case item.Key != "":
		location = item.Key
	default:
		location = string(item.SourceType)
	}

	return string(item.SourceType) + ":" + location
}

type snippetDedupKey struct {
	manifestDigest string
	platform       string
	disposition    Disposition
	sourceLocation string
	layerDigest    string
	detectorName   string
	fingerprint    string
	lineNumber     int
	matchStart     int
	matchEnd       int
}

func findingSnippetDedupKey(item Finding) snippetDedupKey {
	return snippetDedupKey{
		manifestDigest: item.ManifestDigest,
		platform:       item.Platform.String(),
		disposition:    item.Disposition,
		sourceLocation: publicSourceLocation(item),
		layerDigest:    item.LayerDigest,
		detectorName:   item.DetectorName,
		fingerprint:    item.Fingerprint,
		lineNumber:     item.LineNumber,
		matchStart:     item.MatchStart,
		matchEnd:       item.MatchEnd,
	}
}

func detailedFindingSnippetDedupKey(item DetailedFinding) snippetDedupKey {
	key := findingSnippetDedupKey(item.Finding)
	key.sourceLocation = item.SourceLocation
	key.matchStart = item.MatchStart
	key.matchEnd = item.MatchEnd
	return key
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

func publicSourceLocation(item Finding) string {
	location := ""
	switch {
	case item.FilePath != "":
		location = item.FilePath
	case item.Key != "":
		location = item.Key
	default:
		location = string(item.SourceType)
	}

	return string(item.SourceType) + ":" + location
}

func sanitizedProvenance(value string, provenanceMatches, contentMatches []detectors.Match) string {
	if value == "" {
		return ""
	}

	spans := mergeSensitiveSpans(value, provenanceMatches)
	spans = append(spans, exactValueSpans(value, contentMatches)...)
	slices.SortFunc(spans, compareSensitiveSpans)
	spans = mergeSortedSensitiveSpans(spans)

	var builder strings.Builder
	cursor := 0
	for _, span := range spans {
		builder.WriteString(value[cursor:span.start])
		if span.multiline {
			builder.WriteString("[REDACTED MULTILINE]")
		} else {
			builder.WriteString("[REDACTED]")
		}
		cursor = span.end
	}
	builder.WriteString(value[cursor:])
	redacted := strings.ToValidUTF8(builder.String(), "\uFFFD")
	if len(redacted) <= MaxPublicProvenanceBytes {
		return redacted
	}
	return boundedSanitizedProvenance(redacted)
}

func exactValueSpans(value string, matches []detectors.Match) []sensitiveSpan {
	spans := make([]sensitiveSpan, 0)
	seen := make(map[string]struct{})
	for _, match := range matches {
		if match.Value == "" {
			continue
		}
		if _, ok := seen[match.Value]; ok {
			continue
		}
		seen[match.Value] = struct{}{}
		remaining := value
		offset := 0
		for {
			index := strings.Index(remaining, match.Value)
			if index < 0 {
				break
			}
			start := offset + index
			end := start + len(match.Value)
			spans = append(spans, sensitiveSpan{
				start:     start,
				end:       end,
				multiline: strings.Contains(match.Value, "\n"),
			})
			offset = end
			remaining = value[offset:]
		}
	}
	return spans
}

func boundedSanitizedProvenance(value string) string {
	value = strings.ToValidUTF8(value, "\uFFFD")
	if len(value) <= MaxPublicProvenanceBytes {
		return value
	}
	suffix := provenanceDigestSuffix(value)
	prefix := validUTF8Prefix(value, MaxPublicProvenanceBytes-len(suffix))
	return prefix + suffix
}

func provenanceDigestSuffix(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "...[sha256:" + hex.EncodeToString(sum[:]) + "]"
}

func validUTF8Prefix(value string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(value) <= maxBytes {
		return value
	}
	end := maxBytes
	for end > 0 && !utf8.RuneStart(value[end]) {
		end--
	}
	return value[:end]
}

func isValidSourceType(value SourceType) bool {
	switch value {
	case SourceTypeFileFinal, SourceTypeFileDeletedLayer, SourceTypeEnv, SourceTypeLabel, SourceTypeHistory, SourceTypeConfig:
		return true
	default:
		return false
	}
}
