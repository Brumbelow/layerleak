// Package sarif encodes layerleak scan results as SARIF 2.1.0 logs so code
// scanning consumers (for example GitHub code scanning via upload-sarif) can
// ingest findings. The encoding only ever contains the public, redacted
// fields of a result; raw secret material never reaches a SARIF log.
package sarif

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/brumbelow/layerleak/v3/internal/findings"
	"github.com/brumbelow/layerleak/v3/internal/jobs"
)

const (
	// SchemaURI is the published JSON Schema for SARIF 2.1.0.
	SchemaURI = "https://json.schemastore.org/sarif-2.1.0.json"
	// Version is the SARIF specification version this package writes.
	Version = "2.1.0"
	// ToolName is the SARIF tool.driver.name.
	ToolName = "layerleak"
	// InformationURI points consumers at the project.
	InformationURI = "https://github.com/Brumbelow/layerleak"
	// FingerprintKey names the stable partial fingerprint carried by every
	// result: the sha256 of the raw value, identical across installs.
	FingerprintKey = "layerleak/fingerprint/v1"
	// ImageBaseID is the uriBaseId that file locations are relative to.
	ImageBaseID = "IMAGE"
)

// Rule describes a detector for tool.driver.rules. Rules not present in the
// catalog are synthesised from the detector names seen in the result.
type Rule struct {
	ID          string
	Description string
}

// Options tunes the encoding.
type Options struct {
	// ToolVersion is reported as tool.driver.version (for example v3.0.0).
	ToolVersion string
	// ExcludeSuppressed drops suppressed findings instead of reporting them
	// as results with an accepted suppression.
	ExcludeSuppressed bool
	// Rules lists detectors to describe even when they produced no result.
	Rules []Rule
}

// Log is the top-level SARIF document.
type Log struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

// Run is one scan invocation.
type Run struct {
	Tool               Tool                        `json:"tool"`
	AutomationDetails  *AutomationDetails          `json:"automationDetails,omitempty"`
	Invocations        []Invocation                `json:"invocations,omitempty"`
	OriginalURIBaseIDs map[string]ArtifactLocation `json:"originalUriBaseIds,omitempty"`
	Results            []Result                    `json:"results"`
	Properties         map[string]any              `json:"properties,omitempty"`
}

// Tool wraps the driver description.
type Tool struct {
	Driver Driver `json:"driver"`
}

// Driver describes layerleak and its detector rules.
type Driver struct {
	Name            string                `json:"name"`
	Version         string                `json:"version,omitempty"`
	SemanticVersion string                `json:"semanticVersion,omitempty"`
	InformationURI  string                `json:"informationUri,omitempty"`
	Rules           []ReportingDescriptor `json:"rules"`
}

// ReportingDescriptor is one rule.
type ReportingDescriptor struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name,omitempty"`
	ShortDescription     Message        `json:"shortDescription"`
	HelpURI              string         `json:"helpUri,omitempty"`
	DefaultConfiguration *Configuration `json:"defaultConfiguration,omitempty"`
	Properties           map[string]any `json:"properties,omitempty"`
}

// Configuration carries a rule's default level.
type Configuration struct {
	Level string `json:"level"`
}

// Message is SARIF text.
type Message struct {
	Text string `json:"text"`
}

// AutomationDetails identifies the run for consumers that group runs.
type AutomationDetails struct {
	ID string `json:"id"`
}

// Invocation records whether the scan completed.
type Invocation struct {
	ExecutionSuccessful bool `json:"executionSuccessful"`
}

// ArtifactLocation is a URI, optionally relative to a base.
type ArtifactLocation struct {
	URI         string   `json:"uri"`
	URIBaseID   string   `json:"uriBaseId,omitempty"`
	Description *Message `json:"description,omitempty"`
}

// Result is one finding.
type Result struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             Message           `json:"message"`
	Locations           []Location        `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Suppressions        []Suppression     `json:"suppressions,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

// Location is a physical (file) or logical (metadata) location.
type Location struct {
	PhysicalLocation *PhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []LogicalLocation `json:"logicalLocations,omitempty"`
}

// PhysicalLocation points into an image file.
type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           *Region          `json:"region,omitempty"`
}

// Region is the matched line.
type Region struct {
	StartLine int `json:"startLine"`
}

// LogicalLocation names image metadata such as an environment variable.
type LogicalLocation struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
	Kind               string `json:"kind,omitempty"`
}

// Suppression marks a result that layerleak itself classified as
// non-actionable.
type Suppression struct {
	Kind          string `json:"kind"`
	Status        string `json:"status,omitempty"`
	Justification string `json:"justification,omitempty"`
}

var semanticVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)

// FromResult converts one scan result into a SARIF log with a single run.
func FromResult(result jobs.Result, options Options) Log {
	reference := strings.TrimSpace(result.ResolvedReference)
	if reference == "" {
		reference = strings.TrimSpace(result.RequestedReference)
	}

	items := make([]findings.Finding, 0, len(result.Findings)+len(result.SuppressedFindings))
	items = append(items, result.Findings...)
	if !options.ExcludeSuppressed {
		items = append(items, result.SuppressedFindings...)
	}

	rules, index := buildRules(options.Rules, items)
	results := make([]Result, 0, len(items))
	for _, item := range items {
		results = append(results, encodeFinding(item, index[item.DetectorName]))
	}

	run := Run{
		Tool: Tool{Driver: Driver{
			Name:            ToolName,
			Version:         strings.TrimSpace(options.ToolVersion),
			SemanticVersion: semanticVersion(options.ToolVersion),
			InformationURI:  InformationURI,
			Rules:           rules,
		}},
		Invocations: []Invocation{{ExecutionSuccessful: result.Status != jobs.ResultStatusFailed}},
		Results:     results,
		Properties:  runProperties(result),
	}
	if reference != "" {
		run.AutomationDetails = &AutomationDetails{ID: ToolName + "/" + reference}
		run.OriginalURIBaseIDs = map[string]ArtifactLocation{
			ImageBaseID: {URI: imageBaseURI(reference), Description: &Message{Text: "Root filesystem of " + reference}},
		}
	}
	return Log{Schema: SchemaURI, Version: Version, Runs: []Run{run}}
}

// Encode writes the log as indented JSON followed by a newline.
func Encode(writer io.Writer, log Log) error {
	payload, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return fmt.Errorf("encode sarif: %w", err)
	}
	payload = append(payload, '\n')
	if _, err := writer.Write(payload); err != nil {
		return fmt.Errorf("write sarif: %w", err)
	}
	return nil
}

func buildRules(catalog []Rule, items []findings.Finding) ([]ReportingDescriptor, map[string]int) {
	descriptions := make(map[string]string)
	for _, rule := range catalog {
		id := strings.TrimSpace(rule.ID)
		if id == "" {
			continue
		}
		descriptions[id] = strings.TrimSpace(rule.Description)
	}
	for _, item := range items {
		if _, known := descriptions[item.DetectorName]; !known {
			descriptions[item.DetectorName] = ""
		}
	}
	ids := make([]string, 0, len(descriptions))
	for id := range descriptions {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	rules := make([]ReportingDescriptor, 0, len(ids))
	index := make(map[string]int, len(ids))
	for i, id := range ids {
		description := descriptions[id]
		if description == "" {
			description = fmt.Sprintf("Likely secret matched by the %s detector.", id)
		}
		rules = append(rules, ReportingDescriptor{
			ID:                   id,
			Name:                 id,
			ShortDescription:     Message{Text: description},
			HelpURI:              InformationURI,
			DefaultConfiguration: &Configuration{Level: "warning"},
			Properties:           map[string]any{"tags": []string{"security", "secret"}},
		})
		index[id] = i
	}
	return rules, index
}

func encodeFinding(item findings.Finding, ruleIndex int) Result {
	result := Result{
		RuleID:              item.DetectorName,
		RuleIndex:           ruleIndex,
		Level:               LevelForConfidence(item.Confidence),
		Message:             Message{Text: describeFinding(item)},
		Locations:           []Location{locationFor(item)},
		PartialFingerprints: map[string]string{FingerprintKey: item.Fingerprint},
		Properties:          findingProperties(item),
	}
	if item.Disposition != "" && item.Disposition != findings.DispositionActionable {
		justification := "layerleak classified this finding as " + string(item.Disposition)
		if item.DispositionReason != "" {
			justification += " (" + string(item.DispositionReason) + ")"
		}
		result.Suppressions = []Suppression{{Kind: "external", Status: "accepted", Justification: justification}}
	}
	return result
}

// LevelForConfidence maps detector confidence to a SARIF level.
func LevelForConfidence(confidence string) string {
	switch strings.ToLower(strings.TrimSpace(confidence)) {
	case "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

func describeFinding(item findings.Finding) string {
	confidence := strings.ToLower(strings.TrimSpace(item.Confidence))
	if confidence == "" {
		confidence = "unknown"
	}
	text := fmt.Sprintf("Likely secret matched by the %s detector (%s confidence) in %s.", item.DetectorName, confidence, describeLocation(item))
	if item.RedactedValue != "" {
		text += " Redacted value: " + item.RedactedValue + "."
	}
	if !item.PresentInFinalImage {
		text += " The value is not present in the final image filesystem but remains in the image history or an intermediate layer."
	}
	return text
}

func describeLocation(item findings.Finding) string {
	switch item.SourceType {
	case findings.SourceTypeFileFinal, findings.SourceTypeFileDeletedLayer:
		text := "file " + item.FilePath
		if item.LineNumber > 0 {
			text += fmt.Sprintf(" line %d", item.LineNumber)
		}
		if item.SourceType == findings.SourceTypeFileDeletedLayer {
			text += " (deleted by a later layer)"
		}
		return text
	case findings.SourceTypeEnv:
		return "environment variable " + item.Key
	case findings.SourceTypeLabel:
		return "image label " + item.Key
	case findings.SourceTypeHistory:
		return "image history entry " + item.Key
	case findings.SourceTypeConfig:
		return "image config field " + item.Key
	default:
		if item.Key != "" {
			return string(item.SourceType) + " " + item.Key
		}
		return string(item.SourceType)
	}
}

func locationFor(item findings.Finding) Location {
	switch item.SourceType {
	case findings.SourceTypeFileFinal, findings.SourceTypeFileDeletedLayer:
		physical := &PhysicalLocation{ArtifactLocation: ArtifactLocation{URI: ArtifactURI(item.FilePath), URIBaseID: ImageBaseID}}
		if item.LineNumber > 0 {
			physical.Region = &Region{StartLine: item.LineNumber}
		}
		return Location{PhysicalLocation: physical}
	default:
		name := item.Key
		if name == "" {
			name = string(item.SourceType)
		}
		return Location{LogicalLocations: []LogicalLocation{{
			Name:               name,
			FullyQualifiedName: string(item.SourceType) + ":" + name,
			Kind:               logicalKind(item.SourceType),
		}}}
	}
}

func logicalKind(sourceType findings.SourceType) string {
	switch sourceType {
	case findings.SourceTypeEnv:
		return "environmentVariable"
	case findings.SourceTypeLabel:
		return "label"
	case findings.SourceTypeHistory:
		return "historyEntry"
	case findings.SourceTypeConfig:
		return "configField"
	default:
		return "metadata"
	}
}

func findingProperties(item findings.Finding) map[string]any {
	properties := map[string]any{
		"detector_name":          item.DetectorName,
		"confidence":             item.Confidence,
		"source_type":            string(item.SourceType),
		"disposition":            string(item.Disposition),
		"manifest_digest":        item.ManifestDigest,
		"present_in_final_image": item.PresentInFinalImage,
		"match_start":            item.MatchStart,
		"match_end":              item.MatchEnd,
	}
	if item.DispositionReason != "" {
		properties["disposition_reason"] = string(item.DispositionReason)
	}
	if platform := item.Platform.String(); platform != "" {
		properties["platform"] = platform
	}
	if item.LayerDigest != "" {
		properties["layer_digest"] = item.LayerDigest
	}
	if item.FilePath != "" {
		properties["file_path"] = item.FilePath
	}
	if item.Key != "" {
		properties["key"] = item.Key
	}
	if item.LineNumber > 0 {
		properties["line_number"] = item.LineNumber
	}
	return properties
}

func runProperties(result jobs.Result) map[string]any {
	properties := map[string]any{
		"result_schema_version":     result.ResultSchemaVersion,
		"status":                    string(result.Status),
		"mode":                      result.Mode,
		"requested_reference":       result.RequestedReference,
		"repository":                result.Repository,
		"target_count":              result.TargetCount,
		"completed_target_count":    result.CompletedTargetCount,
		"failed_target_count":       result.FailedTargetCount,
		"partial_target_count":      result.PartialTargetCount,
		"manifest_count":            result.ManifestCount,
		"completed_manifest_count":  result.CompletedManifestCount,
		"failed_manifest_count":     result.FailedManifestCount,
		"total_findings":            result.TotalFindings,
		"unique_fingerprints":       result.UniqueFingerprints,
		"suppressed_findings_count": result.SuppressedFindingsCount,
		"coverage":                  result.Coverage,
	}
	if result.ResolvedReference != "" {
		properties["resolved_reference"] = result.ResolvedReference
	}
	if result.RequestedDigest != "" {
		properties["requested_digest"] = result.RequestedDigest
	}
	if len(result.Diagnostics) > 0 {
		properties["diagnostics"] = result.Diagnostics
	}
	return properties
}

// ArtifactURI renders an image file path as a URI reference relative to the
// image root: leading slashes are dropped, reserved characters are
// percent-encoded, and a first segment containing ":" is prefixed with "./"
// so it cannot be mistaken for a scheme.
func ArtifactURI(path string) string {
	trimmed := strings.TrimLeft(path, "/")
	if trimmed == "" {
		trimmed = "."
	}
	escaped := (&url.URL{Path: trimmed}).EscapedPath()
	first, _, _ := strings.Cut(escaped, "/")
	if strings.Contains(first, ":") {
		escaped = "./" + escaped
	}
	return escaped
}

func imageBaseURI(reference string) string {
	host, rest, found := strings.Cut(reference, "/")
	base := &url.URL{Scheme: "oci", Host: host, Path: "/"}
	if found {
		base.Path = "/" + rest + "/"
	}
	return base.String()
}

func semanticVersion(version string) string {
	trimmed := strings.TrimPrefix(strings.TrimSpace(version), "v")
	if semanticVersionPattern.MatchString(trimmed) {
		return trimmed
	}
	return ""
}
