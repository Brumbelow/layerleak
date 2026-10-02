package storage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"

	"github.com/brumbelow/layerleak/v3/internal/findings"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
)

// escapedControlCharacterPattern matches the JSON escapes encoding/json emits
// for U+0000..U+001F. Raw control bytes cannot appear inside a valid JSON
// string, so a text match is sufficient to decide whether the (comparatively
// expensive) decode, sanitise and re-encode walk is needed at all.
var escapedControlCharacterPattern = regexp.MustCompile(`\\u00[01][0-9a-fA-F]`)

// sanitizeScanRecord is the storage-boundary guard behind the shared
// findings.SanitizeControlCharacters policy. The findings layer already
// sanitises public provenance at the source; this guard makes sure a control
// character that reached the store by any other route (raw material, tag or
// manifest errors, the stored result snapshot) is replaced instead of making
// PostgreSQL reject the whole SaveScan transaction. Fingerprints are
// identities and are never rewritten.
func sanitizeScanRecord(record ScanRecord) (ScanRecord, error) {
	clean := findings.SanitizeControlCharacters

	record.Registry = clean(record.Registry)
	record.Repository = clean(record.Repository)
	record.RequestedReference = clean(record.RequestedReference)
	record.ResolvedReference = clean(record.ResolvedReference)
	record.RequestedDigest = clean(record.RequestedDigest)
	record.Mode = clean(record.Mode)
	record.ErrorMessage = clean(record.ErrorMessage)

	record.Tags = sanitizeTagRecords(record.Tags)
	record.Targets = sanitizeTargetRecords(record.Targets)
	record.DetailedFindings = sanitizeDetailedFindings(record.DetailedFindings)

	resultJSON, err := sanitizeResultJSON(record.ResultJSON)
	if err != nil {
		return ScanRecord{}, err
	}
	record.ResultJSON = resultJSON

	return record, nil
}

// sanitizeTagRecords returns a sanitised copy; the caller's slice is not
// modified.
func sanitizeTagRecords(tags []TagRecord) []TagRecord {
	clean := findings.SanitizeControlCharacters
	tags = slices.Clone(tags)
	for index := range tags {
		tag := &tags[index]
		tag.Name = clean(tag.Name)
		tag.RootDigest = clean(tag.RootDigest)
		tag.ManifestDigest = clean(tag.ManifestDigest)
		tag.Platform = sanitizePlatform(tag.Platform)
		tag.Status = clean(tag.Status)
		tag.Error = clean(tag.Error)
	}
	return tags
}

// sanitizeTargetRecords returns a sanitised copy, cloning each target's tag
// and manifest slices too; the caller's slices are not modified.
func sanitizeTargetRecords(targets []TargetRecord) []TargetRecord {
	clean := findings.SanitizeControlCharacters
	targets = slices.Clone(targets)
	for targetIndex := range targets {
		target := &targets[targetIndex]
		target.Reference = clean(target.Reference)
		target.ResolvedReference = clean(target.ResolvedReference)
		target.RequestedDigest = clean(target.RequestedDigest)
		target.Error = clean(target.Error)
		target.Tags = slices.Clone(target.Tags)
		for index := range target.Tags {
			target.Tags[index] = clean(target.Tags[index])
		}
		target.Manifests = sanitizeManifestRecords(target.Manifests)
	}
	return targets
}

func sanitizeManifestRecords(manifests []ManifestRecord) []ManifestRecord {
	clean := findings.SanitizeControlCharacters
	manifests = slices.Clone(manifests)
	for index := range manifests {
		item := &manifests[index]
		item.Digest = clean(item.Digest)
		item.RootDigest = clean(item.RootDigest)
		item.Platform = sanitizePlatform(item.Platform)
		item.Status = clean(item.Status)
		item.Error = clean(item.Error)
	}
	return manifests
}

// sanitizeDetailedFindings returns a sanitised copy of every text field;
// fingerprints are identities and are left untouched.
func sanitizeDetailedFindings(items []findings.DetailedFinding) []findings.DetailedFinding {
	clean := findings.SanitizeControlCharacters
	items = slices.Clone(items)
	for index := range items {
		item := &items[index]
		item.DetectorName = clean(item.DetectorName)
		item.Confidence = clean(item.Confidence)
		item.Disposition = findings.Disposition(clean(string(item.Disposition)))
		item.DispositionReason = findings.DispositionReason(clean(string(item.DispositionReason)))
		item.SourceType = findings.SourceType(clean(string(item.SourceType)))
		item.ManifestDigest = clean(item.ManifestDigest)
		item.Platform = sanitizePlatform(item.Platform)
		item.FilePath = clean(item.FilePath)
		item.LayerDigest = clean(item.LayerDigest)
		item.Key = clean(item.Key)
		item.RedactedValue = clean(item.RedactedValue)
		item.ContextSnippet = clean(item.ContextSnippet)
		item.Value = clean(item.Value)
		item.RawSnippet = clean(item.RawSnippet)
		item.SourceLocation = clean(item.SourceLocation)
	}
	return items
}

func sanitizePlatform(platform manifest.Platform) manifest.Platform {
	return manifest.Platform{
		OS:           findings.SanitizeControlCharacters(platform.OS),
		Architecture: findings.SanitizeControlCharacters(platform.Architecture),
		Variant:      findings.SanitizeControlCharacters(platform.Variant),
	}
}

// sanitizeResultJSON rewrites every string (values and object keys) of an
// already-valid JSON document through findings.SanitizeControlCharacters. It
// returns the input untouched when no escaped control character is present,
// and never pattern-replaces inside the encoded text: the document is decoded,
// walked and re-encoded so escapes and structure stay intact.
func sanitizeResultJSON(body json.RawMessage) (json.RawMessage, error) {
	if len(body) == 0 || !escapedControlCharacterPattern.Match(body) {
		return body, nil
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("decode scan record result json: %w", err)
	}

	encoded, err := json.Marshal(sanitizeJSONValue(value))
	if err != nil {
		return nil, fmt.Errorf("encode sanitized scan record result json: %w", err)
	}
	return json.RawMessage(encoded), nil
}

func sanitizeJSONValue(value any) any {
	switch typed := value.(type) {
	case string:
		return findings.SanitizeControlCharacters(typed)
	case []any:
		for index := range typed {
			typed[index] = sanitizeJSONValue(typed[index])
		}
		return typed
	case map[string]any:
		sanitized := make(map[string]any, len(typed))
		for key, child := range typed {
			sanitized[findings.SanitizeControlCharacters(key)] = sanitizeJSONValue(child)
		}
		return sanitized
	default:
		return value
	}
}
