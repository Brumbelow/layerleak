package jobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/brumbelow/layerleak/internal/detectors"
	"github.com/brumbelow/layerleak/internal/findings"
	"github.com/brumbelow/layerleak/internal/limits"
	"github.com/brumbelow/layerleak/internal/manifest"
	"github.com/brumbelow/layerleak/internal/registry"
	"github.com/brumbelow/layerleak/internal/scanner"
)

type Request struct {
	Reference            manifest.Reference
	Platform             string
	Registry             *registry.Client
	Detectors            detectors.Set
	Logger               *slog.Logger
	MaxFileBytes         int64
	MaxLayerBytes        int64
	MaxLayerEntries      int
	MaxConfigBytes       int64
	MaxImageLayers       int
	MaxImageManifests    int
	MaxImageLayerBytes   int64
	MaxImageArtifacts    int
	MaxRetainedBytes     int64
	MaxFindings          int
	RetainRawSecrets     bool
	MaxRawFindingBytes   int64
	ConfigTimeout        time.Duration
	BlobTimeout          time.Duration
	TagPageSize          int
	MaxRepositoryTags    int
	MaxRepositoryTargets int
	AllTags              bool
	Progress             ProgressFunc
}

type ResultStatus string

const (
	ResultStatusCompleted ResultStatus = "completed"
	ResultStatusPartial   ResultStatus = "partial"
	ResultStatusFailed    ResultStatus = "failed"
)

// IncompleteError reports a scan that produced a usable result without
// covering every requested target. Callers may opt in to accepting this
// result, but incomplete coverage is an error by default.
type IncompleteError struct {
	Status                 ResultStatus
	CompletedManifestCount int
	FailedManifestCount    int
	Cause                  error
}

func (e *IncompleteError) Error() string {
	if e == nil {
		return ""
	}
	message := fmt.Sprintf(
		"scan coverage is %s: %d manifest(s) completed, %d failed",
		e.Status,
		e.CompletedManifestCount,
		e.FailedManifestCount,
	)
	if e.Cause != nil {
		message += ": " + e.Cause.Error()
	}
	return message
}

func (e *IncompleteError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func IsIncomplete(err error) bool {
	var target *IncompleteError
	return errors.As(err, &target)
}

type ProgressPhase string

const (
	ProgressPhaseListingTags   ProgressPhase = "listing_tags"
	ProgressPhaseResolvingTags ProgressPhase = "resolving_tags"
	ProgressPhaseScanning      ProgressPhase = "scanning"
	ProgressPhaseTargetDone    ProgressPhase = "target_done"
	ProgressPhaseTargetFailed  ProgressPhase = "target_failed"
	ProgressPhaseCompleted     ProgressPhase = "completed"
)

type ProgressUpdate struct {
	Phase                 ProgressPhase
	Repository            string
	TagsCompleted         int
	TagsTotal             int
	TagsFailed            int
	TargetsCompleted      int
	TargetsFailed         int
	TargetsTotal          int
	FindingsFound         int
	CurrentTag            string
	CurrentReference      string
	CurrentPlatform       manifest.Platform
	CurrentManifestDigest string
	Message               string
}

type ProgressFunc func(ProgressUpdate)

type Result struct {
	ResultSchemaVersion          int                        `json:"result_schema_version"`
	Status                       ResultStatus               `json:"status"`
	RequestedReference           string                     `json:"requested_reference"`
	Repository                   string                     `json:"repository"`
	Mode                         string                     `json:"mode"`
	ResolvedReference            string                     `json:"resolved_reference,omitempty"`
	RequestedDigest              string                     `json:"requested_digest,omitempty"`
	TagsEnumerated               int                        `json:"tags_enumerated,omitempty"`
	TagsResolved                 int                        `json:"tags_resolved,omitempty"`
	TagsFailed                   int                        `json:"tags_failed,omitempty"`
	TargetCount                  int                        `json:"target_count"`
	CompletedTargetCount         int                        `json:"completed_target_count"`
	FailedTargetCount            int                        `json:"failed_target_count"`
	PartialTargetCount           int                        `json:"partial_target_count"`
	ManifestCount                int                        `json:"manifest_count"`
	CompletedManifestCount       int                        `json:"completed_manifest_count"`
	FailedManifestCount          int                        `json:"failed_manifest_count"`
	TagResults                   []TagResult                `json:"tag_results,omitempty"`
	Targets                      []TargetResult             `json:"targets"`
	Findings                     []findings.Finding         `json:"findings"`
	DetailedFindings             []findings.DetailedFinding `json:"-"`
	SuppressedFindings           []findings.Finding         `json:"suppressed_findings,omitempty"`
	SuppressedDetailedFindings   []findings.DetailedFinding `json:"-"`
	TotalFindings                int                        `json:"total_findings"`
	UniqueFingerprints           int                        `json:"unique_fingerprints"`
	SuppressedFindingsCount      int                        `json:"suppressed_findings_count,omitempty"`
	SuppressedUniqueFingerprints int                        `json:"suppressed_unique_fingerprints,omitempty"`
	Coverage                     scanner.Coverage           `json:"coverage"`
	Diagnostics                  []scanner.Diagnostic       `json:"diagnostics,omitempty"`
}

type TagResult struct {
	Tag             string `json:"tag"`
	RootDigest      string `json:"root_digest,omitempty"`
	TargetReference string `json:"target_reference,omitempty"`
	Status          string `json:"status"`
	Error           string `json:"error,omitempty"`
}

type TargetResult struct {
	Status                 ResultStatus             `json:"status"`
	Reference              string                   `json:"reference"`
	Tags                   []string                 `json:"tags,omitempty"`
	ResolvedReference      string                   `json:"resolved_reference,omitempty"`
	RequestedDigest        string                   `json:"requested_digest,omitempty"`
	ManifestCount          int                      `json:"manifest_count"`
	CompletedManifestCount int                      `json:"completed_manifest_count"`
	FailedManifestCount    int                      `json:"failed_manifest_count"`
	PlatformResults        []scanner.PlatformResult `json:"platform_results,omitempty"`
	FindingsCount          int                      `json:"findings_count"`
	Error                  string                   `json:"error,omitempty"`
}

type targetGroup struct {
	digest string
	tags   []string
}

func Scan(ctx context.Context, request Request) (Result, error) {
	if request.Registry == nil {
		return Result{}, fmt.Errorf("registry client is required")
	}
	if request.AllTags {
		if !request.Reference.IsRepositoryOnly() {
			return Result{}, fmt.Errorf("--all-tags requires a bare repository reference")
		}
		return scanRepository(ctx, request)
	}
	return scanSingleReference(ctx, request)
}

func scanSingleReference(ctx context.Context, request Request) (Result, error) {
	tags := scannedTags(request.Reference)
	scanResult, err := scanTarget(ctx, request, request.Reference, tags, progressState{
		tagsCompleted:  len(tags),
		tagsTotal:      len(tags),
		targetsTotal:   1,
		currentTag:     firstTag(tags),
		currentRef:     request.Reference.CanonicalString(""),
		findingsBefore: 0,
	})
	result := Result{
		ResultSchemaVersion:    1,
		RequestedReference:     request.Reference.Original,
		Repository:             request.Reference.Repository,
		Mode:                   "reference",
		ResolvedReference:      scanResult.ResolvedReference,
		RequestedDigest:        scanResult.RequestedDigest,
		TagsEnumerated:         len(tags),
		TagsResolved:           len(tags),
		TargetCount:            1,
		ManifestCount:          scanResult.ManifestCount,
		CompletedManifestCount: scanResult.CompletedManifestCount,
		FailedManifestCount:    scanResult.FailedManifestCount,
		Targets: []TargetResult{
			targetResultFromScanResult(request.Reference, scanResult, tags),
		},
		Findings:                     scanResult.Findings,
		DetailedFindings:             scanResult.DetailedFindings,
		SuppressedFindings:           scanResult.SuppressedFindings,
		SuppressedDetailedFindings:   scanResult.SuppressedDetailedFindings,
		TotalFindings:                scanResult.TotalFindings,
		UniqueFingerprints:           scanResult.UniqueFingerprints,
		SuppressedFindingsCount:      scanResult.SuppressedFindingsCount,
		SuppressedUniqueFingerprints: scanResult.SuppressedUniqueFingerprints,
		Coverage:                     scanResult.Coverage,
		Diagnostics:                  slices.Clone(scanResult.Diagnostics),
	}
	if err == nil && scanResult.Status == scanner.ResultStatusCompleted {
		result.CompletedTargetCount = 1
	} else if scanResult.CompletedManifestCount > 0 {
		result.PartialTargetCount = 1
	} else {
		result.FailedTargetCount = 1
	}
	if len(tags) > 0 && err == nil {
		result.TagResults = []TagResult{{
			Tag:             tags[0],
			RootDigest:      scanResult.RequestedDigest,
			TargetReference: scanResult.ResolvedReference,
			Status:          "scanned",
		}}
	}
	if err != nil {
		result.Targets[0].Error = err.Error()
		finalizeResult(&result, result.DetailedFindings, result.SuppressedDetailedFindings)
		if hasCompletedManifest(result) && !mustPreserveScanError(err) && !limits.IsExceeded(err) {
			return result, newIncompleteError(result, err)
		}
		return result, err
	}
	finalizeResult(&result, result.DetailedFindings, result.SuppressedDetailedFindings)

	emitProgress(request, ProgressUpdate{
		Phase:            ProgressPhaseCompleted,
		Repository:       request.Reference.Repository,
		TagsCompleted:    result.TagsResolved,
		TagsTotal:        result.TagsEnumerated,
		TargetsCompleted: result.CompletedTargetCount,
		TargetsTotal:     result.TargetCount,
		FindingsFound:    result.TotalFindings,
		Message:          "Scan complete",
	})

	if result.Status != ResultStatusCompleted {
		return result, newIncompleteError(result, nil)
	}
	return result, nil
}

func scanRepository(ctx context.Context, request Request) (Result, error) {
	result := Result{
		ResultSchemaVersion: 1,
		RequestedReference:  request.Reference.Original,
		Repository:          request.Reference.Repository,
		Mode:                "repository",
		ResolvedReference:   request.Reference.RepositoryString(),
		TagResults:          make([]TagResult, 0),
		Targets:             make([]TargetResult, 0),
		Coverage:            scanner.Coverage{Complete: true},
	}

	emitProgress(request, ProgressUpdate{
		Phase:      ProgressPhaseListingTags,
		Repository: request.Reference.Repository,
		Message:    "Listing repository tags",
	})

	tags, err := request.Registry.ListTags(ctx, request.Reference.Repository, request.TagPageSize, request.MaxRepositoryTags)
	result.TagsEnumerated = len(tags)
	if err != nil {
		finalizeResult(&result, nil, nil)
		return result, err
	}

	groups := make(map[string]*targetGroup)
	for _, tag := range tags {
		emitProgress(request, ProgressUpdate{
			Phase:         ProgressPhaseResolvingTags,
			Repository:    request.Reference.Repository,
			TagsCompleted: result.TagsResolved + result.TagsFailed,
			TagsTotal:     result.TagsEnumerated,
			TagsFailed:    result.TagsFailed,
			CurrentTag:    tag,
			Message:       "Resolving tag digest",
		})

		resolved, err := request.Registry.ResolveManifest(ctx, request.Reference.Repository, tag)
		if err != nil {
			result.TagsFailed++
			result.TagResults = append(result.TagResults, TagResult{
				Tag:    tag,
				Status: "failed",
				Error:  err.Error(),
			})
			if mustPreserveScanError(err) || limits.IsExceeded(err) {
				finalizeResult(&result, nil, nil)
				return result, err
			}
			continue
		}
		if strings.TrimSpace(resolved.Digest) == "" {
			result.TagsFailed++
			result.TagResults = append(result.TagResults, TagResult{
				Tag:    tag,
				Status: "failed",
				Error:  "resolved digest is empty",
			})
			continue
		}

		result.TagsResolved++
		targetReference := request.Reference.WithDigest(resolved.Digest).CanonicalString("")
		result.TagResults = append(result.TagResults, TagResult{
			Tag:             tag,
			RootDigest:      resolved.Digest,
			TargetReference: targetReference,
			Status:          "resolved",
		})

		group, ok := groups[resolved.Digest]
		if !ok {
			group = &targetGroup{digest: resolved.Digest}
			groups[resolved.Digest] = group
		}
		group.tags = append(group.tags, tag)
	}

	if len(groups) == 0 {
		finalizeResult(&result, nil, nil)
		return result, fmt.Errorf("repository %s did not resolve any scannable tags", request.Reference.Repository)
	}

	groupList := make([]targetGroup, 0, len(groups))
	for _, group := range groups {
		slices.Sort(group.tags)
		groupList = append(groupList, *group)
	}
	slices.SortFunc(groupList, func(left, right targetGroup) int {
		return strings.Compare(firstTag(left.tags), firstTag(right.tags))
	})

	result.TargetCount = len(groupList)
	if request.MaxRepositoryTargets > 0 && len(groupList) > request.MaxRepositoryTargets {
		finalizeResult(&result, nil, nil)
		return result, limits.NewExceeded(limits.KindRepositoryTargets, int64(request.MaxRepositoryTargets), "repository "+request.Reference.Repository)
	}

	allDetailedFindings := make([]findings.DetailedFinding, 0)
	allSuppressedDetailedFindings := make([]findings.DetailedFinding, 0)
	for _, group := range groupList {
		findingsRetained := len(allDetailedFindings) + len(allSuppressedDetailedFindings)
		rawBytesRetained := detailedRawBytes(allDetailedFindings) + detailedRawBytes(allSuppressedDetailedFindings)
		if request.MaxFindings > 0 && findingsRetained >= request.MaxFindings {
			result.Diagnostics = append(result.Diagnostics, maxFindingsDiagnostic(request.MaxFindings, findingsRetained, group.digest))
			result.Coverage.Complete = false
			finalizeResult(&result, allDetailedFindings, allSuppressedDetailedFindings)
			return result, newIncompleteError(result, nil)
		}
		scanReference := request.Reference.WithDigest(group.digest)
		scanResult, err := scanTarget(ctx, request, scanReference, group.tags, progressState{
			tagsCompleted:    result.TagsResolved,
			tagsTotal:        result.TagsEnumerated,
			tagsFailed:       result.TagsFailed,
			targetsCompleted: result.CompletedTargetCount,
			targetsFailed:    result.FailedTargetCount,
			targetsTotal:     result.TargetCount,
			currentTag:       firstTag(group.tags),
			currentRef:       scanReference.CanonicalString(""),
			findingsBefore:   len(allDetailedFindings),
			findingsRetained: findingsRetained,
			rawBytesRetained: rawBytesRetained,
		})
		targetResult := targetResultFromScanResult(scanReference, scanResult, group.tags)
		if err != nil {
			targetResult.Error = err.Error()
			result.Targets = append(result.Targets, targetResult)
			if scanResult.CompletedManifestCount > 0 {
				result.PartialTargetCount++
			} else {
				result.FailedTargetCount++
			}
			result.ManifestCount += scanResult.ManifestCount
			result.CompletedManifestCount += scanResult.CompletedManifestCount
			result.FailedManifestCount += scanResult.FailedManifestCount
			allDetailedFindings = append(allDetailedFindings, scanResult.DetailedFindings...)
			allSuppressedDetailedFindings = append(allSuppressedDetailedFindings, scanResult.SuppressedDetailedFindings...)
			result.Coverage = mergeCoverage(result.Coverage, scanResult.Coverage)
			result.Diagnostics = append(result.Diagnostics, scanResult.Diagnostics...)
			emitProgress(request, ProgressUpdate{
				Phase:            ProgressPhaseTargetFailed,
				Repository:       request.Reference.Repository,
				TagsCompleted:    result.TagsResolved,
				TagsTotal:        result.TagsEnumerated,
				TagsFailed:       result.TagsFailed,
				TargetsCompleted: result.CompletedTargetCount,
				TargetsFailed:    result.FailedTargetCount,
				TargetsTotal:     result.TargetCount,
				FindingsFound:    len(allDetailedFindings),
				CurrentTag:       firstTag(group.tags),
				CurrentReference: scanReference.CanonicalString(""),
				Message:          err.Error(),
			})
			if limits.IsExceeded(err) {
				finalizeResult(&result, allDetailedFindings, allSuppressedDetailedFindings)
				return result, err
			}
			if mustPreserveScanError(err) {
				finalizeResult(&result, allDetailedFindings, allSuppressedDetailedFindings)
				return result, err
			}
			continue
		}

		result.Targets = append(result.Targets, targetResult)
		if scanResult.Status == scanner.ResultStatusPartial {
			result.PartialTargetCount++
		} else {
			result.CompletedTargetCount++
		}
		result.ManifestCount += scanResult.ManifestCount
		result.CompletedManifestCount += scanResult.CompletedManifestCount
		result.FailedManifestCount += scanResult.FailedManifestCount
		allDetailedFindings = append(allDetailedFindings, scanResult.DetailedFindings...)
		allSuppressedDetailedFindings = append(allSuppressedDetailedFindings, scanResult.SuppressedDetailedFindings...)
		result.Coverage = mergeCoverage(result.Coverage, scanResult.Coverage)
		result.Diagnostics = append(result.Diagnostics, scanResult.Diagnostics...)
		if hasDiagnosticCode(scanResult.Diagnostics, "max_findings_exceeded") || hasDiagnosticCode(scanResult.Diagnostics, "max_raw_finding_bytes_exceeded") {
			finalizeResult(&result, allDetailedFindings, allSuppressedDetailedFindings)
			return result, newIncompleteError(result, nil)
		}
		emitProgress(request, ProgressUpdate{
			Phase:            ProgressPhaseTargetDone,
			Repository:       request.Reference.Repository,
			TagsCompleted:    result.TagsResolved,
			TagsTotal:        result.TagsEnumerated,
			TagsFailed:       result.TagsFailed,
			TargetsCompleted: result.CompletedTargetCount,
			TargetsFailed:    result.FailedTargetCount,
			TargetsTotal:     result.TargetCount,
			FindingsFound:    len(allDetailedFindings),
			CurrentTag:       firstTag(group.tags),
			CurrentReference: scanResult.ResolvedReference,
			Message:          "Target scan complete",
		})
	}

	finalizeResult(&result, allDetailedFindings, allSuppressedDetailedFindings)
	if result.CompletedTargetCount+result.PartialTargetCount == 0 {
		return result, allRepositoryTargetsFailedError(result.Targets)
	}
	emitProgress(request, ProgressUpdate{
		Phase:            ProgressPhaseCompleted,
		Repository:       request.Reference.Repository,
		TagsCompleted:    result.TagsResolved,
		TagsTotal:        result.TagsEnumerated,
		TagsFailed:       result.TagsFailed,
		TargetsCompleted: result.CompletedTargetCount,
		TargetsFailed:    result.FailedTargetCount,
		TargetsTotal:     result.TargetCount,
		FindingsFound:    result.TotalFindings,
		Message:          "Repository scan complete",
	})

	if result.Status != ResultStatusCompleted {
		return result, newIncompleteError(result, nil)
	}
	return result, nil
}

func detailedRawBytes(items []findings.DetailedFinding) int64 {
	var total int64
	for _, item := range items {
		total += int64(len(item.Value)) + int64(len(item.RawSnippet))
	}
	return total
}

func hasDiagnosticCode(items []scanner.Diagnostic, code string) bool {
	for _, item := range items {
		if item.Code == code {
			return true
		}
	}
	return false
}

func maxFindingsDiagnostic(maxFindings, observed int, subject string) scanner.Diagnostic {
	return scanner.Diagnostic{
		Code:     "max_findings_exceeded",
		Scope:    "scan",
		Subject:  subject,
		Message:  fmt.Sprintf("scan reached max findings limit of %d before the next repository target", maxFindings),
		Limit:    int64(maxFindings),
		Observed: int64(observed),
	}
}

type progressState struct {
	tagsCompleted    int
	tagsTotal        int
	tagsFailed       int
	targetsCompleted int
	targetsFailed    int
	targetsTotal     int
	currentTag       string
	currentRef       string
	findingsBefore   int
	findingsRetained int
	rawBytesRetained int64
}

func scanTarget(ctx context.Context, request Request, reference manifest.Reference, tags []string, state progressState) (scanner.Result, error) {
	return scanner.Scan(ctx, scanner.Request{
		Reference:          reference,
		Platform:           request.Platform,
		Registry:           request.Registry,
		Detectors:          request.Detectors,
		Logger:             request.Logger,
		MaxFileBytes:       request.MaxFileBytes,
		MaxLayerBytes:      request.MaxLayerBytes,
		MaxLayerEntries:    request.MaxLayerEntries,
		MaxConfigBytes:     request.MaxConfigBytes,
		MaxImageLayers:     request.MaxImageLayers,
		MaxImageManifests:  request.MaxImageManifests,
		MaxImageLayerBytes: request.MaxImageLayerBytes,
		MaxImageArtifacts:  request.MaxImageArtifacts,
		MaxRetainedBytes:   request.MaxRetainedBytes,
		MaxFindings:        request.MaxFindings,
		ExistingFindings:   state.findingsRetained,
		RetainRawSecrets:   request.RetainRawSecrets,
		MaxRawFindingBytes: request.MaxRawFindingBytes,
		ExistingRawBytes:   state.rawBytesRetained,
		ConfigTimeout:      request.ConfigTimeout,
		BlobTimeout:        request.BlobTimeout,
		Progress: func(update scanner.ProgressUpdate) {
			emitProgress(request, ProgressUpdate{
				Phase:                 mapScannerPhase(update.Phase),
				Repository:            request.Reference.Repository,
				TagsCompleted:         state.tagsCompleted,
				TagsTotal:             state.tagsTotal,
				TagsFailed:            state.tagsFailed,
				TargetsCompleted:      state.targetsCompleted,
				TargetsFailed:         state.targetsFailed,
				TargetsTotal:          state.targetsTotal,
				FindingsFound:         state.findingsBefore + update.FindingsFound,
				CurrentTag:            firstTag(tags),
				CurrentReference:      defaultString(reference.CanonicalString(""), state.currentRef),
				CurrentPlatform:       update.CurrentPlatform,
				CurrentManifestDigest: update.CurrentManifestDigest,
				Message:               update.Message,
			})
		},
	})
}

func targetResultFromScanResult(reference manifest.Reference, scanResult scanner.Result, tags []string) TargetResult {
	referenceValue := scanResult.RequestedReference
	if strings.TrimSpace(referenceValue) == "" {
		referenceValue = reference.CanonicalString("")
	}
	return TargetResult{
		Status:                 mapScannerStatus(scanResult.Status),
		Reference:              referenceValue,
		Tags:                   slices.Clone(tags),
		ResolvedReference:      scanResult.ResolvedReference,
		RequestedDigest:        scanResult.RequestedDigest,
		ManifestCount:          scanResult.ManifestCount,
		CompletedManifestCount: scanResult.CompletedManifestCount,
		FailedManifestCount:    scanResult.FailedManifestCount,
		PlatformResults:        slices.Clone(scanResult.PlatformResults),
		FindingsCount:          scanResult.TotalFindings,
	}
}

func scannedTags(reference manifest.Reference) []string {
	if strings.TrimSpace(reference.Digest) != "" {
		return nil
	}
	return []string{reference.Identifier()}
}

func firstTag(tags []string) string {
	if len(tags) == 0 {
		return ""
	}
	return tags[0]
}

func mapScannerPhase(phase scanner.ProgressPhase) ProgressPhase {
	switch phase {
	case scanner.ProgressPhaseManifestFailed:
		return ProgressPhaseTargetFailed
	case scanner.ProgressPhaseCompleted:
		return ProgressPhaseTargetDone
	default:
		return ProgressPhaseScanning
	}
}

func sortTargetResults(items []TargetResult) {
	slices.SortFunc(items, func(left, right TargetResult) int {
		if value := strings.Compare(firstTag(left.Tags), firstTag(right.Tags)); value != 0 {
			return value
		}
		return strings.Compare(left.RequestedDigest, right.RequestedDigest)
	})
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return strings.TrimSpace(fallback)
	}
	return strings.TrimSpace(value)
}

func emitProgress(request Request, update ProgressUpdate) {
	if request.Progress != nil {
		request.Progress(update)
	}
}

func finalizeResult(result *Result, actionable, suppressed []findings.DetailedFinding) {
	result.DetailedFindings = findings.DeduplicateDetailed(actionable)
	result.Findings = make([]findings.Finding, 0, len(result.DetailedFindings))
	for _, item := range result.DetailedFindings {
		result.Findings = append(result.Findings, item.PublicFinding())
	}
	result.SuppressedDetailedFindings = findings.DeduplicateDetailed(suppressed)
	result.SuppressedFindings = make([]findings.Finding, 0, len(result.SuppressedDetailedFindings))
	for _, item := range result.SuppressedDetailedFindings {
		result.SuppressedFindings = append(result.SuppressedFindings, item.PublicFinding())
	}
	result.TotalFindings = len(result.Findings)
	result.UniqueFingerprints = findings.UniqueFingerprintCount(result.Findings)
	result.SuppressedFindingsCount = len(result.SuppressedFindings)
	result.SuppressedUniqueFingerprints = findings.UniqueFingerprintCount(result.SuppressedFindings)
	result.Status = resultStatus(*result)
	result.Coverage.Complete = result.Status == ResultStatusCompleted
	sortTargetResults(result.Targets)
}

func resultStatus(result Result) ResultStatus {
	if result.CompletedManifestCount == 0 {
		return ResultStatusFailed
	}
	if result.TagsFailed > 0 || result.FailedTargetCount > 0 || result.PartialTargetCount > 0 || result.FailedManifestCount > 0 || !result.Coverage.Complete {
		return ResultStatusPartial
	}
	return ResultStatusCompleted
}

func mapScannerStatus(status scanner.ResultStatus) ResultStatus {
	switch status {
	case scanner.ResultStatusCompleted:
		return ResultStatusCompleted
	case scanner.ResultStatusPartial:
		return ResultStatusPartial
	default:
		return ResultStatusFailed
	}
}

func mergeCoverage(left, right scanner.Coverage) scanner.Coverage {
	return scanner.Coverage{
		Complete:                  left.Complete && right.Complete,
		LayersSeen:                left.LayersSeen + right.LayersSeen,
		LayersCompleted:           left.LayersCompleted + right.LayersCompleted,
		FilesSeen:                 left.FilesSeen + right.FilesSeen,
		FilesScanned:              left.FilesScanned + right.FilesScanned,
		FilesSkippedOversize:      left.FilesSkippedOversize + right.FilesSkippedOversize,
		FilesExcludedBinary:       left.FilesExcludedBinary + right.FilesExcludedBinary,
		EntriesSkippedUnsafe:      left.EntriesSkippedUnsafe + right.EntriesSkippedUnsafe,
		MetadataValuesScanned:     left.MetadataValuesScanned + right.MetadataValuesScanned,
		ExpandedLayerBytes:        left.ExpandedLayerBytes + right.ExpandedLayerBytes,
		RetainedBytes:             left.RetainedBytes + right.RetainedBytes,
		DetectorInputBytesScanned: left.DetectorInputBytesScanned + right.DetectorInputBytesScanned,
	}
}

func newIncompleteError(result Result, cause error) error {
	return &IncompleteError{
		Status:                 result.Status,
		CompletedManifestCount: result.CompletedManifestCount,
		FailedManifestCount:    result.FailedManifestCount,
		Cause:                  cause,
	}
}

func hasCompletedManifest(result Result) bool {
	return result.CompletedManifestCount > 0
}

func mustPreserveScanError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || manifest.IsIntegrityError(err)
}

func allRepositoryTargetsFailedError(items []TargetResult) error {
	errors := collectTargetErrorMessages(items)
	if len(errors) == 0 {
		return fmt.Errorf("all repository targets failed")
	}
	return fmt.Errorf("all repository targets failed: %s", strings.Join(errors, "; "))
}

func collectTargetErrorMessages(items []TargetResult) []string {
	collected := make([]string, 0, len(items))
	seen := make(map[string]struct{})
	for _, item := range items {
		value := strings.TrimSpace(item.Error)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		collected = append(collected, value)
		if len(collected) == 3 {
			break
		}
	}

	return collected
}
