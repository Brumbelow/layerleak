package jobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/detectors"
	"github.com/brumbelow/layerleak/v3/internal/findings"
	"github.com/brumbelow/layerleak/v3/internal/limits"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
	"github.com/brumbelow/layerleak/v3/internal/registry"
	"github.com/brumbelow/layerleak/v3/internal/scanner"
	"github.com/brumbelow/layerleak/v3/internal/version"
)

// ResultSchemaVersion is the result_schema_version every Result reports.
// Version 2 (3.0.0) added scanned_at and scanner, typed tag statuses, always
// present counters and omitted empty platforms.
const ResultSchemaVersion = 2

// ScannerName is the scanner.name every Result reports.
const ScannerName = "layerleak"

type Request struct {
	Reference manifest.Reference
	Platform  string
	Registry  *registry.Client
	Detectors detectors.Set
	Logger    *slog.Logger
	// ScannerVersion is reported as scanner.version; empty means the build
	// version of this binary.
	ScannerVersion string
	// Now supplies scanned_at; nil means time.Now.
	Now                  func() time.Time
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
	TargetsPartial        int
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

// ScannerInfo identifies the scanner build that produced a Result.
type ScannerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Result struct {
	ResultSchemaVersion          int                        `json:"result_schema_version"`
	ScannedAt                    time.Time                  `json:"scanned_at"`
	Scanner                      ScannerInfo                `json:"scanner"`
	Status                       ResultStatus               `json:"status"`
	RequestedReference           string                     `json:"requested_reference"`
	Repository                   string                     `json:"repository"`
	Mode                         string                     `json:"mode"`
	ResolvedReference            string                     `json:"resolved_reference,omitempty"`
	RequestedDigest              string                     `json:"requested_digest,omitempty"`
	TagsEnumerated               int                        `json:"tags_enumerated"`
	TagsResolved                 int                        `json:"tags_resolved"`
	TagsFailed                   int                        `json:"tags_failed"`
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
	SuppressedFindingsCount      int                        `json:"suppressed_findings_count"`
	SuppressedUniqueFingerprints int                        `json:"suppressed_unique_fingerprints"`
	Coverage                     scanner.Coverage           `json:"coverage"`
	Diagnostics                  []scanner.Diagnostic       `json:"diagnostics,omitempty"`
}

// TagStatus is the outcome of one tag in tag_results. Both scan modes use the
// same vocabulary.
type TagStatus string

const (
	// TagStatusResolved: the tag resolved to a digest that has not been scanned
	// yet. It only appears in results of sweeps that stopped before the target.
	TagStatusResolved TagStatus = "resolved"
	// TagStatusScanned: every selected manifest of the tag's target completed.
	TagStatusScanned TagStatus = "scanned"
	// TagStatusPartial: the tag's target completed some but not all manifests.
	TagStatusPartial TagStatus = "partial"
	// TagStatusFailed: the tag could not be resolved or its target failed.
	TagStatusFailed TagStatus = "failed"
	// TagStatusSkipped: the sweep stopped before the tag's target was scanned.
	TagStatusSkipped TagStatus = "skipped"
)

type TagResult struct {
	Tag             string    `json:"tag"`
	RootDigest      string    `json:"root_digest,omitempty"`
	TargetReference string    `json:"target_reference,omitempty"`
	Status          TagStatus `json:"status"`
	Error           string    `json:"error,omitempty"`
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

// newResult starts a Result with the schema version, timestamp and scanner
// identity every result carries.
func newResult(request Request, mode string) Result {
	now := time.Now
	if request.Now != nil {
		now = request.Now
	}
	scannerVersion := strings.TrimSpace(request.ScannerVersion)
	if scannerVersion == "" {
		scannerVersion = version.Effective()
	}
	return Result{
		ResultSchemaVersion: ResultSchemaVersion,
		ScannedAt:           now().UTC().Truncate(time.Second),
		Scanner:             ScannerInfo{Name: ScannerName, Version: scannerVersion},
		RequestedReference:  request.Reference.Original,
		Repository:          request.Reference.Repository,
		Mode:                mode,
	}
}

func scanSingleReference(ctx context.Context, request Request) (Result, error) {
	// scanned_at is the scan start, so the result is created before the
	// target is scanned, exactly as scanRepository does.
	result := newResult(request, "reference")
	tags := scannedTags(request.Reference)
	scanResult, err := scanTarget(ctx, request, request.Reference, tags, progressState{
		targetsTotal:   1,
		currentTag:     firstTag(tags),
		currentRef:     request.Reference.CanonicalString(""),
		findingsBefore: 0,
	})
	result.ResolvedReference = scanResult.ResolvedReference
	result.RequestedDigest = scanResult.RequestedDigest
	result.TargetCount = 1
	result.ManifestCount = scanResult.ManifestCount
	result.CompletedManifestCount = scanResult.CompletedManifestCount
	result.FailedManifestCount = scanResult.FailedManifestCount
	result.Targets = []TargetResult{targetResultFromScanResult(request.Reference, scanResult, tags)}
	result.Findings = scanResult.Findings
	result.DetailedFindings = scanResult.DetailedFindings
	result.SuppressedFindings = scanResult.SuppressedFindings
	result.SuppressedDetailedFindings = scanResult.SuppressedDetailedFindings
	result.TotalFindings = scanResult.TotalFindings
	result.UniqueFingerprints = scanResult.UniqueFingerprints
	result.SuppressedFindingsCount = scanResult.SuppressedFindingsCount
	result.SuppressedUniqueFingerprints = scanResult.SuppressedUniqueFingerprints
	result.Coverage = scanResult.Coverage
	result.Diagnostics = slices.Clone(scanResult.Diagnostics)

	tagStatus := TagStatusFailed
	switch {
	case err == nil && scanResult.Status == scanner.ResultStatusCompleted:
		result.CompletedTargetCount = 1
		tagStatus = TagStatusScanned
	case scanResult.CompletedManifestCount > 0:
		result.PartialTargetCount = 1
		tagStatus = TagStatusPartial
	default:
		result.FailedTargetCount = 1
	}
	// Reference mode never enumerates tags (tags_enumerated stays 0), but the
	// requested tag is reported in tag_results whenever it resolved to a digest.
	if len(tags) > 0 && strings.TrimSpace(scanResult.RequestedDigest) != "" {
		tagResult := TagResult{
			Tag:             tags[0],
			RootDigest:      scanResult.RequestedDigest,
			TargetReference: scanResult.ResolvedReference,
			Status:          tagStatus,
		}
		if err != nil {
			tagResult.Error = err.Error()
		}
		result.TagResults = []TagResult{tagResult}
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

	emitProgress(request, progressFromResult(request, result, ProgressPhaseCompleted, "Scan complete", "", ""))

	if result.Status != ResultStatusCompleted {
		return result, newIncompleteError(result, nil)
	}
	return result, nil
}

// progressFromResult builds a progress update whose counters mirror the
// result so far. Tag counters report resolved tags as completed and failed
// tags separately; target counters include partial targets.
func progressFromResult(request Request, result Result, phase ProgressPhase, message, currentTag, currentReference string) ProgressUpdate {
	return ProgressUpdate{
		Phase:            phase,
		Repository:       request.Reference.Repository,
		TagsCompleted:    result.TagsResolved,
		TagsTotal:        result.TagsEnumerated,
		TagsFailed:       result.TagsFailed,
		TargetsCompleted: result.CompletedTargetCount,
		TargetsPartial:   result.PartialTargetCount,
		TargetsFailed:    result.FailedTargetCount,
		TargetsTotal:     result.TargetCount,
		FindingsFound:    result.TotalFindings,
		CurrentTag:       currentTag,
		CurrentReference: currentReference,
		Message:          message,
	}
}

func scanRepository(ctx context.Context, request Request) (Result, error) {
	result := newResult(request, "repository")
	result.ResolvedReference = request.Reference.RepositoryString()
	result.TagResults = make([]TagResult, 0)
	result.Targets = make([]TargetResult, 0)
	result.Coverage = scanner.Coverage{Complete: true}

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
		emitProgress(request, progressFromResult(request, result, ProgressPhaseResolvingTags, "Resolving tag digest", tag, ""))

		resolved, err := request.Registry.ResolveManifest(ctx, request.Reference.Repository, tag)
		if err != nil {
			result.TagsFailed++
			result.TagResults = append(result.TagResults, TagResult{
				Tag:    tag,
				Status: TagStatusFailed,
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
				Status: TagStatusFailed,
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
			Status:          TagStatusResolved,
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
	// stopEarly records every target the sweep did not reach so the per-target
	// accounting and tag_results describe the whole repository, then finalizes.
	stopEarly := func(from int, cause error) {
		markUnscannedTargets(&result, request, groupList[from:], cause)
		finalizeResult(&result, allDetailedFindings, allSuppressedDetailedFindings)
	}
	for index, group := range groupList {
		findingsRetained := len(allDetailedFindings) + len(allSuppressedDetailedFindings)
		rawBytesRetained := detailedRawBytes(allDetailedFindings) + detailedRawBytes(allSuppressedDetailedFindings)
		if request.MaxFindings > 0 && findingsRetained >= request.MaxFindings {
			diagnostic := maxFindingsDiagnostic(request.MaxFindings, findingsRetained, group.digest)
			result.Diagnostics = append(result.Diagnostics, diagnostic)
			result.Coverage.Complete = false
			stopEarly(index, errors.New(diagnostic.Message))
			return result, newIncompleteError(result, nil)
		}
		scanReference := request.Reference.WithDigest(group.digest)
		scanResult, err := scanTarget(ctx, request, scanReference, group.tags, progressState{
			tagsCompleted:    result.TagsResolved,
			tagsTotal:        result.TagsEnumerated,
			tagsFailed:       result.TagsFailed,
			targetsCompleted: result.CompletedTargetCount,
			targetsPartial:   result.PartialTargetCount,
			targetsFailed:    result.FailedTargetCount,
			targetsTotal:     result.TargetCount,
			currentTag:       firstTag(group.tags),
			currentRef:       scanReference.CanonicalString(""),
			findingsBefore:   len(allDetailedFindings),
			findingsRetained: findingsRetained,
			rawBytesRetained: rawBytesRetained,
		})
		targetResult := targetResultFromScanResult(scanReference, scanResult, group.tags)
		result.ManifestCount += scanResult.ManifestCount
		result.CompletedManifestCount += scanResult.CompletedManifestCount
		result.FailedManifestCount += scanResult.FailedManifestCount
		allDetailedFindings = append(allDetailedFindings, scanResult.DetailedFindings...)
		allSuppressedDetailedFindings = append(allSuppressedDetailedFindings, scanResult.SuppressedDetailedFindings...)
		result.Coverage = mergeCoverage(result.Coverage, scanResult.Coverage)
		result.Diagnostics = append(result.Diagnostics, scanResult.Diagnostics...)
		if err != nil {
			targetResult.Error = err.Error()
			result.Targets = append(result.Targets, targetResult)
			tagStatus := TagStatusFailed
			if scanResult.CompletedManifestCount > 0 {
				result.PartialTargetCount++
				tagStatus = TagStatusPartial
			} else {
				result.FailedTargetCount++
			}
			setTagStatus(&result, group.tags, tagStatus, err.Error())
			result.TotalFindings = len(allDetailedFindings)
			emitProgress(request, progressFromResult(request, result, ProgressPhaseTargetFailed, err.Error(), firstTag(group.tags), scanReference.CanonicalString("")))
			if limits.IsExceeded(err) || mustPreserveScanError(err) {
				stopEarly(index+1, err)
				return result, err
			}
			continue
		}

		result.Targets = append(result.Targets, targetResult)
		if scanResult.Status == scanner.ResultStatusPartial {
			result.PartialTargetCount++
			setTagStatus(&result, group.tags, TagStatusPartial, "")
		} else {
			result.CompletedTargetCount++
			setTagStatus(&result, group.tags, TagStatusScanned, "")
		}
		if hasDiagnosticCode(scanResult.Diagnostics, "max_findings_exceeded") {
			stopEarly(index+1, errors.New("scan reached the max findings limit"))
			return result, newIncompleteError(result, nil)
		}
		result.TotalFindings = len(allDetailedFindings)
		emitProgress(request, progressFromResult(request, result, ProgressPhaseTargetDone, "Target scan complete", firstTag(group.tags), scanResult.ResolvedReference))
	}

	finalizeResult(&result, allDetailedFindings, allSuppressedDetailedFindings)
	if result.CompletedTargetCount+result.PartialTargetCount == 0 {
		return result, allRepositoryTargetsFailedError(result.Targets)
	}
	emitProgress(request, progressFromResult(request, result, ProgressPhaseCompleted, "Repository scan complete", "", ""))

	if result.Status != ResultStatusCompleted {
		return result, newIncompleteError(result, nil)
	}
	return result, nil
}

// setTagStatus records the outcome of a target on every tag that resolved to
// it. An empty message keeps the tag's existing error text.
func setTagStatus(result *Result, tags []string, status TagStatus, message string) {
	for index := range result.TagResults {
		if !slices.Contains(tags, result.TagResults[index].Tag) {
			continue
		}
		result.TagResults[index].Status = status
		if message != "" {
			result.TagResults[index].Error = message
		}
	}
}

// markUnscannedTargets appends a failed TargetResult for every target a sweep
// stopped before reaching and marks their tags skipped, so target_count always
// equals completed + partial + failed and no tag stays "resolved".
func markUnscannedTargets(result *Result, request Request, remaining []targetGroup, cause error) {
	reason := "not scanned: the sweep stopped before this target"
	if cause != nil && strings.TrimSpace(cause.Error()) != "" {
		reason += ": " + cause.Error()
	}
	for _, group := range remaining {
		reference := request.Reference.WithDigest(group.digest)
		result.Targets = append(result.Targets, TargetResult{
			Status:          ResultStatusFailed,
			Reference:       reference.CanonicalString(""),
			Tags:            slices.Clone(group.tags),
			RequestedDigest: group.digest,
			Error:           reason,
		})
		result.FailedTargetCount++
		setTagStatus(result, group.tags, TagStatusSkipped, reason)
	}
	if len(remaining) > 0 {
		result.Coverage.Complete = false
	}
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
	targetsPartial   int
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
			// The scanner's own completion is reported by the jobs layer as one
			// target_done (or completed) update, so it is not forwarded twice.
			if update.Phase == scanner.ProgressPhaseCompleted {
				return
			}
			emitProgress(request, ProgressUpdate{
				Phase:                 mapScannerPhase(update.Phase),
				Repository:            request.Reference.Repository,
				TagsCompleted:         state.tagsCompleted,
				TagsTotal:             state.tagsTotal,
				TagsFailed:            state.tagsFailed,
				TargetsCompleted:      state.targetsCompleted,
				TargetsPartial:        state.targetsPartial,
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

// mapScannerPhase keeps per-manifest scanner events in the scanning phase: a
// failed manifest does not mean the target failed (it may finish partial), and
// the jobs layer reports the target outcome itself.
func mapScannerPhase(scanner.ProgressPhase) ProgressPhase {
	return ProgressPhaseScanning
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
		FilesTranscodedUTF16:      left.FilesTranscodedUTF16 + right.FilesTranscodedUTF16,
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
	// An unsupported manifest (foreign or non-distributable layers) or a
	// platform selector that matched nothing is a per-target coverage outcome:
	// the sweep records it and moves on to the next target.
	if scanner.IsUnsupportedManifest(err) || scanner.IsPlatformNotFound(err) {
		return false
	}
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
