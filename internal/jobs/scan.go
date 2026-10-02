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
	"github.com/brumbelow/layerleak/v3/internal/layers"
	"github.com/brumbelow/layerleak/v3/internal/limits"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
	"github.com/brumbelow/layerleak/v3/internal/scanner"
	"github.com/brumbelow/layerleak/v3/internal/version"
)

// ResultSchemaVersion is the result_schema_version every Result reports.
// Version 2 (3.0.0) added scanned_at, duration_ms and scanner (with
// detector_set_version), typed tag statuses, always present counters and
// omitted empty platforms.
const ResultSchemaVersion = 2

// ScannerName is the scanner.name every Result reports.
const ScannerName = "layerleak"

type Request struct {
	Reference manifest.Reference
	Platform  string
	// Registry is the BlobSource every target of the scan is read from: a
	// *registry.Client, or a local reader for an oci:, oci-archive: or
	// docker-archive: reference.
	Registry  scanner.BlobSource
	Detectors detectors.Set
	Logger    *slog.Logger
	// ScannerVersion is reported as scanner.version; empty means the build
	// version of this binary.
	ScannerVersion string
	// Now supplies scanned_at and, read again when the scan ends,
	// duration_ms; nil means time.Now.
	Now                func() time.Time
	MaxFileBytes       int64
	MaxLayerBytes      int64
	MaxLayerEntries    int
	MaxConfigBytes     int64
	MaxImageLayers     int
	MaxImageManifests  int
	MaxImageLayerBytes int64
	MaxImageArtifacts  int
	MaxRetainedBytes   int64
	// MaxNestedArchiveBytes and MaxNestedArchiveEntries bound the one-level
	// expansion of archives stored in layers.
	MaxNestedArchiveBytes   int64
	MaxNestedArchiveEntries int
	// MaxLayerCacheBytes bounds the per-sweep layer cache of --all-tags; 0
	// disables it. Single-reference scans never use it.
	MaxLayerCacheBytes   int64
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
	// DetectorSetVersion is detectors.Set.CatalogDigest of the detector set
	// the scan ran with: sha256 over its sorted identifiers.
	DetectorSetVersion string `json:"detector_set_version"`
}

type Result struct {
	ResultSchemaVersion          int                        `json:"result_schema_version"`
	ScannedAt                    time.Time                  `json:"scanned_at"`
	DurationMS                   int64                      `json:"duration_ms"`
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
	// TagStatusSkipped: the sweep stopped before the tag's target was scanned,
	// or before the tag was resolved (the repository target bound).
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
	if request.AllTags && !request.Reference.IsRepositoryOnly() {
		return Result{}, fmt.Errorf("--all-tags requires a bare repository reference")
	}
	now := time.Now
	if request.Now != nil {
		now = request.Now
	}
	// The untruncated start keeps time.Now's monotonic reading, so
	// duration_ms is immune to wall-clock steps during the scan.
	started := now()
	var result Result
	var err error
	if request.AllTags {
		result, err = scanRepository(ctx, request, started)
	} else {
		result, err = scanSingleReference(ctx, request, started)
	}
	if result.ResultSchemaVersion > 0 {
		result.DurationMS = durationMillis(started, now())
	}
	return result, err
}

// durationMillis is the elapsed time in whole milliseconds, rounded up so a
// measured scan never reports 0; 0 means the elapsed time is unknown (the
// clock did not advance or went backwards).
func durationMillis(started, finished time.Time) int64 {
	elapsed := finished.Sub(started)
	if elapsed <= 0 {
		return 0
	}
	return int64((elapsed + time.Millisecond - 1) / time.Millisecond)
}

// newResult starts a Result with the schema version, start time and scanner
// identity every result carries.
func newResult(request Request, mode string, started time.Time) Result {
	scannerVersion := strings.TrimSpace(request.ScannerVersion)
	if scannerVersion == "" {
		scannerVersion = version.Effective()
	}
	return Result{
		ResultSchemaVersion: ResultSchemaVersion,
		ScannedAt:           started.UTC().Truncate(time.Second),
		Scanner: ScannerInfo{
			Name:               ScannerName,
			Version:            scannerVersion,
			DetectorSetVersion: request.Detectors.CatalogDigest(),
		},
		RequestedReference: request.Reference.Original,
		Repository:         request.Reference.Repository,
		Mode:               mode,
	}
}

func scanSingleReference(ctx context.Context, request Request, started time.Time) (Result, error) {
	// scanned_at is the scan start, so the result is created before the
	// target is scanned, exactly as scanRepository does.
	result := newResult(request, "reference", started)
	tags := scannedTags(request.Reference)
	scanResult, err := scanTarget(ctx, request, request.Reference, tags, progressState{
		targetsTotal:   1,
		currentTag:     firstTag(tags),
		currentRef:     request.Reference.CanonicalString(""),
		findingsBefore: 0,
	})
	applySingleTargetScan(&result, request.Reference, scanResult, tags)
	tagStatus := countSingleTargetOutcome(&result, scanResult, err)
	// Reference mode never enumerates tags (tags_enumerated stays 0), but the
	// requested tag is reported in tag_results whenever it resolved to a digest.
	if len(tags) > 0 && strings.TrimSpace(scanResult.RequestedDigest) != "" {
		result.TagResults = []TagResult{singleReferenceTagResult(tags[0], scanResult, tagStatus, err)}
	}
	if err != nil {
		return singleReferenceFailure(result, err)
	}
	finalizeResult(&result, result.DetailedFindings, result.SuppressedDetailedFindings)

	emitProgress(request, progressFromResult(request, result, ProgressPhaseCompleted, "Scan complete", "", ""))

	if result.Status != ResultStatusCompleted {
		return result, newIncompleteError(result, nil)
	}
	return result, nil
}

// applySingleTargetScan copies the one target's scan into a reference-mode
// result.
func applySingleTargetScan(result *Result, reference manifest.Reference, scanResult scanner.Result, tags []string) {
	result.ResolvedReference = scanResult.ResolvedReference
	result.RequestedDigest = scanResult.RequestedDigest
	result.TargetCount = 1
	result.ManifestCount = scanResult.ManifestCount
	result.CompletedManifestCount = scanResult.CompletedManifestCount
	result.FailedManifestCount = scanResult.FailedManifestCount
	result.Targets = []TargetResult{targetResultFromScanResult(reference, scanResult, tags)}
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
}

// countSingleTargetOutcome counts the target as completed, partial or failed
// and returns the matching tag status.
func countSingleTargetOutcome(result *Result, scanResult scanner.Result, err error) TagStatus {
	switch {
	case err == nil && scanResult.Status == scanner.ResultStatusCompleted:
		result.CompletedTargetCount = 1
		return TagStatusScanned
	case scanResult.CompletedManifestCount > 0:
		result.PartialTargetCount = 1
		return TagStatusPartial
	default:
		result.FailedTargetCount = 1
		return TagStatusFailed
	}
}

// singleReferenceTagResult is the tag_results entry of the requested tag.
func singleReferenceTagResult(tag string, scanResult scanner.Result, status TagStatus, err error) TagResult {
	tagResult := TagResult{
		Tag:             tag,
		RootDigest:      scanResult.RequestedDigest,
		TargetReference: scanResult.ResolvedReference,
		Status:          status,
	}
	if err != nil {
		tagResult.Error = err.Error()
	}
	return tagResult
}

// singleReferenceFailure finalizes a failed reference scan. A scan that still
// completed a manifest reports an IncompleteError unless the cause must be
// preserved or is a limit.
func singleReferenceFailure(result Result, err error) (Result, error) {
	result.Targets[0].Error = err.Error()
	finalizeResult(&result, result.DetailedFindings, result.SuppressedDetailedFindings)
	if hasCompletedManifest(result) && !mustPreserveScanError(err) && !limits.IsExceeded(err) {
		return result, newIncompleteError(result, err)
	}
	return result, err
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

func scanRepository(ctx context.Context, request Request, started time.Time) (Result, error) {
	result := newResult(request, "repository", started)
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

	groups, err := resolveRepositoryTargets(ctx, request, &result, tags)
	if err != nil {
		return result, err
	}
	if len(groups) == 0 {
		finalizeResult(&result, nil, nil)
		return result, fmt.Errorf("repository %s did not resolve any scannable tags", request.Reference.Repository)
	}

	groupList := sortedTargetGroups(groups)
	result.TargetCount = len(groupList)

	sweep := newRepositorySweep(request, &result, groupList)
	for index, group := range groupList {
		if stopped, err := sweep.scanGroup(ctx, index, group); stopped {
			return result, err
		}
	}
	return sweep.finish()
}

// resolveRepositoryTargets resolves every tag to its root digest and groups
// the tags by digest, recording each tag in tag_results. On an error that
// stops the sweep the result is already finalized.
func resolveRepositoryTargets(ctx context.Context, request Request, result *Result, tags []string) (map[string]*targetGroup, error) {
	groups := make(map[string]*targetGroup)
	for tagIndex, tag := range tags {
		emitProgress(request, progressFromResult(request, *result, ProgressPhaseResolvingTags, "Resolving tag digest", tag, ""))

		digest, err := resolveRepositoryTag(ctx, request, result, tag)
		if err != nil {
			finalizeResult(result, nil, nil)
			return nil, err
		}
		if digest == "" {
			continue
		}
		group, ok := groups[digest]
		if !ok {
			group = &targetGroup{digest: digest}
			groups[digest] = group
		}
		group.tags = append(group.tags, tag)

		// The target bound is applied while resolving: once this tag adds the
		// first target past it, the sweep fails with the limit error without
		// sending one more manifest request for the remaining tags.
		if request.MaxRepositoryTargets > 0 && len(groups) > request.MaxRepositoryTargets {
			return nil, repositoryTargetsExceeded(request, result, tags[tagIndex+1:], len(groups))
		}
	}
	return groups, nil
}

// resolveRepositoryTag resolves one tag and records it in tag_results. It
// returns the digest, or "" for a tag that failed without stopping the sweep;
// an error is returned only when it must stop the sweep.
func resolveRepositoryTag(ctx context.Context, request Request, result *Result, tag string) (string, error) {
	resolved, err := request.Registry.ResolveManifest(ctx, request.Reference.Repository, tag)
	if err != nil {
		result.TagsFailed++
		result.TagResults = append(result.TagResults, TagResult{
			Tag:    tag,
			Status: TagStatusFailed,
			Error:  err.Error(),
		})
		if mustPreserveScanError(err) || limits.IsExceeded(err) {
			return "", err
		}
		return "", nil
	}
	if strings.TrimSpace(resolved.Digest) == "" {
		result.TagsFailed++
		result.TagResults = append(result.TagResults, TagResult{
			Tag:    tag,
			Status: TagStatusFailed,
			Error:  "resolved digest is empty",
		})
		return "", nil
	}

	result.TagsResolved++
	targetReference := request.Reference.WithDigest(resolved.Digest).CanonicalString("")
	result.TagResults = append(result.TagResults, TagResult{
		Tag:             tag,
		RootDigest:      resolved.Digest,
		TargetReference: targetReference,
		Status:          TagStatusResolved,
	})
	return resolved.Digest, nil
}

// repositoryTargetsExceeded builds the repository target limit error, marks
// the tags not yet resolved and finalizes the result.
func repositoryTargetsExceeded(request Request, result *Result, remaining []string, targetCount int) error {
	limitErr := limits.NewExceeded(limits.KindRepositoryTargets, int64(request.MaxRepositoryTargets), "repository "+request.Reference.Repository)
	markUnresolvedTags(result, remaining, limitErr)
	result.TargetCount = targetCount
	finalizeResult(result, nil, nil)
	return limitErr
}

// sortedTargetGroups orders the targets by their first tag, each target's tags
// sorted.
func sortedTargetGroups(groups map[string]*targetGroup) []targetGroup {
	groupList := make([]targetGroup, 0, len(groups))
	for _, group := range groups {
		slices.Sort(group.tags)
		groupList = append(groupList, *group)
	}
	slices.SortFunc(groupList, func(left, right targetGroup) int {
		return strings.Compare(firstTag(left.tags), firstTag(right.tags))
	})
	return groupList
}

// repositorySweep is the state of an --all-tags scan across its targets.
type repositorySweep struct {
	request    Request
	result     *Result
	groups     []targetGroup
	detailed   []findings.DetailedFinding
	suppressed []findings.DetailedFinding
	layerCache *layers.LayerCache
}

func newRepositorySweep(request Request, result *Result, groups []targetGroup) *repositorySweep {
	return &repositorySweep{
		request:    request,
		result:     result,
		groups:     groups,
		detailed:   make([]findings.DetailedFinding, 0),
		suppressed: make([]findings.DetailedFinding, 0),
		// The layer cache lives exactly as long as this sweep: adjacent tags of
		// a repository share most layers, and a layer whose files held no
		// findings is replayed from its metadata instead of being fetched
		// again. It is nil (off) unless LAYERLEAK_MAX_LAYER_CACHE_BYTES is set.
		layerCache: layers.NewLayerCache(request.MaxLayerCacheBytes),
	}
}

// stopEarly records every target the sweep did not reach so the per-target
// accounting and tag_results describe the whole repository, then finalizes.
func (s *repositorySweep) stopEarly(from int, cause error) {
	markUnscannedTargets(s.result, s.request, s.groups[from:], cause)
	finalizeResult(s.result, s.detailed, s.suppressed)
}

// scanGroup scans one target and records its outcome. It reports whether the
// sweep stopped, with the error the scan returns.
func (s *repositorySweep) scanGroup(ctx context.Context, index int, group targetGroup) (bool, error) {
	findingsRetained := len(s.detailed) + len(s.suppressed)
	rawBytesRetained := detailedRawBytes(s.detailed) + detailedRawBytes(s.suppressed)
	if s.request.MaxFindings > 0 && findingsRetained >= s.request.MaxFindings {
		return true, s.stopAtMaxFindings(index, findingsRetained, group)
	}
	scanReference := s.request.Reference.WithDigest(group.digest)
	scanResult, err := scanTarget(ctx, s.request, scanReference, group.tags, s.targetProgress(group, scanReference, findingsRetained, rawBytesRetained))
	targetResult := targetResultFromScanResult(scanReference, scanResult, group.tags)
	s.accumulate(scanResult)
	if err != nil {
		return s.recordFailedTarget(index, group, scanReference, targetResult, scanResult, err)
	}
	return s.recordScannedTarget(index, group, targetResult, scanResult)
}

// stopAtMaxFindings stops the sweep before a target once the retained
// findings reached the max findings limit.
func (s *repositorySweep) stopAtMaxFindings(index, findingsRetained int, group targetGroup) error {
	diagnostic := maxFindingsDiagnostic(s.request.MaxFindings, findingsRetained, group.digest)
	s.result.Diagnostics = append(s.result.Diagnostics, diagnostic)
	s.result.Coverage.Complete = false
	s.stopEarly(index, errors.New(diagnostic.Message))
	return newIncompleteError(*s.result, nil)
}

// targetProgress is the progress context of the target about to be scanned.
func (s *repositorySweep) targetProgress(group targetGroup, scanReference manifest.Reference, findingsRetained int, rawBytesRetained int64) progressState {
	return progressState{
		tagsCompleted:    s.result.TagsResolved,
		tagsTotal:        s.result.TagsEnumerated,
		tagsFailed:       s.result.TagsFailed,
		targetsCompleted: s.result.CompletedTargetCount,
		targetsPartial:   s.result.PartialTargetCount,
		targetsFailed:    s.result.FailedTargetCount,
		targetsTotal:     s.result.TargetCount,
		currentTag:       firstTag(group.tags),
		currentRef:       scanReference.CanonicalString(""),
		findingsBefore:   len(s.detailed),
		findingsRetained: findingsRetained,
		rawBytesRetained: rawBytesRetained,
		layerCache:       s.layerCache,
	}
}

// accumulate adds one target's manifests, findings, coverage and diagnostics
// to the sweep totals.
func (s *repositorySweep) accumulate(scanResult scanner.Result) {
	s.result.ManifestCount += scanResult.ManifestCount
	s.result.CompletedManifestCount += scanResult.CompletedManifestCount
	s.result.FailedManifestCount += scanResult.FailedManifestCount
	s.detailed = append(s.detailed, scanResult.DetailedFindings...)
	s.suppressed = append(s.suppressed, scanResult.SuppressedDetailedFindings...)
	s.result.Coverage = mergeCoverage(s.result.Coverage, scanResult.Coverage)
	s.result.Diagnostics = append(s.result.Diagnostics, scanResult.Diagnostics...)
}

// recordFailedTarget counts a target whose scan returned an error as partial
// or failed. A limit or a preserved error stops the sweep.
func (s *repositorySweep) recordFailedTarget(index int, group targetGroup, scanReference manifest.Reference, targetResult TargetResult, scanResult scanner.Result, err error) (bool, error) {
	targetResult.Error = err.Error()
	s.result.Targets = append(s.result.Targets, targetResult)
	tagStatus := TagStatusFailed
	if scanResult.CompletedManifestCount > 0 {
		s.result.PartialTargetCount++
		tagStatus = TagStatusPartial
	} else {
		s.result.FailedTargetCount++
	}
	setTagStatus(s.result, group.tags, tagStatus, err.Error())
	s.result.TotalFindings = len(s.detailed)
	emitProgress(s.request, progressFromResult(s.request, *s.result, ProgressPhaseTargetFailed, err.Error(), firstTag(group.tags), scanReference.CanonicalString("")))
	if limits.IsExceeded(err) || mustPreserveScanError(err) {
		s.stopEarly(index+1, err)
		return true, err
	}
	return false, nil
}

// recordScannedTarget counts a target whose scan returned no error as
// completed or partial. Reaching the max findings limit stops the sweep.
func (s *repositorySweep) recordScannedTarget(index int, group targetGroup, targetResult TargetResult, scanResult scanner.Result) (bool, error) {
	s.result.Targets = append(s.result.Targets, targetResult)
	if scanResult.Status == scanner.ResultStatusPartial {
		s.result.PartialTargetCount++
		setTagStatus(s.result, group.tags, TagStatusPartial, "")
	} else {
		s.result.CompletedTargetCount++
		setTagStatus(s.result, group.tags, TagStatusScanned, "")
	}
	if hasDiagnosticCode(scanResult.Diagnostics, "max_findings_exceeded") {
		s.stopEarly(index+1, errors.New("scan reached the max findings limit"))
		return true, newIncompleteError(*s.result, nil)
	}
	s.result.TotalFindings = len(s.detailed)
	emitProgress(s.request, progressFromResult(s.request, *s.result, ProgressPhaseTargetDone, "Target scan complete", firstTag(group.tags), scanResult.ResolvedReference))
	return false, nil
}

// finish finalizes a sweep that reached every target.
func (s *repositorySweep) finish() (Result, error) {
	finalizeResult(s.result, s.detailed, s.suppressed)
	if s.result.CompletedTargetCount+s.result.PartialTargetCount == 0 {
		return *s.result, allRepositoryTargetsFailedError(s.result.Targets)
	}
	emitProgress(s.request, progressFromResult(s.request, *s.result, ProgressPhaseCompleted, "Repository scan complete", "", ""))

	if s.result.Status != ResultStatusCompleted {
		return *s.result, newIncompleteError(*s.result, nil)
	}
	return *s.result, nil
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

// markUnresolvedTags records the tags a sweep stopped before resolving as
// skipped, so tag_results still lists every enumerated tag.
func markUnresolvedTags(result *Result, remaining []string, cause error) {
	reason := "not resolved: the sweep stopped before this tag: " + cause.Error()
	for _, tag := range remaining {
		result.TagResults = append(result.TagResults, TagResult{
			Tag:    tag,
			Status: TagStatusSkipped,
			Error:  reason,
		})
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
	layerCache       *layers.LayerCache
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

		MaxNestedArchiveBytes:   request.MaxNestedArchiveBytes,
		MaxNestedArchiveEntries: request.MaxNestedArchiveEntries,
		LayerCache:              state.layerCache,

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

// scannedTags is the tag a reference scan reports in tag_results: none for a
// digest reference, and none for a local source selected without a tag (its
// only image has no tag to report).
func scannedTags(reference manifest.Reference) []string {
	if strings.TrimSpace(reference.Digest) != "" {
		return nil
	}
	identifier := reference.Identifier()
	if identifier == "" {
		return nil
	}
	return []string{identifier}
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
		NestedArchivesExpanded:    left.NestedArchivesExpanded + right.NestedArchivesExpanded,
		NestedEntriesScanned:      left.NestedEntriesScanned + right.NestedEntriesScanned,
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
