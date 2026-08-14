package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/brumbelow/layerleak/internal/detectors"
	"github.com/brumbelow/layerleak/internal/findings"
	"github.com/brumbelow/layerleak/internal/layers"
	"github.com/brumbelow/layerleak/internal/limits"
	"github.com/brumbelow/layerleak/internal/manifest"
	"github.com/brumbelow/layerleak/internal/registry"
)

type Request struct {
	Reference          manifest.Reference
	Platform           string
	Registry           *registry.Client
	Detectors          detectors.Set
	Logger             *slog.Logger
	MaxFileBytes       int64
	MaxLayerBytes      int64
	MaxLayerEntries    int
	MaxConfigBytes     int64
	MaxImageLayers     int
	MaxImageManifests  int
	MaxImageLayerBytes int64
	MaxImageArtifacts  int
	MaxRetainedBytes   int64
	MaxFindings        int
	ExistingFindings   int
	RetainRawSecrets   bool
	MaxRawFindingBytes int64
	ExistingRawBytes   int64
	ConfigTimeout      time.Duration
	BlobTimeout        time.Duration
	Progress           ProgressFunc
}

const maxArchivePathBytes = 4096

type ResultStatus string

const (
	ResultStatusCompleted ResultStatus = "completed"
	ResultStatusPartial   ResultStatus = "partial"
	ResultStatusFailed    ResultStatus = "failed"
)

type Coverage struct {
	Complete                  bool  `json:"complete"`
	LayersSeen                int   `json:"layers_seen"`
	LayersCompleted           int   `json:"layers_completed"`
	FilesSeen                 int   `json:"files_seen"`
	FilesScanned              int   `json:"files_scanned"`
	FilesSkippedOversize      int   `json:"files_skipped_oversize"`
	FilesExcludedBinary       int   `json:"files_excluded_binary"`
	EntriesSkippedUnsafe      int   `json:"entries_skipped_unsafe"`
	MetadataValuesScanned     int   `json:"metadata_values_scanned"`
	ExpandedLayerBytes        int64 `json:"expanded_layer_bytes"`
	RetainedBytes             int64 `json:"retained_bytes"`
	DetectorInputBytesScanned int64 `json:"detector_input_bytes_scanned"`
}

type Diagnostic struct {
	Code     string `json:"code"`
	Scope    string `json:"scope,omitempty"`
	Subject  string `json:"subject,omitempty"`
	Message  string `json:"message"`
	Limit    int64  `json:"limit,omitempty"`
	Observed int64  `json:"observed,omitempty"`
}

type ProgressPhase string

const (
	ProgressPhaseResolvingReference ProgressPhase = "resolving_reference"
	ProgressPhaseSelectingManifests ProgressPhase = "selecting_manifests"
	ProgressPhaseManifestStarted    ProgressPhase = "manifest_started"
	ProgressPhaseManifestCompleted  ProgressPhase = "manifest_completed"
	ProgressPhaseManifestFailed     ProgressPhase = "manifest_failed"
	ProgressPhaseCompleted          ProgressPhase = "completed"
)

type ProgressUpdate struct {
	Phase                 ProgressPhase
	Repository            string
	RepositoriesCompleted int
	RepositoriesTotal     int
	ManifestCompleted     int
	ManifestFailed        int
	ManifestTotal         int
	FindingsFound         int
	CurrentPlatform       manifest.Platform
	CurrentManifestDigest string
	Message               string
}

type ProgressFunc func(ProgressUpdate)

type Result struct {
	Status                       ResultStatus               `json:"status"`
	RequestedReference           string                     `json:"requested_reference"`
	ResolvedReference            string                     `json:"resolved_reference"`
	RequestedDigest              string                     `json:"requested_digest"`
	ManifestCount                int                        `json:"manifest_count"`
	CompletedManifestCount       int                        `json:"completed_manifest_count"`
	FailedManifestCount          int                        `json:"failed_manifest_count"`
	PlatformResults              []PlatformResult           `json:"platform_results"`
	Findings                     []findings.Finding         `json:"findings"`
	DetailedFindings             []findings.DetailedFinding `json:"-"`
	SuppressedFindings           []findings.Finding         `json:"suppressed_findings,omitempty"`
	SuppressedDetailedFindings   []findings.DetailedFinding `json:"-"`
	TotalFindings                int                        `json:"total_findings"`
	UniqueFingerprints           int                        `json:"unique_fingerprints"`
	SuppressedFindingsCount      int                        `json:"suppressed_findings_count,omitempty"`
	SuppressedUniqueFingerprints int                        `json:"suppressed_unique_fingerprints,omitempty"`
	Coverage                     Coverage                   `json:"coverage"`
	Diagnostics                  []Diagnostic               `json:"diagnostics,omitempty"`
}

type PlatformResult struct {
	Status         ResultStatus      `json:"status"`
	Platform       manifest.Platform `json:"platform,omitempty"`
	ManifestDigest string            `json:"manifest_digest"`
	FindingsCount  int               `json:"findings_count"`
	Error          string            `json:"error,omitempty"`
	Coverage       Coverage          `json:"coverage"`
	Diagnostics    []Diagnostic      `json:"diagnostics,omitempty"`
}

func Scan(ctx context.Context, request Request) (Result, error) {
	result := Result{
		RequestedReference: request.Reference.Original,
		Status:             ResultStatusFailed,
		Coverage:           Coverage{Complete: false},
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if request.Registry == nil {
		return result, fmt.Errorf("registry client is required")
	}
	if request.MaxFileBytes <= 0 {
		request.MaxFileBytes = 1 << 20
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if request.Reference.Digest != "" {
		if err := manifest.ValidateDigest(request.Reference.Digest); err != nil {
			return result, err
		}
	}
	budget := newDetectionBudget(ctx, request)

	emitProgress(request, ProgressUpdate{
		Phase:             ProgressPhaseResolvingReference,
		Repository:        request.Reference.Repository,
		RepositoriesTotal: 1,
		Message:           "Resolving image reference",
	})

	rootResponse, err := request.Registry.FetchManifest(ctx, request.Reference.Repository, request.Reference.Identifier())
	if err != nil {
		return result, err
	}

	document, requestedDigest, err := verifyRootDocument(request.Reference, rootResponse)
	if err != nil {
		return result, err
	}
	result.ResolvedReference = request.Reference.CanonicalString(requestedDigest)
	result.RequestedDigest = requestedDigest

	type target struct {
		descriptor manifest.Descriptor
		manifest   *manifest.ImageManifest
	}

	targets := make([]target, 0)
	switch document.Kind {
	case manifest.DocumentKindManifest:
		targets = append(targets, target{
			descriptor: manifest.Descriptor{
				MediaType: document.Manifest.MediaType,
				Digest:    requestedDigest,
				Size:      int64(len(rootResponse.Body)),
			},
			manifest: &document.Manifest,
		})
	case manifest.DocumentKindIndex:
		selected, err := manifest.SelectDescriptors(document.Index, request.Platform)
		if err != nil {
			return result, err
		}
		if request.MaxImageManifests > 0 && len(selected) > request.MaxImageManifests {
			return result, limits.NewExceeded(limits.Kind("image_manifests"), int64(request.MaxImageManifests), "image index")
		}
		for _, descriptor := range selected {
			targets = append(targets, target{descriptor: descriptor})
		}
	default:
		return result, fmt.Errorf("unsupported manifest document kind: %s", document.Kind)
	}

	result.ManifestCount = len(targets)
	emitProgress(request, ProgressUpdate{
		Phase:             ProgressPhaseSelectingManifests,
		Repository:        request.Reference.Repository,
		RepositoriesTotal: 1,
		ManifestTotal:     result.ManifestCount,
		Message:           "Selected manifests",
	})

	allDetailedFindings := make([]findings.DetailedFinding, 0)
	allSuppressedDetailedFindings := make([]findings.DetailedFinding, 0)
	findingsFound := 0
	for _, target := range targets {
		if budget.rawExceeded {
			result.Coverage.Complete = false
			result.Diagnostics = append(result.Diagnostics, budget.diagnostic())
			break
		}
		if budget.exhausted() {
			budget.markExceeded(target.descriptor.Digest)
			result.Coverage.Complete = false
			result.Diagnostics = append(result.Diagnostics, budget.diagnostic())
			break
		}
		if err := ctx.Err(); err != nil {
			finalizeResult(&result, allDetailedFindings, allSuppressedDetailedFindings)
			return result, err
		}
		emitProgress(request, ProgressUpdate{
			Phase:                 ProgressPhaseManifestStarted,
			Repository:            request.Reference.Repository,
			RepositoriesTotal:     1,
			ManifestCompleted:     result.CompletedManifestCount,
			ManifestFailed:        result.FailedManifestCount,
			ManifestTotal:         result.ManifestCount,
			FindingsFound:         findingsFound,
			CurrentPlatform:       target.descriptor.Platform,
			CurrentManifestDigest: target.descriptor.Digest,
			Message:               manifestStatusMessage("Scanning", target.descriptor),
		})

		platformResult, platformFindings, platformSuppressedFindings, err := scanManifestWithBudget(ctx, request, target.descriptor, target.manifest, budget)
		allDetailedFindings = append(allDetailedFindings, platformFindings...)
		allSuppressedDetailedFindings = append(allSuppressedDetailedFindings, platformSuppressedFindings...)
		findingsFound += len(platformFindings)
		if err != nil {
			if platformResult.ManifestDigest == "" {
				platformResult.ManifestDigest = target.descriptor.Digest
			}
			if platformResult.Platform.OS == "" && platformResult.Platform.Architecture == "" && platformResult.Platform.Variant == "" {
				platformResult.Platform = target.descriptor.Platform
			}
			platformResult.Error = err.Error()
			platformResult.Status = ResultStatusFailed
			platformResult.Coverage.Complete = false
			if len(platformResult.Diagnostics) == 0 {
				platformResult.Diagnostics = append(platformResult.Diagnostics, diagnosticForError("platform", target.descriptor.Digest, err))
			}
			result.PlatformResults = append(result.PlatformResults, platformResult)
			result.Coverage = mergeCoverage(result.Coverage, platformResult.Coverage, result.CompletedManifestCount+result.FailedManifestCount > 0)
			result.Diagnostics = append(result.Diagnostics, platformResult.Diagnostics...)
			result.FailedManifestCount++
			emitProgress(request, ProgressUpdate{
				Phase:                 ProgressPhaseManifestFailed,
				Repository:            request.Reference.Repository,
				RepositoriesTotal:     1,
				ManifestCompleted:     result.CompletedManifestCount,
				ManifestFailed:        result.FailedManifestCount,
				ManifestTotal:         result.ManifestCount,
				FindingsFound:         findingsFound,
				CurrentPlatform:       target.descriptor.Platform,
				CurrentManifestDigest: target.descriptor.Digest,
				Message:               err.Error(),
			})
			if limits.IsExceeded(err) || manifest.IsIntegrityError(err) || isCancellationError(err) || ctx.Err() != nil {
				finalizeResult(&result, allDetailedFindings, allSuppressedDetailedFindings)
				return result, err
			}
			continue
		}

		result.PlatformResults = append(result.PlatformResults, platformResult)
		result.Coverage = mergeCoverage(result.Coverage, platformResult.Coverage, result.CompletedManifestCount+result.FailedManifestCount > 0)
		result.Diagnostics = append(result.Diagnostics, platformResult.Diagnostics...)
		result.CompletedManifestCount++
		emitProgress(request, ProgressUpdate{
			Phase:                 ProgressPhaseManifestCompleted,
			Repository:            request.Reference.Repository,
			RepositoriesTotal:     1,
			ManifestCompleted:     result.CompletedManifestCount,
			ManifestFailed:        result.FailedManifestCount,
			ManifestTotal:         result.ManifestCount,
			FindingsFound:         findingsFound,
			CurrentPlatform:       platformResult.Platform,
			CurrentManifestDigest: platformResult.ManifestDigest,
			Message:               manifestStatusMessage("Completed", manifest.Descriptor{Digest: platformResult.ManifestDigest, Platform: platformResult.Platform}),
		})
	}

	finalizeResult(&result, allDetailedFindings, allSuppressedDetailedFindings)
	if result.CompletedManifestCount == 0 {
		return result, allSelectedManifestsFailedError(result.PlatformResults)
	}
	emitProgress(request, ProgressUpdate{
		Phase:                 ProgressPhaseCompleted,
		Repository:            request.Reference.Repository,
		RepositoriesCompleted: 1,
		RepositoriesTotal:     1,
		ManifestCompleted:     result.CompletedManifestCount,
		ManifestFailed:        result.FailedManifestCount,
		ManifestTotal:         result.ManifestCount,
		FindingsFound:         result.TotalFindings,
		Message:               "Scan complete",
	})

	return result, nil
}

func scanManifest(ctx context.Context, request Request, descriptor manifest.Descriptor, preloaded *manifest.ImageManifest) (PlatformResult, []findings.DetailedFinding, []findings.DetailedFinding, error) {
	return scanManifestWithBudget(ctx, request, descriptor, preloaded, newDetectionBudget(ctx, request))
}

func scanManifestWithBudget(ctx context.Context, request Request, descriptor manifest.Descriptor, preloaded *manifest.ImageManifest, budget *detectionBudget) (PlatformResult, []findings.DetailedFinding, []findings.DetailedFinding, error) {
	platformResult := PlatformResult{
		Status:         ResultStatusFailed,
		Platform:       descriptor.Platform,
		ManifestDigest: descriptor.Digest,
		Coverage:       Coverage{Complete: false},
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return platformResult, nil, nil, err
	}
	if descriptor.Digest == "" {
		return platformResult, nil, nil, &manifest.IntegrityError{Kind: manifest.IntegrityInvalidDigest, Subject: "manifest", Expected: "valid OCI digest", Actual: "empty"}
	}
	if err := manifest.ValidateDigest(descriptor.Digest); err != nil {
		return platformResult, nil, nil, err
	}

	imageManifest, err := resolveImageManifest(ctx, request, descriptor, preloaded)
	if err != nil {
		return platformResult, nil, nil, err
	}
	if err := enforceManifestAggregateLimits(imageManifest, request); err != nil {
		platformResult.Diagnostics = append(platformResult.Diagnostics, diagnosticForError("platform", descriptor.Digest, err))
		return platformResult, nil, nil, err
	}

	configBody, err := fetchConfigBody(ctx, request, imageManifest.Config)
	if err != nil {
		return platformResult, nil, nil, err
	}

	imageConfig, err := manifest.ParseImageConfig(configBody)
	if err != nil {
		return platformResult, nil, nil, err
	}
	configPlatform := manifest.Platform{OS: imageConfig.OS, Architecture: imageConfig.Architecture, Variant: imageConfig.Variant}
	if err := manifest.ValidatePlatform(configPlatform, false); err != nil {
		return platformResult, nil, nil, &manifest.IntegrityError{Kind: manifest.IntegrityInvalidDocument, Subject: "image config platform", Expected: "valid OCI platform fields", Actual: "invalid platform", Cause: err}
	}
	if err := verifyPlatformProvenance(descriptor.Platform, configPlatform); err != nil {
		return platformResult, nil, nil, err
	}

	platform := descriptor.Platform
	if platform.OS == "" {
		platform.OS = imageConfig.OS
	}
	if platform.Architecture == "" {
		platform.Architecture = imageConfig.Architecture
	}
	if platform.Variant == "" {
		platform.Variant = imageConfig.Variant
	}
	platformResult.Platform = platform

	budgetStart := budget.snapshot()
	metadataFindings := scanMetadataWithBudget(budget, request.Detectors, descriptor.Digest, platform, imageConfig)
	layerResult := layers.ReplayResult{}
	err = budget.err
	if budget.exhausted() && len(imageManifest.Layers) > 0 {
		budget.markExceeded(descriptor.Digest)
	}
	if !budget.stopped() && err == nil {
		layerResult, err = layers.Replay(ctx, imageManifest.Layers, layers.ReplayOptions{
			MaxFileBytes:     request.MaxFileBytes,
			MaxLayerBytes:    request.MaxLayerBytes,
			MaxLayerEntries:  request.MaxLayerEntries,
			MaxTotalBytes:    request.MaxImageLayerBytes,
			MaxTotalEntries:  request.MaxImageArtifacts,
			MaxRetainedBytes: request.MaxRetainedBytes,
		}, layers.OpenFunc(func(ctx context.Context, layerDescriptor manifest.Descriptor) (io.ReadCloser, error) {
			blobCtx := ctx
			cancel := func() {}
			if request.BlobTimeout > 0 {
				blobCtx, cancel = context.WithTimeout(ctx, request.BlobTimeout)
			}
			response, err := request.Registry.OpenBlob(blobCtx, request.Reference.Repository, layerDescriptor.Digest)
			if err != nil {
				cancel()
				return nil, err
			}
			if err := verifyBlobHeaders(layerDescriptor, response.Digest, response.MediaType, response.Size, true); err != nil {
				_ = response.Body.Close()
				cancel()
				return nil, err
			}
			verifier, err := manifest.NewVerifyingReader(response.Body, layerDescriptor)
			if err != nil {
				_ = response.Body.Close()
				cancel()
				return nil, err
			}
			return &verifiedReadCloser{VerifyingReader: verifier, closer: response.Body, cancel: cancel}, nil
		}))
	}

	fileFindings := scanArtifactsWithBudget(budget, request.Detectors, descriptor.Digest, platform, findings.SourceTypeFileFinal, true, layerResult.FinalFiles)
	fileFindings = append(fileFindings, scanArtifactsWithBudget(budget, request.Detectors, descriptor.Digest, platform, findings.SourceTypeFileDeletedLayer, false, layerResult.DeletedArtifacts)...)
	if err == nil && budget.err != nil {
		err = budget.err
	}

	allFindings := append(metadataFindings, fileFindings...)
	actionableFindings, suppressedFindings := splitDetailedFindings(allFindings)
	platformResult.FindingsCount = len(actionableFindings)
	platformResult.Coverage = coverageFromLayerResult(layerResult.Coverage, budget.delta(budgetStart))
	platformResult.Coverage.Complete = err == nil && layerResult.Coverage.FilesSkippedOversize == 0 && layerResult.Coverage.EntriesSkippedUnsafe == 0 && !budget.stopped()
	if layerResult.Coverage.FilesSkippedOversize > 0 {
		platformResult.Diagnostics = append(platformResult.Diagnostics, Diagnostic{
			Code:     "files_skipped_oversize",
			Scope:    "platform",
			Subject:  descriptor.Digest,
			Message:  fmt.Sprintf("%d file(s) exceeded the per-file scan limit", layerResult.Coverage.FilesSkippedOversize),
			Observed: int64(layerResult.Coverage.FilesSkippedOversize),
		})
	}
	if layerResult.Coverage.EntriesSkippedUnsafe > 0 {
		platformResult.Diagnostics = append(platformResult.Diagnostics, Diagnostic{
			Code:     "unsafe_archive_entries_skipped",
			Scope:    "platform",
			Subject:  descriptor.Digest,
			Message:  fmt.Sprintf("%d unsafe archive entries were skipped", layerResult.Coverage.EntriesSkippedUnsafe),
			Observed: int64(layerResult.Coverage.EntriesSkippedUnsafe),
		})
	}
	if budget.stopped() && budget.diagnosticManifest == descriptor.Digest {
		platformResult.Diagnostics = append(platformResult.Diagnostics, budget.diagnostic())
	}
	if err != nil {
		platformResult.Status = ResultStatusFailed
		platformResult.Diagnostics = appendDiagnostic(platformResult.Diagnostics, diagnosticForError("platform", descriptor.Digest, err))
		return platformResult, actionableFindings, suppressedFindings, err
	}
	if platformResult.Coverage.Complete {
		platformResult.Status = ResultStatusCompleted
	} else {
		platformResult.Status = ResultStatusPartial
	}
	if request.Logger != nil {
		request.Logger.DebugContext(ctx, "scanned platform manifest",
			"manifest_digest", descriptor.Digest,
			"platform", platform.String(),
			"findings", len(actionableFindings),
			"suppressed_findings", len(suppressedFindings),
		)
	}

	return platformResult, actionableFindings, suppressedFindings, nil
}

func resolveImageManifest(ctx context.Context, request Request, descriptor manifest.Descriptor, preloaded *manifest.ImageManifest) (manifest.ImageManifest, error) {
	if preloaded != nil {
		if err := manifest.ValidateImageManifest(*preloaded); err != nil {
			return manifest.ImageManifest{}, fmt.Errorf("validate image manifest: %w", err)
		}
		return *preloaded, nil
	}

	response, err := request.Registry.FetchManifest(ctx, request.Reference.Repository, descriptor.Digest)
	if err != nil {
		return manifest.ImageManifest{}, err
	}
	if err := verifyManifestResponseDescriptor(descriptor, response); err != nil {
		return manifest.ImageManifest{}, fmt.Errorf("verify image manifest %s: %w", descriptor.Digest, err)
	}
	document, err := manifest.ParseDocument(response.MediaType, response.Body)
	if err != nil {
		return manifest.ImageManifest{}, &manifest.IntegrityError{Kind: manifest.IntegrityInvalidDocument, Subject: descriptor.Digest, Expected: "valid image manifest JSON", Actual: "invalid document", Cause: err}
	}
	if document.Kind != manifest.DocumentKindManifest {
		return manifest.ImageManifest{}, &manifest.IntegrityError{Kind: manifest.IntegrityInvalidDocument, Subject: descriptor.Digest, Expected: "image manifest", Actual: string(document.Kind)}
	}
	if err := manifest.ValidateImageManifest(document.Manifest); err != nil {
		return manifest.ImageManifest{}, fmt.Errorf("validate image manifest %s: %w", descriptor.Digest, err)
	}

	return document.Manifest, nil
}

type detectionCoverage struct {
	filesScanned              int
	metadataValuesScanned     int
	detectorInputBytesScanned int64
}

type detectionBudget struct {
	ctx                context.Context
	maxFindings        int
	retained           int
	exceeded           bool
	observed           int
	diagnosticManifest string
	err                error
	retainRaw          bool
	maxRawBytes        int64
	rawBytes           int64
	rawExceeded        bool
	rawObserved        int64
	coverage           detectionCoverage
}

func newDetectionBudget(ctx context.Context, request Request) *detectionBudget {
	return &detectionBudget{
		ctx:         ctx,
		maxFindings: request.MaxFindings,
		retained:    request.ExistingFindings,
		retainRaw:   request.RetainRawSecrets,
		maxRawBytes: request.MaxRawFindingBytes,
		rawBytes:    request.ExistingRawBytes,
	}
}

func (b *detectionBudget) scan(detectorSet detectors.Set, input findings.Input, scanInput detectors.ScanInput) []findings.DetailedFinding {
	if b == nil {
		return scanString(detectorSet, input, scanInput)
	}
	if b.stopped() || b.err != nil {
		return nil
	}
	if b.exhausted() {
		b.markExceeded(input.ManifestDigest)
		return nil
	}
	if b.ctx != nil {
		if err := b.ctx.Err(); err != nil {
			b.err = err
			return nil
		}
	}

	matches := detectorSet.Scan(scanInput)
	if b.ctx != nil {
		if err := b.ctx.Err(); err != nil {
			b.err = err
			return nil
		}
	}
	b.coverage.detectorInputBytesScanned += int64(len(scanInput.Content))
	switch input.SourceType {
	case findings.SourceTypeFileFinal, findings.SourceTypeFileDeletedLayer:
		b.coverage.filesScanned++
	default:
		b.coverage.metadataValuesScanned++
	}

	normalizer, err := findings.NewDetailedNormalizerWithProvenance(
		input,
		matches,
		scanProvenance(detectorSet, input.FilePath, maxArchivePathBytes),
		scanProvenance(detectorSet, input.Key, findings.MaxPublicProvenanceBytes),
	)
	if err != nil {
		return nil
	}
	result := make([]findings.DetailedFinding, 0, len(matches))
	for _, match := range matches {
		if b.maxFindings > 0 && b.retained >= b.maxFindings {
			b.exceeded = true
			b.observed = b.retained + 1
			b.diagnosticManifest = input.ManifestDigest
			break
		}
		retainRaw := b.retainRaw
		if retainRaw && b.maxRawBytes > 0 {
			rawSize, rawSizeErr := normalizer.RawByteSize(match)
			if rawSizeErr != nil {
				continue
			}
			if b.rawBytes > b.maxRawBytes || rawSize > b.maxRawBytes-b.rawBytes {
				b.rawExceeded = true
				b.rawObserved = b.rawBytes + rawSize
				b.diagnosticManifest = input.ManifestDigest
				retainRaw = false
			}
		}
		finding, err := normalizer.NormalizeWithRaw(match, retainRaw)
		if err != nil {
			continue
		}
		result = append(result, finding)
		b.retained++
		if retainRaw {
			b.rawBytes += int64(len(finding.Value)) + int64(len(finding.RawSnippet))
		}
		if b.rawExceeded {
			break
		}
	}
	return result
}

func (b *detectionBudget) exhausted() bool {
	return b != nil && b.maxFindings > 0 && b.retained >= b.maxFindings
}

func (b *detectionBudget) stopped() bool {
	return b != nil && (b.exceeded || b.rawExceeded)
}

func (b *detectionBudget) markExceeded(manifestDigest string) {
	if b == nil || b.exceeded {
		return
	}
	b.exceeded = true
	b.observed = b.retained
	b.diagnosticManifest = manifestDigest
}

func (b *detectionBudget) snapshot() detectionCoverage {
	if b == nil {
		return detectionCoverage{}
	}
	return b.coverage
}

func (b *detectionBudget) delta(before detectionCoverage) detectionCoverage {
	if b == nil {
		return detectionCoverage{}
	}
	return detectionCoverage{
		filesScanned:              b.coverage.filesScanned - before.filesScanned,
		metadataValuesScanned:     b.coverage.metadataValuesScanned - before.metadataValuesScanned,
		detectorInputBytesScanned: b.coverage.detectorInputBytesScanned - before.detectorInputBytesScanned,
	}
}

func (b *detectionBudget) diagnostic() Diagnostic {
	if b.rawExceeded {
		return Diagnostic{
			Code:     "max_raw_finding_bytes_exceeded",
			Scope:    "scan",
			Subject:  b.diagnosticManifest,
			Message:  fmt.Sprintf("scan reached raw finding byte limit of %d before coverage completed", b.maxRawBytes),
			Limit:    b.maxRawBytes,
			Observed: b.rawObserved,
		}
	}
	return Diagnostic{
		Code:     "max_findings_exceeded",
		Scope:    "scan",
		Subject:  b.diagnosticManifest,
		Message:  fmt.Sprintf("scan reached max findings limit of %d before coverage completed", b.maxFindings),
		Limit:    int64(b.maxFindings),
		Observed: int64(b.observed),
	}
}

func scanMetadataWithBudget(budget *detectionBudget, detectorSet detectors.Set, manifestDigest string, platform manifest.Platform, imageConfig manifest.ImageConfig) []findings.DetailedFinding {
	result := make([]findings.DetailedFinding, 0)
	for _, payload := range []struct {
		prefix string
		value  manifest.ImageConfigPayload
	}{
		{prefix: "config", value: imageConfig.Config},
		{prefix: "container_config", value: imageConfig.ContainerConfig},
	} {
		envEntries := slices.Clone(payload.value.Env)
		slices.Sort(envEntries)
		for _, entry := range envEntries {
			key, _, found := strings.Cut(entry, "=")
			if !found {
				key = entry
			}
			result = append(result, budget.scan(detectorSet, findings.Input{
				ManifestDigest: manifestDigest,
				Platform:       platform,
				SourceType:     findings.SourceTypeEnv,
				Key:            payload.prefix + ".env." + key,
				Content:        entry,
			}, detectors.ScanInput{Content: entry, Key: key})...)
		}

		labelKeys := make([]string, 0, len(payload.value.Labels))
		for key := range payload.value.Labels {
			labelKeys = append(labelKeys, key)
		}
		slices.Sort(labelKeys)
		for _, key := range labelKeys {
			value := payload.value.Labels[key]
			content := key + "=" + value
			result = append(result, budget.scan(detectorSet, findings.Input{
				ManifestDigest: manifestDigest,
				Platform:       platform,
				SourceType:     findings.SourceTypeLabel,
				Key:            payload.prefix + ".label." + key,
				Content:        content,
			}, detectors.ScanInput{Content: content, Key: key})...)
		}
	}

	for index, entry := range imageConfig.History {
		for _, field := range []struct {
			key   string
			value string
		}{
			{key: fmt.Sprintf("history[%d].created_by", index), value: entry.CreatedBy},
			{key: fmt.Sprintf("history[%d].comment", index), value: entry.Comment},
			{key: fmt.Sprintf("history[%d].author", index), value: entry.Author},
		} {
			if strings.TrimSpace(field.value) == "" {
				continue
			}
			result = append(result, budget.scan(detectorSet, findings.Input{
				ManifestDigest: manifestDigest,
				Platform:       platform,
				SourceType:     findings.SourceTypeHistory,
				Key:            field.key,
				Content:        field.value,
			}, detectors.ScanInput{
				Content: field.value,
				Key:     field.key,
			})...)
		}
	}

	for _, field := range manifest.ConfigFields(imageConfig) {
		result = append(result, budget.scan(detectorSet, findings.Input{
			ManifestDigest: manifestDigest,
			Platform:       platform,
			SourceType:     findings.SourceTypeConfig,
			Key:            field.Key,
			Content:        field.Value,
		}, detectors.ScanInput{
			Content: field.Value,
			Key:     field.Key,
		})...)
	}

	return result
}

func scanArtifacts(detectorSet detectors.Set, manifestDigest string, platform manifest.Platform, sourceType findings.SourceType, presentInFinalImage bool, artifacts []layers.Artifact) []findings.DetailedFinding {
	return scanArtifactsWithBudget(&detectionBudget{retainRaw: true}, detectorSet, manifestDigest, platform, sourceType, presentInFinalImage, artifacts)
}

func scanArtifactsWithBudget(budget *detectionBudget, detectorSet detectors.Set, manifestDigest string, platform manifest.Platform, sourceType findings.SourceType, presentInFinalImage bool, artifacts []layers.Artifact) []findings.DetailedFinding {
	result := make([]findings.DetailedFinding, 0)
	for _, artifact := range artifacts {
		if budget != nil && (budget.stopped() || budget.err != nil || (budget.ctx != nil && budget.ctx.Err() != nil)) {
			break
		}
		if !artifact.Scannable || len(artifact.Content) == 0 {
			continue
		}
		content := string(artifact.Content)
		result = append(result, budget.scan(detectorSet, findings.Input{
			ManifestDigest:      manifestDigest,
			Platform:            platform,
			SourceType:          sourceType,
			FilePath:            artifact.Path,
			LayerDigest:         artifact.LayerDigest,
			Content:             content,
			PresentInFinalImage: presentInFinalImage,
		}, detectors.ScanInput{
			Content: content,
			Path:    artifact.Path,
		})...)
	}
	return result
}

func scanString(detectorSet detectors.Set, input findings.Input, scanInput detectors.ScanInput) []findings.DetailedFinding {
	matches := detectorSet.Scan(scanInput)
	return normalizeMatches(detectorSet, input, matches, 0)
}

func normalizeMatches(detectorSet detectors.Set, input findings.Input, matches []detectors.Match, maxFindings int) []findings.DetailedFinding {
	normalizer, err := findings.NewDetailedNormalizerWithProvenance(
		input,
		matches,
		scanProvenance(detectorSet, input.FilePath, maxArchivePathBytes),
		scanProvenance(detectorSet, input.Key, findings.MaxPublicProvenanceBytes),
	)
	if err != nil {
		return nil
	}
	result := make([]findings.DetailedFinding, 0, len(matches))
	for _, match := range matches {
		if maxFindings > 0 && len(result) >= maxFindings {
			break
		}
		finding, err := normalizer.Normalize(match)
		if err != nil {
			continue
		}
		result = append(result, finding)
	}
	return result
}

func scanProvenance(detectorSet detectors.Set, value string, maxBytes int) []detectors.Match {
	if value == "" || len(value) > maxBytes {
		return nil
	}
	return detectorSet.Scan(detectors.ScanInput{Content: value})
}

func splitDetailedFindings(items []findings.DetailedFinding) ([]findings.DetailedFinding, []findings.DetailedFinding) {
	actionable := make([]findings.DetailedFinding, 0, len(items))
	suppressed := make([]findings.DetailedFinding, 0)
	for _, item := range items {
		switch item.Disposition {
		case findings.DispositionExample:
			suppressed = append(suppressed, item)
		default:
			actionable = append(actionable, item)
		}
	}

	return actionable, suppressed
}

func sortPlatformResults(items []PlatformResult) {
	slices.SortFunc(items, func(left, right PlatformResult) int {
		if value := strings.Compare(left.Platform.String(), right.Platform.String()); value != 0 {
			return value
		}
		return strings.Compare(left.ManifestDigest, right.ManifestDigest)
	})
}

func allSelectedManifestsFailedError(items []PlatformResult) error {
	errors := collectErrorMessages(len(items), func(index int) string {
		return items[index].Error
	})
	if len(errors) == 0 {
		return fmt.Errorf("all selected manifests failed")
	}
	return fmt.Errorf("all selected manifests failed: %s", strings.Join(errors, "; "))
}

func collectErrorMessages(limit int, message func(index int) string) []string {
	if limit <= 0 {
		return nil
	}

	collected := make([]string, 0, limit)
	seen := make(map[string]struct{})
	for index := 0; index < limit; index++ {
		value := strings.TrimSpace(message(index))
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

func isCancellationError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func emitProgress(request Request, update ProgressUpdate) {
	if request.Progress == nil {
		return
	}
	if update.RepositoriesTotal <= 0 {
		update.RepositoriesTotal = 1
	}
	if update.Repository == "" {
		update.Repository = request.Reference.Repository
	}
	request.Progress(update)
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
	switch {
	case result.CompletedManifestCount == 0:
		result.Status = ResultStatusFailed
		result.Coverage.Complete = false
	case result.FailedManifestCount > 0 || !result.Coverage.Complete:
		result.Status = ResultStatusPartial
	default:
		result.Status = ResultStatusCompleted
		result.Coverage.Complete = true
	}
	sortPlatformResults(result.PlatformResults)
}

func readConfigBody(reader io.Reader, maxBytes int64, digest string) ([]byte, error) {
	if maxBytes <= 0 {
		body, err := io.ReadAll(reader)
		if err != nil {
			return nil, fmt.Errorf("read config blob: %w", err)
		}
		return body, nil
	}

	limited := io.LimitReader(reader, limits.OverflowProbeLimit(maxBytes))
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read config blob: %w", err)
	}
	if int64(len(body)) > maxBytes {
		return nil, limits.NewExceeded(limits.KindConfigBytes, maxBytes, "config blob "+strings.TrimSpace(digest))
	}

	return body, nil
}

func fetchConfigBody(ctx context.Context, request Request, descriptor manifest.Descriptor) ([]byte, error) {
	configCtx := ctx
	cancel := func() {}
	if request.ConfigTimeout > 0 {
		configCtx, cancel = context.WithTimeout(ctx, request.ConfigTimeout)
	}
	defer cancel()

	configBlob, err := request.Registry.OpenBlob(configCtx, request.Reference.Repository, descriptor.Digest)
	if err != nil {
		return nil, fmt.Errorf("fetch config blob: %w", err)
	}
	if err := verifyBlobHeaders(descriptor, configBlob.Digest, configBlob.MediaType, configBlob.Size, true); err != nil {
		_ = configBlob.Body.Close()
		return nil, fmt.Errorf("verify config blob headers: %w", err)
	}
	configBody, err := readConfigBody(configBlob.Body, request.MaxConfigBytes, descriptor.Digest)
	closeErr := configBlob.Body.Close()
	if err != nil {
		if contextErr := configCtx.Err(); contextErr != nil {
			return nil, fmt.Errorf("read config blob: %w", contextErr)
		}
		return nil, err
	}
	if err := configCtx.Err(); err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close config blob: %w", closeErr)
	}
	if err := manifest.VerifyDescriptorBytes(descriptor, configBody, configBlob.MediaType, true); err != nil {
		return nil, fmt.Errorf("verify config blob: %w", err)
	}
	if err := configCtx.Err(); err != nil {
		return nil, err
	}

	return configBody, nil
}

func manifestStatusMessage(prefix string, descriptor manifest.Descriptor) string {
	target := descriptor.Platform.String()
	if target == "" {
		target = descriptor.Digest
	}
	if target == "" {
		return prefix
	}
	return prefix + " " + target
}

func verifyRootDocument(reference manifest.Reference, response registry.ManifestResponse) (manifest.Document, string, error) {
	document, err := manifest.ParseDocument(response.MediaType, response.Body)
	if err != nil {
		return manifest.Document{}, "", &manifest.IntegrityError{
			Kind:     manifest.IntegrityInvalidDocument,
			Subject:  reference.Original,
			Expected: "valid image manifest or index JSON",
			Actual:   "invalid document",
			Cause:    err,
		}
	}
	if err := manifest.ValidateDocument(document); err != nil {
		return manifest.Document{}, "", fmt.Errorf("validate root manifest: %w", err)
	}

	expectedMediaType := document.Manifest.MediaType
	if document.Kind == manifest.DocumentKindIndex {
		expectedMediaType = document.Index.MediaType
	}
	if err := manifest.VerifyMediaType(expectedMediaType, response.MediaType, false, reference.Original); err != nil {
		return manifest.Document{}, "", err
	}

	requestedDigest := strings.TrimSpace(reference.Digest)
	responseDigest := strings.TrimSpace(response.Digest)
	if requestedDigest != "" && responseDigest != "" && requestedDigest != responseDigest {
		return manifest.Document{}, "", &manifest.IntegrityError{
			Kind:     manifest.IntegrityDigestMismatch,
			Subject:  reference.Original,
			Expected: requestedDigest,
			Actual:   responseDigest,
		}
	}
	if requestedDigest == "" {
		requestedDigest = responseDigest
	}
	if requestedDigest == "" {
		requestedDigest, err = manifest.DigestBytes("sha256", response.Body)
		if err != nil {
			return manifest.Document{}, "", err
		}
	}
	rootDescriptor := manifest.Descriptor{
		MediaType: expectedMediaType,
		Digest:    requestedDigest,
		Size:      int64(len(response.Body)),
	}
	if err := manifest.VerifyDescriptorBytes(rootDescriptor, response.Body, response.MediaType, false); err != nil {
		return manifest.Document{}, "", fmt.Errorf("verify root manifest: %w", err)
	}
	if responseDigest != "" && responseDigest != requestedDigest {
		responseDescriptor := rootDescriptor
		responseDescriptor.Digest = responseDigest
		if err := manifest.VerifyDescriptorBytes(responseDescriptor, response.Body, response.MediaType, false); err != nil {
			return manifest.Document{}, "", fmt.Errorf("verify registry manifest digest: %w", err)
		}
	}

	return document, requestedDigest, nil
}

func verifyManifestResponseDescriptor(descriptor manifest.Descriptor, response registry.ManifestResponse) error {
	if response.Digest != "" && response.Digest != descriptor.Digest {
		return &manifest.IntegrityError{
			Kind:     manifest.IntegrityDigestMismatch,
			Subject:  descriptor.Digest,
			Expected: descriptor.Digest,
			Actual:   response.Digest,
		}
	}
	return manifest.VerifyDescriptorBytes(descriptor, response.Body, response.MediaType, false)
}

func verifyBlobHeaders(descriptor manifest.Descriptor, responseDigest, responseMediaType string, responseSize int64, allowGenericMediaType bool) error {
	if err := manifest.ValidateDigest(descriptor.Digest); err != nil {
		return err
	}
	if responseDigest != "" && responseDigest != descriptor.Digest {
		return &manifest.IntegrityError{
			Kind:     manifest.IntegrityDigestMismatch,
			Subject:  descriptor.Digest,
			Expected: descriptor.Digest,
			Actual:   responseDigest,
		}
	}
	if err := manifest.VerifyMediaType(descriptor.MediaType, responseMediaType, allowGenericMediaType, descriptor.Digest); err != nil {
		return err
	}
	if responseSize > 0 && responseSize != descriptor.Size {
		return &manifest.IntegrityError{
			Kind:     manifest.IntegritySizeMismatch,
			Subject:  descriptor.Digest,
			Expected: fmt.Sprintf("%d", descriptor.Size),
			Actual:   fmt.Sprintf("%d", responseSize),
		}
	}
	return nil
}

func verifyPlatformProvenance(descriptor, config manifest.Platform) error {
	for _, field := range []struct {
		name       string
		descriptor string
		config     string
	}{
		{name: "os", descriptor: descriptor.OS, config: config.OS},
		{name: "architecture", descriptor: descriptor.Architecture, config: config.Architecture},
		{name: "variant", descriptor: descriptor.Variant, config: config.Variant},
	} {
		if field.descriptor != "" && field.config != "" && field.descriptor != field.config {
			return &manifest.IntegrityError{
				Kind:     manifest.IntegrityPlatformMismatch,
				Subject:  "image platform " + field.name,
				Expected: field.descriptor,
				Actual:   field.config,
			}
		}
	}
	return nil
}

func enforceManifestAggregateLimits(imageManifest manifest.ImageManifest, request Request) error {
	if request.MaxImageLayers > 0 && len(imageManifest.Layers) > request.MaxImageLayers {
		return limits.NewExceeded(limits.Kind("image_layers"), int64(request.MaxImageLayers), "image manifest")
	}
	if request.MaxImageLayerBytes <= 0 {
		return nil
	}
	var total int64
	for _, descriptor := range imageManifest.Layers {
		if descriptor.Size > request.MaxImageLayerBytes-total {
			return limits.NewExceeded(limits.Kind("image_layer_bytes"), request.MaxImageLayerBytes, "image manifest")
		}
		total += descriptor.Size
	}
	return nil
}

type verifiedReadCloser struct {
	*manifest.VerifyingReader
	closer io.Closer
	cancel context.CancelFunc
}

func (r *verifiedReadCloser) Close() error {
	err := r.closer.Close()
	if r.cancel != nil {
		r.cancel()
	}
	return err
}

func coverageFromLayerResult(layerCoverage layers.Coverage, detection detectionCoverage) Coverage {
	return Coverage{
		LayersSeen:                layerCoverage.LayersSeen,
		LayersCompleted:           layerCoverage.LayersCompleted,
		FilesSeen:                 layerCoverage.FilesSeen,
		FilesScanned:              detection.filesScanned,
		FilesSkippedOversize:      layerCoverage.FilesSkippedOversize,
		FilesExcludedBinary:       layerCoverage.FilesExcludedBinary,
		EntriesSkippedUnsafe:      layerCoverage.EntriesSkippedUnsafe,
		MetadataValuesScanned:     detection.metadataValuesScanned,
		ExpandedLayerBytes:        layerCoverage.ExpandedBytes,
		RetainedBytes:             layerCoverage.RetainedBytes,
		DetectorInputBytesScanned: detection.detectorInputBytesScanned,
	}
}

func mergeCoverage(left, right Coverage, initialized bool) Coverage {
	if !initialized {
		return right
	}
	return Coverage{
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

func diagnosticForError(scope, subject string, err error) Diagnostic {
	diagnostic := Diagnostic{Scope: scope, Subject: subject, Message: err.Error()}
	if integrityErr, ok := manifest.AsIntegrityError(err); ok {
		diagnostic.Code = string(integrityErr.Kind)
		return diagnostic
	}
	if exceeded, ok := limits.AsExceeded(err); ok {
		diagnostic.Code = string(exceeded.Kind) + "_exceeded"
		diagnostic.Subject = exceeded.Subject
		diagnostic.Limit = exceeded.Limit
		return diagnostic
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		diagnostic.Code = "scan_canceled"
		return diagnostic
	}
	diagnostic.Code = "manifest_failed"
	return diagnostic
}

func appendDiagnostic(items []Diagnostic, item Diagnostic) []Diagnostic {
	for _, existing := range items {
		if existing.Code == item.Code && existing.Scope == item.Scope && existing.Subject == item.Subject && existing.Message == item.Message {
			return items
		}
	}
	return append(items, item)
}
