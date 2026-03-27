package scanner

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"

	"github.com/brumbelow/layerleak/internal/detectors"
	"github.com/brumbelow/layerleak/internal/findings"
	"github.com/brumbelow/layerleak/internal/layers"
	"github.com/brumbelow/layerleak/internal/limits"
	"github.com/brumbelow/layerleak/internal/manifest"
	"github.com/brumbelow/layerleak/internal/registry"
)

type Request struct {
	Reference      manifest.Reference
	Platform       string
	Registry       *registry.Client
	Detectors      detectors.Set
	Logger         *slog.Logger
	MaxFileBytes   int64
	MaxConfigBytes int64
	Progress       ProgressFunc
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
}

type PlatformResult struct {
	Platform       manifest.Platform `json:"platform,omitempty"`
	ManifestDigest string            `json:"manifest_digest"`
	FindingsCount  int               `json:"findings_count"`
	Error          string            `json:"error,omitempty"`
}

func Scan(ctx context.Context, request Request) (Result, error) {
	result := Result{
		RequestedReference: request.Reference.Original,
	}
	if request.Registry == nil {
		return result, fmt.Errorf("registry client is required")
	}
	if request.MaxFileBytes <= 0 {
		request.MaxFileBytes = 1 << 20
	}

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

	document, err := manifest.ParseDocument(rootResponse.MediaType, rootResponse.Body)
	if err != nil {
		return result, err
	}

	requestedDigest := firstNonEmpty(rootResponse.Digest, request.Reference.Digest)
	if requestedDigest == "" {
		return result, fmt.Errorf("registry did not return a resolved digest for %s", request.Reference.Original)
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
			},
			manifest: &document.Manifest,
		})
	case manifest.DocumentKindIndex:
		selected, err := manifest.SelectDescriptors(document.Index, request.Platform)
		if err != nil {
			return result, err
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

		platformResult, platformFindings, platformSuppressedFindings, err := scanManifest(ctx, request, target.descriptor, target.manifest)
		if err != nil {
			result.PlatformResults = append(result.PlatformResults, PlatformResult{
				Platform:       target.descriptor.Platform,
				ManifestDigest: target.descriptor.Digest,
				Error:          err.Error(),
			})
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
			if limits.IsExceeded(err) {
				finalizeResult(&result, allDetailedFindings, allSuppressedDetailedFindings)
				return result, err
			}
			continue
		}

		result.PlatformResults = append(result.PlatformResults, platformResult)
		result.CompletedManifestCount++
		findingsFound += platformResult.FindingsCount
		allDetailedFindings = append(allDetailedFindings, platformFindings...)
		allSuppressedDetailedFindings = append(allSuppressedDetailedFindings, platformSuppressedFindings...)
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
	if descriptor.Digest == "" {
		return PlatformResult{}, nil, nil, fmt.Errorf("manifest digest is required")
	}

	imageManifest, err := resolveImageManifest(ctx, request, descriptor, preloaded)
	if err != nil {
		return PlatformResult{}, nil, nil, err
	}

	configBlob, err := request.Registry.OpenBlob(ctx, request.Reference.Repository, imageManifest.Config.Digest)
	if err != nil {
		return PlatformResult{}, nil, nil, fmt.Errorf("fetch config blob: %w", err)
	}
	configBody, err := readConfigBody(configBlob.Body, request.MaxConfigBytes, imageManifest.Config.Digest)
	configBlob.Body.Close()
	if err != nil {
		return PlatformResult{}, nil, nil, err
	}

	imageConfig, err := manifest.ParseImageConfig(configBody)
	if err != nil {
		return PlatformResult{}, nil, nil, err
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

	metadataFindings := scanMetadata(request.Detectors, descriptor.Digest, platform, imageConfig)
	layerResult, err := layers.Replay(ctx, imageManifest.Layers, request.MaxFileBytes, layers.OpenFunc(func(ctx context.Context, layerDescriptor manifest.Descriptor) (io.ReadCloser, error) {
		response, err := request.Registry.OpenBlob(ctx, request.Reference.Repository, layerDescriptor.Digest)
		if err != nil {
			return nil, err
		}
		return response.Body, nil
	}))
	if err != nil {
		return PlatformResult{}, nil, nil, err
	}

	fileFindings := scanArtifacts(request.Detectors, descriptor.Digest, platform, findings.SourceTypeFileFinal, true, layerResult.FinalFiles)
	fileFindings = append(fileFindings, scanArtifacts(request.Detectors, descriptor.Digest, platform, findings.SourceTypeFileDeletedLayer, false, layerResult.DeletedArtifacts)...)

	allFindings := append(metadataFindings, fileFindings...)
	actionableFindings, suppressedFindings := splitDetailedFindings(allFindings)
	if request.Logger != nil {
		request.Logger.DebugContext(ctx, "scanned platform manifest",
			"manifest_digest", descriptor.Digest,
			"platform", platform.String(),
			"findings", len(actionableFindings),
			"suppressed_findings", len(suppressedFindings),
		)
	}

	return PlatformResult{
		Platform:       platform,
		ManifestDigest: descriptor.Digest,
		FindingsCount:  len(actionableFindings),
	}, actionableFindings, suppressedFindings, nil
}

func resolveImageManifest(ctx context.Context, request Request, descriptor manifest.Descriptor, preloaded *manifest.ImageManifest) (manifest.ImageManifest, error) {
	if preloaded != nil {
		return *preloaded, nil
	}

	response, err := request.Registry.FetchManifest(ctx, request.Reference.Repository, descriptor.Digest)
	if err != nil {
		return manifest.ImageManifest{}, err
	}
	document, err := manifest.ParseDocument(response.MediaType, response.Body)
	if err != nil {
		return manifest.ImageManifest{}, err
	}
	if document.Kind != manifest.DocumentKindManifest {
		return manifest.ImageManifest{}, fmt.Errorf("digest %s did not resolve to an image manifest", descriptor.Digest)
	}

	return document.Manifest, nil
}

func scanMetadata(detectorSet detectors.Set, manifestDigest string, platform manifest.Platform, imageConfig manifest.ImageConfig) []findings.DetailedFinding {
	result := make([]findings.DetailedFinding, 0)
	envEntries := slices.Clone(imageConfig.Config.Env)
	slices.Sort(envEntries)
	for _, entry := range envEntries {
		key, _, found := strings.Cut(entry, "=")
		if !found {
			key = entry
		}
		result = append(result, scanString(detectorSet, findings.Input{
			ManifestDigest: manifestDigest,
			Platform:       platform,
			SourceType:     findings.SourceTypeEnv,
			Key:            strings.TrimSpace(key),
			Content:        entry,
		}, detectors.ScanInput{
			Content: entry,
			Key:     key,
		})...)
	}

	labelKeys := make([]string, 0, len(imageConfig.Config.Labels))
	for key := range imageConfig.Config.Labels {
		labelKeys = append(labelKeys, key)
	}
	slices.Sort(labelKeys)
	for _, key := range labelKeys {
		value := imageConfig.Config.Labels[key]
		content := key + "=" + value
		result = append(result, scanString(detectorSet, findings.Input{
			ManifestDigest: manifestDigest,
			Platform:       platform,
			SourceType:     findings.SourceTypeLabel,
			Key:            key,
			Content:        content,
		}, detectors.ScanInput{
			Content: content,
			Key:     key,
		})...)
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
			result = append(result, scanString(detectorSet, findings.Input{
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
		result = append(result, scanString(detectorSet, findings.Input{
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
	result := make([]findings.DetailedFinding, 0)
	for _, artifact := range artifacts {
		if !artifact.Scannable || len(artifact.Content) == 0 {
			continue
		}
		result = append(result, scanString(detectorSet, findings.Input{
			ManifestDigest:      manifestDigest,
			Platform:            platform,
			SourceType:          sourceType,
			FilePath:            artifact.Path,
			LayerDigest:         artifact.LayerDigest,
			Content:             string(artifact.Content),
			PresentInFinalImage: presentInFinalImage,
		}, detectors.ScanInput{
			Content: string(artifact.Content),
			Path:    artifact.Path,
		})...)
	}
	return result
}

func scanString(detectorSet detectors.Set, input findings.Input, scanInput detectors.ScanInput) []findings.DetailedFinding {
	matches := detectorSet.Scan(scanInput)
	result := make([]findings.DetailedFinding, 0, len(matches))
	for _, match := range matches {
		finding, err := findings.NormalizeDetailed(input, match)
		if err != nil {
			continue
		}
		result = append(result, finding)
	}
	return result
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

	limited := io.LimitReader(reader, maxBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read config blob: %w", err)
	}
	if int64(len(body)) > maxBytes {
		return nil, limits.NewExceeded(limits.KindConfigBytes, maxBytes, "config blob "+strings.TrimSpace(digest))
	}

	return body, nil
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
