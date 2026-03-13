package scanner

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"

	"git.tools.cloudfor.ge/andrew/layerleak/internal/detectors"
	"git.tools.cloudfor.ge/andrew/layerleak/internal/findings"
	"git.tools.cloudfor.ge/andrew/layerleak/internal/layers"
	"git.tools.cloudfor.ge/andrew/layerleak/internal/manifest"
	"git.tools.cloudfor.ge/andrew/layerleak/internal/registry"
)

type Request struct {
	Reference    manifest.Reference
	Platform     string
	Registry     *registry.Client
	Detectors    detectors.Set
	Logger       *slog.Logger
	MaxFileBytes int64
}

type Result struct {
	RequestedReference     string             `json:"requested_reference"`
	ResolvedReference      string             `json:"resolved_reference"`
	RequestedDigest        string             `json:"requested_digest"`
	ManifestCount          int                `json:"manifest_count"`
	CompletedManifestCount int                `json:"completed_manifest_count"`
	FailedManifestCount    int                `json:"failed_manifest_count"`
	PlatformResults        []PlatformResult   `json:"platform_results"`
	Findings               []findings.Finding `json:"findings"`
	TotalFindings          int                `json:"total_findings"`
	UniqueFingerprints     int                `json:"unique_fingerprints"`
}

type PlatformResult struct {
	Platform       manifest.Platform `json:"platform,omitempty"`
	ManifestDigest string            `json:"manifest_digest"`
	FindingsCount  int               `json:"findings_count"`
	Error          string            `json:"error,omitempty"`
}

func Scan(ctx context.Context, request Request) (Result, error) {
	if request.Registry == nil {
		return Result{}, fmt.Errorf("registry client is required")
	}
	if request.MaxFileBytes <= 0 {
		request.MaxFileBytes = 1 << 20
	}

	rootResponse, err := request.Registry.FetchManifest(ctx, request.Reference.Repository, request.Reference.Identifier())
	if err != nil {
		return Result{}, err
	}

	document, err := manifest.ParseDocument(rootResponse.MediaType, rootResponse.Body)
	if err != nil {
		return Result{}, err
	}

	requestedDigest := firstNonEmpty(rootResponse.Digest, request.Reference.Digest)
	if requestedDigest == "" {
		return Result{}, fmt.Errorf("registry did not return a resolved digest for %s", request.Reference.Original)
	}

	result := Result{
		RequestedReference: request.Reference.Original,
		ResolvedReference:  request.Reference.CanonicalString(requestedDigest),
		RequestedDigest:    requestedDigest,
	}

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
			return Result{}, err
		}
		for _, descriptor := range selected {
			targets = append(targets, target{descriptor: descriptor})
		}
	default:
		return Result{}, fmt.Errorf("unsupported manifest document kind: %s", document.Kind)
	}

	result.ManifestCount = len(targets)

	allFindings := make([]findings.Finding, 0)
	for _, target := range targets {
		platformResult, platformFindings, err := scanManifest(ctx, request, target.descriptor, target.manifest)
		if err != nil {
			result.PlatformResults = append(result.PlatformResults, PlatformResult{
				Platform:       target.descriptor.Platform,
				ManifestDigest: target.descriptor.Digest,
				Error:          err.Error(),
			})
			result.FailedManifestCount++
			continue
		}

		result.PlatformResults = append(result.PlatformResults, platformResult)
		result.CompletedManifestCount++
		allFindings = append(allFindings, platformFindings...)
	}

	if result.CompletedManifestCount == 0 {
		return result, fmt.Errorf("all selected manifests failed")
	}

	result.Findings = findings.Deduplicate(allFindings)
	result.TotalFindings = len(result.Findings)
	result.UniqueFingerprints = findings.UniqueFingerprintCount(result.Findings)
	sortPlatformResults(result.PlatformResults)

	return result, nil
}

func scanManifest(ctx context.Context, request Request, descriptor manifest.Descriptor, preloaded *manifest.ImageManifest) (PlatformResult, []findings.Finding, error) {
	if descriptor.Digest == "" {
		return PlatformResult{}, nil, fmt.Errorf("manifest digest is required")
	}

	imageManifest, err := resolveImageManifest(ctx, request, descriptor, preloaded)
	if err != nil {
		return PlatformResult{}, nil, err
	}

	configBlob, err := request.Registry.OpenBlob(ctx, request.Reference.Repository, imageManifest.Config.Digest)
	if err != nil {
		return PlatformResult{}, nil, fmt.Errorf("fetch config blob: %w", err)
	}
	configBody, err := io.ReadAll(configBlob.Body)
	configBlob.Body.Close()
	if err != nil {
		return PlatformResult{}, nil, fmt.Errorf("read config blob: %w", err)
	}

	imageConfig, err := manifest.ParseImageConfig(configBody)
	if err != nil {
		return PlatformResult{}, nil, err
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
		return PlatformResult{}, nil, err
	}

	fileFindings := scanArtifacts(request.Detectors, descriptor.Digest, platform, findings.SourceTypeFileFinal, true, layerResult.FinalFiles)
	fileFindings = append(fileFindings, scanArtifacts(request.Detectors, descriptor.Digest, platform, findings.SourceTypeFileDeletedLayer, false, layerResult.DeletedArtifacts)...)

	allFindings := append(metadataFindings, fileFindings...)
	if request.Logger != nil {
		request.Logger.DebugContext(ctx, "scanned platform manifest",
			"manifest_digest", descriptor.Digest,
			"platform", platform.String(),
			"findings", len(allFindings),
		)
	}

	return PlatformResult{
		Platform:       platform,
		ManifestDigest: descriptor.Digest,
		FindingsCount:  len(allFindings),
	}, allFindings, nil
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

func scanMetadata(detectorSet detectors.Set, manifestDigest string, platform manifest.Platform, imageConfig manifest.ImageConfig) []findings.Finding {
	result := make([]findings.Finding, 0)
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

func scanArtifacts(detectorSet detectors.Set, manifestDigest string, platform manifest.Platform, sourceType findings.SourceType, presentInFinalImage bool, artifacts []layers.Artifact) []findings.Finding {
	result := make([]findings.Finding, 0)
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

func scanString(detectorSet detectors.Set, input findings.Input, scanInput detectors.ScanInput) []findings.Finding {
	matches := detectorSet.Scan(scanInput)
	result := make([]findings.Finding, 0, len(matches))
	for _, match := range matches {
		finding, err := findings.Normalize(input, match)
		if err != nil {
			continue
		}
		result = append(result, finding)
	}
	return result
}

func sortPlatformResults(items []PlatformResult) {
	slices.SortFunc(items, func(left, right PlatformResult) int {
		if value := strings.Compare(left.Platform.String(), right.Platform.String()); value != 0 {
			return value
		}
		return strings.Compare(left.ManifestDigest, right.ManifestDigest)
	})
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
