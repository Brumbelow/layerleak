package scanservice

import (
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/brumbelow/layerleak/internal/findings"
	"github.com/brumbelow/layerleak/internal/jobs"
	"github.com/brumbelow/layerleak/internal/limits"
	"github.com/brumbelow/layerleak/internal/manifest"
	"github.com/brumbelow/layerleak/internal/storage"
)

func BuildScanRecord(reference manifest.Reference, result jobs.Result, scannedAt time.Time, scanErr error) (storage.ScanRecord, error) {
	if scannedAt.IsZero() {
		scannedAt = time.Now().UTC()
	} else {
		scannedAt = scannedAt.UTC()
	}

	publicResult := normalizedPublicResult(reference, result)
	resultJSON, err := json.Marshal(publicResult)
	if err != nil {
		return storage.ScanRecord{}, err
	}

	record := storage.ScanRecord{
		Registry:                     reference.Registry,
		Repository:                   reference.Repository,
		RequestedReference:           publicResult.RequestedReference,
		ResolvedReference:            publicResult.ResolvedReference,
		RequestedDigest:              strings.TrimSpace(publicResult.RequestedDigest),
		Mode:                         publicResult.Mode,
		TagsEnumerated:               publicResult.TagsEnumerated,
		TagsResolved:                 publicResult.TagsResolved,
		TagsFailed:                   publicResult.TagsFailed,
		TargetCount:                  publicResult.TargetCount,
		CompletedTargetCount:         publicResult.CompletedTargetCount,
		FailedTargetCount:            publicResult.FailedTargetCount,
		ManifestCount:                publicResult.ManifestCount,
		CompletedManifestCount:       publicResult.CompletedManifestCount,
		FailedManifestCount:          publicResult.FailedManifestCount,
		TotalFindings:                publicResult.TotalFindings,
		UniqueFingerprints:           publicResult.UniqueFingerprints,
		SuppressedFindingsCount:      publicResult.SuppressedFindingsCount,
		SuppressedUniqueFingerprints: publicResult.SuppressedUniqueFingerprints,
		Status:                       scanRunStatus(publicResult, scanErr),
		ErrorMessage:                 scanRunErrorMessage(scanErr),
		ResultJSON:                   resultJSON,
		ScannedAt:                    scannedAt,
		DetailedFindings: findings.DeduplicateDetailed(append(
			slices.Clone(result.DetailedFindings),
			result.SuppressedDetailedFindings...,
		)),
	}

	record.Targets = make([]storage.TargetRecord, 0, len(result.Targets))
	for _, item := range result.Targets {
		requestedDigest := strings.TrimSpace(item.RequestedDigest)
		if requestedDigest == "" {
			requestedDigest = digestFromTargetReference(item.Reference)
		}

		target := storage.TargetRecord{
			Reference:         item.Reference,
			ResolvedReference: item.ResolvedReference,
			RequestedDigest:   requestedDigest,
			Tags:              slices.Clone(item.Tags),
			Error:             strings.TrimSpace(item.Error),
			Manifests:         make([]storage.ManifestRecord, 0, len(item.PlatformResults)),
		}

		if len(item.PlatformResults) == 0 && requestedDigest != "" {
			status := "scanned"
			if target.Error != "" {
				status = "failed"
			}
			target.Manifests = append(target.Manifests, storage.ManifestRecord{
				Digest:     requestedDigest,
				RootDigest: requestedDigest,
				Status:     status,
				Error:      target.Error,
			})
		}

		for _, manifestResult := range item.PlatformResults {
			manifestDigest := strings.TrimSpace(manifestResult.ManifestDigest)
			if manifestDigest == "" {
				manifestDigest = requestedDigest
			}

			status := "scanned"
			errorMessage := strings.TrimSpace(manifestResult.Error)
			if errorMessage != "" {
				status = "failed"
			}

			target.Manifests = append(target.Manifests, storage.ManifestRecord{
				Digest:     manifestDigest,
				RootDigest: firstNonEmpty(requestedDigest, manifestDigest),
				Platform:   manifestResult.Platform,
				Status:     status,
				Error:      errorMessage,
			})
		}

		record.Targets = append(record.Targets, target)
	}

	record.Tags = buildTagRecords(result.TagResults, record.Targets)

	return record, nil
}

func buildTagRecords(tagResults []jobs.TagResult, targets []storage.TargetRecord) []storage.TagRecord {
	output := make([]storage.TagRecord, 0)
	seen := make(map[string]struct{})

	appendTag := func(item storage.TagRecord) {
		item.Name = strings.TrimSpace(item.Name)
		item.RootDigest = strings.TrimSpace(item.RootDigest)
		item.ManifestDigest = strings.TrimSpace(item.ManifestDigest)
		item.Status = strings.TrimSpace(item.Status)
		item.Error = strings.TrimSpace(item.Error)
		if item.Name == "" || item.Status == "" {
			return
		}
		key := strings.Join([]string{
			item.Name,
			item.RootDigest,
			item.ManifestDigest,
			item.Platform.String(),
			item.Status,
			item.Error,
		}, "|")
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		output = append(output, item)
	}

	for _, target := range targets {
		rootDigest := strings.TrimSpace(target.RequestedDigest)
		if rootDigest == "" {
			rootDigest = digestFromTargetReference(target.Reference)
		}
		for _, tag := range target.Tags {
			if len(target.Manifests) == 0 {
				appendTag(storage.TagRecord{
					Name:           tag,
					RootDigest:     rootDigest,
					ManifestDigest: rootDigest,
					Status:         statusFromError(target.Error),
					Error:          target.Error,
				})
				continue
			}

			for _, manifestRecord := range target.Manifests {
				appendTag(storage.TagRecord{
					Name:           tag,
					RootDigest:     firstNonEmpty(manifestRecord.RootDigest, rootDigest, manifestRecord.Digest),
					ManifestDigest: manifestRecord.Digest,
					Platform:       manifestRecord.Platform,
					Status:         manifestRecord.Status,
					Error:          manifestRecord.Error,
				})
			}
		}
	}

	for _, item := range tagResults {
		if item.Status != "failed" {
			continue
		}
		appendTag(storage.TagRecord{
			Name:           item.Tag,
			RootDigest:     strings.TrimSpace(item.RootDigest),
			ManifestDigest: strings.TrimSpace(item.RootDigest),
			Status:         "failed",
			Error:          strings.TrimSpace(item.Error),
		})
	}

	slices.SortFunc(output, func(left, right storage.TagRecord) int {
		if value := strings.Compare(left.Name, right.Name); value != 0 {
			return value
		}
		if value := strings.Compare(left.ManifestDigest, right.ManifestDigest); value != 0 {
			return value
		}
		return strings.Compare(left.Platform.String(), right.Platform.String())
	})

	return output
}

func statusFromError(value string) string {
	if strings.TrimSpace(value) != "" {
		return "failed"
	}
	return "scanned"
}

func digestFromTargetReference(value string) string {
	reference, err := manifest.ParseReference(value)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(reference.Digest)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func normalizedPublicResult(reference manifest.Reference, result jobs.Result) jobs.Result {
	publicResult := result
	if strings.TrimSpace(publicResult.RequestedReference) == "" {
		publicResult.RequestedReference = reference.Original
	}
	if strings.TrimSpace(publicResult.Repository) == "" {
		publicResult.Repository = reference.Repository
	}
	if strings.TrimSpace(publicResult.RequestedDigest) == "" {
		publicResult.RequestedDigest = strings.TrimSpace(reference.Digest)
	}
	if strings.TrimSpace(publicResult.Mode) == "" {
		if reference.IsRepositoryOnly() {
			publicResult.Mode = "repository"
		} else {
			publicResult.Mode = "reference"
		}
	}
	return publicResult
}

func scanRunStatus(result jobs.Result, scanErr error) storage.ScanRunStatus {
	if scanErr != nil {
		if limits.IsExceeded(scanErr) {
			return storage.ScanRunStatusPartial
		}
		return storage.ScanRunStatusFailed
	}
	if result.TagsFailed > 0 || result.FailedTargetCount > 0 || result.FailedManifestCount > 0 {
		return storage.ScanRunStatusPartial
	}
	return storage.ScanRunStatusCompleted
}

func scanRunErrorMessage(scanErr error) string {
	if scanErr == nil {
		return ""
	}
	return strings.TrimSpace(scanErr.Error())
}
