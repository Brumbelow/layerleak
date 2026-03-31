package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/brumbelow/layerleak/internal/findings"
	"github.com/brumbelow/layerleak/internal/manifest"
	"github.com/lib/pq"
)

func (s *PostgresStore) ListRepositories(ctx context.Context, limit, offset int) ([]RepositorySummary, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("postgres store is not initialized")
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT registry, repository, first_seen_at, last_seen_at
		FROM repositories
		ORDER BY last_seen_at DESC, repository ASC
		LIMIT $1 OFFSET $2
	`, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list repositories: %w", err)
	}
	defer rows.Close()

	items := make([]RepositorySummary, 0)
	for rows.Next() {
		var item RepositorySummary
		if err := rows.Scan(&item.Registry, &item.Repository, &item.FirstSeenAt, &item.LastSeenAt); err != nil {
			return nil, fmt.Errorf("scan repository summary: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate repository summaries: %w", err)
	}

	return items, nil
}

func (s *PostgresStore) ListRepositoryScans(ctx context.Context, repository string, limit, offset int) ([]ScanRunSummary, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("postgres store is not initialized")
	}

	repository = strings.TrimSpace(repository)
	if repository == "" {
		return nil, fmt.Errorf("repository is required")
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT
			sr.id,
			sr.requested_reference,
			sr.resolved_reference,
			sr.requested_digest,
			sr.mode,
			sr.status,
			sr.error_message,
			sr.scanned_at,
			sr.tags_enumerated,
			sr.tags_resolved,
			sr.tags_failed,
			sr.target_count,
			sr.completed_target_count,
			sr.failed_target_count,
			sr.manifest_count,
			sr.completed_manifest_count,
			sr.failed_manifest_count,
			sr.total_findings,
			sr.unique_fingerprints,
			sr.suppressed_findings_count,
			sr.suppressed_unique_fingerprints
		FROM scan_runs sr
		JOIN repositories r ON r.id = sr.repository_id
		WHERE r.registry = $1 AND r.repository = $2
		ORDER BY sr.scanned_at DESC, sr.id DESC
		LIMIT $3 OFFSET $4
	`, manifest.DockerHubRegistry, repository, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list repository scans: %w", err)
	}
	defer rows.Close()

	items := make([]ScanRunSummary, 0)
	for rows.Next() {
		item, err := scanScanRunSummary(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate repository scans: %w", err)
	}

	return items, nil
}

func (s *PostgresStore) ListRepositoryFindings(ctx context.Context, repository string, disposition FindingDispositionFilter, limit, offset int) ([]FindingSummary, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("postgres store is not initialized")
	}

	disposition = normalizeFindingDispositionFilter(disposition)
	repository = strings.TrimSpace(repository)
	if repository == "" {
		return nil, fmt.Errorf("repository is required")
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT
			f.id,
			f.manifest_digest,
			f.fingerprint,
			f.redacted_value,
			f.first_seen_at,
			f.last_seen_at,
			COUNT(fo.id) AS occurrence_count,
			COUNT(*) FILTER (WHERE fo.disposition = $3) AS actionable_occurrence_count,
			COUNT(*) FILTER (WHERE fo.disposition = $4) AS suppressed_occurrence_count,
			COALESCE(ARRAY_AGG(DISTINCT fo.detector_name ORDER BY fo.detector_name), ARRAY[]::TEXT[]) AS detectors
		FROM repositories r
		JOIN repository_manifests rm ON rm.repository_id = r.id
		JOIN findings f ON f.manifest_digest = rm.manifest_digest
		JOIN finding_occurrences fo ON fo.finding_id = f.id
		WHERE r.registry = $1 AND r.repository = $2
		GROUP BY f.id
		HAVING
			CASE $5
				WHEN 'actionable' THEN COUNT(*) FILTER (WHERE fo.disposition = $3) > 0
				WHEN 'suppressed' THEN COUNT(*) FILTER (WHERE fo.disposition = $4) > 0
				ELSE TRUE
			END
		ORDER BY f.last_seen_at DESC, f.id DESC
		LIMIT $6 OFFSET $7
	`, manifest.DockerHubRegistry, repository, string(findings.DispositionActionable), string(findings.DispositionExample), string(disposition), limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list repository findings: %w", err)
	}
	defer rows.Close()

	items := make([]FindingSummary, 0)
	for rows.Next() {
		item, err := scanFindingSummary(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate repository findings: %w", err)
	}

	return items, nil
}

func (s *PostgresStore) GetScanRun(ctx context.Context, id int64) (ScanRunDetail, error) {
	if s == nil || s.db == nil {
		return ScanRunDetail{}, fmt.Errorf("postgres store is not initialized")
	}

	row := s.db.QueryRowContext(ctx, `
		SELECT
			sr.id,
			r.registry,
			r.repository,
			sr.requested_reference,
			sr.resolved_reference,
			sr.requested_digest,
			sr.mode,
			sr.status,
			sr.error_message,
			sr.scanned_at,
			sr.tags_enumerated,
			sr.tags_resolved,
			sr.tags_failed,
			sr.target_count,
			sr.completed_target_count,
			sr.failed_target_count,
			sr.manifest_count,
			sr.completed_manifest_count,
			sr.failed_manifest_count,
			sr.total_findings,
			sr.unique_fingerprints,
			sr.suppressed_findings_count,
			sr.suppressed_unique_fingerprints,
			sr.result_json
		FROM scan_runs sr
		JOIN repositories r ON r.id = sr.repository_id
		WHERE sr.id = $1
	`, id)

	var item ScanRunDetail
	var status string
	var resultJSON []byte
	if err := row.Scan(
		&item.ID,
		&item.Registry,
		&item.Repository,
		&item.RequestedReference,
		&item.ResolvedReference,
		&item.RequestedDigest,
		&item.Mode,
		&status,
		&item.ErrorMessage,
		&item.ScannedAt,
		&item.TagsEnumerated,
		&item.TagsResolved,
		&item.TagsFailed,
		&item.TargetCount,
		&item.CompletedTargetCount,
		&item.FailedTargetCount,
		&item.ManifestCount,
		&item.CompletedManifestCount,
		&item.FailedManifestCount,
		&item.TotalFindings,
		&item.UniqueFingerprints,
		&item.SuppressedFindingsCount,
		&item.SuppressedUniqueFingerprints,
		&resultJSON,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ScanRunDetail{}, ErrNotFound
		}
		return ScanRunDetail{}, fmt.Errorf("get scan run: %w", err)
	}

	item.Status = ScanRunStatus(status)
	item.ResultJSON = json.RawMessage(resultJSON)
	return item, nil
}

func (s *PostgresStore) GetFinding(ctx context.Context, id int64) (FindingDetail, error) {
	if s == nil || s.db == nil {
		return FindingDetail{}, fmt.Errorf("postgres store is not initialized")
	}

	row := s.db.QueryRowContext(ctx, `
		SELECT
			f.id,
			f.manifest_digest,
			f.fingerprint,
			f.redacted_value,
			f.first_seen_at,
			f.last_seen_at,
			COUNT(fo.id) AS occurrence_count,
			COUNT(*) FILTER (WHERE fo.disposition = $2) AS actionable_occurrence_count,
			COUNT(*) FILTER (WHERE fo.disposition = $3) AS suppressed_occurrence_count,
			COALESCE(ARRAY_AGG(DISTINCT fo.detector_name ORDER BY fo.detector_name), ARRAY[]::TEXT[]) AS detectors
		FROM findings f
		JOIN finding_occurrences fo ON fo.finding_id = f.id
		WHERE f.id = $1
		GROUP BY f.id
	`, id, string(findings.DispositionActionable), string(findings.DispositionExample))

	summary, err := scanFindingSummary(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return FindingDetail{}, ErrNotFound
		}
		return FindingDetail{}, err
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT
			detector_name,
			confidence,
			disposition,
			disposition_reason,
			source_type,
			platform_os,
			platform_architecture,
			platform_variant,
			file_path,
			layer_digest,
			source_key,
			line_number,
			context_snippet,
			source_location,
			match_start,
			match_end,
			present_in_final_image,
			first_seen_at,
			last_seen_at
		FROM finding_occurrences
		WHERE finding_id = $1
		ORDER BY last_seen_at DESC, source_location ASC, id ASC
	`, id)
	if err != nil {
		return FindingDetail{}, fmt.Errorf("query finding occurrences: %w", err)
	}
	defer rows.Close()

	occurrences := make([]FindingOccurrence, 0)
	for rows.Next() {
		var item FindingOccurrence
		var disposition string
		var dispositionReason string
		var sourceType string
		if err := rows.Scan(
			&item.DetectorName,
			&item.Confidence,
			&disposition,
			&dispositionReason,
			&sourceType,
			&item.Platform.OS,
			&item.Platform.Architecture,
			&item.Platform.Variant,
			&item.FilePath,
			&item.LayerDigest,
			&item.Key,
			&item.LineNumber,
			&item.ContextSnippet,
			&item.SourceLocation,
			&item.MatchStart,
			&item.MatchEnd,
			&item.PresentInFinalImage,
			&item.FirstSeenAt,
			&item.LastSeenAt,
		); err != nil {
			return FindingDetail{}, fmt.Errorf("scan finding occurrence: %w", err)
		}
		item.Disposition = findings.Disposition(disposition)
		item.DispositionReason = findings.DispositionReason(dispositionReason)
		item.SourceType = findings.SourceType(sourceType)
		occurrences = append(occurrences, item)
	}
	if err := rows.Err(); err != nil {
		return FindingDetail{}, fmt.Errorf("iterate finding occurrences: %w", err)
	}

	return FindingDetail{
		FindingSummary: summary,
		Occurrences:    occurrences,
	}, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanScanRunSummary(scanner rowScanner) (ScanRunSummary, error) {
	var item ScanRunSummary
	var status string
	if err := scanner.Scan(
		&item.ID,
		&item.RequestedReference,
		&item.ResolvedReference,
		&item.RequestedDigest,
		&item.Mode,
		&status,
		&item.ErrorMessage,
		&item.ScannedAt,
		&item.TagsEnumerated,
		&item.TagsResolved,
		&item.TagsFailed,
		&item.TargetCount,
		&item.CompletedTargetCount,
		&item.FailedTargetCount,
		&item.ManifestCount,
		&item.CompletedManifestCount,
		&item.FailedManifestCount,
		&item.TotalFindings,
		&item.UniqueFingerprints,
		&item.SuppressedFindingsCount,
		&item.SuppressedUniqueFingerprints,
	); err != nil {
		return ScanRunSummary{}, fmt.Errorf("scan scan run summary: %w", err)
	}
	item.Status = ScanRunStatus(status)
	return item, nil
}

func scanFindingSummary(scanner rowScanner) (FindingSummary, error) {
	var item FindingSummary
	var detectors pq.StringArray
	if err := scanner.Scan(
		&item.ID,
		&item.ManifestDigest,
		&item.Fingerprint,
		&item.RedactedValue,
		&item.FirstSeenAt,
		&item.LastSeenAt,
		&item.OccurrenceCount,
		&item.ActionableOccurrenceCount,
		&item.SuppressedOccurrenceCount,
		&detectors,
	); err != nil {
		return FindingSummary{}, fmt.Errorf("scan finding summary: %w", err)
	}
	item.Detectors = []string(detectors)
	return item, nil
}

func normalizeFindingDispositionFilter(value FindingDispositionFilter) FindingDispositionFilter {
	switch FindingDispositionFilter(strings.TrimSpace(string(value))) {
	case FindingDispositionActionable:
		return FindingDispositionActionable
	case FindingDispositionSuppressed:
		return FindingDispositionSuppressed
	default:
		return FindingDispositionAll
	}
}
