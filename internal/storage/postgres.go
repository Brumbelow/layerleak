package storage

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/brumbelow/layerleak/internal/findings"
	"github.com/brumbelow/layerleak/internal/manifest"
	"github.com/lib/pq"
)

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore(config PostgresConfig) (*PostgresStore, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	db, err := sql.Open("postgres", strings.TrimSpace(config.DatabaseURL))
	if err != nil {
		return nil, fmt.Errorf("open postgres connection: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	return &PostgresStore{db: db}, nil
}

func (s *PostgresStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *PostgresStore) Name() string {
	return "postgres"
}

func (s *PostgresStore) SaveScan(ctx context.Context, record ScanRecord) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("postgres store is not initialized")
	}
	if err := validateScanRecord(record); err != nil {
		return err
	}

	scannedAt := record.ScannedAt.UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin scan transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	repositoryID, err := upsertRepository(ctx, tx, record, scannedAt)
	if err != nil {
		return err
	}

	for _, item := range collectManifestRecords(record) {
		if err := upsertManifest(ctx, tx, item, scannedAt); err != nil {
			return err
		}
		if err := upsertRepositoryManifest(ctx, tx, repositoryID, item, scannedAt); err != nil {
			return err
		}
	}

	if err := replaceTagMappings(ctx, tx, repositoryID, normalizeTagRecords(record.Tags), scannedAt); err != nil {
		return err
	}

	for _, item := range findings.DeduplicateDetailed(record.DetailedFindings) {
		findingID, err := upsertFinding(ctx, tx, item, scannedAt)
		if err != nil {
			return err
		}
		if err := upsertFindingOccurrence(ctx, tx, findingID, item, scannedAt); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit scan transaction: %w", err)
	}

	return nil
}

func upsertRepository(ctx context.Context, tx *sql.Tx, record ScanRecord, scannedAt time.Time) (int64, error) {
	var repositoryID int64
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO repositories (registry, repository, first_seen_at, last_seen_at)
		VALUES ($1, $2, $3, $3)
		ON CONFLICT (registry, repository)
		DO UPDATE SET last_seen_at = EXCLUDED.last_seen_at
		RETURNING id
	`, strings.TrimSpace(record.Registry), strings.TrimSpace(record.Repository), scannedAt).Scan(&repositoryID); err != nil {
		return 0, fmt.Errorf("upsert repository: %w", err)
	}

	return repositoryID, nil
}

func upsertManifest(ctx context.Context, tx *sql.Tx, item ManifestRecord, scannedAt time.Time) error {
	item = normalizeManifestRecord(item)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO manifests (
			digest,
			platform_os,
			platform_architecture,
			platform_variant,
			first_seen_at,
			last_seen_at,
			last_scan_status,
			last_scan_error
		)
		VALUES ($1, $2, $3, $4, $5, $5, $6, $7)
		ON CONFLICT (digest)
		DO UPDATE SET
			platform_os = CASE
				WHEN EXCLUDED.platform_os <> '' THEN EXCLUDED.platform_os
				ELSE manifests.platform_os
			END,
			platform_architecture = CASE
				WHEN EXCLUDED.platform_architecture <> '' THEN EXCLUDED.platform_architecture
				ELSE manifests.platform_architecture
			END,
			platform_variant = CASE
				WHEN EXCLUDED.platform_variant <> '' THEN EXCLUDED.platform_variant
				ELSE manifests.platform_variant
			END,
			last_seen_at = EXCLUDED.last_seen_at,
			last_scan_status = EXCLUDED.last_scan_status,
			last_scan_error = EXCLUDED.last_scan_error
	`, item.Digest, item.Platform.OS, item.Platform.Architecture, item.Platform.Variant, scannedAt, item.Status, item.Error); err != nil {
		return fmt.Errorf("upsert manifest %s: %w", item.Digest, err)
	}

	return nil
}

func upsertRepositoryManifest(ctx context.Context, tx *sql.Tx, repositoryID int64, item ManifestRecord, scannedAt time.Time) error {
	item = normalizeManifestRecord(item)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO repository_manifests (
			repository_id,
			manifest_digest,
			root_digest,
			first_seen_at,
			last_seen_at,
			last_scan_status,
			last_scan_error
		)
		VALUES ($1, $2, $3, $4, $4, $5, $6)
		ON CONFLICT (repository_id, manifest_digest)
		DO UPDATE SET
			root_digest = EXCLUDED.root_digest,
			last_seen_at = EXCLUDED.last_seen_at,
			last_scan_status = EXCLUDED.last_scan_status,
			last_scan_error = EXCLUDED.last_scan_error
	`, repositoryID, item.Digest, item.RootDigest, scannedAt, item.Status, item.Error); err != nil {
		return fmt.Errorf("upsert repository manifest %s: %w", item.Digest, err)
	}

	return nil
}

func replaceTagMappings(ctx context.Context, tx *sql.Tx, repositoryID int64, items []TagRecord, scannedAt time.Time) error {
	tagNames := uniqueTagNames(items)
	if len(tagNames) > 0 {
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM tags
			WHERE repository_id = $1 AND tag = ANY($2)
		`, repositoryID, pq.Array(tagNames)); err != nil {
			return fmt.Errorf("delete existing tag mappings: %w", err)
		}
	}

	for _, item := range items {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO tags (
				repository_id,
				tag,
				manifest_digest,
				root_digest,
				platform_os,
				platform_architecture,
				platform_variant,
				status,
				error,
				first_seen_at,
				last_seen_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10)
		`, repositoryID, item.Name, item.ManifestDigest, item.RootDigest, item.Platform.OS, item.Platform.Architecture, item.Platform.Variant, item.Status, item.Error, scannedAt); err != nil {
			return fmt.Errorf("insert tag mapping %s: %w", item.Name, err)
		}
	}

	return nil
}

func upsertFinding(ctx context.Context, tx *sql.Tx, item findings.DetailedFinding, scannedAt time.Time) (int64, error) {
	var findingID int64
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO findings (
			manifest_digest,
			fingerprint,
			redacted_value,
			value,
			first_seen_at,
			last_seen_at
		)
		VALUES ($1, $2, $3, $4, $5, $5)
		ON CONFLICT (manifest_digest, fingerprint)
		DO UPDATE SET
			redacted_value = EXCLUDED.redacted_value,
			value = EXCLUDED.value,
			last_seen_at = EXCLUDED.last_seen_at
		RETURNING id
	`, strings.TrimSpace(item.ManifestDigest), strings.TrimSpace(item.Fingerprint), item.RedactedValue, item.Value, scannedAt).Scan(&findingID); err != nil {
		return 0, fmt.Errorf("upsert finding %s/%s: %w", item.ManifestDigest, item.Fingerprint, err)
	}

	return findingID, nil
}

func upsertFindingOccurrence(ctx context.Context, tx *sql.Tx, findingID int64, item findings.DetailedFinding, scannedAt time.Time) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO finding_occurrences (
			finding_id,
			detector_name,
			confidence,
			source_type,
			platform_os,
			platform_architecture,
			platform_variant,
			file_path,
			layer_digest,
			source_key,
			context_snippet,
			raw_snippet,
			source_location,
			match_start,
			match_end,
			present_in_final_image,
			first_seen_at,
			last_seen_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $17)
		ON CONFLICT (
			finding_id,
			detector_name,
			confidence,
			source_type,
			platform_os,
			platform_architecture,
			platform_variant,
			file_path,
			layer_digest,
			source_key,
			context_snippet,
			raw_snippet,
			source_location,
			match_start,
			match_end,
			present_in_final_image
		)
		DO UPDATE SET last_seen_at = EXCLUDED.last_seen_at
	`, findingID, item.DetectorName, item.Confidence, string(item.SourceType), item.Platform.OS, item.Platform.Architecture, item.Platform.Variant, item.FilePath, item.LayerDigest, item.Key, item.ContextSnippet, item.RawSnippet, item.SourceLocation, item.MatchStart, item.MatchEnd, item.PresentInFinalImage, scannedAt); err != nil {
		return fmt.Errorf("upsert finding occurrence %s/%s: %w", item.ManifestDigest, item.Fingerprint, err)
	}

	return nil
}

func collectManifestRecords(record ScanRecord) []ManifestRecord {
	manifestsByDigest := make(map[string]ManifestRecord)
	for _, target := range record.Targets {
		rootDigest := strings.TrimSpace(target.RequestedDigest)
		if rootDigest == "" {
			rootDigest = digestFromReference(target.Reference)
		}

		for _, item := range target.Manifests {
			item.RootDigest = firstNonEmpty(item.RootDigest, rootDigest, item.Digest)
			upsertManifestRecord(manifestsByDigest, item)
		}

		if len(target.Manifests) == 0 && rootDigest != "" && strings.TrimSpace(target.Error) != "" {
			upsertManifestRecord(manifestsByDigest, ManifestRecord{
				Digest:     rootDigest,
				RootDigest: rootDigest,
				Status:     "failed",
				Error:      strings.TrimSpace(target.Error),
			})
		}
	}

	for _, item := range record.DetailedFindings {
		upsertManifestRecord(manifestsByDigest, ManifestRecord{
			Digest:     strings.TrimSpace(item.ManifestDigest),
			RootDigest: strings.TrimSpace(item.ManifestDigest),
			Platform:   item.Platform,
			Status:     "scanned",
		})
	}

	items := make([]ManifestRecord, 0, len(manifestsByDigest))
	for _, item := range manifestsByDigest {
		items = append(items, normalizeManifestRecord(item))
	}
	slices.SortFunc(items, func(left, right ManifestRecord) int {
		return strings.Compare(left.Digest, right.Digest)
	})

	return items
}

func upsertManifestRecord(items map[string]ManifestRecord, incoming ManifestRecord) {
	incoming = normalizeManifestRecord(incoming)
	if incoming.Digest == "" {
		return
	}

	current, ok := items[incoming.Digest]
	if !ok {
		items[incoming.Digest] = incoming
		return
	}

	current.RootDigest = firstNonEmpty(current.RootDigest, incoming.RootDigest, current.Digest)
	current.Platform = mergePlatform(current.Platform, incoming.Platform)
	switch {
	case current.Status == "scanned":
	case incoming.Status == "scanned":
		current.Status = incoming.Status
		current.Error = ""
	case current.Status == "":
		current.Status = incoming.Status
		current.Error = incoming.Error
	case current.Status == "failed" && incoming.Error != "":
		current.Error = incoming.Error
	}
	if current.Error == "" && incoming.Error != "" && current.Status != "scanned" {
		current.Error = incoming.Error
	}

	items[incoming.Digest] = current
}

func normalizeManifestRecord(item ManifestRecord) ManifestRecord {
	item.Digest = strings.TrimSpace(item.Digest)
	item.RootDigest = firstNonEmpty(strings.TrimSpace(item.RootDigest), item.Digest)
	item.Status = strings.TrimSpace(item.Status)
	item.Error = strings.TrimSpace(item.Error)
	item.Platform = manifest.Platform{
		OS:           strings.TrimSpace(item.Platform.OS),
		Architecture: strings.TrimSpace(item.Platform.Architecture),
		Variant:      strings.TrimSpace(item.Platform.Variant),
	}
	if item.Status == "" {
		item.Status = "scanned"
	}

	return item
}

func normalizeTagRecords(items []TagRecord) []TagRecord {
	normalized := make([]TagRecord, 0, len(items))
	seen := make(map[string]struct{})
	for _, item := range items {
		item = TagRecord{
			Name:           strings.TrimSpace(item.Name),
			RootDigest:     strings.TrimSpace(item.RootDigest),
			ManifestDigest: strings.TrimSpace(item.ManifestDigest),
			Platform: manifest.Platform{
				OS:           strings.TrimSpace(item.Platform.OS),
				Architecture: strings.TrimSpace(item.Platform.Architecture),
				Variant:      strings.TrimSpace(item.Platform.Variant),
			},
			Status: strings.TrimSpace(item.Status),
			Error:  strings.TrimSpace(item.Error),
		}
		if item.Name == "" || item.Status == "" {
			continue
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
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, item)
	}

	slices.SortFunc(normalized, func(left, right TagRecord) int {
		if value := strings.Compare(left.Name, right.Name); value != 0 {
			return value
		}
		if value := strings.Compare(left.ManifestDigest, right.ManifestDigest); value != 0 {
			return value
		}
		return strings.Compare(left.Platform.String(), right.Platform.String())
	})

	return normalized
}

func uniqueTagNames(items []TagRecord) []string {
	seen := make(map[string]struct{})
	output := make([]string, 0, len(items))
	for _, item := range items {
		name := strings.TrimSpace(item.Name)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		output = append(output, name)
	}
	slices.Sort(output)
	return output
}

func mergePlatform(current, incoming manifest.Platform) manifest.Platform {
	if strings.TrimSpace(current.OS) == "" {
		current.OS = strings.TrimSpace(incoming.OS)
	}
	if strings.TrimSpace(current.Architecture) == "" {
		current.Architecture = strings.TrimSpace(incoming.Architecture)
	}
	if strings.TrimSpace(current.Variant) == "" {
		current.Variant = strings.TrimSpace(incoming.Variant)
	}

	return current
}

func digestFromReference(value string) string {
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
