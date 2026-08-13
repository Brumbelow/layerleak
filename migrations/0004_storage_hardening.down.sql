DROP INDEX IF EXISTS finding_occurrences_disposition_idx;
DROP INDEX IF EXISTS findings_manifest_last_seen_idx;

ALTER TABLE IF EXISTS scan_runs
    DROP CONSTRAINT IF EXISTS scan_runs_counters_nonnegative,
    DROP CONSTRAINT IF EXISTS scan_runs_status_valid,
    DROP COLUMN IF EXISTS partial_target_count;

ALTER TABLE IF EXISTS finding_occurrences
    DROP CONSTRAINT IF EXISTS finding_occurrences_seen_order,
    DROP CONSTRAINT IF EXISTS finding_occurrences_match_range_valid,
    DROP CONSTRAINT IF EXISTS finding_occurrences_line_number_valid,
    DROP CONSTRAINT IF EXISTS finding_occurrences_disposition_valid,
    DROP CONSTRAINT IF EXISTS finding_occurrences_identity_key;

ALTER TABLE IF EXISTS findings
    DROP CONSTRAINT IF EXISTS findings_seen_order,
    DROP CONSTRAINT IF EXISTS findings_fingerprint_not_blank;

ALTER TABLE IF EXISTS tags
    DROP CONSTRAINT IF EXISTS tags_seen_order,
    DROP CONSTRAINT IF EXISTS tags_status_valid,
    DROP CONSTRAINT IF EXISTS tags_name_not_blank;

ALTER TABLE IF EXISTS repository_manifests
    DROP CONSTRAINT IF EXISTS repository_manifests_seen_order,
    DROP CONSTRAINT IF EXISTS repository_manifests_scan_status_valid;

ALTER TABLE IF EXISTS manifests
    DROP CONSTRAINT IF EXISTS manifests_seen_order,
    DROP CONSTRAINT IF EXISTS manifests_scan_status_valid,
    DROP CONSTRAINT IF EXISTS manifests_digest_not_blank;

ALTER TABLE IF EXISTS repositories
    DROP CONSTRAINT IF EXISTS repositories_seen_order,
    DROP CONSTRAINT IF EXISTS repositories_repository_not_blank,
    DROP CONSTRAINT IF EXISTS repositories_registry_not_blank;

DO $$
BEGIN
    IF to_regclass('finding_occurrences') IS NOT NULL THEN
        ALTER TABLE finding_occurrences
            ADD CONSTRAINT finding_occurrences_legacy_identity_key UNIQUE (
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
            );
    END IF;
END $$;

DROP TABLE IF EXISTS schema_migrations;
