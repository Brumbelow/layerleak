CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE scan_runs
    ADD COLUMN partial_target_count INTEGER NOT NULL DEFAULT 0;

LOCK TABLE finding_occurrences IN SHARE ROW EXCLUSIVE MODE;

WITH ranked AS (
    SELECT
        id,
        ROW_NUMBER() OVER identity_ordered_window AS row_number,
        MIN(first_seen_at) OVER identity_window AS earliest_seen_at,
        MAX(last_seen_at) OVER identity_window AS latest_seen_at,
        FIRST_VALUE(raw_snippet) OVER (
            PARTITION BY
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
                source_location,
                match_start,
                match_end,
                present_in_final_image
            ORDER BY (raw_snippet <> '') DESC, last_seen_at DESC, id DESC
        ) AS retained_raw_snippet
    FROM finding_occurrences
    WINDOW identity_window AS (
        PARTITION BY
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
            source_location,
            match_start,
            match_end,
            present_in_final_image
		ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING
	),
	identity_ordered_window AS (
		PARTITION BY
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
			source_location,
			match_start,
			match_end,
			present_in_final_image
		ORDER BY last_seen_at DESC, id DESC
    )
)
UPDATE finding_occurrences AS occurrence
SET
    first_seen_at = ranked.earliest_seen_at,
    last_seen_at = ranked.latest_seen_at,
    raw_snippet = ranked.retained_raw_snippet
FROM ranked
WHERE occurrence.id = ranked.id
  AND ranked.row_number = 1;

WITH ranked AS (
    SELECT
        id,
        ROW_NUMBER() OVER (
            PARTITION BY
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
                source_location,
                match_start,
                match_end,
                present_in_final_image
            ORDER BY last_seen_at DESC, id DESC
        ) AS row_number
    FROM finding_occurrences
)
DELETE FROM finding_occurrences AS occurrence
USING ranked
WHERE occurrence.id = ranked.id
  AND ranked.row_number > 1;

-- Older writers replaced last_seen_at even when an out-of-order scan arrived.
-- Repair those rows before enforcing timestamp ordering on upgraded databases.
UPDATE repositories
SET
    first_seen_at = LEAST(first_seen_at, last_seen_at),
    last_seen_at = GREATEST(first_seen_at, last_seen_at)
WHERE first_seen_at > last_seen_at;

UPDATE manifests
SET
    first_seen_at = LEAST(first_seen_at, last_seen_at),
    last_seen_at = GREATEST(first_seen_at, last_seen_at)
WHERE first_seen_at > last_seen_at;

UPDATE repository_manifests
SET
    first_seen_at = LEAST(first_seen_at, last_seen_at),
    last_seen_at = GREATEST(first_seen_at, last_seen_at)
WHERE first_seen_at > last_seen_at;

UPDATE tags
SET
    first_seen_at = LEAST(first_seen_at, last_seen_at),
    last_seen_at = GREATEST(first_seen_at, last_seen_at)
WHERE first_seen_at > last_seen_at;

UPDATE findings
SET
    first_seen_at = LEAST(first_seen_at, last_seen_at),
    last_seen_at = GREATEST(first_seen_at, last_seen_at)
WHERE first_seen_at > last_seen_at;

UPDATE finding_occurrences
SET
    first_seen_at = LEAST(first_seen_at, last_seen_at),
    last_seen_at = GREATEST(first_seen_at, last_seen_at)
WHERE first_seen_at > last_seen_at;

DO $$
DECLARE
    old_constraint_name TEXT;
BEGIN
    SELECT constraint_row.conname
    INTO old_constraint_name
    FROM pg_constraint AS constraint_row
    WHERE constraint_row.conrelid = 'finding_occurrences'::regclass
      AND constraint_row.contype = 'u'
      AND pg_get_constraintdef(constraint_row.oid) LIKE '%raw_snippet%'
    LIMIT 1;

    IF old_constraint_name IS NOT NULL THEN
        EXECUTE format(
            'ALTER TABLE finding_occurrences DROP CONSTRAINT %I',
            old_constraint_name
        );
    END IF;
END $$;

ALTER TABLE finding_occurrences
    ADD CONSTRAINT finding_occurrences_identity_key UNIQUE (
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
        source_location,
        match_start,
        match_end,
        present_in_final_image
    );

ALTER TABLE repositories
    ADD CONSTRAINT repositories_registry_not_blank CHECK (BTRIM(registry) <> '') NOT VALID,
    ADD CONSTRAINT repositories_repository_not_blank CHECK (BTRIM(repository) <> '') NOT VALID,
    ADD CONSTRAINT repositories_seen_order CHECK (first_seen_at <= last_seen_at) NOT VALID;

ALTER TABLE manifests
    ADD CONSTRAINT manifests_digest_not_blank CHECK (BTRIM(digest) <> '') NOT VALID,
    ADD CONSTRAINT manifests_scan_status_valid CHECK (last_scan_status IN ('scanned', 'partial', 'failed')) NOT VALID,
    ADD CONSTRAINT manifests_seen_order CHECK (first_seen_at <= last_seen_at) NOT VALID;

ALTER TABLE repository_manifests
    ADD CONSTRAINT repository_manifests_scan_status_valid CHECK (last_scan_status IN ('scanned', 'partial', 'failed')) NOT VALID,
    ADD CONSTRAINT repository_manifests_seen_order CHECK (first_seen_at <= last_seen_at) NOT VALID;

ALTER TABLE tags
    ADD CONSTRAINT tags_name_not_blank CHECK (BTRIM(tag) <> '') NOT VALID,
    ADD CONSTRAINT tags_status_valid CHECK (status IN ('scanned', 'partial', 'failed')) NOT VALID,
    ADD CONSTRAINT tags_seen_order CHECK (first_seen_at <= last_seen_at) NOT VALID;

ALTER TABLE findings
    ADD CONSTRAINT findings_fingerprint_not_blank CHECK (BTRIM(fingerprint) <> '') NOT VALID,
    ADD CONSTRAINT findings_seen_order CHECK (first_seen_at <= last_seen_at) NOT VALID;

ALTER TABLE finding_occurrences
    ADD CONSTRAINT finding_occurrences_disposition_valid CHECK (disposition IN ('actionable', 'example')) NOT VALID,
    ADD CONSTRAINT finding_occurrences_line_number_valid CHECK (line_number >= 0) NOT VALID,
    ADD CONSTRAINT finding_occurrences_match_range_valid CHECK (match_start >= 0 AND match_end >= match_start) NOT VALID,
    ADD CONSTRAINT finding_occurrences_seen_order CHECK (first_seen_at <= last_seen_at) NOT VALID;

ALTER TABLE scan_runs
    ADD CONSTRAINT scan_runs_status_valid CHECK (status IN ('completed', 'partial', 'failed')) NOT VALID,
    ADD CONSTRAINT scan_runs_counters_nonnegative CHECK (
        tags_enumerated >= 0
        AND tags_resolved >= 0
        AND tags_failed >= 0
        AND target_count >= 0
        AND completed_target_count >= 0
        AND failed_target_count >= 0
        AND partial_target_count >= 0
        AND manifest_count >= 0
        AND completed_manifest_count >= 0
        AND failed_manifest_count >= 0
        AND total_findings >= 0
        AND unique_fingerprints >= 0
        AND suppressed_findings_count >= 0
        AND suppressed_unique_fingerprints >= 0
    ) NOT VALID;

ALTER TABLE repositories VALIDATE CONSTRAINT repositories_registry_not_blank;
ALTER TABLE repositories VALIDATE CONSTRAINT repositories_repository_not_blank;
ALTER TABLE repositories VALIDATE CONSTRAINT repositories_seen_order;
ALTER TABLE manifests VALIDATE CONSTRAINT manifests_digest_not_blank;
ALTER TABLE manifests VALIDATE CONSTRAINT manifests_scan_status_valid;
ALTER TABLE manifests VALIDATE CONSTRAINT manifests_seen_order;
ALTER TABLE repository_manifests VALIDATE CONSTRAINT repository_manifests_scan_status_valid;
ALTER TABLE repository_manifests VALIDATE CONSTRAINT repository_manifests_seen_order;
ALTER TABLE tags VALIDATE CONSTRAINT tags_name_not_blank;
ALTER TABLE tags VALIDATE CONSTRAINT tags_status_valid;
ALTER TABLE tags VALIDATE CONSTRAINT tags_seen_order;
ALTER TABLE findings VALIDATE CONSTRAINT findings_fingerprint_not_blank;
ALTER TABLE findings VALIDATE CONSTRAINT findings_seen_order;
ALTER TABLE finding_occurrences VALIDATE CONSTRAINT finding_occurrences_disposition_valid;
ALTER TABLE finding_occurrences VALIDATE CONSTRAINT finding_occurrences_line_number_valid;
ALTER TABLE finding_occurrences VALIDATE CONSTRAINT finding_occurrences_match_range_valid;
ALTER TABLE finding_occurrences VALIDATE CONSTRAINT finding_occurrences_seen_order;
ALTER TABLE scan_runs VALIDATE CONSTRAINT scan_runs_status_valid;
ALTER TABLE scan_runs VALIDATE CONSTRAINT scan_runs_counters_nonnegative;

CREATE INDEX findings_manifest_last_seen_idx
    ON findings (manifest_digest, last_seen_at DESC, id DESC);

CREATE INDEX finding_occurrences_disposition_idx
    ON finding_occurrences (finding_id, disposition, last_seen_at DESC);
