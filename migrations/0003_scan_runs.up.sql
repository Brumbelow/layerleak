CREATE TABLE scan_runs (
    id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    requested_reference TEXT NOT NULL,
    resolved_reference TEXT NOT NULL DEFAULT '',
    requested_digest TEXT NOT NULL DEFAULT '',
    mode TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    error_message TEXT NOT NULL DEFAULT '',
    tags_enumerated INTEGER NOT NULL DEFAULT 0,
    tags_resolved INTEGER NOT NULL DEFAULT 0,
    tags_failed INTEGER NOT NULL DEFAULT 0,
    target_count INTEGER NOT NULL DEFAULT 0,
    completed_target_count INTEGER NOT NULL DEFAULT 0,
    failed_target_count INTEGER NOT NULL DEFAULT 0,
    manifest_count INTEGER NOT NULL DEFAULT 0,
    completed_manifest_count INTEGER NOT NULL DEFAULT 0,
    failed_manifest_count INTEGER NOT NULL DEFAULT 0,
    total_findings INTEGER NOT NULL DEFAULT 0,
    unique_fingerprints INTEGER NOT NULL DEFAULT 0,
    suppressed_findings_count INTEGER NOT NULL DEFAULT 0,
    suppressed_unique_fingerprints INTEGER NOT NULL DEFAULT 0,
    result_json JSONB NOT NULL,
    scanned_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX scan_runs_repository_scanned_idx
    ON scan_runs (repository_id, scanned_at DESC, id DESC);

CREATE INDEX scan_runs_status_scanned_idx
    ON scan_runs (status, scanned_at DESC);
