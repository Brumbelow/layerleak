CREATE TABLE repositories (
    id BIGSERIAL PRIMARY KEY,
    registry TEXT NOT NULL,
    repository TEXT NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    UNIQUE (registry, repository)
);

CREATE TABLE manifests (
    digest TEXT PRIMARY KEY,
    platform_os TEXT NOT NULL DEFAULT '',
    platform_architecture TEXT NOT NULL DEFAULT '',
    platform_variant TEXT NOT NULL DEFAULT '',
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    last_scan_status TEXT NOT NULL,
    last_scan_error TEXT NOT NULL DEFAULT ''
);

CREATE INDEX manifests_platform_idx
    ON manifests (platform_os, platform_architecture, platform_variant);

CREATE TABLE repository_manifests (
    repository_id BIGINT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    manifest_digest TEXT NOT NULL REFERENCES manifests(digest) ON DELETE CASCADE,
    root_digest TEXT NOT NULL DEFAULT '',
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    last_scan_status TEXT NOT NULL,
    last_scan_error TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (repository_id, manifest_digest)
);

CREATE INDEX repository_manifests_root_digest_idx
    ON repository_manifests (repository_id, root_digest);

CREATE TABLE tags (
    repository_id BIGINT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    tag TEXT NOT NULL,
    manifest_digest TEXT NOT NULL DEFAULT '',
    root_digest TEXT NOT NULL DEFAULT '',
    platform_os TEXT NOT NULL DEFAULT '',
    platform_architecture TEXT NOT NULL DEFAULT '',
    platform_variant TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    error TEXT NOT NULL DEFAULT '',
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (repository_id, tag, manifest_digest, platform_os, platform_architecture, platform_variant)
);

CREATE INDEX tags_repository_manifest_idx
    ON tags (repository_id, manifest_digest);

CREATE TABLE findings (
    id BIGSERIAL PRIMARY KEY,
    manifest_digest TEXT NOT NULL REFERENCES manifests(digest) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    redacted_value TEXT NOT NULL,
    value TEXT NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    UNIQUE (manifest_digest, fingerprint)
);

CREATE INDEX findings_fingerprint_idx
    ON findings (fingerprint);

CREATE TABLE finding_occurrences (
    id BIGSERIAL PRIMARY KEY,
    finding_id BIGINT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    detector_name TEXT NOT NULL,
    confidence TEXT NOT NULL,
    source_type TEXT NOT NULL,
    platform_os TEXT NOT NULL DEFAULT '',
    platform_architecture TEXT NOT NULL DEFAULT '',
    platform_variant TEXT NOT NULL DEFAULT '',
    file_path TEXT NOT NULL DEFAULT '',
    layer_digest TEXT NOT NULL DEFAULT '',
    source_key TEXT NOT NULL DEFAULT '',
    context_snippet TEXT NOT NULL DEFAULT '',
    raw_snippet TEXT NOT NULL DEFAULT '',
    source_location TEXT NOT NULL DEFAULT '',
    match_start INTEGER NOT NULL DEFAULT 0,
    match_end INTEGER NOT NULL DEFAULT 0,
    present_in_final_image BOOLEAN NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    UNIQUE (
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
);

CREATE INDEX finding_occurrences_finding_idx
    ON finding_occurrences (finding_id);

CREATE INDEX finding_occurrences_source_idx
    ON finding_occurrences (source_type, file_path, layer_digest);
