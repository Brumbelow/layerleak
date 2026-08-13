// Package storage provides Layerleak scan persistence and schema management.
package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	CurrentSchemaVersion  = "0004"
	currentMigrationCount = 4
	migrationAdvisoryKey  = int64(5503803602222863713)
)

var migrationFilenamePattern = regexp.MustCompile(`^([0-9]{4})_([a-z0-9][a-z0-9_]*)\.up\.sql$`)

type MigrationConfig struct {
	DatabaseURL string
	Directory   string
}

type MigrationResult struct {
	Applied []string
	Current string
}

type migrationFile struct {
	Version  string
	Name     string
	Path     string
	Checksum string
	SQL      string
}

type migrationRow struct {
	Version  string
	Name     string
	Checksum string
}

// RunMigrations applies all pending up migrations while holding a database-wide
// advisory lock. Each file and its ledger entry commit in the same transaction.
func RunMigrations(ctx context.Context, config MigrationConfig) (MigrationResult, error) {
	databaseURL := strings.TrimSpace(config.DatabaseURL)
	if err := (PostgresConfig{DatabaseURL: databaseURL}).Validate(); err != nil {
		return MigrationResult{}, err
	}
	migrations, err := loadMigrationFiles(config.Directory)
	if err != nil {
		return MigrationResult{}, err
	}
	if len(migrations) == 0 {
		return MigrationResult{}, fmt.Errorf("no migration files found in %s", strings.TrimSpace(config.Directory))
	}
	for index, migration := range migrations {
		expected := fmt.Sprintf("%04d", index+1)
		if migration.Version != expected {
			return MigrationResult{}, fmt.Errorf("migration sequence is not contiguous: expected %s, found %s", expected, migration.Version)
		}
	}
	if migrations[len(migrations)-1].Version != CurrentSchemaVersion {
		return MigrationResult{}, fmt.Errorf("migration set ends at %s, expected %s", migrations[len(migrations)-1].Version, CurrentSchemaVersion)
	}

	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return MigrationResult{}, fmt.Errorf("open postgres connection: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	connection, err := db.Conn(ctx)
	if err != nil {
		return MigrationResult{}, fmt.Errorf("acquire migration connection: %w", err)
	}
	defer connection.Close()
	if err := connection.PingContext(ctx); err != nil {
		return MigrationResult{}, fmt.Errorf("ping postgres: %w", err)
	}
	if err := ensureMinimumPostgresServerVersion(ctx, connection); err != nil {
		return MigrationResult{}, err
	}
	if _, err := connection.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, migrationAdvisoryKey); err != nil {
		return MigrationResult{}, fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = connection.ExecContext(unlockCtx, `SELECT pg_advisory_unlock($1)`, migrationAdvisoryKey)
	}()

	ledgerExisted, err := tableExistsContext(ctx, connection, "schema_migrations")
	if err != nil {
		return MigrationResult{}, err
	}
	if !ledgerExisted {
		if _, err := connection.ExecContext(ctx, `
			CREATE TABLE schema_migrations (
				version TEXT PRIMARY KEY,
				name TEXT NOT NULL,
				sha256 TEXT NOT NULL,
				applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
			)
		`); err != nil {
			return MigrationResult{}, fmt.Errorf("create schema migration ledger: %w", err)
		}
	}

	applied, err := readAppliedMigrations(ctx, connection)
	if err != nil {
		return MigrationResult{}, err
	}
	if len(applied) == 0 {
		adopted, err := adoptLegacySchema(ctx, connection, migrations)
		if err != nil {
			return MigrationResult{}, err
		}
		applied = adopted
	}
	if err := validateAppliedMigrations(migrations, applied); err != nil {
		return MigrationResult{}, err
	}

	result := MigrationResult{Applied: make([]string, 0), Current: CurrentSchemaVersion}
	for _, migration := range migrations {
		if _, ok := applied[migration.Version]; ok {
			continue
		}
		if err := applyMigration(ctx, connection, migration); err != nil {
			return MigrationResult{}, err
		}
		result.Applied = append(result.Applied, migration.Name)
	}
	if err := checkSchemaVersion(ctx, connection); err != nil {
		return MigrationResult{}, err
	}
	return result, nil
}

func loadMigrationFiles(directory string) ([]migrationFile, error) {
	directory = strings.TrimSpace(directory)
	if directory == "" {
		return nil, fmt.Errorf("migration directory is required")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("read migration directory %s: %w", directory, err)
	}

	migrations := make([]migrationFile, 0)
	versions := make(map[string]string)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		matches := migrationFilenamePattern.FindStringSubmatch(entry.Name())
		if matches == nil {
			continue
		}
		if previous, ok := versions[matches[1]]; ok {
			return nil, fmt.Errorf("duplicate migration version %s in %s and %s", matches[1], previous, entry.Name())
		}
		path := filepath.Join(directory, entry.Name())
		body, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read migration %s: %w", entry.Name(), err)
		}
		if strings.TrimSpace(string(body)) == "" {
			return nil, fmt.Errorf("migration %s is empty", entry.Name())
		}
		digest := sha256.Sum256(body)
		migration := migrationFile{
			Version:  matches[1],
			Name:     strings.TrimSuffix(entry.Name(), ".up.sql"),
			Path:     path,
			Checksum: hex.EncodeToString(digest[:]),
			SQL:      string(body),
		}
		versions[migration.Version] = entry.Name()
		migrations = append(migrations, migration)
	}
	slices.SortFunc(migrations, func(left, right migrationFile) int {
		return strings.Compare(left.Version, right.Version)
	})
	return migrations, nil
}

func readAppliedMigrations(ctx context.Context, queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) (map[string]migrationRow, error) {
	rows, err := queryer.QueryContext(ctx, `
		SELECT version, name, sha256
		FROM schema_migrations
		ORDER BY version
	`)
	if err != nil {
		return nil, fmt.Errorf("read schema migration ledger: %w", err)
	}
	defer rows.Close()

	applied := make(map[string]migrationRow)
	for rows.Next() {
		var item migrationRow
		if err := rows.Scan(&item.Version, &item.Name, &item.Checksum); err != nil {
			return nil, fmt.Errorf("scan schema migration ledger: %w", err)
		}
		applied[item.Version] = item
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate schema migration ledger: %w", err)
	}
	return applied, nil
}

func validateAppliedMigrations(migrations []migrationFile, applied map[string]migrationRow) error {
	known := make(map[string]migrationFile, len(migrations))
	for _, migration := range migrations {
		known[migration.Version] = migration
	}
	for version, row := range applied {
		migration, ok := known[version]
		if !ok {
			return fmt.Errorf("database contains unknown migration version %s", version)
		}
		if row.Name != migration.Name {
			return fmt.Errorf("migration %s name changed: database has %q, file is %q", version, row.Name, migration.Name)
		}
		if row.Checksum != migration.Checksum {
			return fmt.Errorf("migration %s checksum changed", version)
		}
	}

	missingEarlier := false
	for _, migration := range migrations {
		_, ok := applied[migration.Version]
		if !ok {
			missingEarlier = true
			continue
		}
		if missingEarlier {
			return fmt.Errorf("migration ledger has a gap before version %s", migration.Version)
		}
	}
	return nil
}

func applyMigration(ctx context.Context, connection *sql.Conn, migration migrationFile) error {
	tx, err := connection.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration %s: %w", migration.Name, err)
	}
	defer func() {
		_ = tx.Rollback()
	}()
	if _, err := tx.ExecContext(ctx, migration.SQL); err != nil {
		return fmt.Errorf("apply migration %s: %w", migration.Name, err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO schema_migrations (version, name, sha256)
		VALUES ($1, $2, $3)
	`, migration.Version, migration.Name, migration.Checksum); err != nil {
		return fmt.Errorf("record migration %s: %w", migration.Name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration %s: %w", migration.Name, err)
	}
	return nil
}

func adoptLegacySchema(ctx context.Context, connection *sql.Conn, migrations []migrationFile) (map[string]migrationRow, error) {
	state, err := inspectLegacySchema(ctx, connection)
	if err != nil {
		return nil, err
	}
	if len(state) == 0 {
		return map[string]migrationRow{}, nil
	}
	byVersion := make(map[string]migrationFile, len(migrations))
	for _, migration := range migrations {
		byVersion[migration.Version] = migration
	}
	tx, err := connection.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin legacy schema adoption: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()
	applied := make(map[string]migrationRow, len(state))
	for _, version := range state {
		migration, ok := byVersion[version]
		if !ok {
			return nil, fmt.Errorf("legacy schema matches migration %s, but its file is missing", version)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO schema_migrations (version, name, sha256)
			VALUES ($1, $2, $3)
		`, migration.Version, migration.Name, migration.Checksum); err != nil {
			return nil, fmt.Errorf("record adopted migration %s: %w", migration.Name, err)
		}
		applied[version] = migrationRow{Version: version, Name: migration.Name, Checksum: migration.Checksum}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit legacy schema adoption: %w", err)
	}
	return applied, nil
}

type queryRower interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type schemaQueryer interface {
	queryRower
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

type schemaColumnRequirement struct {
	version           string
	table             string
	name              string
	dataType          string
	notNull           bool
	defaultExpression string
}

type schemaConstraintRequirement struct {
	version     string
	lastVersion string
	table       string
	name        string
	definition  string
}

type schemaIndexRequirement struct {
	version    string
	table      string
	name       string
	columns    string
	accessType string
	unique     bool
}

const sequenceDefaultPrefix = "sequence:"

var schemaColumnRequirements = []schemaColumnRequirement{
	{version: "0001", table: "repositories", name: "id", dataType: "bigint", notNull: true, defaultExpression: sequenceDefaultPrefix + "repositories_id_seq"},
	{version: "0001", table: "repositories", name: "registry", dataType: "text", notNull: true},
	{version: "0001", table: "repositories", name: "repository", dataType: "text", notNull: true},
	{version: "0001", table: "repositories", name: "first_seen_at", dataType: "timestamp with time zone", notNull: true},
	{version: "0001", table: "repositories", name: "last_seen_at", dataType: "timestamp with time zone", notNull: true},

	{version: "0001", table: "manifests", name: "digest", dataType: "text", notNull: true},
	{version: "0001", table: "manifests", name: "platform_os", dataType: "text", notNull: true, defaultExpression: "''::text"},
	{version: "0001", table: "manifests", name: "platform_architecture", dataType: "text", notNull: true, defaultExpression: "''::text"},
	{version: "0001", table: "manifests", name: "platform_variant", dataType: "text", notNull: true, defaultExpression: "''::text"},
	{version: "0001", table: "manifests", name: "first_seen_at", dataType: "timestamp with time zone", notNull: true},
	{version: "0001", table: "manifests", name: "last_seen_at", dataType: "timestamp with time zone", notNull: true},
	{version: "0001", table: "manifests", name: "last_scan_status", dataType: "text", notNull: true},
	{version: "0001", table: "manifests", name: "last_scan_error", dataType: "text", notNull: true, defaultExpression: "''::text"},

	{version: "0001", table: "repository_manifests", name: "repository_id", dataType: "bigint", notNull: true},
	{version: "0001", table: "repository_manifests", name: "manifest_digest", dataType: "text", notNull: true},
	{version: "0001", table: "repository_manifests", name: "root_digest", dataType: "text", notNull: true, defaultExpression: "''::text"},
	{version: "0001", table: "repository_manifests", name: "first_seen_at", dataType: "timestamp with time zone", notNull: true},
	{version: "0001", table: "repository_manifests", name: "last_seen_at", dataType: "timestamp with time zone", notNull: true},
	{version: "0001", table: "repository_manifests", name: "last_scan_status", dataType: "text", notNull: true},
	{version: "0001", table: "repository_manifests", name: "last_scan_error", dataType: "text", notNull: true, defaultExpression: "''::text"},

	{version: "0001", table: "tags", name: "repository_id", dataType: "bigint", notNull: true},
	{version: "0001", table: "tags", name: "tag", dataType: "text", notNull: true},
	{version: "0001", table: "tags", name: "manifest_digest", dataType: "text", notNull: true, defaultExpression: "''::text"},
	{version: "0001", table: "tags", name: "root_digest", dataType: "text", notNull: true, defaultExpression: "''::text"},
	{version: "0001", table: "tags", name: "platform_os", dataType: "text", notNull: true, defaultExpression: "''::text"},
	{version: "0001", table: "tags", name: "platform_architecture", dataType: "text", notNull: true, defaultExpression: "''::text"},
	{version: "0001", table: "tags", name: "platform_variant", dataType: "text", notNull: true, defaultExpression: "''::text"},
	{version: "0001", table: "tags", name: "status", dataType: "text", notNull: true},
	{version: "0001", table: "tags", name: "error", dataType: "text", notNull: true, defaultExpression: "''::text"},
	{version: "0001", table: "tags", name: "first_seen_at", dataType: "timestamp with time zone", notNull: true},
	{version: "0001", table: "tags", name: "last_seen_at", dataType: "timestamp with time zone", notNull: true},

	{version: "0001", table: "findings", name: "id", dataType: "bigint", notNull: true, defaultExpression: sequenceDefaultPrefix + "findings_id_seq"},
	{version: "0001", table: "findings", name: "manifest_digest", dataType: "text", notNull: true},
	{version: "0001", table: "findings", name: "fingerprint", dataType: "text", notNull: true},
	{version: "0001", table: "findings", name: "redacted_value", dataType: "text", notNull: true},
	{version: "0001", table: "findings", name: "value", dataType: "text", notNull: true},
	{version: "0001", table: "findings", name: "first_seen_at", dataType: "timestamp with time zone", notNull: true},
	{version: "0001", table: "findings", name: "last_seen_at", dataType: "timestamp with time zone", notNull: true},

	{version: "0001", table: "finding_occurrences", name: "id", dataType: "bigint", notNull: true, defaultExpression: sequenceDefaultPrefix + "finding_occurrences_id_seq"},
	{version: "0001", table: "finding_occurrences", name: "finding_id", dataType: "bigint", notNull: true},
	{version: "0001", table: "finding_occurrences", name: "detector_name", dataType: "text", notNull: true},
	{version: "0001", table: "finding_occurrences", name: "confidence", dataType: "text", notNull: true},
	{version: "0001", table: "finding_occurrences", name: "source_type", dataType: "text", notNull: true},
	{version: "0001", table: "finding_occurrences", name: "platform_os", dataType: "text", notNull: true, defaultExpression: "''::text"},
	{version: "0001", table: "finding_occurrences", name: "platform_architecture", dataType: "text", notNull: true, defaultExpression: "''::text"},
	{version: "0001", table: "finding_occurrences", name: "platform_variant", dataType: "text", notNull: true, defaultExpression: "''::text"},
	{version: "0001", table: "finding_occurrences", name: "file_path", dataType: "text", notNull: true, defaultExpression: "''::text"},
	{version: "0001", table: "finding_occurrences", name: "layer_digest", dataType: "text", notNull: true, defaultExpression: "''::text"},
	{version: "0001", table: "finding_occurrences", name: "source_key", dataType: "text", notNull: true, defaultExpression: "''::text"},
	{version: "0001", table: "finding_occurrences", name: "context_snippet", dataType: "text", notNull: true, defaultExpression: "''::text"},
	{version: "0001", table: "finding_occurrences", name: "raw_snippet", dataType: "text", notNull: true, defaultExpression: "''::text"},
	{version: "0001", table: "finding_occurrences", name: "source_location", dataType: "text", notNull: true, defaultExpression: "''::text"},
	{version: "0001", table: "finding_occurrences", name: "match_start", dataType: "integer", notNull: true, defaultExpression: "0"},
	{version: "0001", table: "finding_occurrences", name: "match_end", dataType: "integer", notNull: true, defaultExpression: "0"},
	{version: "0001", table: "finding_occurrences", name: "present_in_final_image", dataType: "boolean", notNull: true},
	{version: "0001", table: "finding_occurrences", name: "first_seen_at", dataType: "timestamp with time zone", notNull: true},
	{version: "0001", table: "finding_occurrences", name: "last_seen_at", dataType: "timestamp with time zone", notNull: true},

	{version: "0002", table: "finding_occurrences", name: "disposition", dataType: "text", notNull: true, defaultExpression: "'actionable'::text"},
	{version: "0002", table: "finding_occurrences", name: "disposition_reason", dataType: "text", notNull: true, defaultExpression: "''::text"},
	{version: "0002", table: "finding_occurrences", name: "line_number", dataType: "integer", notNull: true, defaultExpression: "1"},

	{version: "0003", table: "scan_runs", name: "id", dataType: "bigint", notNull: true, defaultExpression: sequenceDefaultPrefix + "scan_runs_id_seq"},
	{version: "0003", table: "scan_runs", name: "repository_id", dataType: "bigint", notNull: true},
	{version: "0003", table: "scan_runs", name: "requested_reference", dataType: "text", notNull: true},
	{version: "0003", table: "scan_runs", name: "resolved_reference", dataType: "text", notNull: true, defaultExpression: "''::text"},
	{version: "0003", table: "scan_runs", name: "requested_digest", dataType: "text", notNull: true, defaultExpression: "''::text"},
	{version: "0003", table: "scan_runs", name: "mode", dataType: "text", notNull: true, defaultExpression: "''::text"},
	{version: "0003", table: "scan_runs", name: "status", dataType: "text", notNull: true},
	{version: "0003", table: "scan_runs", name: "error_message", dataType: "text", notNull: true, defaultExpression: "''::text"},
	{version: "0003", table: "scan_runs", name: "tags_enumerated", dataType: "integer", notNull: true, defaultExpression: "0"},
	{version: "0003", table: "scan_runs", name: "tags_resolved", dataType: "integer", notNull: true, defaultExpression: "0"},
	{version: "0003", table: "scan_runs", name: "tags_failed", dataType: "integer", notNull: true, defaultExpression: "0"},
	{version: "0003", table: "scan_runs", name: "target_count", dataType: "integer", notNull: true, defaultExpression: "0"},
	{version: "0003", table: "scan_runs", name: "completed_target_count", dataType: "integer", notNull: true, defaultExpression: "0"},
	{version: "0003", table: "scan_runs", name: "failed_target_count", dataType: "integer", notNull: true, defaultExpression: "0"},
	{version: "0003", table: "scan_runs", name: "manifest_count", dataType: "integer", notNull: true, defaultExpression: "0"},
	{version: "0003", table: "scan_runs", name: "completed_manifest_count", dataType: "integer", notNull: true, defaultExpression: "0"},
	{version: "0003", table: "scan_runs", name: "failed_manifest_count", dataType: "integer", notNull: true, defaultExpression: "0"},
	{version: "0003", table: "scan_runs", name: "total_findings", dataType: "integer", notNull: true, defaultExpression: "0"},
	{version: "0003", table: "scan_runs", name: "unique_fingerprints", dataType: "integer", notNull: true, defaultExpression: "0"},
	{version: "0003", table: "scan_runs", name: "suppressed_findings_count", dataType: "integer", notNull: true, defaultExpression: "0"},
	{version: "0003", table: "scan_runs", name: "suppressed_unique_fingerprints", dataType: "integer", notNull: true, defaultExpression: "0"},
	{version: "0003", table: "scan_runs", name: "result_json", dataType: "jsonb", notNull: true},
	{version: "0003", table: "scan_runs", name: "scanned_at", dataType: "timestamp with time zone", notNull: true},

	{version: "0004", table: "scan_runs", name: "partial_target_count", dataType: "integer", notNull: true, defaultExpression: "0"},
	{version: "0004", table: "schema_migrations", name: "version", dataType: "text", notNull: true},
	{version: "0004", table: "schema_migrations", name: "name", dataType: "text", notNull: true},
	{version: "0004", table: "schema_migrations", name: "sha256", dataType: "text", notNull: true},
	{version: "0004", table: "schema_migrations", name: "applied_at", dataType: "timestamp with time zone", notNull: true, defaultExpression: "now()"},
}

var schemaConstraintRequirements = []schemaConstraintRequirement{
	{version: "0001", table: "repositories", name: "repositories_pkey", definition: "PRIMARY KEY (id)"},
	{version: "0001", table: "repositories", name: "repositories_registry_repository_key", definition: "UNIQUE (registry, repository)"},
	{version: "0001", table: "manifests", name: "manifests_pkey", definition: "PRIMARY KEY (digest)"},
	{version: "0001", table: "repository_manifests", name: "repository_manifests_pkey", definition: "PRIMARY KEY (repository_id, manifest_digest)"},
	{version: "0001", table: "repository_manifests", name: "repository_manifests_repository_id_fkey", definition: "FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE"},
	{version: "0001", table: "repository_manifests", name: "repository_manifests_manifest_digest_fkey", definition: "FOREIGN KEY (manifest_digest) REFERENCES manifests(digest) ON DELETE CASCADE"},
	{version: "0001", table: "tags", name: "tags_pkey", definition: "PRIMARY KEY (repository_id, tag, manifest_digest, platform_os, platform_architecture, platform_variant)"},
	{version: "0001", table: "tags", name: "tags_repository_id_fkey", definition: "FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE"},
	{version: "0001", table: "findings", name: "findings_pkey", definition: "PRIMARY KEY (id)"},
	{version: "0001", table: "findings", name: "findings_manifest_digest_fkey", definition: "FOREIGN KEY (manifest_digest) REFERENCES manifests(digest) ON DELETE CASCADE"},
	{version: "0001", table: "findings", name: "findings_manifest_digest_fingerprint_key", definition: "UNIQUE (manifest_digest, fingerprint)"},
	{version: "0001", table: "finding_occurrences", name: "finding_occurrences_pkey", definition: "PRIMARY KEY (id)"},
	{version: "0001", table: "finding_occurrences", name: "finding_occurrences_finding_id_fkey", definition: "FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE"},
	{version: "0001", lastVersion: "0003", table: "finding_occurrences", definition: "UNIQUE (finding_id, detector_name, confidence, source_type, platform_os, platform_architecture, platform_variant, file_path, layer_digest, source_key, context_snippet, raw_snippet, source_location, match_start, match_end, present_in_final_image)"},
	{version: "0003", table: "scan_runs", name: "scan_runs_pkey", definition: "PRIMARY KEY (id)"},
	{version: "0003", table: "scan_runs", name: "scan_runs_repository_id_fkey", definition: "FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE"},

	{version: "0004", table: "repositories", name: "repositories_registry_not_blank", definition: "CHECK ((btrim(registry) <> ''))"},
	{version: "0004", table: "repositories", name: "repositories_repository_not_blank", definition: "CHECK ((btrim(repository) <> ''))"},
	{version: "0004", table: "repositories", name: "repositories_seen_order", definition: "CHECK ((first_seen_at <= last_seen_at))"},
	{version: "0004", table: "manifests", name: "manifests_digest_not_blank", definition: "CHECK ((btrim(digest) <> ''))"},
	{version: "0004", table: "manifests", name: "manifests_scan_status_valid", definition: "CHECK ((last_scan_status = ANY (ARRAY['scanned', 'partial', 'failed'])))"},
	{version: "0004", table: "manifests", name: "manifests_seen_order", definition: "CHECK ((first_seen_at <= last_seen_at))"},
	{version: "0004", table: "repository_manifests", name: "repository_manifests_scan_status_valid", definition: "CHECK ((last_scan_status = ANY (ARRAY['scanned', 'partial', 'failed'])))"},
	{version: "0004", table: "repository_manifests", name: "repository_manifests_seen_order", definition: "CHECK ((first_seen_at <= last_seen_at))"},
	{version: "0004", table: "tags", name: "tags_name_not_blank", definition: "CHECK ((btrim(tag) <> ''))"},
	{version: "0004", table: "tags", name: "tags_status_valid", definition: "CHECK ((status = ANY (ARRAY['scanned', 'partial', 'failed'])))"},
	{version: "0004", table: "tags", name: "tags_seen_order", definition: "CHECK ((first_seen_at <= last_seen_at))"},
	{version: "0004", table: "findings", name: "findings_fingerprint_not_blank", definition: "CHECK ((btrim(fingerprint) <> ''))"},
	{version: "0004", table: "findings", name: "findings_seen_order", definition: "CHECK ((first_seen_at <= last_seen_at))"},
	{version: "0004", table: "finding_occurrences", name: "finding_occurrences_identity_key", definition: "UNIQUE (finding_id, detector_name, confidence, source_type, platform_os, platform_architecture, platform_variant, file_path, layer_digest, source_key, context_snippet, source_location, match_start, match_end, present_in_final_image)"},
	{version: "0004", table: "finding_occurrences", name: "finding_occurrences_disposition_valid", definition: "CHECK ((disposition = ANY (ARRAY['actionable', 'example'])))"},
	{version: "0004", table: "finding_occurrences", name: "finding_occurrences_line_number_valid", definition: "CHECK ((line_number >= 0))"},
	{version: "0004", table: "finding_occurrences", name: "finding_occurrences_match_range_valid", definition: "CHECK (((match_start >= 0) AND (match_end >= match_start)))"},
	{version: "0004", table: "finding_occurrences", name: "finding_occurrences_seen_order", definition: "CHECK ((first_seen_at <= last_seen_at))"},
	{version: "0004", table: "scan_runs", name: "scan_runs_status_valid", definition: "CHECK ((status = ANY (ARRAY['completed', 'partial', 'failed'])))"},
	{version: "0004", table: "scan_runs", name: "scan_runs_counters_nonnegative", definition: "CHECK (((tags_enumerated >= 0) AND (tags_resolved >= 0) AND (tags_failed >= 0) AND (target_count >= 0) AND (completed_target_count >= 0) AND (failed_target_count >= 0) AND (partial_target_count >= 0) AND (manifest_count >= 0) AND (completed_manifest_count >= 0) AND (failed_manifest_count >= 0) AND (total_findings >= 0) AND (unique_fingerprints >= 0) AND (suppressed_findings_count >= 0) AND (suppressed_unique_fingerprints >= 0)))"},
	{version: "0004", table: "schema_migrations", name: "schema_migrations_pkey", definition: "PRIMARY KEY (version)"},
}

var schemaIndexRequirements = []schemaIndexRequirement{
	{version: "0001", table: "manifests", name: "manifests_platform_idx", columns: "platform_os, platform_architecture, platform_variant", accessType: "btree"},
	{version: "0001", table: "repository_manifests", name: "repository_manifests_root_digest_idx", columns: "repository_id, root_digest", accessType: "btree"},
	{version: "0001", table: "tags", name: "tags_repository_manifest_idx", columns: "repository_id, manifest_digest", accessType: "btree"},
	{version: "0001", table: "findings", name: "findings_fingerprint_idx", columns: "fingerprint", accessType: "btree"},
	{version: "0001", table: "finding_occurrences", name: "finding_occurrences_finding_idx", columns: "finding_id", accessType: "btree"},
	{version: "0001", table: "finding_occurrences", name: "finding_occurrences_source_idx", columns: "source_type, file_path, layer_digest", accessType: "btree"},
	{version: "0003", table: "scan_runs", name: "scan_runs_repository_scanned_idx", columns: "repository_id, scanned_at DESC, id DESC", accessType: "btree"},
	{version: "0003", table: "scan_runs", name: "scan_runs_status_scanned_idx", columns: "status, scanned_at DESC", accessType: "btree"},
	{version: "0004", table: "findings", name: "findings_manifest_last_seen_idx", columns: "manifest_digest, last_seen_at DESC, id DESC", accessType: "btree"},
	{version: "0004", table: "finding_occurrences", name: "finding_occurrences_disposition_idx", columns: "finding_id, disposition, last_seen_at DESC", accessType: "btree"},
}

func inspectLegacySchema(ctx context.Context, queryer schemaQueryer) ([]string, error) {
	baseTables := []string{"repositories", "manifests", "repository_manifests", "tags", "findings", "finding_occurrences"}
	existingBase := 0
	for _, table := range baseTables {
		exists, err := tableExistsContext(ctx, queryer, table)
		if err != nil {
			return nil, err
		}
		if exists {
			existingBase++
		}
	}
	scanRunsExists, err := tableExistsContext(ctx, queryer, "scan_runs")
	if err != nil {
		return nil, err
	}
	if existingBase == 0 && !scanRunsExists {
		return nil, nil
	}
	if existingBase != len(baseTables) {
		return nil, fmt.Errorf("partial legacy schema detected: found %d of %d base tables", existingBase, len(baseTables))
	}

	targetVersion := "0001"
	metadataColumns := []string{"disposition", "disposition_reason", "line_number"}
	metadataCount := 0
	for _, column := range metadataColumns {
		exists, err := columnExistsContext(ctx, queryer, "finding_occurrences", column)
		if err != nil {
			return nil, err
		}
		if exists {
			metadataCount++
		}
	}
	if metadataCount != 0 && metadataCount != len(metadataColumns) {
		return nil, fmt.Errorf("partial legacy migration 0002 detected: found %d of %d columns", metadataCount, len(metadataColumns))
	}
	if metadataCount == len(metadataColumns) {
		targetVersion = "0002"
	}
	if scanRunsExists {
		if metadataCount != len(metadataColumns) {
			return nil, fmt.Errorf("scan_runs exists before migration 0002 is complete")
		}
		targetVersion = "0003"
	}

	hardened, err := hasStorageHardeningMarker(ctx, queryer)
	if err != nil {
		return nil, err
	}
	if hardened {
		if !scanRunsExists {
			return nil, fmt.Errorf("storage hardening exists before migration 0003 is complete")
		}
		targetVersion = "0004"
	}
	if err := validateSchemaContract(ctx, queryer, targetVersion, "legacy schema"); err != nil {
		return nil, err
	}

	versions := make([]string, 0, currentMigrationCount)
	for version := 1; version <= currentMigrationCount; version++ {
		value := fmt.Sprintf("%04d", version)
		if value > targetVersion {
			break
		}
		versions = append(versions, value)
	}
	return versions, nil
}

func tableExistsContext(ctx context.Context, queryer queryRower, table string) (bool, error) {
	var exists bool
	if err := queryer.QueryRowContext(ctx, `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&exists); err != nil {
		return false, fmt.Errorf("check table %s: %w", table, err)
	}
	return exists, nil
}

func columnExistsContext(ctx context.Context, queryer queryRower, table, column string) (bool, error) {
	var exists bool
	if err := queryer.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM information_schema.columns
			WHERE table_schema = current_schema()
			  AND table_name = $1
			  AND column_name = $2
		)
	`, table, column).Scan(&exists); err != nil {
		return false, fmt.Errorf("check column %s.%s: %w", table, column, err)
	}
	return exists, nil
}

func constraintExistsContext(ctx context.Context, queryer queryRower, table, constraint string) (bool, error) {
	var exists bool
	if err := queryer.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM pg_constraint
			WHERE conrelid = to_regclass($1)
			  AND conname = $2
		)
	`, table, constraint).Scan(&exists); err != nil {
		return false, fmt.Errorf("check constraint %s on %s: %w", constraint, table, err)
	}
	return exists, nil
}

func indexExistsContext(ctx context.Context, queryer queryRower, index string) (bool, error) {
	var exists bool
	if err := queryer.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM pg_class AS index_row
			JOIN pg_namespace AS namespace_row ON namespace_row.oid = index_row.relnamespace
			WHERE namespace_row.nspname = current_schema()
			  AND index_row.relname = $1
			  AND index_row.relkind = 'i'
		)
	`, index).Scan(&exists); err != nil {
		return false, fmt.Errorf("check index %s: %w", index, err)
	}
	return exists, nil
}

func hasStorageHardeningMarker(ctx context.Context, queryer queryRower) (bool, error) {
	exists, err := columnExistsContext(ctx, queryer, "scan_runs", "partial_target_count")
	if err != nil || exists {
		return exists, err
	}
	for _, requirement := range schemaConstraintRequirements {
		if requirement.version != "0004" || requirement.table == "schema_migrations" {
			continue
		}
		exists, err := constraintExistsContext(ctx, queryer, requirement.table, requirement.name)
		if err != nil || exists {
			return exists, err
		}
	}
	for _, requirement := range schemaIndexRequirements {
		if requirement.version != "0004" {
			continue
		}
		exists, err := indexExistsContext(ctx, queryer, requirement.name)
		if err != nil || exists {
			return exists, err
		}
	}
	return false, nil
}

func validateSchemaContract(ctx context.Context, queryer schemaQueryer, version, label string) error {
	if err := requireSchemaColumns(ctx, queryer, version, label); err != nil {
		return err
	}
	if err := requireSchemaConstraints(ctx, queryer, version, label); err != nil {
		return err
	}
	return requireSchemaIndexes(ctx, queryer, version, label)
}

type schemaColumnState struct {
	dataType          string
	notNull           bool
	defaultExpression sql.NullString
}

func requireSchemaColumns(ctx context.Context, queryer schemaQueryer, version, label string) error {
	rows, err := queryer.QueryContext(ctx, `
		SELECT
			table_row.relname,
			attribute_row.attname,
			format_type(attribute_row.atttypid, attribute_row.atttypmod),
			attribute_row.attnotnull,
			pg_get_expr(default_row.adbin, default_row.adrelid)
		FROM pg_attribute AS attribute_row
		JOIN pg_class AS table_row ON table_row.oid = attribute_row.attrelid
		JOIN pg_namespace AS namespace_row ON namespace_row.oid = table_row.relnamespace
		LEFT JOIN pg_attrdef AS default_row
		  ON default_row.adrelid = attribute_row.attrelid
		 AND default_row.adnum = attribute_row.attnum
		WHERE namespace_row.nspname = current_schema()
		  AND table_row.relkind IN ('r', 'p')
		  AND attribute_row.attnum > 0
		  AND NOT attribute_row.attisdropped
		  AND table_row.relname IN (
			  'repositories',
			  'manifests',
			  'repository_manifests',
			  'tags',
			  'findings',
			  'finding_occurrences',
			  'scan_runs',
			  'schema_migrations'
		  )
	`)
	if err != nil {
		return fmt.Errorf("inspect database schema columns: %w", err)
	}
	defer rows.Close()

	available := make(map[string]map[string]schemaColumnState)
	for rows.Next() {
		var table, column string
		var state schemaColumnState
		if err := rows.Scan(&table, &column, &state.dataType, &state.notNull, &state.defaultExpression); err != nil {
			return fmt.Errorf("scan database schema column: %w", err)
		}
		if available[table] == nil {
			available[table] = make(map[string]schemaColumnState)
		}
		available[table][column] = state
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate database schema columns: %w", err)
	}
	for _, requirement := range schemaColumnRequirements {
		if requirement.version > version {
			continue
		}
		state, ok := available[requirement.table][requirement.name]
		if !ok {
			return fmt.Errorf("%s is missing %s.%s", label, requirement.table, requirement.name)
		}
		if state.dataType != requirement.dataType {
			return fmt.Errorf("%s column %s.%s has type %s, expected %s", label, requirement.table, requirement.name, state.dataType, requirement.dataType)
		}
		if state.notNull != requirement.notNull {
			return fmt.Errorf("%s column %s.%s has unexpected nullability", label, requirement.table, requirement.name)
		}
		if !schemaColumnDefaultMatches(state.defaultExpression, requirement.defaultExpression) {
			return fmt.Errorf("%s column %s.%s has an unexpected default", label, requirement.table, requirement.name)
		}
	}
	return nil
}

func schemaColumnDefaultMatches(actual sql.NullString, expected string) bool {
	if expected == "" {
		return !actual.Valid
	}
	if !actual.Valid {
		return false
	}
	if strings.HasPrefix(expected, sequenceDefaultPrefix) {
		value := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(actual.String), `"`, ""))
		if !strings.HasPrefix(value, "nextval('") || !strings.HasSuffix(value, "'::regclass)") {
			return false
		}
		sequence := strings.TrimSuffix(strings.TrimPrefix(value, "nextval('"), "'::regclass)")
		if index := strings.LastIndexByte(sequence, '.'); index >= 0 {
			sequence = sequence[index+1:]
		}
		return sequence == strings.TrimPrefix(expected, sequenceDefaultPrefix)
	}
	return normalizeSchemaDefinition(actual.String) == normalizeSchemaDefinition(expected)
}

type schemaConstraintState struct {
	name       string
	definition string
	validated  bool
}

func requireSchemaConstraints(ctx context.Context, queryer schemaQueryer, version, label string) error {
	rows, err := queryer.QueryContext(ctx, `
		SELECT table_row.relname, constraint_row.conname, constraint_row.convalidated, pg_get_constraintdef(constraint_row.oid)
		FROM pg_constraint AS constraint_row
		JOIN pg_class AS table_row ON table_row.oid = constraint_row.conrelid
		JOIN pg_namespace AS namespace_row ON namespace_row.oid = table_row.relnamespace
		WHERE namespace_row.nspname = current_schema()
		  AND table_row.relname IN (
			  'repositories',
			  'manifests',
			  'repository_manifests',
			  'tags',
			  'findings',
			  'finding_occurrences',
			  'scan_runs',
			  'schema_migrations'
		  )
	`)
	if err != nil {
		return fmt.Errorf("inspect database schema constraints: %w", err)
	}
	defer rows.Close()

	available := make(map[string][]schemaConstraintState)
	for rows.Next() {
		var table string
		var state schemaConstraintState
		if err := rows.Scan(&table, &state.name, &state.validated, &state.definition); err != nil {
			return fmt.Errorf("scan database schema constraint: %w", err)
		}
		available[table] = append(available[table], state)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate database schema constraints: %w", err)
	}
	for _, requirement := range schemaConstraintRequirements {
		if requirement.version > version || (requirement.lastVersion != "" && version > requirement.lastVersion) {
			continue
		}
		found := false
		for _, state := range available[requirement.table] {
			if requirement.name != "" && state.name != requirement.name {
				continue
			}
			if requirement.name == "" && normalizeSchemaDefinition(state.definition) != normalizeSchemaDefinition(requirement.definition) {
				continue
			}
			found = true
			if !state.validated {
				return fmt.Errorf("%s constraint %s on %s is not validated", label, constraintLabel(requirement), requirement.table)
			}
			if normalizeSchemaDefinition(state.definition) != normalizeSchemaDefinition(requirement.definition) {
				return fmt.Errorf("%s constraint %s on %s has an unexpected definition", label, constraintLabel(requirement), requirement.table)
			}
			break
		}
		if !found {
			return fmt.Errorf("%s is missing constraint %s on %s", label, constraintLabel(requirement), requirement.table)
		}
	}
	return nil
}

func constraintLabel(requirement schemaConstraintRequirement) string {
	if requirement.name != "" {
		return requirement.name
	}
	return requirement.definition
}

func normalizeSchemaDefinition(value string) string {
	value = strings.ToLower(strings.ReplaceAll(value, "::text", ""))
	return strings.Map(func(character rune) rune {
		switch character {
		case ' ', '\t', '\r', '\n', '"':
			return -1
		default:
			return character
		}
	}, value)
}

type schemaIndexState struct {
	table               string
	columns             []schemaIndexColumnState
	accessType          string
	unique              bool
	valid               bool
	ready               bool
	live                bool
	hasIncludedColumns  bool
	predicateExpression sql.NullString
}

type schemaIndexColumnState struct {
	definition string
	descending sql.NullBool
	nullsFirst sql.NullBool
}

func requireSchemaIndexes(ctx context.Context, queryer schemaQueryer, version, label string) error {
	rows, err := queryer.QueryContext(ctx, `
		SELECT
			index_class.relname,
			table_row.relname,
			access_method.amname,
			index_row.indisunique,
			index_row.indisvalid,
			index_row.indisready,
			index_row.indislive,
			index_row.indnatts <> index_row.indnkeyatts,
			pg_get_expr(index_row.indpred, index_row.indrelid),
			key_row.position,
			pg_get_indexdef(index_row.indexrelid, key_row.position, false),
			pg_index_column_has_property(index_row.indexrelid, key_row.position, 'desc'),
			pg_index_column_has_property(index_row.indexrelid, key_row.position, 'nulls_first')
		FROM pg_index AS index_row
		JOIN pg_class AS index_class ON index_class.oid = index_row.indexrelid
		JOIN pg_class AS table_row ON table_row.oid = index_row.indrelid
		JOIN pg_namespace AS namespace_row ON namespace_row.oid = index_class.relnamespace
		JOIN pg_am AS access_method ON access_method.oid = index_class.relam
		CROSS JOIN LATERAL generate_series(1, index_row.indnkeyatts) AS key_row(position)
		WHERE namespace_row.nspname = current_schema()
		  AND index_class.relkind = 'i'
		  AND table_row.relname IN (
			  'manifests',
			  'repository_manifests',
			  'tags',
			  'findings',
			  'finding_occurrences',
			  'scan_runs'
		  )
		ORDER BY index_class.relname, key_row.position
	`)
	if err != nil {
		return fmt.Errorf("inspect database schema indexes: %w", err)
	}
	defer rows.Close()

	available := make(map[string]schemaIndexState)
	for rows.Next() {
		var index string
		var keyPosition int
		var column schemaIndexColumnState
		var state schemaIndexState
		if err := rows.Scan(
			&index,
			&state.table,
			&state.accessType,
			&state.unique,
			&state.valid,
			&state.ready,
			&state.live,
			&state.hasIncludedColumns,
			&state.predicateExpression,
			&keyPosition,
			&column.definition,
			&column.descending,
			&column.nullsFirst,
		); err != nil {
			return fmt.Errorf("scan database schema index: %w", err)
		}
		existing := available[index]
		if keyPosition != len(existing.columns)+1 {
			return fmt.Errorf("inspect database schema index %s: unexpected key position %d", index, keyPosition)
		}
		state.columns = append(existing.columns, column)
		available[index] = state
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate database schema indexes: %w", err)
	}
	for _, requirement := range schemaIndexRequirements {
		if requirement.version > version {
			continue
		}
		state, ok := available[requirement.name]
		if !ok {
			return fmt.Errorf("%s is missing index %s", label, requirement.name)
		}
		if !state.valid || !state.ready || !state.live {
			return fmt.Errorf("%s index %s is not valid and ready", label, requirement.name)
		}
		if state.table != requirement.table || state.accessType != requirement.accessType || state.unique != requirement.unique || state.hasIncludedColumns || state.predicateExpression.Valid || !schemaIndexColumnsMatch(state.columns, requirement.columns) {
			return fmt.Errorf("%s index %s has an unexpected definition", label, requirement.name)
		}
	}
	return nil
}

func schemaIndexColumnsMatch(actual []schemaIndexColumnState, expected string) bool {
	definitions := make([]string, len(actual))
	for index, column := range actual {
		if !column.descending.Valid || !column.nullsFirst.Valid {
			return false
		}
		definitions[index] = column.definition
		if column.descending.Bool {
			definitions[index] += " DESC"
		}
		if column.nullsFirst.Bool != column.descending.Bool {
			if column.nullsFirst.Bool {
				definitions[index] += " NULLS FIRST"
			} else {
				definitions[index] += " NULLS LAST"
			}
		}
	}
	return normalizeSchemaDefinition(strings.Join(definitions, ", ")) == normalizeSchemaDefinition(expected)
}

func checkSchemaVersion(ctx context.Context, queryer schemaQueryer) error {
	exists, err := tableExistsContext(ctx, queryer, "schema_migrations")
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("database schema is not initialized; run layerleak-migrate-up")
	}
	rows, err := queryer.QueryContext(ctx, `
		SELECT version
		FROM schema_migrations
		ORDER BY version
	`)
	if err != nil {
		return fmt.Errorf("read database schema version: %w", err)
	}
	defer rows.Close()
	versions := make([]string, 0, currentMigrationCount)
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return fmt.Errorf("scan database schema version: %w", err)
		}
		versions = append(versions, version)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate database schema versions: %w", err)
	}
	expectedVersions := make([]string, 0, currentMigrationCount)
	for version := 1; version <= currentMigrationCount; version++ {
		expectedVersions = append(expectedVersions, fmt.Sprintf("%04d", version))
	}
	if !slices.Equal(versions, expectedVersions) {
		return fmt.Errorf("database schema ledger has versions %v, expected %v; run layerleak-migrate-up", versions, expectedVersions)
	}
	if err := validateSchemaContract(ctx, queryer, CurrentSchemaVersion, "database schema"); err != nil {
		return fmt.Errorf("database schema ledger says %s, but required schema objects are missing: %w; restore the database or repair the migration", CurrentSchemaVersion, err)
	}
	return nil
}

func (s *PostgresStore) Ready(ctx context.Context) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("postgres store is not initialized")
	}
	ctx, cancel := withTimeout(ctx, s.queryTimeout)
	defer cancel()
	if err := s.db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping postgres: %w", err)
	}
	return checkSchemaVersion(ctx, s.db)
}
