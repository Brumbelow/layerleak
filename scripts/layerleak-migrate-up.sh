#!/bin/sh
set -eu

if [ -z "${LAYERLEAK_DATABASE_URL:-}" ]; then
	echo "LAYERLEAK_DATABASE_URL is required" >&2
	exit 1
fi

MIGRATIONS_DIR="${LAYERLEAK_MIGRATIONS_DIR:-/app/migrations}"
MIN_SERVER_VERSION_NUM=160013
MIN_SERVER_VERSION_LABEL="16.13"
MIN_CLIENT_VERSION="16.13-1.pgdg24.04+1"
REQUIRED_CLIENT_LINEAGE_SUFFIX=".pgdg24.04+"

query_value() {
	sql="$1"
	psql "$LAYERLEAK_DATABASE_URL" -v ON_ERROR_STOP=1 -Atqc "$sql" | tr -d '[:space:]'
}

require_migration_file() {
	file_path="$1"
	if [ ! -f "$file_path" ]; then
		echo "migration file not found: $file_path" >&2
		exit 1
	fi
}

query_true() {
	sql="$1"
	[ "$(query_value "$sql")" = "t" ]
}

table_exists() {
	table_name="$1"
	query_true "SELECT to_regclass('public.${table_name}') IS NOT NULL;"
}

column_exists() {
	table_name="$1"
	column_name="$2"
	query_true "SELECT EXISTS (
		SELECT 1
		FROM information_schema.columns
		WHERE table_schema = 'public'
		  AND table_name = '${table_name}'
		  AND column_name = '${column_name}'
	);"
}

count_existing_tables() {
	count=0
	for table_name in "$@"; do
		if table_exists "$table_name"; then
			count=$((count + 1))
		fi
	done
	echo "$count"
}

count_existing_columns() {
	table_name="$1"
	shift
	count=0
	for column_name in "$@"; do
		if column_exists "$table_name" "$column_name"; then
			count=$((count + 1))
		fi
	done
	echo "$count"
}

apply_migration() {
	migration_file="$1"
	require_migration_file "$migration_file"
	echo "applying $(basename "$migration_file")"
	psql "$LAYERLEAK_DATABASE_URL" -v ON_ERROR_STOP=1 -f "$migration_file"
}

validate_client_version() {
	if ! command -v dpkg-query >/dev/null 2>&1 || ! command -v dpkg >/dev/null 2>&1; then
		echo "dpkg tooling is required to validate postgresql-client-16 version" >&2
		exit 1
	fi

	client_version="$(dpkg-query --showformat='${Version}' --show postgresql-client-16 2>/dev/null || true)"
	if [ -z "$client_version" ]; then
		echo "postgresql-client-16 package is required" >&2
		exit 1
	fi

	case "$client_version" in
		*"${REQUIRED_CLIENT_LINEAGE_SUFFIX}"*)
			;;
		*)
			echo "postgresql-client-16 must use PGDG Ubuntu 24.04 packaging (got: $client_version)" >&2
			exit 1
			;;
	esac

	if ! dpkg --compare-versions "$client_version" ge "$MIN_CLIENT_VERSION"; then
		echo "postgresql-client-16 must be >= $MIN_CLIENT_VERSION (got: $client_version)" >&2
		exit 1
	fi
}

validate_server_version() {
	server_version_num="$(query_value "SHOW server_version_num")"
	case "$server_version_num" in
		''|*[!0-9]*)
			echo "invalid PostgreSQL server_version_num: $server_version_num" >&2
			exit 1
			;;
	esac

	if [ "$server_version_num" -lt "$MIN_SERVER_VERSION_NUM" ]; then
		echo "PostgreSQL server must be >= ${MIN_SERVER_VERSION_LABEL} (server_version_num >= ${MIN_SERVER_VERSION_NUM}, got ${server_version_num})" >&2
		exit 1
	fi
}

validate_client_version
validate_server_version

set -- "repositories" "manifests" "repository_manifests" "tags" "findings" "finding_occurrences"
existing_0001="$(count_existing_tables "$@")"
total_0001="$#"

if [ "$existing_0001" -eq 0 ]; then
	apply_migration "${MIGRATIONS_DIR}/0001_initial.up.sql"
elif [ "$existing_0001" -eq "$total_0001" ]; then
	echo "skipping 0001_initial.up.sql (already applied)"
else
	echo "detected partial 0001 schema (${existing_0001}/${total_0001} tables); refusing automatic migration" >&2
	exit 1
fi

if ! table_exists "finding_occurrences"; then
	echo "finding_occurrences table is missing after 0001 checks" >&2
	exit 1
fi

set -- "disposition" "disposition_reason" "line_number"
existing_0002="$(count_existing_columns "finding_occurrences" "$@")"
total_0002="$#"

if [ "$existing_0002" -eq 0 ]; then
	apply_migration "${MIGRATIONS_DIR}/0002_finding_occurrence_metadata.up.sql"
elif [ "$existing_0002" -eq "$total_0002" ]; then
	echo "skipping 0002_finding_occurrence_metadata.up.sql (already applied)"
else
	echo "detected partial 0002 schema (${existing_0002}/${total_0002} columns); refusing automatic migration" >&2
	exit 1
fi

if table_exists "scan_runs"; then
	echo "skipping 0003_scan_runs.up.sql (already applied)"
else
	apply_migration "${MIGRATIONS_DIR}/0003_scan_runs.up.sql"
fi

echo "migrations are up to date"
