#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repository_dir=$(CDPATH='' cd -- "${script_dir}/.." && pwd)

if [ -z "${LAYERLEAK_MIGRATIONS_DIR:-}" ]; then
	export LAYERLEAK_MIGRATIONS_DIR="${repository_dir}/migrations"
fi

exec go run "${repository_dir}/cmd/migrate"
