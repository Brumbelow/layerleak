#!/usr/bin/env python3
"""Validate SARIF 2.1.0 files against the OASIS schema.

The schema is fetched from json.schemastore.org and pinned by SHA-256 so a
silently changed copy fails closed; pass --schema to use a local file instead
(for offline runs or tests). Exit status is 0 when every file validates.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import urllib.request

import jsonschema

SCHEMA_URL = 'https://json.schemastore.org/sarif-2.1.0.json'
# sha256 of the schemastore copy reviewed on 2026-10-01. Re-pin deliberately
# after reading the diff when the upstream file changes.
SCHEMA_SHA256 = 'c96eb2d311c37b0a38cbd18c52d79a68f778bbd2d831abed7412d9850740f785'
MAX_SCHEMA_BYTES = 4 * 1024 * 1024


def fetch_schema(cache_dir: str | None) -> dict:
    cache_dir = cache_dir or os.path.join(tempfile.gettempdir(), 'layerleak-sarif-schema')
    os.makedirs(cache_dir, exist_ok=True)
    cached = os.path.join(cache_dir, f'sarif-2.1.0-{SCHEMA_SHA256[:16]}.json')
    if not os.path.exists(cached):
        request = urllib.request.Request(SCHEMA_URL, headers={'User-Agent': 'layerleak-validate-sarif'})
        with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310 - fixed https URL
            payload = response.read(MAX_SCHEMA_BYTES + 1)
        if len(payload) > MAX_SCHEMA_BYTES:
            raise SystemExit('schema download exceeded the size bound')
        digest = hashlib.sha256(payload).hexdigest()
        if digest != SCHEMA_SHA256:
            raise SystemExit(f'schema checksum mismatch: expected {SCHEMA_SHA256}, got {digest}')
        with open(cached + '.partial', 'wb') as handle:
            handle.write(payload)
        os.replace(cached + '.partial', cached)
    with open(cached, 'rb') as handle:
        payload = handle.read()
    if hashlib.sha256(payload).hexdigest() != SCHEMA_SHA256:
        raise SystemExit(f'cached schema {cached} is corrupt; delete it and retry')
    return json.loads(payload)


def load_schema(path: str | None, cache_dir: str | None) -> dict:
    if path:
        with open(path, 'rb') as handle:
            return json.load(handle)
    return fetch_schema(cache_dir)


def validate_file(validator: jsonschema.protocols.Validator, path: str) -> list[str]:
    with open(path, 'rb') as handle:
        try:
            document = json.load(handle)
        except json.JSONDecodeError as error:
            return [f'{path}: invalid JSON: {error}']
    errors = sorted(validator.iter_errors(document), key=lambda error: list(error.absolute_path))
    messages = []
    for error in errors:
        location = '/'.join(str(part) for part in error.absolute_path) or '<root>'
        messages.append(f'{path}: {location}: {error.message}')
    if not errors and document.get('version') != '2.1.0':
        messages.append(f'{path}: version must be 2.1.0')
    return messages


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('files', nargs='+', help='SARIF files to validate')
    parser.add_argument('--schema', help='local schema file instead of the pinned download')
    parser.add_argument('--cache-dir', help='directory for the downloaded schema')
    args = parser.parse_args(argv)
    schema = load_schema(args.schema, args.cache_dir)
    validator_class = jsonschema.validators.validator_for(schema)
    validator_class.check_schema(schema)
    validator = validator_class(schema)
    failures = []
    for path in args.files:
        failures.extend(validate_file(validator, path))
    for message in failures:
        print(message, file=sys.stderr)
    if failures:
        return 1
    print(f'{len(args.files)} SARIF file(s) valid against SARIF 2.1.0')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
