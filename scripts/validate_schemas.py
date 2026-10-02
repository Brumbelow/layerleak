#!/usr/bin/env python3
"""Validate Layerleak's published JSON Schemas and the fixtures they govern."""
from __future__ import annotations

import argparse
import json
import os
import sys

import jsonschema
from referencing import Registry, Resource

DETAILS = '''\
Checks that web/docs/schemas/result-v2.schema.json and
scan-record-v2.schema.json are valid JSON Schema 2020-12 documents, then
validates the golden CLI fixtures (internal/cli/testdata/result-v2.json and
scan-record-v2.json) and every result object embedded in the API contract
fixtures (web/testdata/api/*.json) against them. Extra files given on the
command line are validated too: a document with a top-level
record_schema_version is a scan record, one with result_schema_version is a
result, and any other document is searched for embedded results.

Exit status is 0 when every document validates.'''

RESULT_SCHEMA = os.path.join('web', 'docs', 'schemas', 'result-v2.schema.json')
RECORD_SCHEMA = os.path.join('web', 'docs', 'schemas', 'scan-record-v2.schema.json')
RESULT_FIXTURE = os.path.join('internal', 'cli', 'testdata', 'result-v2.json')
RECORD_FIXTURE = os.path.join('internal', 'cli', 'testdata', 'scan-record-v2.json')
API_FIXTURE_DIR = os.path.join('web', 'testdata', 'api')


def repository_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_json(path: str):
    with open(path, 'rb') as handle:
        return json.load(handle)


class Validators:
    """The two schema validators sharing one reference registry."""

    def __init__(self, root: str):
        """Load both schemas from root, check them, and share one registry."""
        result_schema = load_json(os.path.join(root, RESULT_SCHEMA))
        record_schema = load_json(os.path.join(root, RECORD_SCHEMA))
        for schema in (result_schema, record_schema):
            jsonschema.Draft202012Validator.check_schema(schema)
        registry = Registry().with_resources(
            (schema['$id'], Resource.from_contents(schema)) for schema in (result_schema, record_schema)
        )
        checker = jsonschema.Draft202012Validator.FORMAT_CHECKER
        self.result = jsonschema.Draft202012Validator(result_schema, registry=registry, format_checker=checker)
        self.record = jsonschema.Draft202012Validator(record_schema, registry=registry, format_checker=checker)


def format_errors(validator: jsonschema.protocols.Validator, document, label: str) -> list[str]:
    errors = sorted(validator.iter_errors(document), key=lambda error: [str(part) for part in error.absolute_path])
    messages = []
    for error in errors:
        location = '/'.join(str(part) for part in error.absolute_path) or '<root>'
        messages.append(f'{label}: {location}: {error.message}')
    return messages


def embedded_results(document, path: str = '$'):
    """Yield (json_path, object) for every embedded result object."""
    if isinstance(document, dict):
        if 'result_schema_version' in document:
            yield path, document
            return
        for key, child in document.items():
            yield from embedded_results(child, f'{path}.{key}')
    elif isinstance(document, list):
        for index, child in enumerate(document):
            yield from embedded_results(child, f'{path}[{index}]')


def validate_document(validators: Validators, path: str, document) -> list[str]:
    if isinstance(document, dict) and 'record_schema_version' in document:
        return format_errors(validators.record, document, path)
    if isinstance(document, dict) and 'result_schema_version' in document:
        return format_errors(validators.result, document, path)
    messages = []
    found = 0
    for location, result in embedded_results(document):
        found += 1
        messages.extend(format_errors(validators.result, result, f'{path} {location}'))
    if found == 0:
        messages.append(f'{path}: no result or scan record found to validate')
    return messages


def validate_file(validators: Validators, path: str) -> list[str]:
    try:
        document = load_json(path)
    except json.JSONDecodeError as error:
        return [f'{path}: invalid JSON: {error}']
    return validate_document(validators, path, document)


def default_files(root: str) -> list[str]:
    files = [os.path.join(root, RESULT_FIXTURE), os.path.join(root, RECORD_FIXTURE)]
    api_dir = os.path.join(root, API_FIXTURE_DIR)
    for name in sorted(os.listdir(api_dir)):
        if name.endswith('.json'):
            document = load_json(os.path.join(api_dir, name))
            if any(True for _ in embedded_results(document)):
                files.append(os.path.join(api_dir, name))
    return files


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, epilog=DETAILS, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('files', nargs='*', help='additional result or scan-record JSON files to validate')
    parser.add_argument('--root', default=repository_root(), help='repository root (default: the parent of scripts/)')
    parser.add_argument('--no-defaults', action='store_true', help='validate only the files given on the command line')
    args = parser.parse_args(argv)

    validators = Validators(args.root)
    files = [] if args.no_defaults else default_files(args.root)
    files.extend(args.files)
    if not files:
        print('no files to validate', file=sys.stderr)
        return 1
    failures = []
    for path in files:
        failures.extend(validate_file(validators, path))
    for message in failures:
        print(message, file=sys.stderr)
    if failures:
        return 1
    print(f'{len(files)} document(s) valid against result-v2 and scan-record-v2 schemas')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
