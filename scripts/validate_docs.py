#!/usr/bin/env python3
"""Validate the static documentation, OpenAPI contract, and synthetic demo."""

from __future__ import annotations

import json
import sys
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

import yaml
from openapi_schema_validator import OAS31Validator
from openapi_spec_validator import validate as validate_openapi
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012


class ValidationFailure(Exception):
    pass


def load_yaml(path: Path):
    with path.open(encoding="utf-8") as stream:
        return yaml.safe_load(stream)


def dump_yaml(value) -> str:
    return yaml.safe_dump(value, sort_keys=False, width=100)


class _LocalReferenceParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.references: list[tuple[str, str]] = []
        self.ids: set[str] = set()

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        element_id = attributes.get("id")
        if element_id:
            self.ids.add(element_id)
        for attribute in ("href", "src"):
            value = attributes.get(attribute)
            if value:
                self.references.append((attribute, value))


def _format_json_path(parts) -> str:
    if not parts:
        return "$"
    return "$" + "".join(
        f"[{part}]" if isinstance(part, int) else f".{part}" for part in parts
    )


def _validate_instance(spec, schema, instance, label):
    base_uri = "urn:layerleak:openapi"
    registry = Registry().with_resource(
        base_uri,
        Resource.from_contents(spec, default_specification=DRAFT202012),
    )
    validator = OAS31Validator(
        schema,
        _resolver=registry.resolver(base_uri),
        format_checker=OAS31Validator.FORMAT_CHECKER,
    )
    errors = sorted(
        validator.iter_errors(instance),
        key=lambda error: [str(part) for part in error.absolute_path],
    )
    if errors:
        error = errors[0]
        raise ValidationFailure(
            f"{label} {_format_json_path(error.absolute_path)}: {error.message}"
        )


def _resolve_local_ref(spec, value):
    if not isinstance(value, dict) or "$ref" not in value:
        return value
    reference = value["$ref"]
    if not reference.startswith("#/"):
        raise ValidationFailure(f"unsupported non-local OpenAPI reference: {reference}")
    target = spec
    for part in reference[2:].split("/"):
        target = target[part.replace("~1", "/").replace("~0", "~")]
    return target


def _response_schema(spec, path, method, status, media_type):
    try:
        response = spec["paths"][path][method]["responses"][status]
        response = _resolve_local_ref(spec, response)
        return response["content"][media_type]["schema"]
    except KeyError as error:
        raise ValidationFailure(
            f"OpenAPI response is missing {method.upper()} {path} "
            f"{status} {media_type}: {error}"
        ) from error


def validate_contract_fixtures(root: Path, spec):
    manifest_path = root / "web" / "testdata" / "api-contract.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    required_outcomes = {"completed", "partial", "failed", "storage_error"}
    seen_outcomes = set()
    fixture_values = {}
    for case in manifest.get("cases", []):
        outcome = case.get("outcome")
        seen_outcomes.add(outcome)
        relative_fixture = case["fixture"]
        fixture_path = root / relative_fixture
        instance = json.loads(fixture_path.read_text(encoding="utf-8"))
        schema = _response_schema(
            spec, case["path"], case["method"], str(case["status"]), case["media_type"]
        )
        _validate_instance(spec, schema, instance, relative_fixture)
        fixture_values[relative_fixture] = instance
    if seen_outcomes != required_outcomes:
        raise ValidationFailure(
            "contract fixtures must cover completed, partial, failed, "
            "and storage_error outcomes"
        )
    return fixture_values


def _documented_response_media(spec):
    for path, path_item in spec.get("paths", {}).items():
        for method in ("get", "post", "put", "patch", "delete"):
            operation = path_item.get(method)
            if not operation:
                continue
            for status, raw_response in operation.get("responses", {}).items():
                response = _resolve_local_ref(spec, raw_response)
                for media in response.get("content", {}).values():
                    yield f"documented example {method.upper()} {path} {status}", media


def _resolve_repository_path(root: Path, directory: Path, reference, label):
    path = (directory / reference).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as error:
        raise ValidationFailure(f"{label} points outside the repository") from error
    return path


def _load_documented_example(root: Path, spec_directory: Path, name, example):
    if "value" in example:
        return example["value"]
    external_path = _resolve_repository_path(
        root, spec_directory, example["externalValue"], f"documented example {name}"
    )
    return json.loads(external_path.read_text(encoding="utf-8"))


def _validate_example_fixture(
    root: Path, example, example_value, fixture_values, label
):
    fixture_reference = example.get("x-contract-fixture")
    if not fixture_reference:
        return
    fixture_path = _resolve_repository_path(
        root, root / "web" / "docs", fixture_reference, label
    )
    relative_fixture = fixture_path.relative_to(root.resolve()).as_posix()
    expected = fixture_values.get(relative_fixture)
    if expected is None:
        raise ValidationFailure(f"{label} references an unregistered fixture")
    if example_value != expected:
        raise ValidationFailure(f"{label} differs from {relative_fixture}")


def validate_documented_examples(root: Path, spec, fixture_values):
    spec_directory = root / "web" / "docs"
    example_count = 0
    for response_label, media in _documented_response_media(spec):
        schema = media.get("schema")
        for name, example in media.get("examples", {}).items():
            if "value" not in example and "externalValue" not in example:
                continue
            example_value = _load_documented_example(
                root, spec_directory, name, example
            )
            label = f"{response_label} {name}"
            _validate_instance(spec, schema, example_value, label)
            _validate_example_fixture(
                root, example, example_value, fixture_values, label
            )
            example_count += 1
    if example_count < 4:
        raise ValidationFailure("OpenAPI must document at least four response examples")


def _local_target_path(root: Path, html_path: Path, attribute, reference, parsed):
    web_root = root / "web"
    target_path = (
        html_path if not parsed.path else html_path.parent / unquote(parsed.path)
    )
    if parsed.path.endswith("/") or target_path.is_dir():
        target_path /= "index.html"
    try:
        target_path.resolve().relative_to(web_root.resolve())
    except ValueError as error:
        raise ValidationFailure(
            f"{html_path.relative_to(root)} {attribute} "
            f"points outside web/: {reference}"
        ) from error
    if not target_path.exists():
        raise ValidationFailure(
            f"{html_path.relative_to(root)} has missing local target: {reference}"
        )
    return target_path


def _validate_local_reference(root: Path, html_path: Path, attribute, reference):
    parsed = urlsplit(reference)
    if parsed.scheme or parsed.netloc or reference.startswith(("mailto:", "tel:")):
        return
    target_path = _local_target_path(root, html_path, attribute, reference, parsed)
    if parsed.fragment:
        fragment_parser = _LocalReferenceParser()
        fragment_parser.feed(target_path.read_text(encoding="utf-8"))
        if unquote(parsed.fragment) not in fragment_parser.ids:
            raise ValidationFailure(
                f"{html_path.relative_to(root)} "
                f"has missing fragment target: {reference}"
            )


def validate_local_references(root: Path):
    web_root = root / "web"
    for html_path in sorted(web_root.rglob("*.html")):
        parser = _LocalReferenceParser()
        parser.feed(html_path.read_text(encoding="utf-8"))
        for attribute, reference in parser.references:
            _validate_local_reference(root, html_path, attribute, reference)


def _validate_demo_run_result(run_result):
    if run_result.get("raw_storage_enabled") is not False:
        raise ValidationFailure("demo-data.json raw_storage_enabled must be false")
    if run_result.get("status") not in {"completed", "partial", "failed"}:
        raise ValidationFailure("demo-data.json run_result.status is invalid")
    if run_result.get("coverage", {}).get("complete") != (
        run_result["status"] == "completed"
    ):
        raise ValidationFailure(
            "demo-data.json coverage.complete conflicts with status"
        )
    artifacts = run_result.get("artifacts", {})
    if set(artifacts) != {"findings", "scan_record"}:
        raise ValidationFailure(
            "demo-data.json must name findings and scan_record artifacts"
        )
    if PurePosixPath(artifacts["scan_record"]).parent.name != "scans":
        raise ValidationFailure(
            "demo-data.json scan_record artifact must be under scans/"
        )


def _validate_demo_table(table_name, table):
    columns = table.get("columns", [])
    if not columns or len(columns) != len(set(columns)):
        raise ValidationFailure(
            f"demo-data.json table {table_name} has invalid columns"
        )
    for row in table.get("rows", []):
        if set(row) != set(columns):
            raise ValidationFailure(
                f"demo-data.json table {table_name} row does not match columns"
            )
        for raw_field in ("value", "raw_snippet"):
            if raw_field in row and row[raw_field] is not None:
                raise ValidationFailure(
                    f"demo-data.json table {table_name} {raw_field} "
                    "must be null when raw storage is disabled"
                )


def validate_demo(root: Path):
    fixture_path = root / "web" / "assets" / "demo-data.json"
    demo = json.loads(fixture_path.read_text(encoding="utf-8"))
    required_top_level = {
        "version",
        "synthetic",
        "command",
        "run_result",
        "stats",
        "frames",
        "table_order",
        "tables",
    }
    missing = sorted(required_top_level - demo.keys())
    if missing:
        raise ValidationFailure(f"demo-data.json missing fields: {', '.join(missing)}")
    if demo["synthetic"] is not True:
        raise ValidationFailure("demo-data.json synthetic must be true")
    _validate_demo_run_result(demo["run_result"])
    table_order = demo["table_order"]
    tables = demo["tables"]
    if len(table_order) != len(set(table_order)) or set(table_order) != set(tables):
        raise ValidationFailure(
            "demo-data.json table_order must list every table exactly once"
        )
    for table_name, table in tables.items():
        _validate_demo_table(table_name, table)
    if not demo["frames"] or any(
        not isinstance(frame.get("terminal"), str) for frame in demo["frames"]
    ):
        raise ValidationFailure(
            "demo-data.json frames must contain terminal transcripts"
        )


def validate_repository(root: Path):
    root = root.resolve()
    spec_path = root / "web" / "docs" / "openapi.yaml"
    spec = load_yaml(spec_path)
    try:
        validate_openapi(spec)
    except Exception as error:
        raise ValidationFailure(f"invalid OpenAPI 3.1 document: {error}") from error
    if spec.get("openapi") != "3.1.0":
        raise ValidationFailure("web/docs/openapi.yaml must remain OpenAPI 3.1.0")
    fixtures = validate_contract_fixtures(root, spec)
    validate_documented_examples(root, spec, fixtures)
    validate_local_references(root)
    validate_demo(root)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    try:
        validate_repository(root)
    except (ValidationFailure, OSError, json.JSONDecodeError, yaml.YAMLError) as error:
        print(f"documentation validation failed: {error}", file=sys.stderr)
        return 1
    print(
        "OpenAPI contract, response examples, local links, and synthetic demo are valid"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
