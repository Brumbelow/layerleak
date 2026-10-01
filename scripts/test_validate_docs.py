import importlib.util
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPOSITORY_ROOT / "scripts" / "validate_docs.py"
SPEC = importlib.util.spec_from_file_location("validate_docs", MODULE_PATH)
validate_docs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validate_docs)


class DocumentationValidationTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        shutil.copytree(REPOSITORY_ROOT / "web", self.root / "web")
        shutil.copy(REPOSITORY_ROOT / "CHANGELOG.md", self.root / "CHANGELOG.md")
        shutil.copy(REPOSITORY_ROOT / "README.md", self.root / "README.md")

    def tearDown(self):
        self.temporary_directory.cleanup()

    def assert_invalid(self, expected_message):
        with self.assertRaises(validate_docs.ValidationFailure) as caught:
            validate_docs.validate_repository(self.root)
        self.assertIn(expected_message, str(caught.exception))

    def test_rejects_response_that_does_not_match_operation_schema(self):
        fixture = self.root / "web" / "testdata" / "api" / "scan-completed.json"
        response = json.loads(fixture.read_text())
        response["result"]["status"] = "unknown"
        fixture.write_text(json.dumps(response))

        self.assert_invalid("scan-completed.json")

    def test_accepts_stored_version_1_result_without_v2_only_fields(self):
        # GET /api/v1/scans/{id} returns result_json as it was stored, so a
        # scan persisted by 2.x (result_schema_version 1, no scanned_at or
        # scanner, zero counters omitted) must still satisfy ScanResult.
        spec = validate_docs.load_yaml(self.root / "web" / "docs" / "openapi.yaml")
        schema = validate_docs._response_schema(
            spec, "/api/v1/scans/{id}", "get", "200", "application/json"
        )
        detail = json.loads(
            (self.root / "web" / "testdata" / "api" / "scan-detail.json").read_text()
        )
        result = detail["scan"]["result"]
        result["result_schema_version"] = 1
        for field in (
            "scanned_at",
            "scanner",
            "tags_enumerated",
            "tags_resolved",
            "tags_failed",
            "suppressed_findings_count",
            "suppressed_unique_fingerprints",
        ):
            result.pop(field, None)

        validate_docs._validate_instance(spec, schema, detail, "stored v1 result")

    def test_rejects_openapi_version_that_differs_from_changelog_release(self):
        spec_path = self.root / "web" / "docs" / "openapi.yaml"
        spec = validate_docs.load_yaml(spec_path)
        spec["info"]["version"] = "9.9.9"
        spec_path.write_text(validate_docs.dump_yaml(spec))

        self.assert_invalid("info.version 9.9.9 differs")

    def test_rejects_release_tag_that_differs_from_documented_version(self):
        with patch.dict(os.environ, {"GITHUB_REF_TYPE": "tag", "GITHUB_REF_NAME": "v9.9.9-rc.1"}):
            self.assert_invalid("release tag v9.9.9-rc.1")
        with patch.dict(os.environ, {"GITHUB_REF_TYPE": "tag", "GITHUB_REF_NAME": "v3.0.0-rc.1"}):
            validate_docs.validate_repository(self.root)

    def test_rejects_broken_local_documentation_link(self):
        index = self.root / "web" / "index.html"
        index.write_text(
            index.read_text().replace('href="./docs/"', 'href="./missing/"')
        )

        self.assert_invalid("missing")

    def test_rejects_demo_without_default_raw_storage_state(self):
        fixture = self.root / "web" / "assets" / "demo-data.json"
        demo = json.loads(fixture.read_text())
        demo["run_result"]["raw_storage_enabled"] = True
        fixture.write_text(json.dumps(demo))

        self.assert_invalid("raw_storage_enabled")

    def test_rejects_documented_example_that_differs_from_handler_fixture(self):
        spec_path = self.root / "web" / "docs" / "openapi.yaml"
        spec = validate_docs.load_yaml(spec_path)
        example = spec["paths"]["/api/v1/scans"]["post"]["responses"]["200"]["content"][
            "application/json"
        ]["examples"]["completed"]
        example["externalValue"] = "../testdata/api/scan-partial.json"
        spec_path.write_text(validate_docs.dump_yaml(spec))

        self.assert_invalid("documented example")

    def test_rejects_documented_example_paths_outside_repository(self):
        spec_path = self.root / "web" / "docs" / "openapi.yaml"
        original_spec = spec_path.read_text()
        for field in ("externalValue", "x-contract-fixture"):
            with self.subTest(field=field):
                spec_path.write_text(original_spec)
                spec = validate_docs.load_yaml(spec_path)
                media = spec["paths"]["/api/v1/scans"]["post"]["responses"]["200"][
                    "content"
                ]["application/json"]
                media["examples"]["completed"][field] = "../../../outside.json"
                spec_path.write_text(validate_docs.dump_yaml(spec))

                self.assert_invalid("points outside the repository")

    def test_rejects_missing_local_fragment(self):
        page = self.root / "web" / "fragment-test.html"
        page.write_text('<a href="#missing">Missing fragment</a>')

        self.assert_invalid("missing fragment target")

    def test_rejects_local_target_outside_web(self):
        page = self.root / "web" / "outside-test.html"
        page.write_text('<a href="../outside.html">Outside web</a>')
        (self.root / "outside.html").write_text("Outside web")

        self.assert_invalid("points outside web/")

    def test_accepts_directory_links_and_encoded_fragments(self):
        directory = self.root / "web" / "link-test"
        directory.mkdir()
        (directory / "index.html").write_text('<p id="a b">Target</p>')
        page = self.root / "web" / "link-test.html"
        page.write_text(
            '<a href="./link-test#a%20b">Without trailing slash</a>'
            '<a href="./link-test/#a%20b">With trailing slash</a>'
        )

        validate_docs.validate_repository(self.root)

    def test_rejects_demo_with_inconsistent_coverage(self):
        fixture = self.root / "web" / "assets" / "demo-data.json"
        demo = json.loads(fixture.read_text())
        demo["run_result"]["coverage"]["complete"] = False
        fixture.write_text(json.dumps(demo))

        self.assert_invalid("coverage.complete conflicts with status")

    def test_rejects_demo_with_mismatched_table_row(self):
        fixture = self.root / "web" / "assets" / "demo-data.json"
        demo = json.loads(fixture.read_text())
        del demo["tables"]["findings"]["rows"][0]["value"]
        fixture.write_text(json.dumps(demo))

        self.assert_invalid("row does not match columns")

    def test_rejects_demo_with_stored_raw_fields(self):
        fixture = self.root / "web" / "assets" / "demo-data.json"
        original_demo = fixture.read_text()
        for table, field in (
            ("findings", "value"),
            ("finding_occurrences", "raw_snippet"),
        ):
            with self.subTest(field=field):
                demo = json.loads(original_demo)
                demo["tables"][table]["rows"][0][field] = "raw example"
                fixture.write_text(json.dumps(demo))

                self.assert_invalid(f"{field} must be empty")

    def test_rejects_demo_with_legacy_two_file_artifacts(self):
        fixture = self.root / "web" / "assets" / "demo-data.json"
        original_demo = fixture.read_text()
        record = json.loads(original_demo)["run_result"]["artifacts"]["scan_record"]
        name = record.rsplit("/", 1)[-1]
        for artifacts, message in (
            (
                {"findings": "findings/" + name, "scan_record": "findings/scans/" + name},
                "exactly one scan_record artifact",
            ),
            ({"scan_record": "findings/scans/" + name}, "<utc-timestamp>"),
            ({"scan_record": "findings/20260328T182355Z-app-demo.json"}, "<utc-timestamp>"),
        ):
            with self.subTest(artifacts=artifacts):
                demo = json.loads(original_demo)
                demo["run_result"]["artifacts"] = artifacts
                fixture.write_text(json.dumps(demo))

                self.assert_invalid(message)

    def test_rejects_demo_with_unknown_exit_code_or_schema_version(self):
        fixture = self.root / "web" / "assets" / "demo-data.json"
        original_demo = fixture.read_text()
        for field, value, message in (
            ("exit_code", 4, "exit_code"),
            ("result_schema_version", 1, "result_schema_version must be 2"),
            ("record_schema_version", 1, "record_schema_version must be 2"),
        ):
            with self.subTest(field=field):
                demo = json.loads(original_demo)
                demo["run_result"][field] = value
                fixture.write_text(json.dumps(demo))

                self.assert_invalid(message)

    def test_rejects_web_variable_without_readme_row(self):
        index = self.root / "web" / "docs" / "index.html"
        index.write_text(
            index.read_text().replace(
                "<code>LAYERLEAK_LOG_LEVEL</code>", "<code>LAYERLEAK_NOT_A_REAL_SETTING</code>", 1
            )
        )

        self.assert_invalid("LAYERLEAK_NOT_A_REAL_SETTING")

    def test_rejects_damaged_readme_variable_tables(self):
        readme = self.root / "README.md"
        readme.write_text(readme.read_text().replace("| `LAYERLEAK_", "| LAYERLEAK_"))

        self.assert_invalid("tables look damaged")


if __name__ == "__main__":
    unittest.main()
