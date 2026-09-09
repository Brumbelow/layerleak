import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest


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

    def test_rejects_broken_local_documentation_link(self):
        index = self.root / "web" / "index.html"
        index.write_text(index.read_text().replace('href="./docs/"', 'href="./missing/"'))

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
        example = spec["paths"]["/api/v1/scans"]["post"]["responses"]["200"]["content"]["application/json"]["examples"]["completed"]
        example["externalValue"] = "../testdata/api/scan-partial.json"
        spec_path.write_text(validate_docs.dump_yaml(spec))

        self.assert_invalid("documented example")


if __name__ == "__main__":
    unittest.main()
