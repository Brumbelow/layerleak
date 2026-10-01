import copy
import json
import os
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

try:
    import validate_schemas  # noqa: E402
except ImportError as error:  # jsonschema and referencing come from requirements-docs.txt
    raise unittest.SkipTest(f"documentation validators are not installed: {error}") from error

ROOT = str(pathlib.Path(__file__).resolve().parents[2])


class ValidateSchemasTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.validators = validate_schemas.Validators(ROOT)
        with open(os.path.join(ROOT, validate_schemas.RESULT_FIXTURE), 'rb') as handle:
            self.result = json.load(handle)
        with open(os.path.join(ROOT, validate_schemas.RECORD_FIXTURE), 'rb') as handle:
            self.record = json.load(handle)

    def write(self, name, document):
        path = os.path.join(self.directory.name, name)
        with open(path, 'w', encoding='utf-8') as handle:
            if isinstance(document, str):
                handle.write(document)
            else:
                json.dump(document, handle)
        return path

    def test_repository_fixtures_validate(self):
        self.assertEqual(validate_schemas.main(['--root', ROOT]), 0)

    def test_default_files_include_api_fixtures_with_results(self):
        files = [os.path.relpath(path, ROOT) for path in validate_schemas.default_files(ROOT)]
        self.assertIn(validate_schemas.RESULT_FIXTURE, files)
        self.assertIn(validate_schemas.RECORD_FIXTURE, files)
        self.assertIn(os.path.join('web', 'testdata', 'api', 'scan-completed.json'), files)
        self.assertIn(os.path.join('web', 'testdata', 'api', 'scan-detail.json'), files)
        self.assertNotIn(os.path.join('web', 'testdata', 'api', 'repositories.json'), files)

    def test_golden_result_matches_schema(self):
        self.assertEqual(validate_schemas.validate_document(self.validators, 'result', self.result), [])

    def test_unknown_property_is_rejected(self):
        broken = copy.deepcopy(self.result)
        broken['unexpected'] = 1
        errors = validate_schemas.validate_document(self.validators, 'result', broken)
        self.assertTrue(any('unexpected' in message for message in errors), errors)

    def test_missing_counter_is_rejected(self):
        broken = copy.deepcopy(self.result)
        del broken['tags_enumerated']
        errors = validate_schemas.validate_document(self.validators, 'result', broken)
        self.assertTrue(any('tags_enumerated' in message for message in errors), errors)

    def test_tag_status_enum_is_enforced(self):
        broken = copy.deepcopy(self.result)
        broken['tag_results'][0]['status'] = 'unknown'
        errors = validate_schemas.validate_document(self.validators, 'result', broken)
        self.assertTrue(any('tag_results/0/status' in message for message in errors), errors)

    def test_empty_platform_object_is_allowed_but_unknown_platform_key_is_not(self):
        document = copy.deepcopy(self.result)
        document['findings'][0]['platform'] = {}
        self.assertEqual(validate_schemas.validate_document(self.validators, 'result', document), [])
        document['findings'][0]['platform'] = {'cpu': 'x'}
        self.assertNotEqual(validate_schemas.validate_document(self.validators, 'result', document), [])

    def test_raw_value_fields_are_rejected_in_record_findings(self):
        broken = copy.deepcopy(self.record)
        broken['findings'][0]['value'] = 'leak'
        errors = validate_schemas.validate_document(self.validators, 'record', broken)
        self.assertTrue(any('findings/0' in message for message in errors), errors)

    def test_record_embeds_a_valid_result(self):
        broken = copy.deepcopy(self.record)
        broken['result']['status'] = 'done'
        errors = validate_schemas.validate_document(self.validators, 'record', broken)
        self.assertTrue(any('result/status' in message for message in errors), errors)

    def test_persistence_status_enum(self):
        broken = copy.deepcopy(self.record)
        broken['persistence']['status'] = 'pending'
        errors = validate_schemas.validate_document(self.validators, 'record', broken)
        self.assertTrue(any('persistence/status' in message for message in errors), errors)

    def test_embedded_results_are_discovered(self):
        wrapped = {'scan': {'id': 1, 'result': self.result}, 'other': [{'result': self.result}]}
        locations = [location for location, _ in validate_schemas.embedded_results(wrapped)]
        self.assertEqual(locations, ['$.scan.result', '$.other[0].result'])

    def test_command_line_files_and_failures(self):
        good = self.write('good.json', self.record)
        broken = copy.deepcopy(self.result)
        broken['result_schema_version'] = 1
        bad = self.write('bad.json', broken)
        self.assertEqual(validate_schemas.main(['--root', ROOT, '--no-defaults', good]), 0)
        self.assertEqual(validate_schemas.main(['--root', ROOT, '--no-defaults', bad]), 1)
        invalid = self.write('invalid.json', '{"result_schema_version": ')
        self.assertEqual(validate_schemas.main(['--root', ROOT, '--no-defaults', invalid]), 1)
        unrelated = self.write('unrelated.json', {'hello': 'world'})
        self.assertEqual(validate_schemas.main(['--root', ROOT, '--no-defaults', unrelated]), 1)

    def test_no_files_is_an_error(self):
        self.assertEqual(validate_schemas.main(['--root', ROOT, '--no-defaults']), 1)


if __name__ == '__main__':
    unittest.main()
