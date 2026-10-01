import json
import os
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import validate_sarif  # noqa: E402

MINIMAL_SCHEMA = {
    '$schema': 'http://json-schema.org/draft-07/schema#',
    'type': 'object',
    'required': ['version', 'runs'],
    'properties': {
        'version': {'type': 'string', 'enum': ['2.1.0']},
        'runs': {'type': 'array', 'items': {'type': 'object', 'required': ['tool', 'results']}},
    },
    'additionalProperties': True,
}


class ValidateSarifTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.schema = os.path.join(self.directory.name, 'schema.json')
        with open(self.schema, 'w', encoding='utf-8') as handle:
            json.dump(MINIMAL_SCHEMA, handle)

    def write(self, name, document):
        path = os.path.join(self.directory.name, name)
        with open(path, 'w', encoding='utf-8') as handle:
            if isinstance(document, str):
                handle.write(document)
            else:
                json.dump(document, handle)
        return path

    def test_valid_document_passes(self):
        path = self.write('ok.sarif.json', {'version': '2.1.0', 'runs': [{'tool': {}, 'results': []}]})
        self.assertEqual(validate_sarif.main([path, '--schema', self.schema]), 0)

    def test_schema_violation_fails(self):
        path = self.write('bad.sarif.json', {'version': '2.1.0', 'runs': [{'tool': {}}]})
        self.assertEqual(validate_sarif.main([path, '--schema', self.schema]), 1)

    def test_invalid_json_fails(self):
        path = self.write('broken.sarif.json', '{"version": ')
        self.assertEqual(validate_sarif.main([path, '--schema', self.schema]), 1)

    def test_wrong_version_fails(self):
        path = self.write('old.sarif.json', {'version': '2.0.0', 'runs': []})
        self.assertEqual(validate_sarif.main([path, '--schema', self.schema]), 1)

    def test_pinned_schema_checksum_is_sha256(self):
        self.assertRegex(validate_sarif.SCHEMA_SHA256, r'^[0-9a-f]{64}$')
        self.assertTrue(validate_sarif.SCHEMA_URL.startswith('https://'))


if __name__ == '__main__':
    unittest.main()
