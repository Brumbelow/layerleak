import base64
import importlib.util
import json
import os
import shutil
import subprocess  # Tests run owned scripts with absolute interpreters and shell=False.  # nosec B404
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'release-preflight.py'


class ReleasePreflightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('release_preflight', SCRIPT)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def command(self, args, **kwargs):
        output = {
            ('gh', '--version'): 'gh version 2.100.0 (2026-09-03)\n',
            ('gh', 'release', 'verify', '--help'): '--repo\n',
            ('gh', 'release', 'verify-asset', '--help'): '--repo\n',
            ('gh', 'attestation', 'verify', '--help'): (
                '--bundle-from-oci --signer-workflow --source-ref --source-digest '
                '--deny-self-hosted-runners --repo --format --predicate-type'),
            ('gh', 'release', 'view', '--json'): '  isDraft\n  isImmutable\n  isPrerelease\n  publishedAt\n',
        }.get(tuple(args))
        if output is None:
            self.fail(f'unexpected command or external write: {args}')
        return subprocess.CompletedProcess(args, 1 if args[-1] == '--json' else 0, output, '')

    @staticmethod
    def executable(directory, name):
        command = Path(directory) / name
        command.write_text(f'#!{sys.executable}\nimport json, sys\nprint(json.dumps(sys.argv))\n')
        command.chmod(0o700)
        return command

    def test_run_uses_absolute_tool_path_and_preserves_arguments(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'PATH': directory}):
            command = self.executable(directory, 'gh')
            arguments = ['--version', 'one argument with spaces', 'literal;value']
            with patch.object(self.module.subprocess, 'run', wraps=subprocess.run) as invoked:
                result = self.module.run(['gh', *arguments])
            self.assertEqual(json.loads(result.stdout), [str(command), *arguments])
            self.assertEqual(invoked.call_args.args[0], [str(command), *arguments])
            self.assertFalse(invoked.call_args.kwargs['shell'])

    def test_run_rejects_unreviewed_executable_names_and_paths(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'PATH': directory}):
            command = self.executable(directory, 'unreviewed-release-tool')
            for name in ('unreviewed-release-tool', str(command)):
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'unsupported release tool'):
                    self.module.run([name])

    def test_run_rejects_relative_path_entries(self):
        with tempfile.TemporaryDirectory(dir='.') as directory, patch.dict(os.environ, {'PATH': os.path.relpath(directory)}):
            self.executable(directory, 'gh')
            with self.assertRaisesRegex(ValueError, 'command unavailable'):
                self.module.run(['gh', '--version'])

    def test_run_cannot_override_process_policy(self):
        with self.assertRaises(TypeError):
            self.module.run(['gh', '--version'], shell=False)
        with self.assertRaises(TypeError):
            self.module.run(['gh', '--version'], executable='/usr/bin/other')

    def test_run_rejects_missing_executable(self):
        with (tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'PATH': directory}),
              self.assertRaisesRegex(ValueError, 'command unavailable')):
            self.module.run(['gh', '--version'])

    def test_supported_gh_capabilities_pass_without_network(self):
        with patch.object(self.module, 'run', side_effect=self.command):
            self.module.check_tools(False)

    def test_old_or_unreviewed_gh_is_rejected(self):
        for version in ('2.46.0', '2.93.0', '2.101.0'):
            result = subprocess.CompletedProcess([], 0, f'gh version {version}\n', '')
            with (self.subTest(version=version), patch.object(self.module, 'run', return_value=result),
                  self.assertRaisesRegex(ValueError, '2.100.0')):
                self.module.check_tools(False)

    def test_missing_required_field_is_rejected(self):
        def command(args, **kwargs):
            result = self.command(args, **kwargs)
            result.stdout = result.stdout.replace('isImmutable', 'unknown')
            return result
        with patch.object(self.module, 'run', side_effect=command), self.assertRaisesRegex(ValueError, 'isImmutable'):
            self.module.check_tools(False)

    def test_missing_attestation_option_is_rejected(self):
        def command(args, **kwargs):
            result = self.command(args, **kwargs)
            result.stdout = result.stdout.replace('--predicate-type', '')
            return result
        with patch.object(self.module, 'run', side_effect=command), self.assertRaisesRegex(ValueError, 'predicate-type'):
            self.module.check_tools(False)

    def test_full_check_requires_exact_cosign_grype_and_buildx_versions(self):
        full = {
            ('cosign', 'version'): 'GitVersion: v3.0.2',
            ('cosign', 'verify', '--help'): '--certificate-identity --certificate-oidc-issuer',
            ('cosign', 'sign', '--help'): '--yes',
            ('grype', 'version'): 'Version: 0.99.1',
            ('grype', '--help'): '--fail-on --only-fixed --platform',
            ('docker', 'buildx', 'version'): 'github.com/docker/buildx v0.37.0 hash',
            ('docker', 'buildx', 'imagetools', 'inspect', '--help'): '--raw',
            ('docker', 'buildx', 'imagetools', 'create', '--help'): '--tag',
            ('docker', 'info', '--format', '{{.ServerVersion}}'): '29.6.1',
            ('git', '--version'): 'git version',
            ('gpg', '--version'): 'gpg version',
            ('jq', '--version'): 'jq version',
            ('curl', '--version'): 'curl version',
        }

        def command(args, **kwargs):
            if tuple(args) in full:
                return subprocess.CompletedProcess(args, 0, full[tuple(args)], '')
            return self.command(args, **kwargs)
        with patch.object(self.module, 'run', side_effect=command):
            self.module.check_tools(True)
            for key, version in ((('cosign', 'version'), 'v3.0.2'), (('grype', 'version'), '0.99.1'), (('docker', 'buildx', 'version'), 'v0.37.0')):
                original = full[key]
                full[key] = original.replace(version, version + '0')
                with self.subTest(key=key), self.assertRaises(ValueError):
                    self.module.check_tools(True)
                full[key] = original

    def test_oversized_stdin_is_rejected_before_object_import(self):
        # The current Python interpreter runs an owned script; fixture bytes are passed on stdin.
        result = subprocess.run(  # nosec B603
            [sys.executable, str(SCRIPT), 'tag', '--version', 'v1.1.0-rc.1', '--source', 'a' * 40],
            input=self.payload() + '\n' * 20000, check=False, shell=False,
            text=True, capture_output=True, timeout=60)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('16384', result.stderr)

    def test_installer_rejects_corrupt_cached_archive_without_installation(self):
        bash = shutil.which('bash', path=os.defpath)
        self.assertIsNotNone(bash, 'Bash must be installed in the system executable path')
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / 'downloads'
            cache.mkdir()
            (cache / 'gh.tar.gz').write_bytes(b'corrupt archive')
            # System-path Bash runs an owned script against a disposable corrupt-cache fixture.
            result = subprocess.run(  # nosec B603
                [bash, str(SCRIPT.with_name('release-tools.sh')), directory],
                check=False, shell=False, text=True, capture_output=True, timeout=60)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Checksum verification failed', result.stderr)
            self.assertFalse((Path(directory) / 'bin' / 'gh').exists())

    @staticmethod
    def payload(header=None, signature='-----BEGIN PGP SIGNATURE-----\ntest\n-----END PGP SIGNATURE-----\n'):
        header = header or f'object {"a" * 40}\ntype commit\ntag v1.1.0-rc.1\ntagger Maintainer <maintainer@example.test> 1788900000 +0000'
        return base64.b64encode((header + '\n\nRelease\n' + signature).encode()).decode()

    def test_tag_payload_retains_exact_object_bytes(self):
        payload = self.payload()
        self.assertEqual(self.module.decode_tag(payload, 'v1.1.0-rc.1', 'a' * 40), base64.b64decode(payload))

    def test_tag_rejects_mismatched_source_name_type_or_extra_headers(self):
        normal = f'object {"a" * 40}\ntype commit\ntag v1.1.0-rc.1\ntagger Maintainer <maintainer@example.test> 1788900000 +0000'
        for header in (normal.replace('a' * 40, 'b' * 40), normal.replace('type commit', 'type tag'),
                       normal.replace('v1.1.0-rc.1', 'v1.2.0'), normal + '\nobject ' + 'a' * 40):
            with self.subTest(header=header), self.assertRaises(ValueError):
                self.module.decode_tag(self.payload(header), 'v1.1.0-rc.1', 'a' * 40)

    def test_tag_rejects_missing_signature_invalid_base64_and_oversize(self):
        for payload in (self.payload(signature=''), '!!!', 'A' * 16385):
            with self.subTest(payload=payload[:30]), self.assertRaises(ValueError):
                self.module.decode_tag(payload, 'v1.1.0-rc.1', 'a' * 40)

    def test_tag_rejects_noncanonical_encoding_and_control_bytes(self):
        raw = base64.b64decode(self.payload())
        payloads = ['', 'Zh==', base64.b64encode(b'\xff').decode()]
        payloads.extend(base64.b64encode(raw + suffix).decode() for suffix in (b'\x00', b'\r'))
        for payload in payloads:
            with self.subTest(payload=payload[:30]), self.assertRaises(ValueError):
                self.module.decode_tag(payload, 'v1.1.0-rc.1', 'a' * 40)

    def test_tag_rejects_noncanonical_version_and_source(self):
        for version, source in (('v1.01.0', 'a' * 40), ('v1.1.0-rc.0', 'a' * 40),
                                ('v1.1.0-rc.1', 'A' * 40), ('v1.1.0-rc.1', 'a' * 39)):
            with self.subTest(version=version, source=source), self.assertRaises(ValueError):
                self.module.decode_tag(self.payload(), version, source)

    def test_tag_rejects_incomplete_or_repeated_signature_envelope(self):
        envelope = '-----BEGIN PGP SIGNATURE-----\ntest\n-----END PGP SIGNATURE-----\n'
        for signature in (envelope.rstrip('\n'), envelope + envelope):
            with self.subTest(signature=signature), self.assertRaises(ValueError):
                self.module.decode_tag(self.payload(signature=signature), 'v1.1.0-rc.1', 'a' * 40)

    def test_tag_signature_and_existing_object_must_match(self):
        object_id = 'c' * 40
        fingerprint = self.module.SOURCE_FINGERPRINT

        def command(args, **kwargs):
            if args[:2] == ['gpg', '--batch']:
                return subprocess.CompletedProcess(args, 0, '', '')
            if args[:2] == ['git', 'hash-object']:
                self.assertEqual(kwargs['input_text'], base64.b64decode(self.payload()).decode())
                return subprocess.CompletedProcess(args, 0, object_id + '\n', '')
            if args[:2] == ['git', 'verify-tag']:
                return subprocess.CompletedProcess(args, 0, '', f'[GNUPG:] VALIDSIG {fingerprint} 2026-09-09 0 0 4 0 22 8 00 {fingerprint}\n')
            self.fail(f'unexpected command: {args}')
        with patch.object(self.module, 'run', side_effect=command):
            self.assertEqual(self.module.verify_tag(self.payload(), 'v1.1.0-rc.1', 'a' * 40, object_id), object_id)
            with self.assertRaisesRegex(ValueError, 'existing'):
                self.module.verify_tag(self.payload(), 'v1.1.0-rc.1', 'a' * 40, 'd' * 40)

        def invalid(args, **kwargs):
            result = command(args, **kwargs)
            if args[1] == 'verify-tag':
                result.returncode = 1
            return result
        with patch.object(self.module, 'run', side_effect=invalid), self.assertRaisesRegex(ValueError, 'verification'):
            self.module.verify_tag(self.payload(), 'v1.1.0-rc.1', 'a' * 40)

    def test_candidate_requires_exact_source_and_at_least_72_hours(self):
        state = {'isDraft': False, 'isImmutable': True, 'isPrerelease': True, 'publishedAt': '2026-09-06T12:00:00Z'}
        now = 1788955200  # 2026-09-09T12:00:00Z
        self.module.validate_candidate(state, 'v1.1.0', 'v1.1.0-rc.1', 'a' * 40, 'a' * 40, now)
        with self.assertRaisesRegex(ValueError, '72-hour'):
            self.module.validate_candidate(state, 'v1.1.0', 'v1.1.0-rc.1', 'a' * 40, 'a' * 40, now - 1)
        with self.assertRaisesRegex(ValueError, 'commit'):
            self.module.validate_candidate(state, 'v1.1.0', 'v1.1.0-rc.1', 'a' * 40, 'b' * 40, now)
        with self.assertRaises(ValueError):
            self.module.validate_candidate(dict(state, isDraft=True), 'v1.1.0', 'v1.1.0-rc.1', 'a' * 40, 'a' * 40, now)
        for published in ('2026-09-10T12:00:00Z', 'invalidZ', None):
            with self.subTest(published=published), self.assertRaises(ValueError):
                self.module.validate_candidate(dict(state, publishedAt=published), 'v1.1.0', 'v1.1.0-rc.1', 'a' * 40, 'a' * 40, now)
        for field in ('isImmutable', 'isPrerelease'):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.module.validate_candidate(dict(state, **{field: False}), 'v1.1.0', 'v1.1.0-rc.1', 'a' * 40, 'a' * 40, now)
        with self.assertRaisesRegex(ValueError, 'candidate'):
            self.module.validate_candidate(state, 'v1.1.0', 'v1.2.0-rc.1', 'a' * 40, 'a' * 40, now)


if __name__ == '__main__':
    unittest.main()
