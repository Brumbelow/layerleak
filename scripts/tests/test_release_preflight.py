import base64
import hashlib
import importlib.util
import json
import os
import re
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
            ('gh', '--version'): 'gh version 2.102.0 (2026-09-30)\n',
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
        for version in ('2.46.0', '2.93.0', '2.100.0', '2.101.0'):
            result = subprocess.CompletedProcess([], 0, f'gh version {version}\n', '')
            with (self.subTest(version=version), patch.object(self.module, 'run', return_value=result),
                  self.assertRaisesRegex(ValueError, '2.102.0')):
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
            ('cosign', 'version'): 'GitVersion: v3.1.3',
            ('cosign', 'verify', '--help'): '--certificate-identity --certificate-oidc-issuer',
            ('cosign', 'sign', '--help'): '--yes',
            ('cosign', 'sign-blob', '--help'): '--bundle --yes',
            ('cosign', 'verify-blob', '--help'): '--bundle --certificate-identity --certificate-oidc-issuer',
            ('grype', 'version'): 'Version: 0.119.0',
            ('grype', '--help'): '--fail-on --only-fixed --platform',
            ('docker', 'buildx', 'version'): 'github.com/docker/buildx v0.37.2 hash',
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
            for key, version in ((('cosign', 'version'), 'v3.1.3'), (('grype', 'version'), '0.119.0'), (('docker', 'buildx', 'version'), 'v0.37.2')):
                original = full[key]
                full[key] = original.replace(version, version + '0')
                with self.subTest(key=key), self.assertRaises(ValueError):
                    self.module.check_tools(True)
                full[key] = original
            # Blob signing and verification of the CLI checksums file need these options.
            for key, option in ((('cosign', 'sign-blob', '--help'), '--bundle'),
                                (('cosign', 'verify-blob', '--help'), '--certificate-identity')):
                original = full[key]
                full[key] = original.replace(option, '')
                with self.subTest(key=key), self.assertRaisesRegex(ValueError, re.escape(option)):
                    self.module.check_tools(True)
                full[key] = original

    def test_oversized_stdin_is_rejected_before_object_import(self):
        # The current Python interpreter runs an owned script; fixture bytes are passed on stdin.
        result = subprocess.run(  # nosec B603
            [sys.executable, str(SCRIPT), 'tag', '--version', 'v3.0.0-rc.1', '--source', 'a' * 40],
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
        header = header or f'object {"a" * 40}\ntype commit\ntag v3.0.0-rc.1\ntagger Maintainer <maintainer@example.test> 1788900000 +0000'
        return base64.b64encode((header + '\n\nRelease\n' + signature).encode()).decode()

    def test_tag_payload_retains_exact_object_bytes(self):
        payload = self.payload()
        self.assertEqual(self.module.decode_tag(payload, 'v3.0.0-rc.1', 'a' * 40), base64.b64decode(payload))

    def test_tag_rejects_mismatched_source_name_type_or_extra_headers(self):
        normal = f'object {"a" * 40}\ntype commit\ntag v3.0.0-rc.1\ntagger Maintainer <maintainer@example.test> 1788900000 +0000'
        for header in (normal.replace('a' * 40, 'b' * 40), normal.replace('type commit', 'type tag'),
                       normal.replace('v3.0.0-rc.1', 'v3.1.0'), normal + '\nobject ' + 'a' * 40):
            with self.subTest(header=header), self.assertRaises(ValueError):
                self.module.decode_tag(self.payload(header), 'v3.0.0-rc.1', 'a' * 40)

    def test_tag_rejects_missing_signature_invalid_base64_and_oversize(self):
        for payload in (self.payload(signature=''), '!!!', 'A' * 16385):
            with self.subTest(payload=payload[:30]), self.assertRaises(ValueError):
                self.module.decode_tag(payload, 'v3.0.0-rc.1', 'a' * 40)

    def test_tag_rejects_noncanonical_encoding_and_control_bytes(self):
        raw = base64.b64decode(self.payload())
        payloads = ['', 'Zh==', base64.b64encode(b'\xff').decode()]
        payloads.extend(base64.b64encode(raw + suffix).decode() for suffix in (b'\x00', b'\r'))
        for payload in payloads:
            with self.subTest(payload=payload[:30]), self.assertRaises(ValueError):
                self.module.decode_tag(payload, 'v3.0.0-rc.1', 'a' * 40)

    def test_tag_rejects_noncanonical_version_and_source(self):
        for version, source in (('v3.01.0', 'a' * 40), ('v3.0.0-rc.0', 'a' * 40),
                                ('v3.0.0-rc.1', 'A' * 40), ('v3.0.0-rc.1', 'a' * 39),
                                ('v1.1.0', 'a' * 40), ('v2.5.0', 'a' * 40), ('v4.0.0', 'a' * 40)):
            with self.subTest(version=version, source=source), self.assertRaises(ValueError):
                self.module.decode_tag(self.payload(), version, source)

    def test_tag_rejects_incomplete_or_repeated_signature_envelope(self):
        envelope = '-----BEGIN PGP SIGNATURE-----\ntest\n-----END PGP SIGNATURE-----\n'
        for signature in (envelope.rstrip('\n'), envelope + envelope):
            with self.subTest(signature=signature), self.assertRaises(ValueError):
                self.module.decode_tag(self.payload(signature=signature), 'v3.0.0-rc.1', 'a' * 40)

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
            self.assertEqual(self.module.verify_tag(self.payload(), 'v3.0.0-rc.1', 'a' * 40, object_id), object_id)
            with self.assertRaisesRegex(ValueError, 'existing'):
                self.module.verify_tag(self.payload(), 'v3.0.0-rc.1', 'a' * 40, 'd' * 40)

        def invalid(args, **kwargs):
            result = command(args, **kwargs)
            if args[1] == 'verify-tag':
                result.returncode = 1
            return result
        with patch.object(self.module, 'run', side_effect=invalid), self.assertRaisesRegex(ValueError, 'verification'):
            self.module.verify_tag(self.payload(), 'v3.0.0-rc.1', 'a' * 40)

    def test_candidate_requires_exact_source_and_at_least_72_hours(self):
        state = {'isDraft': False, 'isImmutable': True, 'isPrerelease': True, 'publishedAt': '2026-09-06T12:00:00Z'}
        now = 1788955200  # 2026-09-09T12:00:00Z
        self.module.validate_candidate(state, 'v3.0.0', 'v3.0.0-rc.1', 'a' * 40, 'a' * 40, now)
        with self.assertRaisesRegex(ValueError, '72-hour'):
            self.module.validate_candidate(state, 'v3.0.0', 'v3.0.0-rc.1', 'a' * 40, 'a' * 40, now - 1)
        with self.assertRaisesRegex(ValueError, 'commit'):
            self.module.validate_candidate(state, 'v3.0.0', 'v3.0.0-rc.1', 'a' * 40, 'b' * 40, now)
        with self.assertRaises(ValueError):
            self.module.validate_candidate(dict(state, isDraft=True), 'v3.0.0', 'v3.0.0-rc.1', 'a' * 40, 'a' * 40, now)
        for published in ('2026-09-10T12:00:00Z', 'invalidZ', None):
            with self.subTest(published=published), self.assertRaises(ValueError):
                self.module.validate_candidate(dict(state, publishedAt=published), 'v3.0.0', 'v3.0.0-rc.1', 'a' * 40, 'a' * 40, now)
        for field in ('isImmutable', 'isPrerelease'):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.module.validate_candidate(dict(state, **{field: False}), 'v3.0.0', 'v3.0.0-rc.1', 'a' * 40, 'a' * 40, now)
        with self.assertRaisesRegex(ValueError, 'candidate'):
            self.module.validate_candidate(state, 'v3.0.0', 'v3.1.0-rc.1', 'a' * 40, 'a' * 40, now)
        with self.assertRaisesRegex(ValueError, 'candidate'):
            self.module.validate_candidate(state, 'v1.1.0', 'v1.1.0-rc.1', 'a' * 40, 'a' * 40, now)

    # --- CLI binaries: checksums file format and archive verification ---

    EXPECTED_ARCHIVES = [
        'layerleak_v3.0.0_darwin_amd64.tar.gz',
        'layerleak_v3.0.0_darwin_arm64.tar.gz',
        'layerleak_v3.0.0_linux_amd64.tar.gz',
        'layerleak_v3.0.0_linux_arm64.tar.gz',
        'layerleak_v3.0.0_windows_amd64.zip',
    ]

    @staticmethod
    def digest_of(name):
        return hashlib.sha256(f'synthetic archive {name}'.encode()).hexdigest()

    def checksums(self, names=None, digest=None):
        names = self.EXPECTED_ARCHIVES if names is None else names
        return ''.join(f'{digest or self.digest_of(name)}  {name}\n' for name in names)

    def write_release_dir(self, directory, version='v3.0.0'):
        directory = Path(directory)
        for name in self.module.expected_cli_archives(version):
            (directory / name).write_bytes(f'synthetic archive {name}'.encode())
        checksums = directory / self.module.cli_checksums_name(version)
        checksums.write_text(self.checksums(self.module.expected_cli_archives(version)))
        # Companions that legitimately share the archive prefix.
        (checksums.with_name(checksums.name + '.sigstore.json')).write_text('{}')
        return checksums

    def test_expected_cli_archives_cover_the_five_supported_targets(self):
        self.assertEqual(self.module.expected_cli_archives('v3.0.0'), self.EXPECTED_ARCHIVES)
        self.assertEqual(self.module.expected_cli_archives('v3.0.0-rc.1')[-1], 'layerleak_v3.0.0-rc.1_windows_amd64.zip')
        self.assertEqual(self.module.cli_checksums_name('v3.0.0-rc.1'), 'layerleak_v3.0.0-rc.1_checksums.txt')
        for version in ('v1.1.0', 'v3.01.0', 'v3.0.0-rc.0', '3.0.0', 'v3.0.0-rc.1\n'):
            with self.subTest(version=version), self.assertRaises(ValueError):
                self.module.expected_cli_archives(version)

    def test_cli_checksums_accept_the_exact_sorted_archive_set(self):
        entries = self.module.parse_cli_checksums(self.checksums(), 'v3.0.0')
        self.assertEqual(list(entries), self.EXPECTED_ARCHIVES)
        self.assertEqual(entries['layerleak_v3.0.0_linux_amd64.tar.gz'], self.digest_of('layerleak_v3.0.0_linux_amd64.tar.gz'))

    def test_cli_checksums_reject_malformed_lines(self):
        good = self.checksums()
        digest = self.digest_of(self.EXPECTED_ARCHIVES[0])
        malformed = {
            'single space': good.replace('  ', ' ', 1),
            'binary marker': good.replace('  layerleak', '  *layerleak', 1),
            'uppercase hex': good.replace(digest, digest.upper(), 1),
            'short digest': good.replace(digest, digest[:-1], 1),
            'sha512 length': good.replace(digest, digest * 2, 1),
            'crlf': good.replace('\n', '\r\n'),
            'no trailing newline': good.rstrip('\n'),
            'path component': good.replace('  layerleak_v3.0.0_darwin_amd64', '  dist/layerleak_v3.0.0_darwin_amd64', 1),
            'parent path': good.replace('  layerleak_v3.0.0_darwin_amd64', '  ../layerleak_v3.0.0_darwin_amd64', 1),
            'blank line': good.replace('\n', '\n\n', 1),
            'empty': '',
            'oversize': good + ' ' * self.module.MAX_CHECKSUMS_BYTES,
        }
        for label, text in malformed.items():
            with self.subTest(label=label), self.assertRaises(ValueError):
                self.module.parse_cli_checksums(text, 'v3.0.0')

    def test_cli_checksums_reject_missing_extra_duplicate_or_unsorted_archives(self):
        cases = {
            'missing target': self.EXPECTED_ARCHIVES[:-1],
            'extra target': self.EXPECTED_ARCHIVES + ['layerleak_v3.0.0_linux_386.tar.gz'],
            'duplicate': self.EXPECTED_ARCHIVES + [self.EXPECTED_ARCHIVES[0]],
            'unsorted': list(reversed(self.EXPECTED_ARCHIVES)),
            'candidate names under stable': [name.replace('v3.0.0', 'v3.0.0-rc.1') for name in self.EXPECTED_ARCHIVES],
            'wrong extension': [name.replace('.zip', '.tar.gz') for name in self.EXPECTED_ARCHIVES],
            'checksums lists itself': self.EXPECTED_ARCHIVES + ['layerleak_v3.0.0_checksums.txt'],
        }
        for label, names in cases.items():
            with self.subTest(label=label), self.assertRaises(ValueError):
                self.module.parse_cli_checksums(self.checksums(names), 'v3.0.0')

    def test_cli_archives_must_match_recorded_digests_without_strays(self):
        with tempfile.TemporaryDirectory() as directory:
            checksums = self.write_release_dir(directory)
            entries = self.module.check_cli_binaries('v3.0.0', checksums, directory)
            self.assertEqual(len(entries), 5)
            self.assertEqual(self.module.check_cli_binaries('v3.0.0', checksums), entries)

            stray = Path(directory) / 'layerleak_v3.0.0_linux_386.tar.gz'
            stray.write_bytes(b'stray')
            with self.assertRaisesRegex(ValueError, 'linux_386'):
                self.module.check_cli_binaries('v3.0.0', checksums, directory)
            stray.unlink()

            tampered = Path(directory) / self.EXPECTED_ARCHIVES[2]
            tampered.write_bytes(b'tampered')
            with self.assertRaisesRegex(ValueError, 'does not match'):
                self.module.check_cli_binaries('v3.0.0', checksums, directory)
            tampered.unlink()
            with self.assertRaisesRegex(ValueError, 'missing'):
                self.module.check_cli_binaries('v3.0.0', checksums, directory)

    def test_cli_checksums_file_must_carry_the_release_name(self):
        with tempfile.TemporaryDirectory() as directory:
            checksums = self.write_release_dir(directory)
            renamed = checksums.with_name('checksums.txt')
            renamed.write_text(checksums.read_text())
            with self.assertRaisesRegex(ValueError, 'layerleak_v3.0.0_checksums.txt'):
                self.module.check_cli_binaries('v3.0.0', renamed, directory)
            with self.assertRaises(ValueError):
                self.module.check_cli_binaries('v3.0.0-rc.1', checksums, directory)
            oversized = checksums.with_name('layerleak_v3.0.1_checksums.txt')
            oversized.write_bytes(b'a' * (self.module.MAX_CHECKSUMS_BYTES + 1))
            with self.assertRaisesRegex(ValueError, 'at most'):
                self.module.check_cli_binaries('v3.0.1', oversized)

    def test_binaries_subcommand_verifies_a_release_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            checksums = self.write_release_dir(directory, 'v3.0.0-rc.1')
            command = [sys.executable, str(SCRIPT), 'binaries', '--version', 'v3.0.0-rc.1',
                       '--checksums', str(checksums), '--dir', directory]
            # The current Python interpreter runs an owned script against a synthetic release directory.
            result = subprocess.run(command, check=False, shell=False, text=True, capture_output=True, timeout=60)  # nosec B603
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('5 CLI archives', result.stdout)
            (Path(directory) / 'layerleak_v3.0.0-rc.1_linux_arm64.tar.gz').write_bytes(b'tampered')
            result = subprocess.run(command, check=False, shell=False, text=True, capture_output=True, timeout=60)  # nosec B603
            self.assertEqual(result.returncode, 1)
            self.assertIn('Release preflight failed', result.stderr)

    def test_composite_action_pins_the_reviewed_cosign_release(self):
        root = SCRIPT.parents[1]
        installer = (root / 'scripts' / 'release-tools.sh').read_text(encoding='utf-8')
        pin = re.search(r'cosign/releases/download/(v[0-9.]+)/cosign-linux-amd64 \\\n\s+([0-9a-f]{64})', installer)
        self.assertIsNotNone(pin, 'release-tools.sh must pin cosign-linux-amd64 by version and SHA-256')
        action = (root / 'action.yml').read_text(encoding='utf-8')
        self.assertIn(f'COSIGN_VERSION: {pin.group(1)}\n', action)
        self.assertIn(f'COSIGN_SHA256: {pin.group(2)}\n', action)
        # Every other runner target the action supports selects its own pinned
        # cosign digest, so the checksums bundle is verified everywhere.
        for goos, goarch in self.module.CLI_TARGETS:
            if (goos, goarch) == ('linux', 'amd64'):
                continue
            key = f'COSIGN_SHA256_{goos.upper()}_{goarch.upper()}'
            digest = re.search(rf'^\s+{key}: ([0-9a-f]{{64}})\n', action, re.MULTILINE)
            with self.subTest(target=f'{goos}/{goarch}'):
                self.assertIsNotNone(digest, f'action.yml must pin {key}')
                self.assertNotEqual(digest.group(1), pin.group(2))
                self.assertIn(f'{goos}/{goarch}) cosign_digest="${{{key}}}"', action)
        # The action verifies against the release workflow identity the release
        # documents: anchored, exact in path and ref, tolerant only in the
        # owner's initial, and used by both cosign and gh.
        identity = r'^https://github\.com/[Bb]rumbelow/layerleak/\.github/workflows/container-release\.yml@refs/heads/main$'
        self.assertIn(f'SIGNING_IDENTITY_REGEXP: {identity}\n', action)
        self.assertRegex(identity, r'^\^.*\$$')
        self.assertIsNotNone(re.fullmatch(identity, 'https://github.com/Brumbelow/layerleak/.github/workflows/container-release.yml@refs/heads/main'))
        self.assertIsNotNone(re.fullmatch(identity, 'https://github.com/brumbelow/layerleak/.github/workflows/container-release.yml@refs/heads/main'))
        for other in ('https://github.com/Brumbelow/layerleak/.github/workflows/container-release.yml@refs/heads/dev',
                      'https://github.com/Brumbelow/layerleak/.github/workflows/test.yml@refs/heads/main',
                      'https://github.com/Brumbelow/layerleak-fork/.github/workflows/container-release.yml@refs/heads/main',
                      'https://github.com/evil/Brumbelow/layerleak/.github/workflows/container-release.yml@refs/heads/main'):
            with self.subTest(identity=other):
                self.assertIsNone(re.fullmatch(identity, other))
        self.assertIn('--certificate-identity-regexp "${SIGNING_IDENTITY_REGEXP}"', action)
        self.assertIn('--cert-identity-regex "${SIGNING_IDENTITY_REGEXP}"', action)
        self.assertIn('--deny-self-hosted-runners', action)

    def test_release_workflow_builds_exactly_the_preflight_cli_targets(self):
        workflow = (SCRIPT.parents[1] / '.github' / 'workflows' / 'container-release.yml').read_text(encoding='utf-8')
        match = re.search(r'^  CLI_TARGETS: (.+)$', workflow, re.MULTILINE)
        self.assertIsNotNone(match, 'container-release.yml must declare CLI_TARGETS in its env block')
        self.assertEqual(match.group(1).split(), [f'{goos}/{goarch}' for goos, goarch in self.module.CLI_TARGETS])

    def test_module_path_must_match_release_major(self):
        self.module.check_module_path()
        with tempfile.TemporaryDirectory() as directory:
            go_mod = Path(directory) / 'go.mod'
            for declared in ('github.com/brumbelow/layerleak', 'github.com/brumbelow/layerleak/v4'):
                go_mod.write_text(f'module {declared}\n\ngo 1.27.1\n')
                with self.subTest(declared=declared), self.assertRaisesRegex(ValueError, 'go.mod declares'):
                    self.module.check_module_path(go_mod)


if __name__ == '__main__':
    unittest.main()
