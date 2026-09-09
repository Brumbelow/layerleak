import importlib.util
import json
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class ContainerPlatformTests(unittest.TestCase):
    def setUp(self):
        script = Path(__file__).parents[1] / 'verify-container-platform.py'
        self.assertTrue(script.exists(), 'container architecture verifier is not implemented')
        spec = importlib.util.spec_from_file_location('container_platform', script)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    @staticmethod
    def header(machine, byte_order=1, elf_class=2):
        data = bytearray(64)
        data[:6] = b'\x7fELF' + bytes([elf_class, byte_order])
        struct.pack_into('<H', data, 18, machine)
        return bytes(data)

    def test_docker_uses_absolute_tool_path_and_preserves_arguments(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'PATH': directory}):
            command = Path(directory) / 'docker'
            command.write_text(f'#!{sys.executable}\nimport json, sys\nprint(json.dumps(sys.argv))\n')
            command.chmod(0o700)
            arguments = ['image', 'inspect', '--', 'literal image;value']
            self.assertEqual(json.loads(self.module.docker(*arguments)), [str(command), *arguments])

    def test_docker_rejects_relative_path_entries(self):
        with tempfile.TemporaryDirectory(dir='.') as directory, patch.dict(os.environ, {'PATH': os.path.relpath(directory)}):
            command = Path(directory) / 'docker'
            command.write_text(f'#!{sys.executable}\nprint("relative executable")\n')
            command.chmod(0o700)
            with self.assertRaisesRegex(ValueError, 'docker executable unavailable'):
                self.module.docker('--version')

    def test_image_operands_are_separated_from_docker_options(self):
        commands = []
        container_id = 'a1' * 32

        def docker(*arguments):
            commands.append(arguments)
            if arguments[:2] == ('image', 'inspect'):
                return '[{"Os": "linux", "Architecture": "amd64"}]'
            if arguments[0] == 'create':
                return container_id
            if arguments[0] == 'cp':
                Path(arguments[-1]).write_bytes(self.header(62))
            return ''

        images = ('layerleak-ci:amd64', 'registry.example:5000/team/layerleak:RC-1',
                  'ghcr.io/brumbelow/layerleak@sha256:' + 'a1' * 32,
                  '[2001:db8::1]:5000/team/layerleak:amd64')
        for image in images:
            with self.subTest(image=image), patch.object(self.module, 'docker', side_effect=docker):
                commands.clear()
                self.module.verify_image(image, 'linux/amd64')
                self.assertEqual(commands[0], ('image', 'inspect', '--', image))
                self.assertEqual(commands[1], ('create', '--platform', 'linux/amd64', '--', image))
                for command in commands[2:-1]:
                    self.assertEqual(command[:2], ('cp', '--'))
                    self.assertTrue(command[2].startswith(container_id + ':/usr/local/bin/'))
                self.assertEqual(commands[-1], ('rm', '--', container_id))

    def test_invalid_image_is_rejected_before_docker_runs(self):
        images = ('', '--help', 'image name', 'image;name', 'image$name', 'image\nname',
                  'image\x00name', 'im\N{LATIN SMALL LETTER A WITH ACUTE}ge', 'a' * 1025)
        for image in images:
            with (self.subTest(image=image),
                  patch.object(self.module.subprocess, 'run', side_effect=AssertionError('Docker must not run')),
                  self.assertRaisesRegex(ValueError, 'image reference')):
                self.module.verify_image(image, 'linux/amd64')

    def test_unsupported_platform_is_rejected_before_docker_runs(self):
        platforms = ('linux/s390x', 'darwin/amd64', 'linux/amd64/extra')
        for platform in platforms:
            with (self.subTest(platform=platform),
                  patch.object(self.module.subprocess, 'run', side_effect=AssertionError('Docker must not run')),
                  self.assertRaisesRegex(ValueError, 'unsupported platform')):
                self.module.verify_image('layerleak-ci:amd64', platform)

    def test_invalid_container_id_is_never_used_for_copy_or_removal(self):
        invalid_ids = ('', 'a' * 12, 'a' * 63, 'a' * 65, 'A' * 64,
                       '--help', 'a' * 64 + '\nextra', 'a' * 32 + '\n' + 'a' * 32)
        for container_id in invalid_ids:
            def docker(*arguments):
                if arguments[:2] == ('image', 'inspect'):
                    return '[{"Os": "linux", "Architecture": "amd64"}]'
                if arguments[0] == 'create':
                    return container_id
                self.fail('invalid container ID reached a Docker copy or removal operation')

            with (self.subTest(container_id=container_id), patch.object(self.module, 'docker', side_effect=docker),
                  self.assertRaisesRegex(ValueError, 'invalid container ID')):
                self.module.verify_image('layerleak-ci:amd64', 'linux/amd64')

    def test_matching_64_bit_executables_pass(self):
        self.module.verify_elf_header(self.header(62), 'amd64')
        self.module.verify_elf_header(self.header(183), 'arm64')

    def test_mislabeled_arm_image_executable_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'machine 62.*arm64'):
            self.module.verify_elf_header(self.header(62), 'arm64')

    def test_invalid_executable_headers_are_rejected(self):
        for header in (b'', b'not an executable', self.header(183, byte_order=2),
                       self.header(183, elf_class=1)):
            with self.subTest(header=header), self.assertRaises(ValueError):
                self.module.verify_elf_header(header, 'arm64')


if __name__ == '__main__':
    unittest.main()
