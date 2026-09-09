#!/usr/bin/env python3
"""Verify image metadata and packaged executables match a release platform."""

import argparse
import json
from pathlib import Path
import struct
import subprocess
import tempfile


MACHINES = {'amd64': 62, 'arm64': 183}
EXECUTABLES = ('layerleak-api', 'layerleak-migrate-up',
               'layerleak-purge-raw-secrets', 'layerleak-healthcheck')


def verify_elf_header(header, architecture):
    if len(header) < 64 or header[:6] != b'\x7fELF\x02\x01':
        raise ValueError('expected a 64-bit little-endian ELF executable')
    machine = struct.unpack_from('<H', header, 18)[0]
    if machine != MACHINES[architecture]:
        raise ValueError(f'executable machine {machine} does not match {architecture}')


def docker(*arguments):
    result = subprocess.run(['docker', *arguments], check=True, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    return result.stdout.strip()


def verify_image(image, platform):
    operating_system, architecture = platform.split('/')
    metadata = json.loads(docker('image', 'inspect', '--', image))[0]
    if metadata['Os'] != operating_system or metadata['Architecture'] != architecture:
        raise ValueError(f'image metadata does not match {platform}')
    container = docker('create', '--platform', platform, '--', image)
    try:
        with tempfile.TemporaryDirectory(prefix='layerleak-platform-') as directory:
            for executable in EXECUTABLES:
                local_file = Path(directory) / executable
                docker('cp', f'{container}:/usr/local/bin/{executable}', str(local_file))
                with local_file.open('rb') as stream:
                    try:
                        verify_elf_header(stream.read(64), architecture)
                    except ValueError as error:
                        raise ValueError(f'{executable}: {error}') from error
    finally:
        docker('rm', container)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image')
    parser.add_argument('platform', choices=('linux/amd64', 'linux/arm64'))
    arguments = parser.parse_args()
    try:
        verify_image(arguments.image, arguments.platform)
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, f'Container platform verification failed: {error}\n')
    print(f'Verified {arguments.platform}: {len(EXECUTABLES)} packaged executables')


if __name__ == '__main__':
    main()
