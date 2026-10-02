#!/usr/bin/env python3
"""Read-only release capability checks and source-tag handoff validation."""

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import shutil
import subprocess  # Reviewed allowlisted executables and shell=False in run().  # nosec B404
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

GH_VERSION = '2.102.0'
SOURCE_FINGERPRINT = '2B6DF408BD973740052925DC894C75E1B1D05EA2'
# The released Go major. go.mod must declare the matching /vN module path.
RELEASE_MAJOR = 3
MODULE_PATH = f'github.com/brumbelow/layerleak/v{RELEASE_MAJOR}'
VERSION = rf'v{RELEASE_MAJOR}\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)'
MAX_TAG_INPUT = 16384
RELEASE_TOOLS = frozenset({'gh', 'cosign', 'grype', 'docker', 'git', 'gpg', 'jq', 'curl'})
# The prebuilt CLI targets, in the order the release workflow builds them. The
# workflow's CLI_TARGETS env entry must list the same pairs (a test enforces it).
CLI_TARGETS = (('linux', 'amd64'), ('linux', 'arm64'), ('darwin', 'amd64'), ('darwin', 'arm64'), ('windows', 'amd64'))
MAX_CHECKSUMS_BYTES = 16384
CHECKSUM_LINE = re.compile(r'([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)')


def run(args, *, input_text=None, env=None):
    if not args or args[0] not in RELEASE_TOOLS:
        raise ValueError('unsupported release tool')
    # The operator configures PATH for reviewed tools; never search the current directory.
    search_path = os.pathsep.join(path for path in os.get_exec_path(env) if os.path.isabs(path))
    executable = shutil.which(args[0], path=search_path)
    if executable is None:
        raise ValueError(f'command unavailable: {args[0]}')
    # Only allowlisted absolute executables run; tag bytes use stdin and operands stay separate.
    return subprocess.run([executable, *args[1:]], check=False, shell=False,  # nosec B603
                          capture_output=True, text=True, timeout=60, input=input_text, env=env)


def require_command(args, required):
    result = run(args)
    output = result.stdout + result.stderr
    if result.returncode != 0:
        raise ValueError(f'command unavailable: {" ".join(args)}')
    for option in required:
        if option not in output:
            raise ValueError(f'{" ".join(args)} lacks {option}')
    return output


def check_tools(full):
    version = require_command(['gh', '--version'], [])
    if not re.search(rf'^gh version {re.escape(GH_VERSION)}(?:\s|$)', version):
        raise ValueError(f'release tooling requires reviewed gh {GH_VERSION}; run scripts/release-tools.sh')
    require_command(['gh', 'release', 'verify', '--help'], ['--repo'])
    require_command(['gh', 'release', 'verify-asset', '--help'], ['--repo'])
    require_command(['gh', 'attestation', 'verify', '--help'], [
        '--bundle-from-oci', '--signer-workflow', '--source-ref',
        '--source-digest', '--deny-self-hosted-runners', '--repo',
        '--format', '--predicate-type'])
    # With no fields this is local CLI introspection, without an API request.
    fields = run(['gh', 'release', 'view', '--json'])
    available = set((fields.stdout + fields.stderr).split())
    for field in ('isDraft', 'isImmutable', 'isPrerelease', 'publishedAt'):
        if field not in available:
            raise ValueError(f'gh release view lacks required JSON field {field}')
    if full:
        cosign = require_command(['cosign', 'version'], [])
        if not re.search(r'^GitVersion:\s+v3\.1\.3(?:\s|$)', cosign, re.MULTILINE):
            raise ValueError('release tooling requires reviewed Cosign v3.1.3')
        require_command(['cosign', 'verify', '--help'], ['--certificate-identity', '--certificate-oidc-issuer'])
        require_command(['cosign', 'sign', '--help'], ['--yes'])
        # The CLI checksums file is keyless-signed as a blob with a Sigstore bundle.
        require_command(['cosign', 'sign-blob', '--help'], ['--bundle', '--yes'])
        require_command(['cosign', 'verify-blob', '--help'], ['--bundle', '--certificate-identity', '--certificate-oidc-issuer'])
        grype = require_command(['grype', 'version'], [])
        if not re.search(r'^Version:\s+0\.119\.0(?:\s|$)', grype, re.MULTILINE):
            raise ValueError('release tooling requires reviewed Grype v0.119.0')
        require_command(['grype', '--help'], ['--fail-on', '--only-fixed', '--platform'])
        buildx = require_command(['docker', 'buildx', 'version'], [])
        if not re.search(r'^github\.com/docker/buildx v0\.37\.2(?:\s|$)', buildx):
            raise ValueError('release tooling requires reviewed Buildx v0.37.2')
        require_command(['docker', 'buildx', 'imagetools', 'inspect', '--help'], ['--raw'])
        require_command(['docker', 'buildx', 'imagetools', 'create', '--help'], ['--tag'])
        require_command(['docker', 'info', '--format', '{{.ServerVersion}}'], [])
        for command in (['git', '--version'], ['gpg', '--version'], ['jq', '--version'], ['curl', '--version']):
            require_command(command, [])


def decode_tag_bytes(payload):
    if not payload or len(payload) > MAX_TAG_INPUT:
        raise ValueError('source_tag must contain at most 16384 base64 characters')
    try:
        raw = base64.b64decode(payload, validate=True)
        value = raw.decode('utf-8')
    except (binascii.Error, UnicodeError, ValueError) as error:
        raise ValueError('source_tag must be canonical base64 of a UTF-8 tag object') from error
    if base64.b64encode(raw).decode() != payload or '\x00' in value or '\r' in value:
        raise ValueError('source_tag has invalid encoding')
    return raw, value


def validate_tag_object(value, version, source):
    header, separator, message = value.partition('\n\n')
    lines = header.split('\n')
    if (not separator or len(lines) != 4 or lines[:3] != [
            f'object {source}', 'type commit', f'tag {version}'] or
            not re.fullmatch(r'tagger [^<>\n]+ <[^<>\n]+> [0-9]+ [+-][0-9]{4}', lines[3])):
        raise ValueError('source_tag headers must name the exact requested commit and version')
    if (message.count('-----BEGIN PGP SIGNATURE-----') != 1 or
            not message.endswith('-----END PGP SIGNATURE-----\n')):
        raise ValueError('source_tag requires a complete verification envelope')


def decode_tag(payload, version, source):
    if not re.fullmatch(VERSION + r'(-rc\.[1-9][0-9]*)?', version):
        raise ValueError(f'invalid canonical v{RELEASE_MAJOR} version')
    if not re.fullmatch(r'[0-9a-f]{40}', source):
        raise ValueError('source must be a full lowercase commit SHA')
    raw, value = decode_tag_bytes(payload)
    validate_tag_object(value, version, source)
    return raw


def check_module_path(go_mod=None):
    """Refuse to release when go.mod does not declare the module path for RELEASE_MAJOR."""
    go_mod = Path(go_mod) if go_mod else Path(__file__).resolve().parents[1] / 'go.mod'
    declared = None
    for line in go_mod.read_text(encoding='utf-8').splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] == 'module':
            declared = parts[1]
            break
    if declared != MODULE_PATH:
        raise ValueError(f'go.mod declares {declared}, expected {MODULE_PATH}')


def verify_tag(payload, version, source, existing=None):
    check_module_path()
    raw = decode_tag(payload, version, source)
    key = Path(__file__).with_name('release-source-key.asc')
    with tempfile.TemporaryDirectory(prefix='release-verify-') as keyring:
        env = dict(os.environ, GNUPGHOME=keyring)
        imported = run(['gpg', '--batch', '--import', str(key)], env=env)
        if imported.returncode:
            raise ValueError('source-tag verification key could not be loaded')
        result = run(['git', 'hash-object', '-t', 'tag', '-w', '--stdin'], input_text=raw.decode())
        object_id = result.stdout.strip()
        if result.returncode or not re.fullmatch(r'[0-9a-f]{40}', object_id):
            raise ValueError('source_tag could not be imported')
        if existing and object_id != existing:
            raise ValueError('existing source tag does not match the supplied object')
        verified = run(['git', 'verify-tag', '--raw', '--', object_id], env=env)
        valid = re.search(r'^\[GNUPG:\] VALIDSIG ([A-F0-9]{40}) ', verified.stderr, re.MULTILINE)
        if verified.returncode or not valid or valid.group(1) != SOURCE_FINGERPRINT:
            raise ValueError('source-tag verification failed')
    return object_id


def _require_release_version(version):
    if not re.fullmatch(VERSION + r'(-rc\.[1-9][0-9]*)?', version):
        raise ValueError(f'invalid canonical v{RELEASE_MAJOR} version')


def cli_archive_name(version, goos, goarch):
    """The release asset name of one prebuilt CLI archive."""
    extension = 'zip' if goos == 'windows' else 'tar.gz'
    return f'layerleak_{version}_{goos}_{goarch}.{extension}'


def cli_checksums_name(version):
    return f'layerleak_{version}_checksums.txt'


def expected_cli_archives(version):
    """Every CLI archive a release must attach, sorted as sha256sum output is."""
    _require_release_version(version)
    return sorted(cli_archive_name(version, goos, goarch) for goos, goarch in CLI_TARGETS)


def _checksum_lines(text):
    """Yield (line number, line) after checking the file's size and line endings."""
    if not text or len(text) > MAX_CHECKSUMS_BYTES:
        raise ValueError(f'checksums file must contain at most {MAX_CHECKSUMS_BYTES} bytes and at least one line')
    if '\r' in text or not text.endswith('\n'):
        raise ValueError('checksums file must use LF line endings and end with a newline')
    return enumerate(text[:-1].split('\n'), 1)


def _checksum_entry(number, line, entries, expected):
    """Parse one checksums line, rejecting malformed, duplicate and unexpected names."""
    match = CHECKSUM_LINE.fullmatch(line)
    if not match:
        raise ValueError(f'checksums line {number} is not "<sha256>  <archive>"')
    digest, name = match.groups()
    if name in entries:
        raise ValueError(f'checksums list {name} twice')
    if name not in expected:
        raise ValueError(f'checksums name unexpected archive {name}')
    return name, digest


def parse_cli_checksums(text, version):
    """
    Parse a sha256sum-format checksums file that names exactly the expected archives.

    Returns an ordered mapping of archive name to lowercase hex digest. The file
    must use LF line endings, end with a newline, carry two-space separators
    without the binary marker, contain no paths, and list the archives in
    sorted order with no duplicates, omissions or extras.
    """
    expected = expected_cli_archives(version)
    entries = {}
    for number, line in _checksum_lines(text):
        name, digest = _checksum_entry(number, line, entries, expected)
        entries[name] = digest
    missing = [name for name in expected if name not in entries]
    if missing:
        raise ValueError(f'checksums omit {", ".join(missing)}')
    if list(entries) != expected:
        raise ValueError('checksums must list archives in sorted order')
    return entries


def _sha256_file(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def verify_cli_archives(entries, directory, version):
    """Every listed archive must exist with the recorded digest and no stray release-named file may sit beside it."""
    directory = Path(directory)
    companions = {cli_checksums_name(version), cli_checksums_name(version) + '.sigstore.json'}
    strays = sorted(path.name for path in directory.glob(f'layerleak_{version}_*')
                    if path.name not in entries and path.name not in companions)
    if strays:
        raise ValueError(f'unexpected release-named files beside the archives: {", ".join(strays)}')
    for name, digest in entries.items():
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f'{name} is missing from {directory}')
        if _sha256_file(path) != digest:
            raise ValueError(f'{name} does not match its recorded checksum')


def check_cli_binaries(version, checksums, directory=None):
    """Validate the CLI checksums file and, with a directory, the archives it describes."""
    _require_release_version(version)
    checksums = Path(checksums)
    if checksums.name != cli_checksums_name(version):
        raise ValueError(f'checksums file must be named {cli_checksums_name(version)}, not {checksums.name}')
    if checksums.is_symlink() or not checksums.is_file():
        raise ValueError(f'checksums file {checksums} is missing')
    if checksums.stat().st_size > MAX_CHECKSUMS_BYTES:
        raise ValueError(f'checksums file must contain at most {MAX_CHECKSUMS_BYTES} bytes')
    entries = parse_cli_checksums(checksums.read_text(encoding='utf-8'), version)
    if directory is not None:
        verify_cli_archives(entries, directory, version)
    return entries


def validate_candidate(state, version, candidate, source, candidate_source, now):
    if not re.fullmatch(VERSION, version) or not re.fullmatch(re.escape(version) + r'-rc\.[1-9][0-9]*', candidate):
        raise ValueError('candidate must be a canonical RC of the requested stable version')
    if source != candidate_source:
        raise ValueError('stable releases must use the accepted RC commit without changes')
    if not (state.get('isDraft') is False and state.get('isImmutable') is True and state.get('isPrerelease') is True):
        raise ValueError('candidate must be a published immutable prerelease')
    published = state.get('publishedAt')
    if not isinstance(published, str) or not published.endswith('Z'):
        raise ValueError('candidate publication timestamp is missing or invalid')
    age = now - datetime.fromisoformat(published.replace('Z', '+00:00')).timestamp()
    if age < 72 * 60 * 60:
        raise ValueError('candidate has not completed the required 72-hour soak')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    tools = commands.add_parser('tools')
    tools.add_argument('--full', action='store_true')
    tag = commands.add_parser('tag')
    tag.add_argument('--version', required=True)
    tag.add_argument('--source', required=True)
    tag.add_argument('--existing')
    candidate = commands.add_parser('candidate')
    candidate.add_argument('--version', required=True)
    candidate.add_argument('--candidate', required=True)
    candidate.add_argument('--source', required=True)
    candidate.add_argument('--candidate-source', required=True)
    binaries = commands.add_parser('binaries', help='validate the CLI checksums file and, with --dir, the archives')
    binaries.add_argument('--version', required=True)
    binaries.add_argument('--checksums', required=True)
    binaries.add_argument('--dir')
    args = parser.parse_args()
    try:
        if args.command == 'tools':
            check_tools(args.full)
            print('Release tool capabilities verified.')
        elif args.command == 'binaries':
            entries = check_cli_binaries(args.version, args.checksums, args.dir)
            print(f'Verified {len(entries)} CLI archives for {args.version}.')
        elif args.command == 'tag':
            payload = sys.stdin.read(MAX_TAG_INPUT + 2)
            if len(payload) > MAX_TAG_INPUT + 1:
                raise ValueError('source_tag must contain at most 16384 base64 characters')
            payload = payload.removesuffix('\n')
            print(verify_tag(payload, args.version, args.source, args.existing))
        else:
            validate_candidate(json.load(sys.stdin), args.version, args.candidate,
                               args.source, args.candidate_source, datetime.now(timezone.utc).timestamp())
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, f'Release preflight failed: {error}\n')


if __name__ == '__main__':
    main()
