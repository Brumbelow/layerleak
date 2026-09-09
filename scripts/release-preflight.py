#!/usr/bin/env python3
"""Read-only release capability checks and source-tag handoff validation."""

import argparse
import base64
import binascii
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

GH_VERSION = '2.100.0'
SOURCE_FINGERPRINT = '2B6DF408BD973740052925DC894C75E1B1D05EA2'
VERSION = r'v1\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)'
MAX_TAG_INPUT = 16384


def run(args, **kwargs):
    return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, timeout=60, **kwargs)


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
        if not re.search(r'^GitVersion:\s+v3\.0\.2(?:\s|$)', cosign, re.MULTILINE):
            raise ValueError('release tooling requires reviewed Cosign v3.0.2')
        require_command(['cosign', 'verify', '--help'], ['--certificate-identity', '--certificate-oidc-issuer'])
        require_command(['cosign', 'sign', '--help'], ['--yes'])
        grype = require_command(['grype', 'version'], [])
        if not re.search(r'^Version:\s+0\.99\.1(?:\s|$)', grype, re.MULTILINE):
            raise ValueError('release tooling requires reviewed Grype v0.99.1')
        require_command(['grype', '--help'], ['--fail-on', '--only-fixed', '--platform'])
        buildx = require_command(['docker', 'buildx', 'version'], [])
        if not re.search(r'^github\.com/docker/buildx v0\.37\.0(?:\s|$)', buildx):
            raise ValueError('release tooling requires reviewed Buildx v0.37.0')
        require_command(['docker', 'buildx', 'imagetools', 'inspect', '--help'], ['--raw'])
        require_command(['docker', 'buildx', 'imagetools', 'create', '--help'], ['--tag'])
        require_command(['docker', 'info', '--format', '{{.ServerVersion}}'], [])
        for command in (['git', '--version'], ['gpg', '--version'], ['jq', '--version'], ['curl', '--version']):
            require_command(command, [])


def decode_tag(payload, version, source):
    if not re.fullmatch(VERSION + r'(-rc\.[1-9][0-9]*)?', version):
        raise ValueError('invalid canonical v1 version')
    if not re.fullmatch(r'[0-9a-f]{40}', source):
        raise ValueError('source must be a full lowercase commit SHA')
    if not payload or len(payload) > MAX_TAG_INPUT:
        raise ValueError('source_tag must contain at most 16384 base64 characters')
    try:
        raw = base64.b64decode(payload, validate=True)
        value = raw.decode('utf-8')
    except (binascii.Error, UnicodeError, ValueError) as error:
        raise ValueError('source_tag must be canonical base64 of a UTF-8 tag object') from error
    if base64.b64encode(raw).decode() != payload or '\x00' in value or '\r' in value:
        raise ValueError('source_tag has invalid encoding')
    header, separator, message = value.partition('\n\n')
    lines = header.split('\n')
    if (not separator or len(lines) != 4 or lines[:3] != [
            f'object {source}', 'type commit', f'tag {version}'] or
            not re.fullmatch(r'tagger [^<>\n]+ <[^<>\n]+> [0-9]+ [+-][0-9]{4}', lines[3])):
        raise ValueError('source_tag headers must name the exact requested commit and version')
    if (message.count('-----BEGIN PGP SIGNATURE-----') != 1 or
            not message.endswith('-----END PGP SIGNATURE-----\n')):
        raise ValueError('source_tag requires a complete verification envelope')
    return raw


def verify_tag(payload, version, source, existing=None):
    raw = decode_tag(payload, version, source)
    key = Path(__file__).with_name('release-source-key.asc')
    with tempfile.TemporaryDirectory(prefix='release-verify-') as keyring:
        env = dict(os.environ, GNUPGHOME=keyring)
        imported = run(['gpg', '--batch', '--import', str(key)], env=env)
        if imported.returncode:
            raise ValueError('source-tag verification key could not be loaded')
        result = run(['git', 'hash-object', '-t', 'tag', '-w', '--stdin'], input=raw.decode())
        object_id = result.stdout.strip()
        if result.returncode or not re.fullmatch(r'[0-9a-f]{40}', object_id):
            raise ValueError('source_tag could not be imported')
        if existing and object_id != existing:
            raise ValueError('existing source tag does not match the supplied object')
        verified = run(['git', 'verify-tag', '--raw', object_id], env=env)
        valid = re.search(r'^\[GNUPG:\] VALIDSIG ([A-F0-9]{40}) ', verified.stderr, re.MULTILINE)
        if verified.returncode or not valid or valid.group(1) != SOURCE_FINGERPRINT:
            raise ValueError('source-tag verification failed')
    return object_id


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
    args = parser.parse_args()
    try:
        if args.command == 'tools':
            check_tools(args.full)
            print('Release tool capabilities verified.')
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
