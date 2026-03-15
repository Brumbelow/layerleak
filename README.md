# layerleak the Docker Hub Secret Scanner

See [CONTRIBUTING.md](./CONTRIBUTING.md) for development and contribution guidelines.

- Docker Hub / OCI image secret scanner that analyzes image layers, config metadata, and image history, then stores deduplicated findings by manifest digest.
- Traditional secret scanners often treat a container image as a flat blob or depend on a local Docker daemon. This project is designed around OCI image internals


## Current Scope:

- Public Docker Hub images only
- Read-only scanning
- No secret verification
- No Docker daemon dependency required
- Manifest-aware and layer-aware scanning
- Scans final filesystem and deleted-layer artifacts
- Scans image config metadata, env vars, labels, and history
- Deduplicates findings by secret fingerprint


## This project will:
- Scan public Docker Hub repositories and tags
- Resolve tags to manifests and scan by digest
- Treat a bare repository name such as `mongo` as a repository-wide scan across all public tags
- Support multi-arch images by scanning platform-specific manifests
- Skip attestation and provenance manifests embedded in OCI indexes and scan only runnable image manifests
- Inspect image metadata:
  - config
  - env
  - labels
  - history
- Inspect layer contents:
  - final filesystem contents
  - deleted-layer artifacts recoverable from prior layers
- Detect likely secrets using structured, contextual, and file-aware detectors
- Include the upstream TruffleHog default git-source detector catalog alongside local file-aware and entropy detectors
- Redact secrets in output and persist only stable fingerprints for deduplication
- Provide a CLI-first workflow, then an API and UI

## How to install

Prerequisites:

- Go 1.24+

Build from source:

```bash
git clone https://git.tools.cloudfor.ge/andrew/layerleak.git
cd layerleak
go build -o scanner ./cmd/scanner
```

Optional environment configuration:

```bash
cp .env.example .env
```

Result file configuration:

```bash
export LAYERLEAK_FINDINGS_DIR=findings
export LAYERLEAK_TAG_PAGE_SIZE=100
```

If `LAYERLEAK_FINDINGS_DIR` is not set, layerleak writes JSON findings files to `findings/` under the repo root.
Saved findings files contain only detections, including unredacted finding values and unredacted context snippets.
`LAYERLEAK_TAG_PAGE_SIZE` controls Docker Hub tag-list pagination for repository-wide scans.

## How to start

Show the CLI help:

```bash
./scanner --help
./scanner scan --help
```
![help_output](https://github.com/user-attachments/assets/8af9af41-30b1-4ee4-a0e5-2c20ed826e5f)


Run a scan against a public Docker Hub image:

```bash
./scanner scan ubuntu
./scanner scan library/nginx:latest --format json
./scanner scan alpine:latest --platform linux/amd64
./scanner scan mongo
```
![cli pic](https://github.com/user-attachments/assets/ec9586a0-42a2-49d7-b121-fdd52cc1025d)


Every scan also writes a JSON findings file to the findings output directory.
Those saved findings files contain only finding records, including the exact match value, exact source location, and unredacted snippet for each finding.
For multi-arch images, layerleak skips attestation and provenance manifests such as `application/vnd.in-toto+json` instead of counting them as failed platform scans.
If you pass a bare repository name such as `mongo`, layerleak enumerates all public tags in that repository, resolves each tag to a digest, groups duplicate digests, and scans the distinct targets. If you want a single image only, pass an explicit tag or digest such as `mongo:latest` or `mongo@sha256:...`.

Command syntax:

```text
scanner [command]
scanner scan <image-ref> [flags]
```
