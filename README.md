# layerleak the Docker Hub Secret Scanner

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
- Support multi-arch images by scanning platform-specific manifests
- Inspect image metadata:
  - config
  - env
  - labels
  - history
- Inspect layer contents:
  - final filesystem contents
  - deleted-layer artifacts recoverable from prior layers
- Detect likely secrets using structured, contextual, and file-aware detectors
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
```

If `LAYERLEAK_FINDINGS_DIR` is not set, layerleak writes full JSON scan results to `findings/` under the repo root.
Saved findings files contain unredacted finding values and unredacted context snippets.

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
```
![cli pic](https://github.com/user-attachments/assets/ec9586a0-42a2-49d7-b121-fdd52cc1025d)


Every scan also writes the full JSON result to the findings output directory.
Those saved findings files include the exact match value, exact source location, and unredacted snippet for each finding.

Command syntax:

```text
scanner [command]
scanner scan <image-ref> [flags]
```
