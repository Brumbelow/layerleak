#!/usr/bin/env bash
# Install reviewed release tools in a caller-selected directory.
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 || ! "$1" = /* ]]; then
  echo 'Usage: scripts/release-tools.sh /absolute/install/directory [gh|all]' >&2
  exit 1
fi
mode="${2:-gh}"
if [[ "${mode}" != gh && "${mode}" != all ]]; then
  echo 'Tool selection must be gh or all.' >&2
  exit 1
fi
if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  echo 'The reviewed release tool bundle supports Linux x86_64 only.' >&2
  exit 1
fi
release_tools_dir="$1"
mkdir -p "${release_tools_dir}/bin" "${release_tools_dir}/downloads"
release_unpack_dir="$(mktemp -d "${release_tools_dir}/unpack.XXXXXX")"
trap 'rm -rf "${release_unpack_dir}"' EXIT

download() {
  local url="$1" expected="$2" target="$3"
  if [[ ! -f "${target}" ]]; then
    curl --fail --silent --show-error --location --retry 3 \
      --proto '=https' --tlsv1.2 "${url}" -o "${target}.partial"
    mv "${target}.partial" "${target}"
  fi
  if ! printf '%s  %s\n' "${expected}" "${target}" | sha256sum --check --status; then
    echo "Checksum verification failed for ${target}; remove it and retry." >&2
    exit 1
  fi
}

download https://github.com/cli/cli/releases/download/v2.102.0/gh_2.102.0_linux_amd64.tar.gz \
  bb766f710eef8ede859c18578c72c327597cd4c8a85b06001b1f3843c6019386 \
  "${release_tools_dir}/downloads/gh.tar.gz"
tar -xzf "${release_tools_dir}/downloads/gh.tar.gz" -C "${release_unpack_dir}" gh_2.102.0_linux_amd64/bin/gh
install -m 0755 "${release_unpack_dir}/gh_2.102.0_linux_amd64/bin/gh" "${release_tools_dir}/bin/gh"

if [[ "${mode}" == all ]]; then
  download https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-linux-amd64 \
    4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71 \
    "${release_tools_dir}/downloads/cosign"
  install -m 0755 "${release_tools_dir}/downloads/cosign" "${release_tools_dir}/bin/cosign"
  download https://github.com/anchore/grype/releases/download/v0.119.0/grype_0.119.0_linux_amd64.tar.gz \
    3fa2dc4b924621ab65404cf08d0b8438d896d80ab949c9d5a4ca283c36004c9b \
    "${release_tools_dir}/downloads/grype.tar.gz"
  tar -xzf "${release_tools_dir}/downloads/grype.tar.gz" -C "${release_unpack_dir}" grype
  install -m 0755 "${release_unpack_dir}/grype" "${release_tools_dir}/bin/grype"
fi
printf '%s\n' "${release_tools_dir}/bin"
