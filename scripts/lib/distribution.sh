#!/usr/bin/env bash

# The one place consumers pin who may sign a Premier release: tag builds of
# .github/workflows/release.yml in PremierStudio/premier. It must match the
# identity that workflow signs with; scripts/tests/distribution.sh enforces it.
# shellcheck disable=SC2034 # consumed by install.sh and verify-release.sh
DISTRIBUTION_SIGNER_IDENTITY_REGEXP='^https://github\.com/PremierStudio/premier/\.github/workflows/release\.yml@refs/tags/v[0-9].*$'
# The same identity for one release: append the version (0.1.0, 0.2.0-rc.1).
# shellcheck disable=SC2034
DISTRIBUTION_SIGNER_IDENTITY_PREFIX='https://github.com/PremierStudio/premier/.github/workflows/release.yml@refs/tags/v'
# shellcheck disable=SC2034
DISTRIBUTION_SIGNER_OIDC_ISSUER='https://token.actions.githubusercontent.com'

# The newest glibc a published Linux binary may require: the glibc of the
# release runners (ubuntu-24.04). package-release.sh records what a binary
# actually requires as GLIBC_MIN and refuses one that requires more.
# shellcheck disable=SC2034
DISTRIBUTION_GLIBC_CEILING='2.39'

distribution_host_target() {
  local machine os
  machine="$(uname -m)"
  os="$(uname -s)"
  case "$os:$machine" in
    Darwin:x86_64) printf '%s\n' x86_64-apple-darwin ;;
    Darwin:arm64|Darwin:aarch64) printf '%s\n' aarch64-apple-darwin ;;
    Linux:x86_64|Linux:amd64) printf '%s\n' x86_64-unknown-linux-gnu ;;
    Linux:arm64|Linux:aarch64) printf '%s\n' aarch64-unknown-linux-gnu ;;
    *) return 1 ;;
  esac
}

distribution_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    echo "missing checksum tool: install sha256sum or shasum" >&2
    return 1
  fi
}

distribution_metadata_value() {
  local file="$1" key="$2"
  awk -F= -v key="$key" '$1 == key { print substr($0, index($0, "=") + 1); exit }' "$file"
}

distribution_safe_extract() {
  local archive="$1" destination="$2"
  command -v python3 >/dev/null 2>&1 || {
    echo "python3 is required to validate and extract release archives safely" >&2
    return 1
  }
  python3 - "$archive" "$destination" <<'PY'
import os
import pathlib
import shutil
import sys
import tarfile

archive_path, destination = sys.argv[1:]
destination_path = pathlib.Path(destination).resolve()
destination_path.mkdir(parents=True, exist_ok=True)

with tarfile.open(archive_path, "r:gz") as archive:
    members = archive.getmembers()
    if not members:
        raise SystemExit("release archive is empty")
    for member in members:
        path = pathlib.PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts or not path.parts:
            raise SystemExit(f"unsafe archive path: {member.name}")
        if member.issym() or member.islnk() or member.isdev() or member.isfifo():
            raise SystemExit(f"unsupported archive entry: {member.name}")
        output = (destination_path / pathlib.Path(*path.parts)).resolve()
        if destination_path != output and destination_path not in output.parents:
            raise SystemExit(f"archive path escapes destination: {member.name}")
    for member in members:
        path = pathlib.PurePosixPath(member.name)
        output = destination_path / pathlib.Path(*path.parts)
        if member.isdir():
            output.mkdir(parents=True, exist_ok=True)
            os.chmod(output, 0o755)
        elif member.isfile():
            output.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                raise SystemExit(f"could not read archive entry: {member.name}")
            with source, open(output, "wb") as target:
                shutil.copyfileobj(source, target)
            os.chmod(output, member.mode & 0o777)
        else:
            raise SystemExit(f"unsupported archive entry: {member.name}")
PY
}

# distribution_version_compare A B -> prints lt, eq or gt by semantic-version
# precedence (a prerelease sorts before its release; build metadata is
# ignored). Fails when either argument is not a version.
distribution_version_compare() {
  python3 - "$1" "$2" <<'PY'
import re
import sys

PATTERN = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


def key(text):
    match = PATTERN.match(text.strip())
    if not match:
        raise SystemExit(f"not a version: {text}")
    core = tuple(int(part) for part in match.group(1, 2, 3))
    if match.group(4) is None:
        return core, (1,)
    identifiers = tuple(
        (0, int(part), "") if part.isdigit() else (1, 0, part)
        for part in match.group(4).split(".")
    )
    return core, (0, identifiers)


left, right = key(sys.argv[1]), key(sys.argv[2])
print("lt" if left < right else "gt" if left > right else "eq")
PY
}

# distribution_latest_archive DIRECTORY TARGET -> prints the archive for
# TARGET with the highest version, or nothing when there is none. A glob's
# last match is not it: 0.9.0 sorts after 0.10.0.
distribution_latest_archive() {
  local directory="$1" target="$2" candidate version best="" best_version=""
  for candidate in "$directory"/premier-*-"$target".tar.gz; do
    [[ -f "$candidate" ]] || continue
    version="$(basename "$candidate")"
    version="${version#premier-}"
    version="${version%-"$target".tar.gz}"
    distribution_version_compare "$version" 0.0.0 >/dev/null 2>&1 || continue
    if [[ -z "$best" || "$(distribution_version_compare "$version" "$best_version")" == gt ]]; then
      best="$candidate"
      best_version="$version"
    fi
  done
  [[ -z "$best" ]] || printf '%s\n' "$best"
}

# distribution_binary_format FILE -> prints the Rust-target family the
# executable's header declares (for example aarch64-apple-darwin or
# x86_64-unknown-linux), or `unknown`.
distribution_binary_format() {
  python3 - "$1" <<'PY'
import struct
import sys

with open(sys.argv[1], "rb") as handle:
    head = handle.read(20)
result = "unknown"
if head[:4] == b"\x7fELF" and len(head) >= 20 and head[5] == 1:
    machine = struct.unpack_from("<H", head, 18)[0]
    result = {62: "x86_64-unknown-linux", 183: "aarch64-unknown-linux"}.get(machine, "unknown")
elif head[:4] == b"\xcf\xfa\xed\xfe" and len(head) >= 8:
    cpu = struct.unpack_from("<I", head, 4)[0]
    result = {0x01000007: "x86_64-apple-darwin", 0x0100000C: "aarch64-apple-darwin"}.get(cpu, "unknown")
print(result)
PY
}

# distribution_glibc_requirement FILE -> prints the highest GLIBC_x.y symbol
# version a Linux executable requires, or nothing when it cannot be read.
distribution_glibc_requirement() {
  command -v objdump >/dev/null 2>&1 || return 0
  # `|| true`: a binary with no such symbols is not an error under pipefail.
  { objdump -T "$1" 2>/dev/null || true; } |
    { grep -o 'GLIBC_[0-9][0-9.]*' || true; } | sed 's/^GLIBC_//' | sort -u -t. -k1,1n -k2,2n -k3,3n | tail -n 1
}
