#!/usr/bin/env bash
# Stage the script-free npm platform packages from release archives: copy each
# archive's executable into npm/platforms/<platform>/bin/premier, record the
# glibc it requires for the launcher to check, and copy LICENSE into every
# package. Run scripts/verify-staged-npm.mjs afterwards, before publishing.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/distribution.sh
source "$ROOT/scripts/lib/distribution.sh"

VERSION=""
ASSETS=""
PACKAGES="$ROOT"
usage() { echo "Usage: ./scripts/stage-npm-packages.sh --version VERSION --assets DIRECTORY [--root DIRECTORY]"; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="${2:?missing version}"; shift 2 ;;
    --assets) ASSETS="${2:?missing assets directory}"; shift 2 ;;
    --root) PACKAGES="${2:?missing root}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done
[[ -n "$VERSION" && -d "$ASSETS" ]] || { usage >&2; exit 1; }

stage_platform() {
  local target="$1" directory="$2" package_root archive destination metadata viewer glibc
  package_root="premier-$VERSION-$target"
  archive="$ASSETS/$package_root.tar.gz"
  destination="$PACKAGES/npm/platforms/$directory/bin/premier"
  [[ -f "$archive" ]] || { echo "missing release archive: $archive" >&2; exit 1; }
  metadata="$(tar -xOf "$archive" "$package_root/RELEASE-METADATA")"
  value() { printf '%s\n' "$metadata" | awk -F= -v key="$1" '$1 == key { print $2; exit }'; }
  [[ "$(value VERSION)" == "$VERSION" ]] || { echo "$archive says it is version $(value VERSION), not $VERSION" >&2; exit 1; }
  [[ "$(value TARGET)" == "$target" ]] || { echo "$archive says it is for $(value TARGET), not $target" >&2; exit 1; }
  viewer="$(value VIEWER)"
  [[ "$viewer" == embedded ]] || { echo "$archive was packaged without a verified embedded viewer (VIEWER=$viewer)" >&2; exit 1; }
  mkdir -p "$(dirname "$destination")"
  tar -xOf "$archive" "$package_root/bin/premier" >"$destination"
  chmod 0755 "$destination"
  [[ "$(distribution_binary_format "$destination")" == "${target%-gnu}" ]] || {
    echo "$archive does not contain a $target executable" >&2
    exit 1
  }
  glibc="$(value GLIBC_MIN)"
  if [[ "$target" == *-linux-gnu ]]; then
    [[ -n "$glibc" ]] || { echo "$archive does not record the glibc its binary requires (GLIBC_MIN)" >&2; exit 1; }
    # The launcher compares this with the system's glibc before running the binary.
    # shellcheck disable=SC2016 # JavaScript, not shell
    node -e '
      const fs = require("node:fs");
      const [path, glibc] = process.argv.slice(1);
      const manifest = JSON.parse(fs.readFileSync(path, "utf8"));
      manifest.premier = { glibc };
      fs.writeFileSync(path, `${JSON.stringify(manifest, null, 2)}\n`);
    ' "$PACKAGES/npm/platforms/$directory/package.json" "$glibc"
  fi
  cp "$ROOT/LICENSE" "$PACKAGES/npm/platforms/$directory/LICENSE"
  echo "staged $directory from $(basename "$archive")${glibc:+ (glibc $glibc)}"
}

stage_platform aarch64-apple-darwin darwin-arm64
stage_platform x86_64-apple-darwin darwin-x64
stage_platform aarch64-unknown-linux-gnu linux-arm64-gnu
stage_platform x86_64-unknown-linux-gnu linux-x64-gnu
cp "$ROOT/LICENSE" "$PACKAGES/packages/premier-cli/LICENSE"
