#!/usr/bin/env bash
# Authenticate Premier's aggregate checksum manifest, then verify every downloaded asset.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/distribution.sh
source "$ROOT/scripts/lib/distribution.sh"

DIRECTORY="."
CHECKSUMS="SHA256SUMS"
BUNDLE="SHA256SUMS.sigstore.json"
IDENTITY_REGEXP="$DISTRIBUTION_SIGNER_IDENTITY_REGEXP"
ISSUER="$DISTRIBUTION_SIGNER_OIDC_ISSUER"

usage() {
  echo "Usage: ./scripts/verify-release.sh [--directory PATH] [--checksums PATH] [--bundle PATH]"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --directory) DIRECTORY="${2:?missing directory}"; shift 2 ;;
    --checksums) CHECKSUMS="${2:?missing checksums}"; shift 2 ;;
    --bundle) BUNDLE="${2:?missing bundle}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done

[[ "$CHECKSUMS" = /* ]] || CHECKSUMS="$DIRECTORY/$CHECKSUMS"
[[ "$BUNDLE" = /* ]] || BUNDLE="$DIRECTORY/$BUNDLE"
[[ -f "$CHECKSUMS" && -f "$BUNDLE" ]] || { echo "signed checksum manifest is incomplete" >&2; exit 1; }
command -v cosign >/dev/null 2>&1 || { echo "cosign is required" >&2; exit 1; }

cosign verify-blob \
  --bundle "$BUNDLE" \
  --certificate-identity-regexp "$IDENTITY_REGEXP" \
  --certificate-oidc-issuer "$ISSUER" \
  "$CHECKSUMS" >/dev/null

LISTED=()
while read -r expected name; do
  [[ -n "$expected" && -n "$name" ]] || continue
  name="${name#./}"
  case "$name" in */*|..) echo "unsafe name in checksum manifest: $name" >&2; exit 1 ;; esac
  asset="$DIRECTORY/$name"
  [[ -f "$asset" ]] || { echo "missing release asset: $name" >&2; exit 1; }
  [[ "$(distribution_sha256 "$asset")" == "$expected" ]] || { echo "checksum mismatch: $name" >&2; exit 1; }
  LISTED+=("$name")
done <"$CHECKSUMS"
[[ ${#LISTED[@]} -gt 0 ]] || { echo "signed checksum manifest lists no assets" >&2; exit 1; }

is_listed() {
  local wanted="$1" entry
  for entry in "${LISTED[@]}"; do
    [[ "$entry" == "$wanted" ]] && return 0
  done
  return 1
}

# Everything else in the directory must be accounted for, or "verified" would
# also be printed for a directory holding files nobody signed. Allowed beside
# the listed assets: the manifest and its bundle, a Sigstore bundle of a listed
# asset, and a .sha256 sidecar that agrees with its listed asset.
for path in "$DIRECTORY"/* "$DIRECTORY"/.[!.]*; do
  [[ -e "$path" || -L "$path" ]] || continue
  name="$(basename "$path")"
  [[ "$path" -ef "$CHECKSUMS" || "$path" -ef "$BUNDLE" ]] && continue
  is_listed "$name" && continue
  [[ -f "$path" && ! -L "$path" ]] || { echo "unexpected entry in release directory: $name" >&2; exit 1; }
  case "$name" in
    *.sigstore.json)
      is_listed "${name%.sigstore.json}" && continue
      ;;
    *.sha256)
      if is_listed "${name%.sha256}"; then
        [[ "$(awk 'NR == 1 { print $1 }' "$path")" == "$(distribution_sha256 "$DIRECTORY/${name%.sha256}")" ]] || {
          echo "checksum sidecar disagrees with the signed manifest: $name" >&2
          exit 1
        }
        continue
      fi
      ;;
  esac
  echo "release file is not covered by the signed checksum manifest: $name" >&2
  exit 1
done

echo "verified Premier release publisher identity and ${#LISTED[@]} asset checksums; no unlisted files"
