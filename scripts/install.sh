#!/usr/bin/env bash
# Install Premier from a local release archive, or build from source as fallback.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# The next two lines are replaced by the library itself in the standalone
# installer that scripts/build-standalone-installer.sh writes.
# shellcheck source=scripts/lib/distribution.sh
source "$ROOT/scripts/lib/distribution.sh"
# Whether this script runs from a source checkout (which can build from source).
IN_CHECKOUT=0
[[ -f "$ROOT/Cargo.toml" && -d "$ROOT/crates/premier-cli" ]] && IN_CHECKOUT=1

PREFIX="${CARGO_HOME:-$HOME/.cargo}"
ARCHIVE=""
EXPECTED_CHECKSUM=""
FORCE=0
ALLOW_DOWNGRADE=0
DRY_RUN=0
SKIP_VIEWER=0
ALLOW_FOREIGN=0
ALLOW_UNSIGNED=0
SIGNATURE_BUNDLE=""
VERIFICATION_KEY=""
CERTIFICATE_IDENTITY_REGEXP="$DISTRIBUTION_SIGNER_IDENTITY_REGEXP"
CERTIFICATE_OIDC_ISSUER="$DISTRIBUTION_SIGNER_OIDC_ISSUER"

usage() {
  cat <<'EOF'
Usage: ./scripts/install.sh [options]

  --archive PATH        Install a supplied local prebuilt archive (preferred)
  --checksum SHA256     Require this archive SHA-256 before extraction
  --signature-bundle PATH
                        Sigstore bundle for the archive (default: ARCHIVE.sigstore.json)
  --verification-key PATH
                        Verify a key-signed bundle instead of GitHub keyless identity
  --certificate-identity-regexp REGEXP
                        Expected keyless signer identity (pinned to Premier release workflow)
  --certificate-oidc-issuer URL
                        Expected keyless OIDC issuer
  --allow-unsigned      Developer-only escape hatch for local archives
  --prefix PATH         Explicit install prefix (default: $CARGO_HOME or ~/.cargo)
  --force               Atomically replace an existing binary; the replaced
                        one is kept beside it as premier.previous
  --allow-downgrade     With --force, permit replacing a newer installed version
  --dry-run             Print the resolved operation without changing files
  --allow-foreign-architecture
                        Permit installing an archive for a different host
  --skip-viewer         Source fallback: use an existing viewer dist

No URL is accepted and this script never downloads or executes archive content.
In a source checkout, if no archive is supplied or found in ./dist (the highest
version wins), it falls back to a local source build.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --archive) ARCHIVE="${2:?missing archive path}"; shift 2 ;;
    --checksum) EXPECTED_CHECKSUM="${2:?missing checksum}"; shift 2 ;;
    --signature-bundle) SIGNATURE_BUNDLE="${2:?missing signature bundle}"; shift 2 ;;
    --verification-key) VERIFICATION_KEY="${2:?missing verification key}"; shift 2 ;;
    --certificate-identity-regexp) CERTIFICATE_IDENTITY_REGEXP="${2:?missing certificate identity regexp}"; shift 2 ;;
    --certificate-oidc-issuer) CERTIFICATE_OIDC_ISSUER="${2:?missing certificate OIDC issuer}"; shift 2 ;;
    --allow-unsigned) ALLOW_UNSIGNED=1; shift ;;
    --prefix) PREFIX="${2:?missing prefix}"; shift 2 ;;
    --force) FORCE=1; shift ;;
    --allow-downgrade) ALLOW_DOWNGRADE=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --skip-viewer) SKIP_VIEWER=1; shift ;;
    --allow-foreign-architecture) ALLOW_FOREIGN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done

case "$ARCHIVE" in http://*|https://*) echo "remote archives are not accepted; download and authenticate it separately" >&2; exit 1 ;; esac
HOST_TARGET="$(distribution_host_target || true)"
if [[ -z "$ARCHIVE" && -n "$HOST_TARGET" && "$IN_CHECKOUT" -eq 1 ]]; then
  ARCHIVE="$(distribution_latest_archive "$ROOT/dist" "$HOST_TARGET")"
fi

# Shown after an install when the binary would not be found by name.
path_hint() {
  case ":$PATH:" in
    *":$PREFIX/bin:"*) ;;
    *) echo "note: $PREFIX/bin is not on PATH; add it (export PATH=\"$PREFIX/bin:\$PATH\") or run $PREFIX/bin/premier directly" ;;
  esac
}

if [[ -z "$ARCHIVE" ]]; then
  if [[ "$IN_CHECKOUT" -ne 1 ]]; then
    echo "an --archive is required: this installer is not running from a Premier source checkout" >&2
    exit 1
  fi
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "would build Premier from source and install to $PREFIX/bin/premier"
    exit 0
  fi
  command -v cargo >/dev/null 2>&1 || { echo "no local archive found and cargo is unavailable" >&2; exit 1; }
  command -v npm >/dev/null 2>&1 || { echo "no local archive found and npm is unavailable" >&2; exit 1; }
  if [[ "$SKIP_VIEWER" -eq 0 ]]; then
    (cd "$ROOT" && [[ -d node_modules ]] || npm install)
    (cd "$ROOT" && npm run build)
  elif [[ ! -f "$ROOT/apps/viewer/dist/index.html" ]]; then
    echo "apps/viewer/dist/index.html is missing; omit --skip-viewer" >&2
    exit 1
  fi
  args=(install --path "$ROOT/crates/premier-cli" --locked --root "$PREFIX")
  [[ "$FORCE" -eq 1 ]] && args+=(--force)
  cargo "${args[@]}"
  echo "installed locally built Premier to $PREFIX/bin/premier"
  path_hint
  exit 0
fi

[[ -f "$ARCHIVE" ]] || { echo "archive not found: $ARCHIVE" >&2; exit 1; }
if [[ -z "$SIGNATURE_BUNDLE" && -f "$ARCHIVE.sigstore.json" ]]; then
  SIGNATURE_BUNDLE="$ARCHIVE.sigstore.json"
fi
# Who vouches for the archive, as reported on success. Only the pinned release
# workflow identity is "the publisher"; a caller-supplied key, identity or
# issuer is named as what it is.
SIGNER=""
if [[ -n "$SIGNATURE_BUNDLE" ]]; then
  [[ -f "$SIGNATURE_BUNDLE" ]] || { echo "signature bundle not found: $SIGNATURE_BUNDLE" >&2; exit 1; }
  command -v cosign >/dev/null 2>&1 || {
    echo "cosign is required to verify the Premier release signature" >&2
    exit 1
  }
  if [[ -n "$VERIFICATION_KEY" ]]; then
    cosign verify-blob --key "$VERIFICATION_KEY" --bundle "$SIGNATURE_BUNDLE" "$ARCHIVE" >/dev/null
    SIGNER="signature verified with the caller-supplied key $VERIFICATION_KEY, not the pinned publisher identity"
  else
    cosign verify-blob \
      --bundle "$SIGNATURE_BUNDLE" \
      --certificate-identity-regexp "$CERTIFICATE_IDENTITY_REGEXP" \
      --certificate-oidc-issuer "$CERTIFICATE_OIDC_ISSUER" \
      "$ARCHIVE" >/dev/null
    if [[ "$CERTIFICATE_IDENTITY_REGEXP" == "$DISTRIBUTION_SIGNER_IDENTITY_REGEXP" &&
      "$CERTIFICATE_OIDC_ISSUER" == "$DISTRIBUTION_SIGNER_OIDC_ISSUER" ]]; then
      SIGNER="publisher signature verified"
    else
      SIGNER="signature verified against the caller-supplied identity $CERTIFICATE_IDENTITY_REGEXP (issuer $CERTIFICATE_OIDC_ISSUER), not the pinned publisher identity"
    fi
  fi
elif [[ "$ALLOW_UNSIGNED" -ne 1 ]]; then
  echo "refusing unsigned release archive; provide --signature-bundle or use --allow-unsigned only for a local developer build" >&2
  exit 1
else
  echo "WARNING: installing an unsigned local developer archive" >&2
fi
ACTUAL_CHECKSUM="$(distribution_sha256 "$ARCHIVE")"
if [[ -z "$EXPECTED_CHECKSUM" && -f "$ARCHIVE.sha256" ]]; then
  EXPECTED_CHECKSUM="$(awk 'NR == 1 { print $1 }' "$ARCHIVE.sha256")"
fi
if [[ -n "$EXPECTED_CHECKSUM" && "$ACTUAL_CHECKSUM" != "$EXPECTED_CHECKSUM" ]]; then
  echo "archive checksum mismatch" >&2
  exit 1
fi

STAGING="$(mktemp -d "${TMPDIR:-/tmp}/premier-install.XXXXXX")"
TEMP_DESTINATION=""
cleanup() {
  rm -rf "$STAGING"
  [[ -z "$TEMP_DESTINATION" ]] || rm -f "$TEMP_DESTINATION"
}
trap cleanup EXIT
distribution_safe_extract "$ARCHIVE" "$STAGING"
METADATA_LIST="$(find "$STAGING" -type f -name RELEASE-METADATA)"
METADATA_COUNT="$(printf '%s\n' "$METADATA_LIST" | awk 'NF { count += 1 } END { print count + 0 }')"
[[ "$METADATA_COUNT" -eq 1 ]] || { echo "archive must contain exactly one release metadata file" >&2; exit 1; }
PACKAGE="$(dirname "$METADATA_LIST")"
VERSION="$(distribution_metadata_value "$PACKAGE/RELEASE-METADATA" VERSION)"
TARGET="$(distribution_metadata_value "$PACKAGE/RELEASE-METADATA" TARGET)"
[[ -n "$VERSION" && -n "$TARGET" ]] || { echo "invalid release metadata" >&2; exit 1; }
if [[ "$ALLOW_FOREIGN" -eq 0 && -n "$HOST_TARGET" && "$TARGET" != "$HOST_TARGET" ]]; then
  echo "archive target $TARGET does not match host $HOST_TARGET" >&2
  exit 1
fi
[[ -f "$PACKAGE/bin/premier" && -f "$PACKAGE/SHA256SUMS" ]] || { echo "incomplete release archive" >&2; exit 1; }
# The pinned identity accepts any release tag. The archive says which version
# it is, so require the signature to come from that version's tag: an archive
# signed for one tag cannot pass as another release.
if [[ "$SIGNER" == "publisher signature verified" ]]; then
  cosign verify-blob \
    --bundle "$SIGNATURE_BUNDLE" \
    --certificate-identity "$DISTRIBUTION_SIGNER_IDENTITY_PREFIX$VERSION" \
    --certificate-oidc-issuer "$CERTIFICATE_OIDC_ISSUER" \
    "$ARCHIVE" >/dev/null || {
    echo "archive says it is version $VERSION but was not signed by the release workflow at tag v$VERSION" >&2
    exit 1
  }
fi
# Files the archive must carry, and the shell helper newer archives add.
PAYLOAD=(LICENSE README.md RELEASE-METADATA bin/premier)
HELPER="share/premier/premier-emit.sh"
[[ ! -f "$PACKAGE/$HELPER" ]] || PAYLOAD+=("$HELPER")
(
  cd "$PACKAGE"
  for path in "${PAYLOAD[@]}"; do
    expected="$(awk -v path="$path" '$2 == path { print $1 }' SHA256SUMS)"
    [[ -n "$expected" && "$(printf '%s\n' "$expected" | wc -l | tr -d ' ')" -eq 1 ]] || {
      echo "missing or duplicate checksum: $path" >&2
      exit 1
    }
    [[ -f "$path" ]] || { echo "missing checksummed file: $path" >&2; exit 1; }
    [[ "$(distribution_sha256 "$path")" == "$expected" ]] || { echo "checksum mismatch: $path" >&2; exit 1; }
  done
)

DESTINATION="$PREFIX/bin/premier"
PREVIOUS="$PREFIX/bin/premier.previous"
INSTALLED=""
if [[ -e "$DESTINATION" || -L "$DESTINATION" ]]; then
  # `mv` onto a directory would move the binary inside it and report success.
  [[ -f "$DESTINATION" ]] || { echo "$DESTINATION exists and is not a regular file; refusing to replace it" >&2; exit 1; }
  if [[ "$FORCE" -eq 0 ]]; then
    echo "$DESTINATION already exists; pass --force to replace it" >&2
    exit 1
  fi
  INSTALLED="$("$DESTINATION" --version 2>/dev/null | awk 'NR == 1 { print $NF }' || true)"
  ORDER="$(distribution_version_compare "$VERSION" "${INSTALLED:-unknown}" 2>/dev/null || true)"
  if [[ "$ORDER" == lt && "$ALLOW_DOWNGRADE" -eq 0 ]]; then
    echo "installed Premier $INSTALLED is newer than the archive ($VERSION); pass --allow-downgrade to replace it anyway" >&2
    exit 1
  fi
fi
if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "would install Premier $VERSION ($TARGET) to $DESTINATION"
  exit 0
fi
mkdir -p "$PREFIX/bin"
TEMP_DESTINATION="$(mktemp "$PREFIX/bin/.premier.install.XXXXXX")"
install -m 0755 "$PACKAGE/bin/premier" "$TEMP_DESTINATION"
if [[ -f "$DESTINATION" ]]; then
  cp -p "$DESTINATION" "$PREVIOUS"
  echo "kept the replaced binary${INSTALLED:+ ($INSTALLED)} as $PREVIOUS"
fi
mv -f "$TEMP_DESTINATION" "$DESTINATION"
TEMP_DESTINATION=""
if [[ -f "$PACKAGE/$HELPER" ]]; then
  mkdir -p "$PREFIX/$(dirname "$HELPER")"
  install -m 0755 "$PACKAGE/$HELPER" "$PREFIX/$HELPER"
fi
echo "installed Premier $VERSION ($TARGET) to $DESTINATION"
if [[ -n "$SIGNER" ]]; then
  echo "archive SHA-256: $ACTUAL_CHECKSUM ($SIGNER)"
else
  echo "archive SHA-256: $ACTUAL_CHECKSUM (unsigned developer override)"
fi
path_hint
