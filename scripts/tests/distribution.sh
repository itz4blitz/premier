#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/premier-distribution.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

fail() {
  echo "distribution test failed: $*" >&2
  exit 1
}

assert_file() {
  [[ -f "$1" ]] || fail "missing file: $1"
}

assert_absent() {
  [[ ! -e "$1" ]] || fail "expected absent: $1"
}

FAKE="$WORK/premier"
cat >"$FAKE" <<'EOF'
#!/usr/bin/env sh
printf 'premier 0.1.0\n'
EOF
chmod +x "$FAKE"

# shellcheck source=scripts/lib/distribution.sh
source "$ROOT/scripts/lib/distribution.sh"
TARGET="$(distribution_host_target)"

OUT="$WORK/dist"
"$ROOT/scripts/package-release.sh" \
  --binary "$FAKE" \
  --target "$TARGET" \
  --version 0.1.0 \
  --output-dir "$OUT"

ARCHIVE="$OUT/premier-0.1.0-$TARGET.tar.gz"
assert_file "$ARCHIVE"
assert_file "$ARCHIVE.sha256"

# Public installs fail closed until publisher identity has been verified.
if "$ROOT/scripts/install.sh" --archive "$ARCHIVE" --prefix "$WORK/unsigned-prefix" >/dev/null 2>&1; then
  fail "installer accepted an unsigned archive without an explicit developer override"
fi

# Deterministic fake cosign validates that the installer authenticates the blob
# before extraction and pins the GitHub workflow identity + OIDC issuer.
FAKE_BIN="$WORK/fake-bin"
mkdir -p "$FAKE_BIN"
cat >"$FAKE_BIN/cosign" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${COSIGN_LOG:?}"
bundle=""
blob="${!#}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --bundle) bundle="$2"; shift 2 ;;
    *) shift ;;
  esac
done
expected="$(awk 'NR == 1 { print $1 }' "$bundle")"
if command -v sha256sum >/dev/null 2>&1; then actual="$(sha256sum "$blob" | awk '{print $1}')"; else actual="$(shasum -a 256 "$blob" | awk '{print $1}')"; fi
[[ "$actual" == "$expected" ]]
EOF
chmod +x "$FAKE_BIN/cosign"
cp "$ARCHIVE.sha256" "$ARCHIVE.sigstore.json"
COSIGN_LOG="$WORK/cosign.log"
export COSIGN_LOG

OUT_AGAIN="$WORK/dist-again"
"$ROOT/scripts/package-release.sh" \
  --binary "$FAKE" \
  --target "$TARGET" \
  --version 0.1.0 \
  --output-dir "$OUT_AGAIN" >/dev/null
cmp "$ARCHIVE" "$OUT_AGAIN/$(basename "$ARCHIVE")" >/dev/null || fail "release archive is not reproducible"

EXTRACTED="$WORK/extracted"
mkdir -p "$EXTRACTED"
tar -xzf "$ARCHIVE" -C "$EXTRACTED"
PACKAGE="$EXTRACTED/premier-0.1.0-$TARGET"
assert_file "$PACKAGE/bin/premier"
assert_file "$PACKAGE/README.md"
assert_file "$PACKAGE/LICENSE"
assert_file "$PACKAGE/RELEASE-METADATA"
assert_file "$PACKAGE/SHA256SUMS"
(cd "$PACKAGE" && shasum -a 256 -c SHA256SUMS >/dev/null)

PREFIX="$WORK/prefix"
PATH="$FAKE_BIN:$PATH" "$ROOT/scripts/install.sh" --archive "$ARCHIVE" --prefix "$PREFIX"
assert_file "$PREFIX/bin/premier"
grep -q -- '--certificate-identity-regexp' "$COSIGN_LOG" || fail "installer did not pin signer identity"
grep -q -- '--certificate-oidc-issuer https://token.actions.githubusercontent.com' "$COSIGN_LOG" || fail "installer did not pin OIDC issuer"

# The identity consumers pin must be the identity the release workflow signs
# with; otherwise every official release fails verification. Derive the signer
# from release.yml and match it against what each script hands to cosign.
logged_identity_regexp() {
  awk '{ for (i = 1; i < NF; i++) if ($i == "--certificate-identity-regexp") found = $(i + 1) } END { print found }' "$COSIGN_LOG"
}
assert_pins_release_signer() {
  local who="$1" regexp
  regexp="$(logged_identity_regexp)"
  [[ -n "$regexp" ]] || fail "$who did not pass a signer identity to cosign"
  [[ "$SIGNER_IDENTITY" =~ $regexp ]] || fail "$who pins $regexp, which rejects the release workflow identity $SIGNER_IDENTITY"
  [[ ! "${SIGNER_IDENTITY/PremierStudio\/premier\//PremierStudio/premier.dev/}" =~ $regexp ]] || fail "$who accepts a signer from another repository"
  [[ ! "${SIGNER_IDENTITY/refs\/tags\/v0.1.0/refs/heads/main}" =~ $regexp ]] || fail "$who accepts a signer from a branch build"
}
SIGNER_TEMPLATE="$(sed -n 's/.*--certificate-identity "\(https:[^"]*\)".*/\1/p' "$ROOT/.github/workflows/release.yml")"
# shellcheck disable=SC2016 # the literal ${GITHUB_REF} placeholder in release.yml
REF_PLACEHOLDER='${GITHUB_REF}'
[[ "$SIGNER_TEMPLATE" == *"@$REF_PLACEHOLDER" ]] || fail "could not read the signer identity from release.yml: $SIGNER_TEMPLATE"
SIGNER_IDENTITY="${SIGNER_TEMPLATE%"$REF_PLACEHOLDER"}refs/tags/v0.1.0"
assert_pins_release_signer "install.sh"

RELEASE_DIR="$WORK/release"
mkdir -p "$RELEASE_DIR"
cp "$ARCHIVE" "$RELEASE_DIR/"
(cd "$RELEASE_DIR" && printf '%s  %s\n' "$(distribution_sha256 "$(basename "$ARCHIVE")")" "./$(basename "$ARCHIVE")" >SHA256SUMS)
printf '%s\n' "$(distribution_sha256 "$RELEASE_DIR/SHA256SUMS")" >"$RELEASE_DIR/SHA256SUMS.sigstore.json"
: >"$COSIGN_LOG"
PATH="$FAKE_BIN:$PATH" "$ROOT/scripts/verify-release.sh" --directory "$RELEASE_DIR" >/dev/null || fail "verify-release rejected an intact release"
assert_pins_release_signer "verify-release.sh"
grep -q -- '--certificate-oidc-issuer https://token.actions.githubusercontent.com' "$COSIGN_LOG" || fail "verify-release did not pin OIDC issuer"
printf 'tamper' >>"$RELEASE_DIR/$(basename "$ARCHIVE")"
if PATH="$FAKE_BIN:$PATH" "$ROOT/scripts/verify-release.sh" --directory "$RELEASE_DIR" >/dev/null 2>&1; then
  fail "verify-release accepted an asset that did not match the signed manifest"
fi

TAMPERED="$WORK/tampered.tar.gz"
cp "$ARCHIVE" "$TAMPERED"
printf 'tamper' >>"$TAMPERED"
if PATH="$FAKE_BIN:$PATH" "$ROOT/scripts/install.sh" --archive "$TAMPERED" --signature-bundle "$ARCHIVE.sigstore.json" --prefix "$WORK/tampered-prefix" >/dev/null 2>&1; then
  fail "installer accepted a blob that did not match its signature bundle"
fi

CHECK_OUTPUT="$("$ROOT/scripts/version-check.sh" --archive "$ARCHIVE" --prefix "$PREFIX")"
[[ "$CHECK_OUTPUT" == *"installed: 0.1.0"* ]] || fail "version check omitted installed version"
[[ "$CHECK_OUTPUT" == *"available: 0.1.0"* ]] || fail "version check omitted archive version"

UPDATED="$WORK/updated"
mkdir -p "$UPDATED"
cp "$PREFIX/bin/premier" "$UPDATED/before"
PATH="$FAKE_BIN:$PATH" "$ROOT/scripts/update.sh" --archive "$ARCHIVE" --prefix "$PREFIX" --dry-run >/dev/null
cmp "$UPDATED/before" "$PREFIX/bin/premier" >/dev/null || fail "dry-run update changed binary"
PATH="$FAKE_BIN:$PATH" "$ROOT/scripts/update.sh" --archive "$ARCHIVE" --prefix "$PREFIX" >/dev/null

"$ROOT/scripts/uninstall.sh" --prefix "$PREFIX" --dry-run >/dev/null
assert_file "$PREFIX/bin/premier"
"$ROOT/scripts/uninstall.sh" --prefix "$PREFIX" >/dev/null
assert_absent "$PREFIX/bin/premier"

# Extraction must reject traversal before writing outside the staging directory.
BAD="$WORK/bad.tar.gz"
python3 - "$BAD" <<'PY'
import io, tarfile, sys
with tarfile.open(sys.argv[1], "w:gz") as archive:
    info = tarfile.TarInfo("../escape")
    data = b"nope"
    info.size = len(data)
    archive.addfile(info, io.BytesIO(data))
PY
if "$ROOT/scripts/install.sh" --archive "$BAD" --prefix "$PREFIX" --allow-unsigned >/dev/null 2>&1; then
  fail "installer accepted a traversal archive"
fi
assert_absent "$WORK/escape"

echo "distribution shell tests passed"
