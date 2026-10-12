#!/usr/bin/env bash
# Packaging, installer, updater, uninstaller and release-verifier checks.
# Everything is written inside one mktemp directory; cosign is a stand-in that
# enforces the digest, signer identity, issuer and key it is asked to check.
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

# refuses WHY PATTERN COMMAND... -> COMMAND must fail and say PATTERN on stderr.
refuses() {
  local why="$1" pattern="$2" output
  shift 2
  if output="$("$@" 2>&1 >/dev/null)"; then
    fail "$why (the command succeeded)"
  fi
  [[ "$output" == *"$pattern"* ]] || fail "$why: expected '$pattern' on stderr, got: $output"
}

# shellcheck source=scripts/lib/distribution.sh
source "$ROOT/scripts/lib/distribution.sh"
TARGET="$(distribution_host_target)"
if [[ "$TARGET" == x86_64-unknown-linux-gnu ]]; then
  FOREIGN_TARGET=aarch64-apple-darwin
else
  FOREIGN_TARGET=x86_64-unknown-linux-gnu
fi

# make_fake VERSION [VIEWER] [TARGET] -> path of a stand-in `premier` that
# answers `--version` and `build-info` the way the real binary does.
make_fake() {
  local version="$1" viewer="${2:-embedded}" target="${3:-$TARGET}" path
  path="$WORK/fake-$version-$viewer-$target"
  cat >"$path" <<EOF
#!/usr/bin/env sh
if [ "\${1:-}" = build-info ]; then
  printf 'version=%s\ntarget=%s\nviewer=%s\n' '$version' '$target' '$viewer'
else
  printf 'premier $version\n'
fi
EOF
  chmod +x "$path"
  printf '%s\n' "$path"
}

# make_foreign_binary TARGET -> path of a file with that target's executable header.
make_foreign_binary() {
  local path="$WORK/foreign-$1"
  python3 - "$1" "$path" <<'PY'
import struct, sys
target, path = sys.argv[1:]
if "linux" in target:
    machine = 62 if target.startswith("x86_64") else 183
    head = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9) + struct.pack("<HH", 2, machine)
else:
    cpu = 0x01000007 if target.startswith("x86_64") else 0x0100000C
    head = b"\xcf\xfa\xed\xfe" + struct.pack("<I", cpu) + bytes(12)
with open(path, "wb") as handle:
    handle.write(head + bytes(64))
PY
  chmod +x "$path"
  printf '%s\n' "$path"
}

FAKE="$(make_fake 0.1.0)"
OUT="$WORK/dist"
"$ROOT/scripts/package-release.sh" \
  --binary "$FAKE" \
  --target "$TARGET" \
  --version 0.1.0 \
  --output-dir "$OUT"

ARCHIVE="$OUT/premier-0.1.0-$TARGET.tar.gz"
assert_file "$ARCHIVE"
assert_file "$ARCHIVE.sha256"

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
# The shell helper ships in the archive, executable and checksummed.
assert_file "$PACKAGE/share/premier/premier-emit.sh"
[[ -x "$PACKAGE/share/premier/premier-emit.sh" ]] || fail "packaged shell helper is not executable"
cmp "$PACKAGE/share/premier/premier-emit.sh" "$ROOT/sdk/shell/premier-emit.sh" >/dev/null || fail "packaged shell helper differs from sdk/shell/premier-emit.sh"
grep -q 'share/premier/premier-emit.sh$' "$PACKAGE/SHA256SUMS" || fail "shell helper is not in the archive's checksums"
(cd "$PACKAGE" && shasum -a 256 -c SHA256SUMS >/dev/null)
grep -qx 'VIEWER=embedded' "$PACKAGE/RELEASE-METADATA" || fail "metadata does not record the verified viewer"
grep -qx "TARGET=$TARGET" "$PACKAGE/RELEASE-METADATA" || fail "metadata does not record the target"

# Metadata is only written about a binary that was checked. A binary for this
# host is run; one that embeds the placeholder page, reports another version,
# or was built for another target is refused.
refuses "packaged a binary without the embedded viewer" "placeholder page" \
  "$ROOT/scripts/package-release.sh" --binary "$(make_fake 0.1.0 placeholder)" --target "$TARGET" --version 0.1.0 --output-dir "$WORK/refused"
refuses "packaged a binary of another version" "reports version 0.0.9" \
  "$ROOT/scripts/package-release.sh" --binary "$(make_fake 0.0.9)" --target "$TARGET" --version 0.1.0 --output-dir "$WORK/refused"
refuses "packaged a binary built for another target" "was built for $FOREIGN_TARGET" \
  "$ROOT/scripts/package-release.sh" --binary "$(make_fake 0.1.0 embedded "$FOREIGN_TARGET")" --target "$TARGET" --version 0.1.0 --output-dir "$WORK/refused"
SILENT="$WORK/silent"
printf '#!/usr/bin/env sh\nexit 3\n' >"$SILENT"
chmod +x "$SILENT"
refuses "packaged a binary that does not answer build-info" "build-info" \
  "$ROOT/scripts/package-release.sh" --binary "$SILENT" --target "$TARGET" --version 0.1.0 --output-dir "$WORK/refused"
# A binary for another host cannot be run, so its header must match the target.
refuses "packaged a file that is not an executable of the target" "is not a $FOREIGN_TARGET executable" \
  "$ROOT/scripts/package-release.sh" --binary "$FAKE" --target "$FOREIGN_TARGET" --version 0.1.0 --output-dir "$WORK/refused"
assert_absent "$WORK/refused"
# Stand-in objdump: reports the dynamic symbols of a Linux binary that needs
# glibc $FAKE_GLIBC (and older versions, in no particular order).
OBJDUMP_BIN="$WORK/objdump-bin"
mkdir -p "$OBJDUMP_BIN"
cat >"$OBJDUMP_BIN/objdump" <<'EOF'
#!/usr/bin/env sh
printf '0000 DF *UND* 0000 (GLIBC_2.17) memcpy\n0000 DF *UND* 0000 (GLIBC_%s) fstat\n0000 DF *UND* 0000 (GLIBC_2.4) abort\n' "${FAKE_GLIBC:?}"
EOF
chmod +x "$OBJDUMP_BIN/objdump"
package_foreign() { PATH="$OBJDUMP_BIN:$PATH" "$ROOT/scripts/package-release.sh" "$@"; }

FOREIGN_OUT="$WORK/dist-foreign"
FAKE_GLIBC=2.34 package_foreign --binary "$(make_foreign_binary "$FOREIGN_TARGET")" \
  --target "$FOREIGN_TARGET" --version 0.1.0 --output-dir "$FOREIGN_OUT" >/dev/null 2>&1 ||
  fail "could not package a binary with the foreign target's header"

# A Linux binary's glibc requirement is measured and recorded, the highest
# version by number (2.34 over 2.4 and 2.17), and one above the documented
# ceiling is refused.
if [[ "$TARGET" == aarch64-unknown-linux-gnu ]]; then LINUX_TARGET=x86_64-unknown-linux-gnu; else LINUX_TARGET=aarch64-unknown-linux-gnu; fi
LINUX_BINARY="$(make_foreign_binary "$LINUX_TARGET")"
FAKE_GLIBC=2.34 package_foreign --binary "$LINUX_BINARY" --target "$LINUX_TARGET" --version 0.1.0 --output-dir "$WORK/dist-linux" >/dev/null 2>&1 ||
  fail "could not package a Linux binary"
tar -xzOf "$WORK/dist-linux/premier-0.1.0-$LINUX_TARGET.tar.gz" "premier-0.1.0-$LINUX_TARGET/RELEASE-METADATA" | grep -qx 'GLIBC_MIN=2.34' ||
  fail "metadata does not record the glibc a Linux binary requires"
refuses "packaged a Linux binary that needs a glibc newer than the ceiling" "requires glibc 2.41, newer than the documented ceiling $DISTRIBUTION_GLIBC_CEILING" \
  env FAKE_GLIBC=2.41 PATH="$OBJDUMP_BIN:$PATH" "$ROOT/scripts/package-release.sh" --binary "$LINUX_BINARY" --target "$LINUX_TARGET" --version 0.1.0 --output-dir "$WORK/refused"
assert_absent "$WORK/refused"
FOREIGN_ARCHIVE="$FOREIGN_OUT/premier-0.1.0-$FOREIGN_TARGET.tar.gz"
tar -xzOf "$FOREIGN_ARCHIVE" "premier-0.1.0-$FOREIGN_TARGET/RELEASE-METADATA" | grep -qx 'VIEWER=unverified' ||
  fail "an unchecked foreign binary was described as having an embedded viewer"

# Public installs fail closed until publisher identity has been verified.
refuses "installer accepted an unsigned archive without an explicit developer override" "refusing unsigned release archive" \
  "$ROOT/scripts/install.sh" --archive "$ARCHIVE" --prefix "$WORK/unsigned-prefix"
assert_absent "$WORK/unsigned-prefix"

# Stand-in cosign. A "bundle" is one line: DIGEST IDENTITY ISSUER. It refuses
# a blob with another digest, a signer the caller's identity (exact or regexp)
# or issuer does not accept, and a key other than the one that "signed".
FAKE_BIN="$WORK/fake-bin"
mkdir -p "$FAKE_BIN"
cat >"$FAKE_BIN/cosign" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${COSIGN_LOG:?}"
[[ "${1:-}" == verify-blob ]] || { echo "fake cosign only verifies blobs" >&2; exit 2; }
bundle="" regexp="" exact="" issuer="" key=""
blob="${!#}"
while [[ $# -gt 1 ]]; do
  case "$1" in
    --bundle) bundle="$2"; shift 2 ;;
    --certificate-identity-regexp) regexp="$2"; shift 2 ;;
    --certificate-identity) exact="$2"; shift 2 ;;
    --certificate-oidc-issuer) issuer="$2"; shift 2 ;;
    --key) key="$2"; shift 2 ;;
    *) shift ;;
  esac
done
read -r expected identity signed_issuer <"$bundle" || true
if command -v sha256sum >/dev/null 2>&1; then actual="$(sha256sum "$blob" | awk '{print $1}')"; else actual="$(shasum -a 256 "$blob" | awk '{print $1}')"; fi
[[ "$actual" == "$expected" ]] || { echo "digest does not match the bundle" >&2; exit 1; }
if [[ -n "$key" ]]; then
  [[ "$identity" == "key:$(cat "$key")" ]] || { echo "signed by another key" >&2; exit 1; }
  exit 0
fi
[[ -n "$issuer" && "$issuer" == "$signed_issuer" ]] || { echo "issuer not accepted" >&2; exit 1; }
if [[ -n "$exact" ]]; then
  [[ "$identity" == "$exact" ]] || { echo "identity not accepted" >&2; exit 1; }
elif [[ -n "$regexp" ]]; then
  [[ "$identity" =~ $regexp ]] || { echo "identity not accepted" >&2; exit 1; }
else
  echo "no signer identity was required" >&2
  exit 1
fi
EOF
chmod +x "$FAKE_BIN/cosign"
COSIGN_LOG="$WORK/cosign.log"
export COSIGN_LOG
: >"$COSIGN_LOG"

# The identity consumers pin must be the identity the release workflow signs
# with; otherwise every official release fails verification. Derive the signer
# from release.yml.
SIGNER_TEMPLATE="$(sed -n 's/.*--certificate-identity "\(https:[^"]*\)".*/\1/p' "$ROOT/.github/workflows/release.yml")"
# shellcheck disable=SC2016 # the literal ${GITHUB_REF} placeholder in release.yml
REF_PLACEHOLDER='${GITHUB_REF}'
[[ "$SIGNER_TEMPLATE" == *"@$REF_PLACEHOLDER" ]] || fail "could not read the signer identity from release.yml: $SIGNER_TEMPLATE"
SIGNER_BASE="${SIGNER_TEMPLATE%"$REF_PLACEHOLDER"}"
SIGNER_IDENTITY="${SIGNER_BASE}refs/tags/v0.1.0"
ISSUER='https://token.actions.githubusercontent.com'
[[ "${SIGNER_BASE}refs/tags/v" == "$DISTRIBUTION_SIGNER_IDENTITY_PREFIX" ]] ||
  fail "the per-release identity prefix does not match release.yml"

# sign FILE [IDENTITY] [ISSUER] [BUNDLE] -> writes FILE.sigstore.json (or BUNDLE)
sign() {
  printf '%s %s %s\n' "$(distribution_sha256 "$1")" "${2:-$SIGNER_IDENTITY}" "${3:-$ISSUER}" >"${4:-$1.sigstore.json}"
}
install_signed() { PATH="$FAKE_BIN:$PATH" "$ROOT/scripts/install.sh" "$@"; }

sign "$ARCHIVE"
PREFIX="$WORK/prefix"
INSTALL_OUTPUT="$(install_signed --archive "$ARCHIVE" --prefix "$PREFIX")"
assert_file "$PREFIX/bin/premier"
assert_file "$PREFIX/share/premier/premier-emit.sh"
[[ "$INSTALL_OUTPUT" == *"(publisher signature verified)"* ]] || fail "pinned install did not report the publisher signature: $INSTALL_OUTPUT"
[[ "$INSTALL_OUTPUT" == *"$PREFIX/bin is not on PATH"* ]] || fail "installer gave no PATH hint for a prefix that is not on PATH"
ON_PATH_OUTPUT="$(PATH="$FAKE_BIN:$WORK/on-path/bin:$PATH" "$ROOT/scripts/install.sh" --archive "$ARCHIVE" --prefix "$WORK/on-path")"
[[ "$ON_PATH_OUTPUT" != *"is not on PATH"* ]] || fail "installer gave a PATH hint for a prefix that is on PATH"
grep -q -- '--certificate-identity-regexp' "$COSIGN_LOG" || fail "installer did not pin signer identity"
grep -q -- "--certificate-oidc-issuer $ISSUER" "$COSIGN_LOG" || fail "installer did not pin OIDC issuer"
grep -q -- "--certificate-identity ${SIGNER_BASE}refs/tags/v0.1.0 " "$COSIGN_LOG" ||
  fail "installer did not require the signature to come from the archive's own release tag"

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
assert_pins_release_signer "install.sh"

# One negative case per signature guard, each decided by the stand-in cosign.
REJECTED="$WORK/rejected-prefix"
OTHER="$WORK/other.sigstore.json"
sign "$ARCHIVE" "${SIGNER_IDENTITY/PremierStudio\/premier\//EvilCorp/premier/}" "$ISSUER" "$OTHER"
refuses "installer accepted an archive signed by another repository" "identity not accepted" \
  install_signed --archive "$ARCHIVE" --signature-bundle "$OTHER" --prefix "$REJECTED"
sign "$ARCHIVE" "${SIGNER_BASE}refs/heads/main" "$ISSUER" "$OTHER"
refuses "installer accepted an archive signed by a branch build" "identity not accepted" \
  install_signed --archive "$ARCHIVE" --signature-bundle "$OTHER" --prefix "$REJECTED"
sign "$ARCHIVE" "$SIGNER_IDENTITY" "https://issuer.example" "$OTHER"
refuses "installer accepted an archive from another OIDC issuer" "issuer not accepted" \
  install_signed --archive "$ARCHIVE" --signature-bundle "$OTHER" --prefix "$REJECTED"
sign "$ARCHIVE" "${SIGNER_BASE}refs/tags/v0.2.0" "$ISSUER" "$OTHER"
refuses "installer accepted a 0.1.0 archive signed by the v0.2.0 release" "was not signed by the release workflow at tag v0.1.0" \
  install_signed --archive "$ARCHIVE" --signature-bundle "$OTHER" --prefix "$REJECTED"
TAMPERED="$WORK/tampered.tar.gz"
cp "$ARCHIVE" "$TAMPERED"
printf 'tamper' >>"$TAMPERED"
refuses "installer accepted a blob that did not match its signature bundle" "digest does not match" \
  install_signed --archive "$TAMPERED" --signature-bundle "$ARCHIVE.sigstore.json" --prefix "$REJECTED"
refuses "installer accepted a missing signature bundle" "signature bundle not found" \
  install_signed --archive "$ARCHIVE" --signature-bundle "$WORK/nowhere.json" --prefix "$REJECTED"
if ! command -v cosign >/dev/null 2>&1; then
  refuses "installer verified a signature without cosign" "cosign is required" \
    "$ROOT/scripts/install.sh" --archive "$ARCHIVE" --prefix "$REJECTED"
fi
assert_absent "$REJECTED"

# A caller who replaces the trust root is told so: only the pinned release
# workflow identity is reported as the publisher.
printf 'local-key\n' >"$WORK/cosign.pub"
printf 'other-key\n' >"$WORK/other.pub"
KEYED="$WORK/keyed.sigstore.json"
printf '%s key:local-key\n' "$(distribution_sha256 "$ARCHIVE")" >"$KEYED"
KEY_OUTPUT="$(install_signed --archive "$ARCHIVE" --signature-bundle "$KEYED" --verification-key "$WORK/cosign.pub" --prefix "$WORK/key-prefix")"
[[ "$KEY_OUTPUT" == *"caller-supplied key $WORK/cosign.pub"* ]] || fail "key-verified install did not name the key: $KEY_OUTPUT"
[[ "$KEY_OUTPUT" != *"publisher signature verified"* ]] || fail "key-verified install claimed the publisher signature"
refuses "installer accepted a bundle signed by another key" "signed by another key" \
  install_signed --archive "$ARCHIVE" --signature-bundle "$KEYED" --verification-key "$WORK/other.pub" --prefix "$REJECTED"
sign "$ARCHIVE" "https://example.test/fork@refs/tags/v0.1.0" "https://issuer.example" "$OTHER"
CUSTOM_OUTPUT="$(install_signed --archive "$ARCHIVE" --signature-bundle "$OTHER" --prefix "$WORK/custom-prefix" \
  --certificate-identity-regexp '^https://example\.test/fork@' --certificate-oidc-issuer https://issuer.example)"
[[ "$CUSTOM_OUTPUT" == *"caller-supplied identity ^https://example\\.test/fork@ (issuer https://issuer.example)"* ]] ||
  fail "custom-identity install did not name the identity: $CUSTOM_OUTPUT"
[[ "$CUSTOM_OUTPUT" != *"(publisher signature verified)"* ]] || fail "custom-identity install claimed the publisher signature"

# Checksums: the --checksum argument, the sidecar, and the archive's own list.
refuses "installer accepted a wrong --checksum" "archive checksum mismatch" \
  install_signed --archive "$ARCHIVE" --checksum 0000 --prefix "$REJECTED"
SIDECAR_DIR="$WORK/sidecar"
mkdir -p "$SIDECAR_DIR"
cp "$ARCHIVE" "$ARCHIVE.sigstore.json" "$SIDECAR_DIR/"
printf '%s  %s\n' 0000 "$(basename "$ARCHIVE")" >"$SIDECAR_DIR/$(basename "$ARCHIVE").sha256"
refuses "installer accepted an archive that disagrees with its .sha256 sidecar" "archive checksum mismatch" \
  install_signed --archive "$SIDECAR_DIR/$(basename "$ARCHIVE")" --prefix "$REJECTED"

# repack MODE OUTPUT -> a copy of the archive with one thing wrong inside.
repack() {
  python3 - "$ARCHIVE" "$2" "$1" <<'PY'
import io, sys, tarfile
source, output, mode = sys.argv[1:]
with tarfile.open(source, "r:gz") as archive, tarfile.open(output, "w:gz") as result:
    for member in archive.getmembers():
        data = archive.extractfile(member).read() if member.isfile() else None
        if mode == "inner-checksum" and member.name.endswith("/README.md"):
            data += b"\nedited after checksums were written\n"
            member.size = len(data)
        if mode == "no-metadata" and member.name.endswith("/RELEASE-METADATA"):
            continue
        result.addfile(member, io.BytesIO(data) if data is not None else None)
    if mode == "symlink":
        link = tarfile.TarInfo("premier-link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        result.addfile(link)
    if mode == "hardlink":
        link = tarfile.TarInfo("premier-hardlink")
        link.type = tarfile.LNKTYPE
        link.linkname = "../outside"
        result.addfile(link)
PY
}
BROKEN="$WORK/broken.tar.gz"
repack inner-checksum "$BROKEN"
refuses "installer accepted a file that disagrees with the archive's SHA256SUMS" "checksum mismatch: README.md" \
  "$ROOT/scripts/install.sh" --archive "$BROKEN" --allow-unsigned --prefix "$REJECTED"
repack no-metadata "$BROKEN"
refuses "installer accepted an archive without release metadata" "exactly one release metadata file" \
  "$ROOT/scripts/install.sh" --archive "$BROKEN" --allow-unsigned --prefix "$REJECTED"
repack symlink "$BROKEN"
refuses "installer accepted an archive containing a symbolic link" "unsupported archive entry: premier-link" \
  "$ROOT/scripts/install.sh" --archive "$BROKEN" --allow-unsigned --prefix "$REJECTED"
repack hardlink "$BROKEN"
refuses "installer accepted an archive containing a hard link" "unsupported archive entry: premier-hardlink" \
  "$ROOT/scripts/install.sh" --archive "$BROKEN" --allow-unsigned --prefix "$REJECTED"

# An archive for another host is refused unless that is asked for.
refuses "installer accepted an archive for another target" "does not match host" \
  "$ROOT/scripts/install.sh" --archive "$FOREIGN_ARCHIVE" --allow-unsigned --prefix "$REJECTED"
"$ROOT/scripts/install.sh" --archive "$FOREIGN_ARCHIVE" --allow-unsigned --allow-foreign-architecture --dry-run --prefix "$REJECTED" >/dev/null 2>&1 ||
  fail "--allow-foreign-architecture did not permit a foreign archive"

# Extraction must reject traversal before writing outside the staging
# directory. Staging is a mktemp directory under TMPDIR, so "../escape" would
# land in TMPDIR itself: give the installer a TMPDIR of its own and look there.
BAD="$WORK/bad.tar.gz"
python3 - "$BAD" <<'PY'
import io, tarfile, sys
with tarfile.open(sys.argv[1], "w:gz") as archive:
    info = tarfile.TarInfo("../escape")
    data = b"nope"
    info.size = len(data)
    archive.addfile(info, io.BytesIO(data))
PY
STAGING_TMP="$WORK/staging-tmp"
mkdir -p "$STAGING_TMP"
refuses "installer accepted a traversal archive" "unsafe archive path: ../escape" \
  env TMPDIR="$STAGING_TMP" "$ROOT/scripts/install.sh" --archive "$BAD" --prefix "$REJECTED" --allow-unsigned
assert_absent "$STAGING_TMP/escape"
assert_absent "$WORK/escape"
[[ -z "$(ls -A "$STAGING_TMP")" ]] || fail "a refused install left its staging directory behind: $(ls -A "$STAGING_TMP")"
assert_absent "$REJECTED"

# A directory where the binary belongs is not something to "replace".
DIRECTORY_PREFIX="$WORK/directory-prefix"
mkdir -p "$DIRECTORY_PREFIX/bin/premier"
refuses "installer reported success onto a directory" "is not a regular file" \
  install_signed --archive "$ARCHIVE" --prefix "$DIRECTORY_PREFIX" --force
[[ -z "$(ls -A "$DIRECTORY_PREFIX/bin/premier")" ]] || fail "installer moved the binary inside a directory"
[[ "$(ls -A "$DIRECTORY_PREFIX/bin")" == premier ]] || fail "a refused install left temporary files: $(ls -A "$DIRECTORY_PREFIX/bin")"
refuses "installer replaced an existing binary without --force" "pass --force" \
  install_signed --archive "$ARCHIVE" --prefix "$PREFIX"

CHECK_OUTPUT="$("$ROOT/scripts/version-check.sh" --archive "$ARCHIVE" --prefix "$PREFIX")"
[[ "$CHECK_OUTPUT" == *"installed: 0.1.0"* ]] || fail "version check omitted installed version"
[[ "$CHECK_OUTPUT" == *"available: 0.1.0"* ]] || fail "version check omitted archive version"
[[ "$CHECK_OUTPUT" == *"status: current"* ]] || fail "version check did not report a current install: $CHECK_OUTPUT"
[[ "$("$ROOT/scripts/version-check.sh" --archive "$ARCHIVE" --prefix "$WORK/empty-prefix")" == *"status: not installed"* ]] ||
  fail "version check did not report a missing install"

UPDATED="$WORK/updated"
mkdir -p "$UPDATED"
cp "$PREFIX/bin/premier" "$UPDATED/before"
PATH="$FAKE_BIN:$PATH" "$ROOT/scripts/update.sh" --archive "$ARCHIVE" --prefix "$PREFIX" --dry-run >/dev/null
cmp "$UPDATED/before" "$PREFIX/bin/premier" >/dev/null || fail "dry-run update changed binary"
assert_absent "$PREFIX/bin/premier.previous"

# Updating keeps the replaced binary, and an older archive is not an update.
NEWER_OUT="$WORK/dist-newer"
"$ROOT/scripts/package-release.sh" --binary "$(make_fake 0.10.0)" --target "$TARGET" --version 0.10.0 --output-dir "$NEWER_OUT" >/dev/null
NEWER="$NEWER_OUT/premier-0.10.0-$TARGET.tar.gz"
sign "$NEWER" "${SIGNER_BASE}refs/tags/v0.10.0"
[[ "$("$ROOT/scripts/version-check.sh" --archive "$NEWER" --prefix "$PREFIX")" == *"status: update available"* ]] ||
  fail "version check did not offer a newer archive"
UPDATE_OUTPUT="$(PATH="$FAKE_BIN:$PATH" "$ROOT/scripts/update.sh" --archive "$NEWER" --prefix "$PREFIX")"
[[ "$("$PREFIX/bin/premier" --version)" == "premier 0.10.0" ]] || fail "update did not install the newer binary"
cmp "$UPDATED/before" "$PREFIX/bin/premier.previous" >/dev/null || fail "update did not keep the replaced binary as premier.previous"
[[ "$UPDATE_OUTPUT" == *"kept the replaced binary (0.1.0) as $PREFIX/bin/premier.previous"* ]] || fail "update did not say where the old binary went: $UPDATE_OUTPUT"
[[ "$("$ROOT/scripts/version-check.sh" --archive "$ARCHIVE" --prefix "$PREFIX")" == *"installed version is newer than this archive"* ]] ||
  fail "version check called a downgrade an update"
refuses "update silently downgraded 0.10.0 to 0.1.0" "is newer than the archive (0.1.0)" \
  env PATH="$FAKE_BIN:$PATH" "$ROOT/scripts/update.sh" --archive "$ARCHIVE" --prefix "$PREFIX"
[[ "$("$PREFIX/bin/premier" --version)" == "premier 0.10.0" ]] || fail "a refused downgrade changed the binary"
PATH="$FAKE_BIN:$PATH" "$ROOT/scripts/update.sh" --archive "$ARCHIVE" --prefix "$PREFIX" --allow-downgrade >/dev/null
[[ "$("$PREFIX/bin/premier" --version)" == "premier 0.1.0" ]] || fail "--allow-downgrade did not install the older binary"
[[ "$("$PREFIX/bin/premier.previous" --version)" == "premier 0.10.0" ]] || fail "the downgraded-from binary was not kept"
[[ -z "$(find "$PREFIX/bin" -name '.premier.install.*')" ]] || fail "an install left a temporary file behind"

# With several archives present the highest version is chosen, not the last name.
PICK="$WORK/pick"
mkdir -p "$PICK"
for version in 0.9.0 0.10.0 0.10.0-rc.1 not-a-version; do : >"$PICK/premier-$version-$TARGET.tar.gz"; done
: >"$PICK/premier-9.0.0-$FOREIGN_TARGET.tar.gz"
[[ "$(distribution_latest_archive "$PICK" "$TARGET")" == "$PICK/premier-0.10.0-$TARGET.tar.gz" ]] ||
  fail "archive discovery picked $(distribution_latest_archive "$PICK" "$TARGET")"
[[ -z "$(distribution_latest_archive "$WORK/nowhere" "$TARGET")" ]] || fail "archive discovery invented an archive"
[[ "$(distribution_version_compare 0.9.0 0.10.0)" == lt && "$(distribution_version_compare 1.0.0-rc.1 1.0.0)" == lt &&
  "$(distribution_version_compare 1.0.0-rc.10 1.0.0-rc.9)" == gt && "$(distribution_version_compare 1.2.3 1.2.3+build)" == eq ]] ||
  fail "version comparison does not follow semantic-version precedence"
git -C "$ROOT" check-ignore -q dist/premier-0.1.0-"$TARGET".tar.gz || fail "the default packaging output directory ./dist is not ignored by git"

# Uninstall removes what the installer wrote and says what it leaves alone.
UNINSTALL_DRY="$("$ROOT/scripts/uninstall.sh" --prefix "$PREFIX" --dry-run)"
assert_file "$PREFIX/bin/premier"
[[ "$UNINSTALL_DRY" == *"would remove $PREFIX/bin/premier.previous"* ]] || fail "dry-run uninstall did not list the kept binary"
UNINSTALL_OUTPUT="$("$ROOT/scripts/uninstall.sh" --prefix "$PREFIX")"
assert_absent "$PREFIX/bin/premier"
assert_absent "$PREFIX/bin/premier.previous"
assert_absent "$PREFIX/share/premier"
[[ "$UNINSTALL_OUTPUT" == *".premier/traces"* ]] || fail "uninstall did not mention recorded traces"
[[ "$UNINSTALL_OUTPUT" == *"npm uninstall --global @premierstudio/premier"* ]] || fail "uninstall did not mention other install channels"
[[ "$("$ROOT/scripts/uninstall.sh" --prefix "$PREFIX")" == *"is not installed"*".premier/traces"* ]] ||
  fail "uninstall of a missing install did not mention what remains"
refuses "uninstall accepted a relative prefix" "refusing unsafe prefix" "$ROOT/scripts/uninstall.sh" --prefix relative/prefix
refuses "uninstall accepted / as prefix" "refusing unsafe prefix" "$ROOT/scripts/uninstall.sh" --prefix /

# The standalone installer is install.sh with the library inlined: it works
# from a directory that is not a checkout, and never tries to build from source.
STANDALONE_DIR="$WORK/standalone"
"$ROOT/scripts/build-standalone-installer.sh" "$STANDALONE_DIR/premier-install.sh" >/dev/null
if grep -q '^source ' "$STANDALONE_DIR/premier-install.sh"; then fail "standalone installer still sources a file"; fi
STANDALONE_OUTPUT="$(cd "$STANDALONE_DIR" && PATH="$FAKE_BIN:$PATH" ./premier-install.sh --archive "$ARCHIVE" --prefix "$WORK/standalone-prefix")"
assert_file "$WORK/standalone-prefix/bin/premier"
[[ "$STANDALONE_OUTPUT" == *"(publisher signature verified)"* ]] || fail "standalone installer did not verify the publisher: $STANDALONE_OUTPUT"
refuses "standalone installer tried a source build" "an --archive is required" \
  "$STANDALONE_DIR/premier-install.sh" --prefix "$WORK/standalone-source"

# verify-release.sh: every file in a release directory is either listed in the
# signed manifest or one of the files that belong beside a listed one.
RELEASE_DIR="$WORK/release"
mkdir -p "$RELEASE_DIR"
cp "$ARCHIVE" "$ARCHIVE.sha256" "$ARCHIVE.sigstore.json" "$RELEASE_DIR/"
ARCHIVE_NAME="$(basename "$ARCHIVE")"
printf '{"spdxVersion":"SPDX-2.3"}\n' >"$RELEASE_DIR/premier-$TARGET.spdx.json"
cp "$STANDALONE_DIR/premier-install.sh" "$RELEASE_DIR/"
write_manifest() {
  (cd "$RELEASE_DIR" && for name in "$@"; do printf '%s  ./%s\n' "$(distribution_sha256 "$name")" "$name"; done >SHA256SUMS)
  sign "$RELEASE_DIR/SHA256SUMS"
}
verify_release() { PATH="$FAKE_BIN:$PATH" "$ROOT/scripts/verify-release.sh" --directory "$RELEASE_DIR"; }
write_manifest "$ARCHIVE_NAME" "premier-$TARGET.spdx.json" premier-install.sh
: >"$COSIGN_LOG"
VERIFY_OUTPUT="$(verify_release)" || fail "verify-release rejected an intact release"
[[ "$VERIFY_OUTPUT" == *"3 asset checksums"* ]] || fail "verify-release did not count the listed assets: $VERIFY_OUTPUT"
assert_pins_release_signer "verify-release.sh"
grep -q -- "--certificate-oidc-issuer $ISSUER" "$COSIGN_LOG" || fail "verify-release did not pin OIDC issuer"

printf 'extra' >"$RELEASE_DIR/premier-9.9.9-$TARGET.tar.gz"
refuses "verify-release accepted an archive the manifest does not list" "not covered by the signed checksum manifest: premier-9.9.9-$TARGET.tar.gz" verify_release
rm "$RELEASE_DIR/premier-9.9.9-$TARGET.tar.gz"
printf '{"spdxVersion":"SPDX-2.3","tampered":true}\n' >"$RELEASE_DIR/premier-$TARGET.spdx.json"
refuses "verify-release accepted a tampered SBOM" "checksum mismatch: premier-$TARGET.spdx.json" verify_release
write_manifest "$ARCHIVE_NAME" premier-install.sh
refuses "verify-release accepted an SBOM outside the signed manifest" "not covered by the signed checksum manifest: premier-$TARGET.spdx.json" verify_release
write_manifest "$ARCHIVE_NAME" "premier-$TARGET.spdx.json" premier-install.sh
printf '0000  %s\n' "$ARCHIVE_NAME" >"$RELEASE_DIR/$ARCHIVE_NAME.sha256"
refuses "verify-release accepted a sidecar that disagrees with the manifest" "checksum sidecar disagrees" verify_release
cp "$ARCHIVE.sha256" "$RELEASE_DIR/"
verify_release >/dev/null || fail "verify-release rejected the restored release"
sign "$RELEASE_DIR/SHA256SUMS" "${SIGNER_BASE}refs/heads/main"
refuses "verify-release accepted a manifest signed by a branch build" "identity not accepted" verify_release
sign "$RELEASE_DIR/SHA256SUMS"
printf 'tamper' >>"$RELEASE_DIR/$ARCHIVE_NAME"
refuses "verify-release accepted an asset that did not match the signed manifest" "checksum mismatch: $ARCHIVE_NAME" verify_release

echo "distribution shell tests passed"
