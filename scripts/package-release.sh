#!/usr/bin/env bash
# Build a reproducible Premier release archive around one embedded-viewer binary.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/distribution.sh
source "$ROOT/scripts/lib/distribution.sh"

TARGET=""
VERSION=""
BINARY=""
OUTPUT_DIR="$ROOT/dist"
SKIP_VIEWER=0
EXPECT_SIGSTORE=0

usage() {
  cat <<'EOF'
Usage: ./scripts/package-release.sh [options]

  --target TARGET       Rust target triple (defaults to this host)
  --version VERSION     Release version (defaults to workspace Cargo.toml)
  --binary PATH         Package an already-built binary (required for cross packaging)
  --output-dir PATH     Archive destination (default: ./dist)
  --skip-viewer         Use the existing apps/viewer/dist when building locally
  --expect-sigstore     Mark metadata for a Sigstore bundle added by release CI

The output contains the single embedded-viewer binary, the premier-emit.sh
shell helper, README, LICENSE, release metadata, internal checksums, and an
archive checksum sidecar.

Before anything is written the binary is checked against what the metadata
will say about it: a binary for this host is run (`premier build-info`) and
must report the version, the target, and an embedded viewer; a binary for
another host must at least be an executable of the target's format.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET="${2:?missing target}"; shift 2 ;;
    --version) VERSION="${2:?missing version}"; shift 2 ;;
    --binary) BINARY="${2:?missing binary}"; shift 2 ;;
    --output-dir) OUTPUT_DIR="${2:?missing output directory}"; shift 2 ;;
    --skip-viewer) SKIP_VIEWER=1; shift ;;
    --expect-sigstore) EXPECT_SIGSTORE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done

TARGET="${TARGET:-$(distribution_host_target || true)}"
[[ -n "$TARGET" ]] || { echo "unsupported host; pass --target" >&2; exit 1; }
case "$TARGET" in
  x86_64-apple-darwin|aarch64-apple-darwin|x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu) ;;
  *) echo "unsupported release target: $TARGET" >&2; exit 1 ;;
esac

if [[ -z "$VERSION" ]]; then
  VERSION="$(awk -F' *= *' '/^version = / { gsub(/\"/, "", $2); print $2; exit }' "$ROOT/Cargo.toml")"
fi
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] || {
  echo "invalid release version: $VERSION" >&2
  exit 1
}

if [[ -z "$BINARY" ]]; then
  command -v cargo >/dev/null 2>&1 || { echo "cargo is required for a source build" >&2; exit 1; }
  if [[ "$SKIP_VIEWER" -eq 0 ]]; then
    command -v npm >/dev/null 2>&1 || { echo "npm is required to build the embedded viewer" >&2; exit 1; }
    (cd "$ROOT" && [[ -d node_modules ]] || npm install)
    (cd "$ROOT" && npm run build)
  elif [[ ! -f "$ROOT/apps/viewer/dist/index.html" ]]; then
    echo "apps/viewer/dist/index.html is missing; omit --skip-viewer" >&2
    exit 1
  fi
  # PREMIER_REQUIRE_VIEWER makes the build fail rather than embed the
  # placeholder page (crates/premier-cli/build.rs).
  (cd "$ROOT" && PREMIER_REQUIRE_VIEWER=1 cargo build --release --locked --target "$TARGET" -p premier-cli)
  BINARY="$ROOT/target/$TARGET/release/premier"
fi

[[ -f "$BINARY" && -x "$BINARY" ]] || { echo "binary is not an executable file: $BINARY" >&2; exit 1; }
[[ -f "$ROOT/README.md" ]] || { echo "README.md is missing" >&2; exit 1; }
[[ -f "$ROOT/LICENSE" ]] || { echo "LICENSE is missing" >&2; exit 1; }
HELPER_SOURCE="$ROOT/sdk/shell/premier-emit.sh"
[[ -f "$HELPER_SOURCE" ]] || { echo "sdk/shell/premier-emit.sh is missing" >&2; exit 1; }

# Check the binary before describing it. RELEASE-METADATA is signed along with
# the archive, so every line of it has to be something that was observed.
VIEWER="unverified"
if [[ "$TARGET" == "$(distribution_host_target || true)" ]]; then
  BUILD_INFO="$("$BINARY" build-info 2>/dev/null)" || {
    echo "binary does not answer \`premier build-info\`: $BINARY" >&2
    exit 1
  }
  info() { printf '%s\n' "$BUILD_INFO" | awk -F= -v key="$1" '$1 == key { print $2; exit }'; }
  [[ "$(info version)" == "$VERSION" ]] || {
    echo "binary reports version $(info version), not the release version $VERSION" >&2
    exit 1
  }
  [[ "$(info target)" == "$TARGET" ]] || {
    echo "binary was built for $(info target), not $TARGET" >&2
    exit 1
  }
  [[ "$(info viewer)" == "embedded" ]] || {
    echo "binary embeds the placeholder page instead of the viewer; run \`npm run build\` and rebuild" >&2
    exit 1
  }
  VIEWER="embedded"
else
  FORMAT="$(distribution_binary_format "$BINARY")"
  [[ "$TARGET" == "$FORMAT"* ]] || {
    echo "binary is not a $TARGET executable (header says: $FORMAT)" >&2
    exit 1
  }
  echo "note: $TARGET cannot run on this host; version and embedded viewer were not checked" >&2
fi
GLIBC_MIN=""
if [[ "$TARGET" == *-linux-gnu ]]; then
  GLIBC_MIN="$(distribution_glibc_requirement "$BINARY")"
  # A real Linux executable always names the glibc symbols it needs; the
  # launcher relies on this to refuse a system that is too old.
  if [[ -z "$GLIBC_MIN" && "$(distribution_binary_format "$BINARY")" == *-unknown-linux ]]; then
    echo "could not read the glibc version $BINARY requires (is objdump installed?)" >&2
    exit 1
  fi
  # glibc versions have two or three parts; compare them as three.
  three_part() { case "$1" in *.*.*) printf '%s\n' "$1" ;; *) printf '%s.0\n' "$1" ;; esac; }
  if [[ -n "$GLIBC_MIN" && "$(distribution_version_compare "$(three_part "$GLIBC_MIN")" "$(three_part "$DISTRIBUTION_GLIBC_CEILING")")" == gt ]]; then
    echo "binary requires glibc $GLIBC_MIN, newer than the documented ceiling $DISTRIBUTION_GLIBC_CEILING" >&2
    exit 1
  fi
fi

NAME="premier-$VERSION-$TARGET"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/premier-release.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
PACKAGE="$WORK/$NAME"
mkdir -p "$PACKAGE/bin" "$PACKAGE/share/premier" "$OUTPUT_DIR"
install -m 0755 "$BINARY" "$PACKAGE/bin/premier"
install -m 0755 "$HELPER_SOURCE" "$PACKAGE/share/premier/premier-emit.sh"
install -m 0644 "$ROOT/README.md" "$PACKAGE/README.md"
install -m 0644 "$ROOT/LICENSE" "$PACKAGE/LICENSE"
SIGNATURE="none"
[[ "$EXPECT_SIGSTORE" -eq 1 ]] && SIGNATURE="sigstore-keyless"
cat >"$PACKAGE/RELEASE-METADATA" <<EOF
NAME=premier
VERSION=$VERSION
TARGET=$TARGET
VIEWER=$VIEWER
SIGNATURE=$SIGNATURE
EOF
[[ -z "$GLIBC_MIN" ]] || printf 'GLIBC_MIN=%s\n' "$GLIBC_MIN" >>"$PACKAGE/RELEASE-METADATA"

(
  cd "$PACKAGE"
  for path in LICENSE README.md RELEASE-METADATA bin/premier share/premier/premier-emit.sh; do
    printf '%s  %s\n' "$(distribution_sha256 "$path")" "$path"
  done >SHA256SUMS
)

ARCHIVE="$OUTPUT_DIR/$NAME.tar.gz"
python3 - "$PACKAGE" "$ARCHIVE" <<'PY'
import gzip
import pathlib
import tarfile
import sys

source = pathlib.Path(sys.argv[1])
archive_path = pathlib.Path(sys.argv[2])
paths = [source, *sorted(source.rglob("*"), key=lambda path: path.as_posix())]
with open(archive_path, "wb") as raw:
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for path in paths:
                relative = pathlib.Path(source.name) / path.relative_to(source)
                info = archive.gettarinfo(str(path), arcname=relative.as_posix())
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mtime = 0
                executable = relative.as_posix().endswith(("/bin/premier", "/share/premier/premier-emit.sh"))
                info.mode = 0o755 if path.is_dir() or executable else 0o644
                if path.is_file():
                    with open(path, "rb") as payload:
                        archive.addfile(info, payload)
                else:
                    archive.addfile(info)
PY

ARCHIVE_HASH="$(distribution_sha256 "$ARCHIVE")"
printf '%s  %s\n' "$ARCHIVE_HASH" "$(basename "$ARCHIVE")" >"$ARCHIVE.sha256"
echo "packaged $ARCHIVE"
echo "checksum $ARCHIVE_HASH"
