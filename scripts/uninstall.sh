#!/usr/bin/env bash
# Remove what scripts/install.sh put under an explicit install prefix: the
# Premier executable, the binary kept by the last update, and the shell helper.
# Recorded traces and copies installed another way are never touched.
set -euo pipefail

PREFIX="${CARGO_HOME:-$HOME/.cargo}"
DRY_RUN=0
usage() { echo "Usage: ./scripts/uninstall.sh [--prefix PATH] [--dry-run]"; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix) PREFIX="${2:?missing prefix}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done
PREFIX="${PREFIX%/}"
[[ -n "$PREFIX" && "$PREFIX" == /* ]] || { echo "refusing unsafe prefix: give an absolute path other than /" >&2; exit 1; }
DESTINATION="$PREFIX/bin/premier"

# What is left behind is the same whether or not anything was removed here.
leftovers() {
  cat <<'EOF'
Not removed:
  - recorded traces: every .premier/traces directory under the projects you
    recorded in, and any path given to `premier record --output`. They are
    your evidence; delete them yourself when you no longer need them.
  - key files you created with `premier keygen`.
  - copies installed another way: `npm uninstall --global @premierstudio/premier`
    (or without --global in a project), `cargo uninstall premier-cli`.
EOF
}

if [[ ! -e "$DESTINATION" && ! -L "$DESTINATION" ]]; then
  echo "Premier is not installed at $DESTINATION"
  leftovers
  exit 0
fi
if [[ ! -f "$DESTINATION" && ! -L "$DESTINATION" ]]; then
  echo "refusing to remove non-file path: $DESTINATION" >&2
  exit 1
fi
EXTRAS=()
for extra in "$PREFIX/bin/premier.previous" "$PREFIX/share/premier/premier-emit.sh"; do
  if [[ -f "$extra" || -L "$extra" ]]; then EXTRAS+=("$extra"); fi
done
# (The `+` expansion keeps an empty array valid under `set -u` on bash 3.2.)
for path in "$DESTINATION" ${EXTRAS[@]+"${EXTRAS[@]}"}; do
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "would remove $path"
  else
    rm -- "$path"
    echo "removed $path"
  fi
done
if [[ "$DRY_RUN" -eq 0 && -d "$PREFIX/share/premier" ]]; then
  rmdir "$PREFIX/share/premier" 2>/dev/null || true
fi
leftovers
