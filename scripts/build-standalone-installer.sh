#!/usr/bin/env bash
# Write a single-file installer: scripts/install.sh with scripts/lib/distribution.sh
# inlined, so a signed archive can be installed without a source checkout.
# The release workflow publishes it as the signed asset premier-install.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT="${1:-$ROOT/dist/premier-install.sh}"
INSTALLER="$ROOT/scripts/install.sh"
LIBRARY="$ROOT/scripts/lib/distribution.sh"
# shellcheck disable=SC2016 # the literal line of install.sh that is replaced
SOURCE_LINE='source "$ROOT/scripts/lib/distribution.sh"'

[[ "$(grep -cFx "$SOURCE_LINE" "$INSTALLER")" -eq 1 ]] || {
  echo "scripts/install.sh no longer sources the library on one line of its own" >&2
  exit 1
}
mkdir -p "$(dirname "$OUTPUT")"
{
  while IFS= read -r line; do
    if [[ "$line" == "$SOURCE_LINE" ]]; then
      echo "# --- scripts/lib/distribution.sh, inlined ---"
      # The library's own shebang is dropped.
      sed '1{/^#!/d;}' "$LIBRARY"
      echo "# --- end of scripts/lib/distribution.sh ---"
    else
      printf '%s\n' "$line"
    fi
  done <"$INSTALLER"
} >"$OUTPUT"
chmod 0755 "$OUTPUT"
bash -n "$OUTPUT"
echo "wrote $OUTPUT"
