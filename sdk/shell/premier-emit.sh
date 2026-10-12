#!/usr/bin/env bash
# Emit a Premier agent event to the active local collector.
# Prefer `premier emit` when the binary is on PATH; this script is a pure-shell fallback.
# Exits non-zero when the collector is unreachable, slow, or rejects the event.
set -euo pipefail

if [[ -z "${PREMIER_COLLECTOR_URL:-}" || -z "${PREMIER_COLLECTOR_TOKEN:-}" ]]; then
  echo "Premier collector is not active. Run under: premier record -- <command>" >&2
  exit 1
fi

if command -v premier >/dev/null 2>&1; then
  if [[ $# -eq 0 || "$1" == "-" ]]; then
    exec premier emit --json -
  fi
  # If first arg looks like JSON, pass through; otherwise forward flags.
  if [[ "$1" == \{* ]]; then
    exec premier emit --json "$1"
  fi
  exec premier emit "$@"
fi

if [[ $# -eq 0 || "$1" == "-" ]]; then
  BODY="$(cat)"
elif [[ "$1" == \{* ]]; then
  BODY="$1"
else
  echo "usage: premier-emit.sh '{\"kind\":\"agent.spawn\",...}'" >&2
  echo "   or: echo '{...}' | premier-emit.sh -" >&2
  echo "   or: install premier and use: premier emit --kind ..." >&2
  exit 1
fi

# Seconds to wait for the collector (PREMIER_EMIT_TIMEOUT, default 10).
TIMEOUT="${PREMIER_EMIT_TIMEOUT:-10}"
[[ "$TIMEOUT" =~ ^[0-9]+([.][0-9]+)?$ ]] || TIMEOUT=10

# The status code is appended on its own line so a rejected event (401/400/500)
# fails this script instead of printing the error body and exiting 0.
# --noproxy keeps the bearer token and payload away from HTTP(S)_PROXY/ALL_PROXY.
if ! OUTPUT="$(curl -sS --noproxy '*' --max-time "$TIMEOUT" \
  -w '\n%{http_code}' \
  -X POST "$PREMIER_COLLECTOR_URL" \
  -H "Authorization: Bearer $PREMIER_COLLECTOR_TOKEN" \
  -H "Content-Type: application/json" \
  --data-raw "$BODY")"; then
  echo "premier-emit: failed to POST event to the Premier collector" >&2
  exit 1
fi
STATUS="${OUTPUT##*$'\n'}"
RESPONSE="${OUTPUT%$'\n'*}"
if [[ "$STATUS" != 2[0-9][0-9] ]]; then
  echo "premier-emit: collector rejected event ($STATUS): $RESPONSE" >&2
  exit 1
fi
printf '%s\n' "$RESPONSE"
