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

# Host of the collector URL: scheme, path, credentials, and port removed.
HOST="${PREMIER_COLLECTOR_URL#*://}"
HOST="${HOST%%[/?#]*}"
HOST="${HOST##*@}"
if [[ "$HOST" == \[* ]]; then
  HOST="${HOST#\[}"
  HOST="${HOST%%\]*}"
else
  HOST="${HOST%%:*}"
fi
HOST="${HOST%.}"

# A loopback collector (localhost, 127.0.0.0/8, ::1) is authenticated only by
# its bearer token, so --noproxy keeps the token and payload away from
# HTTP(S)_PROXY/ALL_PROXY. A remote collector keeps the proxy settings: a
# mandatory egress proxy may be the only route to it.
NOPROXY=()
shopt -s nocasematch
if [[ "$HOST" == localhost || "$HOST" == *.localhost ||
  "$HOST" =~ ^127([.][0-9]+){1,3}$ || "$HOST" =~ ^(0*:){2,7}0*1$ ]]; then
  NOPROXY=(--noproxy '*')
fi
shopt -u nocasematch

# The status code is appended on its own line so a rejected event (401/400/500)
# fails this script instead of printing the error body and exiting 0.
# (The `+` expansion keeps an empty array valid under `set -u` on bash 3.2.)
if ! OUTPUT="$(curl -sS ${NOPROXY[@]+"${NOPROXY[@]}"} --max-time "$TIMEOUT" \
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
