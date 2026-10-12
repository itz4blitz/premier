#!/usr/bin/env bash
# Exercise the pure-shell curl fallback of sdk/shell/premier-emit.sh against
# loopback stub collectors. Writes only inside a mktemp directory.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EMIT="$ROOT/sdk/shell/premier-emit.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/premier-emit.XXXXXX")"
PIDS=()
cleanup() {
  if [[ ${#PIDS[@]} -gt 0 ]]; then kill "${PIDS[@]}" 2>/dev/null || true; fi
  rm -rf "$WORK"
}
trap cleanup EXIT

fail() {
  echo "premier-emit test failed: $*" >&2
  exit 1
}

# The fallback only runs when `premier` is not on PATH, so resolve the tools it
# needs into a private bin directory and use that as the whole PATH.
BIN="$WORK/bin"
mkdir -p "$BIN"
for tool in bash cat curl; do
  ln -s "$(command -v "$tool")" "$BIN/$tool"
done
PYTHON="$(command -v python3)" || fail "python3 is required for the stub collector"

cat >"$WORK/stub.py" <<'PY'
import http.server
import sys
import time

mode, port_file, log_file = sys.argv[1:]


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode()
        with open(log_file, "a") as log:
            log.write(f"{self.path} {self.headers.get('Authorization', '')} {body}\n")
        if mode == "hang":
            time.sleep(30)
            return
        status, reply = {
            "ok": (200, '{"event_id":"evt-1"}'),
            "unauthorized": (401, '{"error":"invalid collector token"}'),
            "error": (500, '{"error":"event kind cannot be empty"}'),
        }[mode]
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(reply)))
        self.end_headers()
        self.wfile.write(reply.encode())

    def log_message(self, *args):
        pass


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
with open(port_file, "w") as handle:
    handle.write(str(server.server_address[1]))
server.serve_forever()
PY

# start_stub NAME MODE -> sets STUB_PORT; requests are logged to $WORK/NAME.log
start_stub() {
  local name="$1" mode="$2"
  : >"$WORK/$name.log"
  "$PYTHON" "$WORK/stub.py" "$mode" "$WORK/$name.port" "$WORK/$name.log" &
  PIDS+=("$!")
  for _ in $(seq 1 100); do
    [[ -s "$WORK/$name.port" ]] && break
    sleep 0.05
  done
  [[ -s "$WORK/$name.port" ]] || fail "stub collector $name did not start"
  STUB_PORT="$(cat "$WORK/$name.port")"
}

# run_emit PORT [ENV=VALUE...] -> sets EMIT_STATUS, stdout in $WORK/out, stderr in $WORK/err
run_emit() {
  local port="$1"
  shift
  EMIT_STATUS=0
  env -i PATH="$BIN" \
    PREMIER_COLLECTOR_URL="http://127.0.0.1:$port/v1/events" \
    PREMIER_COLLECTOR_TOKEN=secret-token \
    "$@" \
    "$BIN/bash" "$EMIT" '{"kind":"agent.spawn"}' >"$WORK/out" 2>"$WORK/err" || EMIT_STATUS=$?
}

start_stub ok ok
OK_PORT="$STUB_PORT"
run_emit "$OK_PORT"
[[ "$EMIT_STATUS" -eq 0 ]] || fail "accepted event exited $EMIT_STATUS: $(cat "$WORK/err")"
grep -q 'evt-1' "$WORK/out" || fail "accepted event did not print the collector reply"
grep -q 'Bearer secret-token {"kind":"agent.spawn"}' "$WORK/ok.log" || fail "collector did not receive the event"

start_stub unauthorized unauthorized
run_emit "$STUB_PORT"
[[ "$EMIT_STATUS" -ne 0 ]] || fail "a 401 from the collector exited 0"
grep -q 'invalid collector token' "$WORK/err" || fail "401 response body was not printed to stderr"
[[ ! -s "$WORK/out" ]] || fail "401 response body was printed to stdout"

start_stub error error
run_emit "$STUB_PORT"
[[ "$EMIT_STATUS" -ne 0 ]] || fail "a 500 from the collector exited 0"
grep -q 'event kind cannot be empty' "$WORK/err" || fail "500 response body was not printed to stderr"

# A configured proxy must never see the loopback collector's token or payload.
start_stub proxy ok
: >"$WORK/ok.log"
run_emit "$OK_PORT" \
  "http_proxy=http://127.0.0.1:$STUB_PORT" "HTTP_PROXY=http://127.0.0.1:$STUB_PORT" \
  "all_proxy=http://127.0.0.1:$STUB_PORT" "ALL_PROXY=http://127.0.0.1:$STUB_PORT"
[[ ! -s "$WORK/proxy.log" ]] || fail "event was sent through the proxy: $(cat "$WORK/proxy.log")"
[[ "$EMIT_STATUS" -eq 0 ]] || fail "emit with a proxy configured exited $EMIT_STATUS: $(cat "$WORK/err")"
[[ -s "$WORK/ok.log" ]] || fail "collector did not receive the event when a proxy was configured"

# A collector that never answers must not hang the caller.
start_stub hang hang
STARTED="$(date +%s)"
run_emit "$STUB_PORT" PREMIER_EMIT_TIMEOUT=1
ELAPSED=$(($(date +%s) - STARTED))
[[ "$EMIT_STATUS" -ne 0 ]] || fail "an unanswered request exited 0"
[[ "$ELAPSED" -lt 10 ]] || fail "an unanswered request took ${ELAPSED}s"

echo "premier-emit shell tests passed"
