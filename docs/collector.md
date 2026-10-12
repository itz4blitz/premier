# The local collector

`premier record` runs a small HTTP server for the duration of a recording.
Any process started under the recorder can POST typed events to it, in any
language. The JavaScript SDK, `premier emit`, and the shell helper are thin
clients of this one endpoint.

The event vocabulary is described in [events.md](events.md).

## Environment

`premier record` adds three variables to the recorded command's environment.
Child processes inherit them in the usual way.

| Variable | Value |
| --- | --- |
| `PREMIER_COLLECTOR_URL` | `http://127.0.0.1:<port>/v1/events`. The port is chosen by the OS for each recording. |
| `PREMIER_COLLECTOR_TOKEN` | A bearer token generated for this recording. |
| `PREMIER_TRACE_ID` | The id of the trace being recorded. |

If `PREMIER_COLLECTOR_URL` and `PREMIER_COLLECTOR_TOKEN` are not set, the
process is not being recorded and there is nothing to send to.

## Endpoint

```text
POST /v1/events
Authorization: Bearer <PREMIER_COLLECTOR_TOKEN>
Content-Type: application/json

<one JSON event>
```

One request carries one event. There is no batch form.

```sh
curl -sS -X POST "$PREMIER_COLLECTOR_URL" \
  -H "Authorization: Bearer $PREMIER_COLLECTOR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "kind": "tool.execution",
    "actor_id": "coder",
    "actor_type": "agent",
    "status": "ok",
    "span_id": "apply-patch",
    "parent_span_id": "implementation",
    "duration_ms": 176,
    "payload": {"tool": "apply_patch", "files_changed": 1}
  }'
```

`GET /health` on the same port answers `{"service":"premier-collector","status":"ok"}`
without authentication.

## Authentication

The `Authorization` header must be `Bearer ` followed by the exact token. The
comparison is constant-time. A missing or wrong token is rejected with `401`
before the body is read.

The collector listens on `127.0.0.1` only, and the token is the only
credential. Any local process that learns the port and token can append events
to the trace while it is being recorded. See [security.md](security.md#the-collector).

## Request body

A JSON object. Unknown fields are ignored.

| Field | Type | Required | Default | Notes |
| --- | --- | --- | --- | --- |
| `kind` | string | yes | | Must not be blank. Some kinds are reserved; see below. |
| `source` | string | no | `"sdk"` | A label for the producer. Some sources are reserved. |
| `actor_id` | string | no | `""` | Who did it. Empty is shown as `root`. |
| `actor_type` | string | no | `""` | `agent`, `subagent`, `human`, `process`, or `system`. |
| `status` | string | no | `""` | See [events.md](events.md#statuses). |
| `span_id` | string | no | `""` | |
| `parent_span_id` | string | no | `""` | |
| `parent_event_id` | string | no | `""` | The `event_id` of an earlier event. |
| `correlation_id` | string | no | `""` | |
| `links` | array of strings | no | `[]` | Event ids or span ids. |
| `duration_ms` | unsigned integer | no | `0` | A fractional or negative number is rejected with `400`. |
| `payload` | any JSON value | no | `null` | Should be an object. |
| `timestamp` | string or null | no | receipt time | RFC 3339. Stored verbatim when given and not blank; the collector does not parse or validate it. |

The recorder assigns `event_id`, `trace_id`, and `sequence`. A client cannot
set them.

Two things are accepted but flagged later. For the kinds listed under
[lifecycle validation](events.md#lifecycle-validation), an event with no
`status`, or with a `payload` that is not a JSON object, produces a diagnostic
when the trace is finalized. Send `"payload": {}` rather than omitting it.

The redaction rules of the recording are applied to `payload` before the event
is stored; see [redaction.md](redaction.md).

## Response

`200` with the stored event as JSON:

```json
{
  "event_id": "01a13085-0ad7-7370-b9cc-2c65d8e04137",
  "trace_id": "01a13085-0a02-7830-add6-0eae8a599cc9",
  "sequence": 5,
  "timestamp": "2026-10-12T14:29:47.863118+00:00",
  "kind": "agent.spawn",
  "source": "sdk",
  "payload_json": "{\"task\":\"t\"}",
  "actor_id": "researcher",
  "actor_type": "subagent",
  "parent_event_id": "",
  "span_id": "research",
  "parent_span_id": "",
  "correlation_id": "",
  "status": "running",
  "duration_ms": 0,
  "links": []
}
```

`payload_json` is the payload as stored, serialized to a string, after
redaction. Keep `event_id` if later events should name this one as their
parent.

Errors have the body `{"error": "<message>"}`.

## Status codes

| Status | When |
| --- | --- |
| `200` | The event was stored. |
| `400` | The body is not valid JSON, `kind` is missing, a field has the wrong type, or the body is larger than the size limit. |
| `401` | The bearer token is missing or wrong. |
| `405` | Any method other than `POST` on `/v1/events`. |
| `422` | The event claims a kind or source that only the recorder may write. |
| `500` | The event could not be stored: `kind` is blank, or the journal write failed. |

### Size limit

The request body may be at most 2 MiB (2,097,152 bytes). A larger body is
rejected with **`400`** and `{"error":"length limit exceeded"}`. The collector
does not use `413`.

### Reserved kinds and sources

The recorded process holds the collector token, so the collector refuses
events that would let it forge what only the recorder can observe: its own
exit status, its terminal output, or adapter-normalized provider events.

Rejected with `422`, compared case-insensitively after trimming whitespace:

| | Reserved values |
| --- | --- |
| `kind` | `session.start`, `session.interrupted`, and anything starting with `process.` (`process.exit`, `process.stdout`, `process.stderr`, `process.terminal`, `process.spawn_failed`, ...) |
| `source` | `premier`, `command`, `process`, `recorder`, `premier-recovery`, and anything starting with `adapter.` |

```text
$ curl -sS -X POST "$PREMIER_COLLECTOR_URL" \
    -H "Authorization: Bearer $PREMIER_COLLECTOR_TOKEN" -H "Content-Type: application/json" \
    -d '{"kind":"process.exit","payload":{"exit_code":0}}'
{"error":"event kind `process.exit` is recorded by Premier itself and cannot be emitted through the collector"}
```

Every other kind and source is accepted, including kinds Premier has never
heard of.

## Lifetime

- The collector starts before the recorded command and is reachable for as
  long as the recorder is capturing.
- It stops when the recorder finalizes the trace: after the recorded command
  has exited and its output has been drained. Requests already in flight
  complete.
- After that the port is closed. A late event from a process that outlived the
  recorded command gets a connection error and is lost. Nothing is queued or
  retried by the collector, and the port and token are not reused.
- An event that arrives after the command has exited but before the collector
  stops is stored after `process.exit`.
- Events are stored in arrival order. `sequence` is that order.

If a harness detaches background workers, have the recorded command wait for
them before it exits.

## `premier emit`

`premier emit` posts one event using the environment above.

```sh
premier emit --kind agent.spawn --actor researcher --actor-type subagent \
  --status running --span research --payload '{"task":"find the first divergence"}'

premier emit --json '{"kind":"agent.message","actor_id":"researcher","status":"ok","payload":{"to":["coder"]}}'

jq -n '{kind:"tool.execution",actor_id:"coder",status:"ok",payload:{tool:"rg"}}' | premier emit --json -
```

- Flag form: `--kind` is required. `--actor-type` defaults to `agent` and
  `--source` to `premier-emit`. `--payload` must be valid JSON. If `--status`
  or `--payload` is omitted the field is not sent, which triggers the
  diagnostics described above for the validated kinds.
- `--json` sends the given body unchanged; the other flags are ignored. The
  collector's default `source` (`sdk`) applies if the body has none.
- On success it prints the new `event_id` and exits `0`.
- It exits `1` when the collector variables are not set, the collector cannot
  be reached, it does not answer within `PREMIER_EMIT_TIMEOUT` seconds
  (default `10`), or it rejects the event. Decide in your harness whether that
  should fail the step: `premier emit ... || true` keeps telemetry optional.
- When the collector URL is loopback, `HTTP_PROXY`, `HTTPS_PROXY`, and
  `ALL_PROXY` are ignored.

The full flag list is in [cli.md](cli.md#emit).

## `sdk/shell/premier-emit.sh`

A bash fallback for environments where the `premier` binary may not be on
`PATH` inside the recorded process.

```sh
sdk/shell/premier-emit.sh '{"kind":"agent.spawn","actor_id":"researcher","status":"running","payload":{}}'
echo '{"kind":"agent.result","actor_id":"researcher","status":"ok","payload":{}}' | sdk/shell/premier-emit.sh -
```

- If `premier` is on `PATH`, the script runs `premier emit`: a first argument
  starting with `{` is passed as `--json`, no argument or `-` reads JSON from
  stdin, and anything else is passed through as `premier emit` flags.
- Otherwise it uses `curl` and accepts only a JSON body, as the first argument
  or on stdin. Flags are not supported in this mode.
- In `curl` mode it prints the collector's response body on success.

Failure behaviour, in both modes:

| Situation | Result |
| --- | --- |
| Collector variables not set | Message on stderr, exit `1` |
| Collector unreachable, or no answer within `PREMIER_EMIT_TIMEOUT` seconds (default `10`) | Message on stderr, exit `1` |
| Collector answers with a non-2xx status | `premier-emit: collector rejected event (<status>): <body>` on stderr, exit `1` |

For a loopback collector URL the script passes `--noproxy '*'` to `curl`, so
the token is not sent through a proxy configured in the environment.

## JavaScript

`@premierstudio/trace` wraps this endpoint with typed helpers, a timeout, and
non-throwing delivery. See [sdk/js/README.md](../sdk/js/README.md).
