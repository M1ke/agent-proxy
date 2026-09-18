# agent-proxy

A local recording proxy that captures a browsing session in a form an agent can
read — so that automating a web task starts from a transcript of someone doing
it once, rather than from guesswork.

Single Go binary, no dependencies outside the standard library.

```
make build
./agent-proxy record --name checkout-flow
```

Or grab a prebuilt binary for macOS or Linux (arm64 and amd64) from the
[latest release](https://github.com/M1ke/agent-proxy/releases/latest):

```
tar -xzf agent-proxy-<version>-darwin-arm64.tar.gz
./agent-proxy record --name checkout-flow
```

On macOS the binary is unsigned, so the first run needs
`xattr -d com.apple.quarantine agent-proxy`.

It prints the listen address, the CA certificate path and the Firefox setup
steps, then a line per recorded exchange:

```
[+   1.7s] GET    app.example.com/login -> 200 (73ms)
[+   4.2s] NOTE   about to sign in
[+   4.9s] POST   app.example.com/api/login -> 200 (191ms) [3 redacted]
[+   5.1s] GET    app.example.com/api/me -> 200 (44ms)
```

## What gets recorded

The point is a transcript short enough to read, so most traffic is discarded:
CORS preflights, subresources the browser fetched to render a page, static
assets, analytics, error reporting, ads, support widgets, public CDNs, and
first-party telemetry at well-known paths.

An app's own custom telemetry — a `/api/track`, say — is deliberately not
guessed at, because any rule general enough to catch it would eventually eat a
real endpoint. It stays in the recording; annotate it as noise, or add the path
to `drop_paths`.

Of what remains, only headers that affect auth, routing or content negotiation
are kept — cookies, `authorization`, `apikey`, `content-type`, `referer`,
`origin` and `x-*` headers. Query strings and JSON, form and multipart bodies
are parsed and kept. HTML responses keep only their `<title>`, as a landmark.
Uploaded file contents are reduced to name, type and size.

## Redaction

Per-user credentials are removed; app-level identifiers are kept, because an
automation cannot replay the flow without them.

Removed: values under secret-looking keys in JSON, form and query data
(`password`, `access_token`, `refresh_token`, `client_secret`, `otp`, card
fields), cookie values (names and attributes survive: `sid=<REDACTED:34>;
theme=dark`), `authorization` values keeping the scheme (`Bearer
<REDACTED:212>`), and tokens embedded in URL-ish strings.

Kept, deliberately: `apikey` / `api_key` / `X-Api-Key`, `client_id`,
`anon_key`, `publishable_key` and `grant_type`.

Each removal is listed in that record's `redacted` array — which tells an agent
exactly which values a generated automation must take from the environment
rather than hardcode. If a rule fires on something it shouldn't, `allow_keys`
exempts it.

## Annotating

While recording, the proxy answers on a hostname it never forwards:

| | |
| --- | --- |
| `http://proxy.note/` | a box to type what you just did |
| `http://proxy.note/signed%20in` | shorthand for the same thing |
| `http://proxy.note/status` | counts so far, as JSON |
| `http://proxy.note/stop` | finish the recording |
| `http://proxy.note/ca.crt` | download the CA certificate |

If the browser will not accept the made-up hostname, the listener's own address
(`http://127.0.0.1:8080/`) serves the same UI.

Notes are what make a recording legible — they bracket a wall of requests into
steps. One before and after each meaningful action is about right.

## Output

`recordings/<timestamp>-<name>/session.jsonl`, one object per line, `type`
being one of `session_start`, `request`, `note`, `websocket`, `session_end`.

```json
{"type":"request","seq":12,"t":"2026-09-17T21:03:11.412Z","offset_ms":48213,
 "gap_ms":3104,"duration_ms":312,"method":"POST",
 "url":"https://app.example.com/api/login","host":"app.example.com","path":"/api/login",
 "query":{"redirect":"/dash"},
 "req_headers":{"content-type":"application/json","cookie":"csrftoken=<REDACTED:64>"},
 "req_body":{"kind":"json","data":{"email":"a@b.com","password":"<REDACTED>"},"bytes":48},
 "status":200,
 "resp_headers":{"set-cookie":"sid=<REDACTED:32>; HttpOnly; Secure"},
 "resp_body":{"kind":"json","data":{"ok":true,"user_id":91},"bytes":24},
 "redacted":["req.body.password","resp.header.set-cookie.sid"]}
```

Each record carries three timings: `t` (wall clock), `offset_ms` (position in
the session) and `gap_ms` (time since the previous record), which is the one
that shows how long a step took to become available.

## Flags

```
agent-proxy record
  --port 8080          port to listen on
  --host 127.0.0.1     address to listen on
  --dir recordings     where to write sessions
  --name NAME          appended to the session directory
  --filters PATH       filter override file (default ~/.agent-proxy/filters.json)
  --no-filter          record everything, for debugging
  --quiet              no live console summary

agent-proxy ca [--export PATH]
```

## Tuning the filter

`~/.agent-proxy/filters.json`, merged over the built-in rules. `keep_hosts`
overrides every drop rule, including the `OPTIONS` and subresource ones.

```json
{
  "drop_hosts": ["telemetry.internal.example.com"],
  "keep_hosts": ["cdn.example.com"],
  "drop_paths": ["/api/metrics", "/internal/telemetry*"],
  "drop_extensions": [".tiff"],
  "redact_keys": ["customer_reference"],
  "allow_keys": ["secret_menu"]
}
```

`redact_keys` adds terms; `allow_keys` exempts an exact field name whose
built-in match is a false positive.

A `drop_paths` entry matches the path exactly or as a parent segment, so
`/api/metrics` covers `/api/metrics/batch` but not `/api/metrics-report`. End it
with `*` for raw prefix matching.

Whatever the filter did, `session_end` reports the counts by reason, so nothing
disappears silently.

## TLS

On first run the binary generates a CA into `~/.agent-proxy/` and mints
certificates per host as it goes.

Import the CA into a **separate Firefox profile** (`firefox -P`, or
`about:profiles`). It has to be trusted for interception to work, and it should
not be trusted in everyday browsing.

WebSocket upgrades are passed straight through; the session notes that a socket
was opened but does not record its frames.

## The agent skill

`skills/web-recorder/SKILL.md` teaches an agent to drive all of this: start the
proxy, relay the setup, wait, stop, and read the transcript. Install it with

```
ln -s "$PWD/skills/web-recorder" ~/.claude/skills/web-recorder
```

## Development

```
make test    # unit tests plus an end-to-end test through a real CONNECT tunnel
make vet
make dist    # darwin and linux, arm64 and amd64
```

## Releases

```
bin/release 0.2.0
```

That bumps the version in `main.go`, commits, tags `v0.2.0` and pushes. The tag
triggers the GitHub Actions workflow, which runs the tests, cross-compiles the
four targets and attaches them to the release with checksums. It refuses to run
on a dirty tree, off `main`, out of sync with `origin/main`, or if the tag is
already taken.
