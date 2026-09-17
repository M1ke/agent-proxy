---
name: web-recorder
description: Record a human performing a task in a browser through a local recording proxy, producing a filtered, secret-redacted transcript of the HTTP flow. Use when the user wants to automate a website workflow, capture how a site's login or form submission works, reverse-engineer an undocumented web API by watching it, or says something like "record what I do in the browser".
---

# Recording a browser session

`agent-proxy` is a local MITM proxy that records a browsing session as JSONL. It
drops the noise (static assets, analytics, ads, CORS preflights), keeps only the
headers that matter for auth and content negotiation, and replaces
credential-shaped values with `<REDACTED>` while recording where each one was.

The user drives the browser; you set the recording up, tell them what to do, and
read the result.

## 1. Start the proxy

Build it if the binary is missing:

```
make build
```

Start a recording in the background, naming the session after the task:

```
./agent-proxy record --name checkout-flow
```

It prints the listen address, CA path, transcript path and the Firefox setup
steps, then one line per recorded exchange as it happens.

## 2. Relay the setup to the user

Pass on the setup block the binary printed, verbatim — it contains the real
paths and port. Two things to emphasise:

- **Use a separate Firefox profile** (`firefox -P`, or `about:profiles`). The CA
  must be trusted for interception to work, and it should not be trusted in
  their everyday browsing.
- Tell them to **annotate as they go** by visiting `http://proxy.note/` and
  typing what they just did, or using the shorthand
  `http://proxy.note/signed%20in`. Notes are what turn a wall of requests into
  legible steps — ask for one before and after each meaningful action. They can
  also dismiss traffic: a note like "the /api/track calls are just analytics"
  is how the user tells you to ignore first-party telemetry the filter cannot
  safely guess at.

Then wait. Do not poll the transcript or guess at progress; let the user say
when they are done.

## 3. Stop

The user can visit `http://proxy.note/stop`, or you can fetch that URL. Either
writes the `session_end` record and shuts the proxy down cleanly. Ctrl-C works
too.

## 4. Read the transcript

`recordings/<timestamp>-<name>/session.jsonl`, one JSON object per line:

| `type` | what it is |
| --- | --- |
| `session_start` | version, listen address, filter mode |
| `request` | one recorded exchange |
| `note` | something the user typed at `proxy.note` |
| `websocket` | a socket was opened; its frames are not recorded |
| `session_end` | totals, plus what was filtered out and why |

Read notes and requests together in `seq` order: the notes bracket the requests
into steps, and a note may also declare some requests noise — honour that and
leave them out of any automation you build. Useful fields on a `request`:

- `gap_ms` — time since the previous record. This is what tells you how long a
  step actually took to become available, which matters when replaying.
- `query`, `req_body`, `resp_body` — parsed, so JSON and form structures are
  walkable. HTML responses keep only their `<title>`, as a page landmark.
- `req_headers` / `resp_headers` — cookies keep their names, `authorization`
  keeps its scheme.
- `redacted` — the paths of every value that was removed.

## Rules

**Never echo, guess at, or reconstruct a redacted value.** `<REDACTED>` means
the real value was deliberately withheld from you.

**Every path in `redacted` is an environment variable, not a literal.** When you
build an automation from a recording, each one becomes a named variable the user
supplies (`EXAMPLE_PASSWORD`, `EXAMPLE_API_KEY`). Prompt for them; do not invent
placeholder values that silently ship as real ones.

**Session credentials are stale by replay time.** A recorded `sid` cookie tells
you the flow needs a session, not what that session is. An automation has to
perform the login step itself.

## When the recording looks wrong

- **Nothing recorded** — the browser is probably not actually proxied, or the CA
  was not trusted. Check `http://proxy.note/status` for counts.
- **Something you expected is missing** — the filter dropped it. `session_end`
  reports the counts by reason. Re-record with `--no-filter` to see everything,
  or add the host to `keep_hosts` in `~/.agent-proxy/filters.json`.
- **Too much noise** — add hosts to `drop_hosts` in the same file.
