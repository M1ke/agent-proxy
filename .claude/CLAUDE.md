# agent-proxy

A local MITM proxy that records a browsing session as JSONL, so an agent can
build a web automation from a transcript of someone doing the task once.

Go, stdlib only. **Adding a third-party dependency needs a real justification** —
`go.mod` having no `require` block is a feature, it keeps the released binary
trivially auditable for something that sits in the middle of the user's traffic.

## Layout

| path | role |
| --- | --- |
| `main.go` | flag parsing, wiring, the setup block printed at startup |
| `internal/ca` | CA generation in `~/.agent-proxy/`, per-host leaf certs |
| `internal/proxy` | `proxy.go` forwarding, `mitm.go` CONNECT + TLS, `capture.go` request/response → `record.Entry` |
| `internal/filter` | drop decisions; `rules.go` holds the built-in rule set |
| `internal/redact` | secret detection and masking |
| `internal/record` | the JSONL schema, writer and console output |
| `internal/control` | the `proxy.note` UI (notes, status, stop, CA download) |
| `skills/web-recorder` | the skill that teaches an agent to drive the tool |

Request path: `ServeHTTP` → control host check → `filter.CheckRequest` → forward →
`filter.CheckResponse` → `capture` (which calls into `redact`) → `record.Write`.
A dropped request is still forwarded normally; filtering only decides what gets
written.

## Invariants

- **The proxy must never break the page.** Capture is best-effort and sits off to
  the side: bodies are read through a capped tee (`readCapped`, 64KB) and the
  full stream still reaches the client. A capture bug must degrade the recording,
  never the browsing.
- **Redaction happens before anything is written**, not after. There is no pass
  that scrubs a finished file.
- **Every removal is recorded** in the entry's `redacted` array. A value that
  vanishes without a path there is a bug — that array is the contract that tells
  a downstream agent which values must come from the environment.
- **`keep_hosts` overrides every drop rule**, including the structural ones
  (`OPTIONS`, subresources). It is the user's escape hatch.
- **Nothing disappears silently.** Drops are counted by reason and reported in
  `session_end`.
- `proxy.note` is intercepted and never resolved or forwarded.

## Design decisions worth preserving

**The filter is conservative about first-party traffic.** Static assets,
subresources (via `Sec-Fetch-Dest`), preflights and known third-party analytics
hosts are dropped freely. An app's own telemetry endpoint is *not* guessed at:
any pattern general enough to catch `/api/track` eventually eats a real
endpoint. The user annotates it as noise instead, or adds it to `drop_paths`.

**Redaction draws the line at per-user credentials, not secrets in general.**
Passwords, session cookies, bearer tokens and OTPs go. Publishable API keys,
`client_id`, `anon_key` and `grant_type` stay — they are shipped to every
browser, and an automation cannot replay the flow without them. Getting this
wrong in the cautious direction produces a useless recording.

**Name matching is segment-based, not substring.** Short terms match whole
segments so `pan` misses `p_company_id` and `auth` misses `author`. When adding
a term, add the false-positive test alongside it; `substringMinLen` guards the
rest.

**Headers are kept only when they change the response.** Auth, routing and
content negotiation (including `Prefer`, `Range`, `If-Match`). Not `user-agent`,
`sec-ch-*` or caching headers.

**Timing is recorded three ways** (`t`, `offset_ms`, `gap_ms`) because replay
needs all three, and `gap_ms` is the one that tells an automation how long a step
took to become available.

**The CA advertises `http/1.1` only**, so browsers downgrade from HTTP/2 and the
intercepting side stays a plain HTTP/1.1 server. Don't add h2 to the ALPN list
without rewriting that side.

## Principles from building automations on top of recordings

These came out of actually generating automations from transcripts, and belong
in any skill that reads one:

- A redacted path is a named environment variable the user supplies, never a
  literal and never a plausible-looking placeholder.
- Recorded session credentials are stale by replay time. The recording proves the
  flow needs a login; the automation has to perform that login itself.
- Notes are the structure. Requests alone read as a wall; the notes bracket them
  into steps, and a note is also how the user declares traffic irrelevant.
- Read notes and requests together in `seq` order, and trust the user's
  annotation over the filter's judgement.
- The useful unit is the smallest set of requests that reproduces the outcome —
  a recording contains far more than the automation needs.

## Working on it

```
make test    # unit tests plus an end-to-end test through a real CONNECT tunnel
make vet
make build
bin/release 0.2.0 "one-line release note"
```

`internal/proxy/integration_test.go` drives a real tunnel with a real CA and is
the test that catches interception regressions — run it after touching `proxy`,
`mitm` or `ca`. Filter and redaction changes need a case in the table tests,
including the false positive the rule must *not* fire on.

`version` in `main.go` is a `var` so release builds can stamp the tag via
`-ldflags`; `bin/release` keeps the source default in step. The optional release
note rides in the annotated tag's message, which the workflow reads back out and
puts above the generated changelog.

Commits: single line, imperative, no emoji. Document *why* in the message when a
filter or redaction rule changes — the history is the record of where those
lines were drawn.

The README is user-facing: how to run it, configure it and read the output.
Rationale and internals live here instead.
