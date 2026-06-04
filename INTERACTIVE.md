# Design: Interactive enforcement ("carve as you go, live")

## Status

Design draft for a follow-up coding session. Decisions captured below; open
questions flagged inline.

## Summary

Today the proxy has two modes ([DESIGN.md](DESIGN.md#recording-and-enforcement-modes)):

- **record** — forward everything, log resolved actions.
- **enforce** — check each resolved action against a static `policy.json`,
  forge `AccessDenied` on a miss.

This adds a third: **interactive** — when a request resolves to an action that
isn't already allowed, *pause the request and ask a human* **always allow /
allow once / deny**. The answer is applied immediately and, for "always allow",
persisted to the policy. The policy is thus built up in real time from real
traffic, instead of being authored up front (enforce) or reviewed after the
fact (record → `iam-agent-proxy policy`).

The mechanism is intentionally simple: a **decision broker** in the proxy parent
process, with a **stdin/stdout front-end** as the default. Everything else
(a review TUI, a Claude Code native-approval transport) is an optional
front-end over the *same* broker and can be added later without touching the
gate. v1 is buildable in one session.

## Goals / non-goals

**Goals**
- Pause a request on an unallowed action and get a live human decision.
- Three outcomes: `always_allow` (persist), `allow_once` (this request only),
  `deny` (forge `AccessDenied`).
- Work for **any SigV4 caller** — boto, AWS CLI, Terraform, a Go binary, signed
  `curl`. The gate lives at the proxy, not at any agent's tool layer.
- Fail **closed**: if no human answers within a timeout, deny.
- Keep the proxy's stdout clean enough that a prompt is readable.

**Non-goals (v1)**
- Resource-level prompting. v1 accumulates **action-only** decisions, matching
  the existing `Allowlist` shape. Resource awareness is Phase 2 (see below).
- Replacing record/enforce. Interactive is a third mode, selected by
  `PROXY_MODE=interactive`.
- Making any single agent (Claude/Codex/…) a hard dependency. The Claude
  transport is experimental and optional.

## Where it plugs in

The gate is one branch in `ResignPlugin._handle`, right where enforce mode
checks the allowlist today ([core/addon.py:199](core/addon.py:199)):

```python
# today
if _allowlist is not None:
    if not _allowlist.permits(actions):
        _emit_actions(..., blocked=True)
        raise EnforcementError(...)
```

becomes, in interactive mode:

```python
decision = _broker.decide(actions, resource=None)   # BLOCKS until answered/timeout
if decision == DENY:
    _emit_actions(..., blocked=True)
    raise EnforcementError(...)
# ALLOW_ONCE / ALWAYS_ALLOW → fall through and forward; ALWAYS_ALLOW also persists
```

This works because `handle_client_request` is **already synchronous and already
blocks the HTTP request** while the plugin runs ([core/addon.py:147](core/addon.py:147)).
The request being paused at the proxy *is* the human-in-the-loop pause. No async
machinery is needed on the request path.

## The decision broker

A single object owned by the **proxy parent process**, started alongside the
creds server in `_cmd_start` ([core/_proxy.py:140](core/_proxy.py:140)).

Why the parent: proxy.py can run workers that don't share memory — that's why
creds are fetched over `creds.sock` rather than shared in-process
([core/addon.py:90](core/addon.py:90), [core/credentials.py:124](core/credentials.py:124)).
For the same reason, decisions must funnel through one place. Workers ask the
broker over a socket (mirroring `creds.sock`); the broker is the only thing that
talks to a human.

Responsibilities:

- **Pending queue**: `{id, actions, resource, ts}` per blocked request.
- **Block & wake**: `decide()` blocks the calling worker until an answer for its
  `id` arrives or the timeout fires.
- **Idempotent answers**: first answer for an `id` wins; later answers
  (from a second front-end) are no-ops. This matters once more than one
  front-end can be attached.
- **Persistence**: `always_allow` / `always_deny` are written to the policy file
  so they never re-prompt and feed straight into `iam-agent-proxy policy`.
- **Fail-closed timeout**: no answer within `INTERACTIVE_TIMEOUT` (default e.g.
  60s) → `DENY`. Matches enforce-mode semantics; the caller sees a normal
  `AccessDenied`.

### Decision model

```
always_allow  → forward now; add action to persisted allow set; never ask again
allow_once    → forward now; do not persist
deny          → forge AccessDenied now; do not persist
(always_deny) → forge now; persist to a deny set so it never re-prompts  [optional]
```

The persisted allow set is exactly the existing `Allowlist` policy JSON, so an
interactive session *is* a policy-authoring session. Stop the proxy and you have
a `policy.json` you can run in plain `enforce` mode.

## Front-ends (transports over the one broker)

The broker speaks one thing: "here is a pending question / here is its answer."
Every front-end is a renderer of that stream. Build the broker + protocol once;
add front-ends independently.

### (A) stdin/stdout — v1, the default

If the proxy is attached to a TTY and no other front-end is connected, the
broker prints the question to stdout and reads `a` / `o` / `d` (always / once /
deny) from stdin. No extra process, no socket. This is the whole v1 UX.

```
[14:32:09] PROMPT  s3:GetObject  — allow? [a]lways / [o]nce / [d]eny: a
[14:32:09] ALLOWED s3:GetObject  (always)
```

**Prerequisite: output cleanup.** Today `_emit_actions` does
`print(..., flush=True)` interleaved with botocore/proxy.py logging
([core/addon.py:60](core/addon.py:60)). A readable prompt requires routing proxy
diagnostics to stderr/logfile and reserving stdout for the action stream +
prompt. This is a real first task, not a footnote.

### (B) Review TUI — later, optional

`iam-agent-proxy review` connects to the broker's Unix socket
(`decisions.sock`, same pattern as `creds.sock`), receives the same question
JSON, renders a queue you arrow through, and posts `{id, decision}` back. Pure
presentation. Exists for when the proxy runs headless or you're at a different
terminal than where the proxy was launched. **Not a new architecture** — just a
second client of the broker socket.

### (C) Claude Code native approval — experimental, optional

Goal: surface the **always / once / deny** choice in Claude Code's own
human-in-the-loop dialog, driven by the proxy. This is desirable but **must not
be a dependency** — it only works when the supervising agent is Claude (or the
Agent SDK), and it has a real constraint.

**The constraint (researched).** MCP lets a *server* prompt the user via
`elicitation/create` and get back `accept`/`decline`/`cancel` — but only while
one of that server's **tool calls is in flight**. There is no mechanism for an
external process to inject a yes/no into an idle Claude session (`Notification`
hooks can't originate externally and can't block; `PreToolUse` hooks can't open
a tty as of v2.1.139 and only see the shell command, not the resolved action).

**Why a naive version fails for arbitrary callers.** With `HTTPS_PROXY`
interception, a Terraform/Go-binary/`curl` SigV4 request arrives with *no*
associated MCP activity. At the instant the gate blocks, there is no open MCP
channel to elicit on. So you **cannot** elicit on the blocked request's own
thread for a generic SigV4 caller. (For boto/CLI specifically you couldn't
either, since the HTTP request and any MCP tool call are still decoupled.)

**The version that works — invert it.** Don't elicit on the blocked request.
Have Claude **subscribe** to the broker's pending queue through a long-poll MCP
tool:

1. Any SigV4 caller hits the proxy → unallowed → broker enqueues, request blocks
   (this is transport (A)'s machinery, unchanged).
2. Claude has the proxy's MCP server connected and is instructed to call
   `proxy.await_decision()` (a supervisor loop).
3. `await_decision` **parks until a decision is pending**, then — because a tool
   call is now in flight — the proxy calls `elicitation/create`:
   `"Allow s3:GetObject on <resource>?"` with an enum
   `always_allow | allow_once | deny`. Claude renders its native dialog. The
   answer returns through the tool, the broker unblocks the waiting binary, and
   persists as usual.

```
  Terraform / any SigV4 binary                Claude Code (supervisor)
            │                                          │
   signed HTTPS request                       proxy.await_decision()
            ▼                                          │ (tool call in flight)
   ┌─────────────────────────────────────────────────┐
   │  Proxy + decision broker (the meeting point)     │
   │  • binary's request BLOCKS in the queue          │
   │  • await_decision in-flight ──► elicitation ────►│──► native Claude dialog
   │  • human answers ──► unblock binary, persist     │◄── always / once / deny
   └─────────────────────────────────────────────────┘
```

The SigV4 universality lives entirely on the interception side; the elicitation
lives entirely on the supervisor side; the broker is the seam. Claude becomes an
*interchangeable supervisor UI* — a human at the TUI, or Codex, could play the
same role.

**Caveats to keep this honest.** Needs a supervisor actively polling; if nobody
polls, the blocked request hits the fail-closed timeout and denies (graceful
degradation, not a hang). Latency is bounded by poll cadence (a true long-poll
that parks until pending makes it near-instant when a poll is outstanding).
Relies on MCP elicitation + long-lived tool-call behavior that should be
prototyped before being relied on.

## Resource awareness — Phase 2

v1 prompts on **action only**. Phase 2 prompts on **action + resource ARN**,
which requires extracting resources from the wire request. This is its own
chunk of work and **must not block v1**.

**Prior art: `../trailtool` already does this in Go** (from CloudTrail). The
structure ports closely:

| trailtool (Go, CloudTrail) | here (Python, wire request) |
|---|---|
| `ExtractResources` dispatches on `event.EventSource` (`ingestor/lib/resources/resources.go`) | resolver already dispatches on `service_slug` ([core/resolver.py:165](core/resolver.py:165)) |
| reads parsed `event.RequestParameters` (`bucketName`, `tableName`, …) | the request **body** is that same parameter map for `json`/`query` services |
| `resourceIdentifierToARN(id, accountID)` → `arn:aws:s3:::%s/*` (`core/policy/generate.go`) | directly portable ARN templates |
| groups action→resources into statements | this is the `iam-agent-proxy policy` emitter, which today hardcodes `"Resource": "*"` ([core/_proxy.py:189](core/_proxy.py:189)) |

**The nuance:** trailtool reads CloudTrail's already-parsed `requestParameters`.
The proxy sees the raw wire body, which differs by protocol:

- `json` (DynamoDB/KMS/Lambda) — body is JSON ≈ `requestParameters`. trailtool's
  extractors port almost verbatim.
- `query` (IAM/STS/SQS/EC2) — body is `x-www-form-urlencoded`
  (`Action=…&RoleName=…`); parse form fields, same field→resource logic.
- `rest-*` (S3) — resource comes from host+path, and the resolver **already
  captures `{Bucket}`/`{Key}` during URI matching and currently discards them**
  ([core/resolver.py:41](core/resolver.py:41)). Surfacing those is the cheapest
  win.

So Phase 2 = "port trailtool's per-service extractor table (adapted for three
body encodings) + stop discarding the path vars the resolver already parses."
Recommend vendoring trailtool's service→field map as the spec; it's a lookup
table representing coverage already validated against real CloudTrail.

`Allowlist.permits` would extend from `list[str]` to action+resource matching,
and `decide()` would carry the resource into the prompt and the persisted
statement.

## Phasing

1. **v1 — interactive gate, action-only, stdin front-end.**
   - Output cleanup: proxy diagnostics off stdout.
   - Decision broker in the parent (queue, block/wake, idempotent answers,
     fail-closed timeout, persistence to policy JSON).
   - Worker→broker socket (mirror `creds.sock`).
   - stdin/stdout prompt; `PROXY_MODE=interactive`.
2. **v2 — review TUI** (`iam-agent-proxy review`) over `decisions.sock`.
3. **Phase 2 — resource awareness** (port trailtool extractors; surface resolver
   path vars; extend `Allowlist` + persisted statements).
4. **Experimental — Claude native approval** via `proxy.await_decision` MCP
   long-poll + elicitation. Prototype before relying on it.

## Open questions

- **Timeout default.** 60s a sane fail-closed default? SDKs retry/timeout on
  their own — pick a value below common client timeouts.
- **Persistence target.** Write `always_allow` into `ALLOWLIST_PATH` directly,
  or a separate `decisions.json` merged at read time? Latter keeps
  human-authored and machine-learned policy separable.
- **Coalescing.** One operation can resolve to multiple actions
  (e.g. `S3.CopyObject` → `s3:GetObject` + `s3:PutObject`). Prompt once for the
  set, or per action? Propose: once for the set, all-or-nothing.
- **Multi-worker prompt routing** beyond the broker — confirm proxy.py worker
  count in our config; if single-threaded, stdin path is trivial; if not, the
  socket-to-parent path is mandatory even for stdin.
- **`always_deny`** — worth persisting, or always re-evaluate denies? (Avoids
  re-prompting for known-bad actions.)
