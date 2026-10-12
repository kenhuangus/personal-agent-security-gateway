# Personal Agent Security Gateway — Design

**Document:** `docs/02-design.md`
**Phase:** 2 of 4 (Design) — planning only, no implementation
**Product owner:** Ken
**Status:** Draft for review
**Baseline:** `docs/01-requirements.md` (Phase 1)

---

## 1. Design principles

These constrain every choice below. They come from the requirements, not from taste.

1. **Default-deny is visible, not hidden.** FR-017 forces the posture. The design must show the deny rule explicitly (console, docs, dry-run) so Ken never wonders why a call failed.
2. **The agent never gets a path around the human.** Anything that would let an agent approve, elevate, or read credentials is rejected by design, even if it would be convenient.
3. **Statelessness over cleverness.** MCP over Streamable HTTP is request/response. The design never assumes the server can push to an agent or hold a connection open.
4. **Every decision is explainable in one screen.** Each allow/deny/approval must map to one audit row, one policy rule, and (if sensitive) one approval record.
5. **No invented platform behavior.** Where Muse/Grok/Dots behavior is unverified (OQ-1–OQ-5), the design flags the gap instead of designing around a guess.

Latency and scale targets are design targets, not promises: policy + inspection < 100 ms at p95 (NFR-PERF-001), 10 concurrent sessions (NFR-PERF-002). Single stateful service in MVP (NFR-REL-001).

---

## 2. MCP tool / API surface

### 2.1 Tool naming convention

`<connector>.<action>` — lowercase, dots separate namespace from verb.

- `email.read`, `email.search`, `email.send`
- `email.draft` (routine; a draft permission never authorizes send — FR-PAA07-001)
- `email.settings.read`, `email.settings.write` (read-only recovery-settings review vs. sensitive recovery-affecting changes — FR-PAA02-002/005)
- `calendar.list`, `calendar.create`, `calendar.update`, `calendar.delete`
- `code.file.read`, `code.pr.open`
- `gateway.approval_status` (meta tool; see 2.5)

Rationale: FR-INT-002 requires a clean `tools/list` surface because Muse builds its integration from what the endpoint advertises. Dotted names group by connector in any alphabetical listing and stay readable in logs. Tool names are expected to stay within the MCP-allowed character set (letters, digits, dot, underscore, hyphen) — verify against the MCP spec at implementation (M0 verification item).

**Authentication on discovery (Fix A).** `tools/list` and `initialize` REQUIRE the agent credential, exactly like `tools/call`. Unauthenticated callers get `auth_failed` (2.7). There is no anonymous surface enumeration on the public endpoint.

**Public exceptions (OAuth necessity).** The OAuth 2.1 discovery/metadata, authorization, and JWKS endpoints are publicly reachable by necessity — an OAuth client must reach them before it can authenticate. Everything else on the public endpoint requires the agent credential.

`code.pr.merge` is deferred out of the MVP inventory until the approval loop proves itself on `email.send` (00 §3); `email.send` stays the MVP-sensitive write action.

### 2.2 MVP tool inventory

| Tool | Connector | Sensitivity (default) | Notes |
|---|---|---|---|
| `email.search` | email | routine | read-only |
| `email.read` | email | routine | read-only |
| `email.send` | email | **sensitive** | step-up approval; FR-018, story 7 |
| `email.draft` | email | routine | draft only; send always needs its own approval (FR-PAA07-001) |
| `email.settings.read` | email | routine | read-only recovery-relevant settings (forwarding/filter rules) for console review (FR-PAA02-005) |
| `email.settings.write` | email | **sensitive** | recovery-affecting changes; step-up approval, protected flow (FR-PAA02-002/003) |
| `calendar.list` | calendar | routine | read-only |
| `calendar.create` | calendar | conditional | routine; sensitive when external attendees are included (example conditional rule) |
| `calendar.update` | calendar | routine | |
| `calendar.delete` | calendar | **sensitive** | destructive; story 7 |
| `code.file.read` | code host | routine | read-only |
| `code.pr.open` | code host | **sensitive** | write action; OQ-7 recommends sensitive from day one |
| `gateway.approval_status` | meta | routine | poll a pending approval; 2.5 |

Deferred out of MVP: `code.pr.merge` (and other code-host write actions beyond PR open) — deferred until the approval loop proves itself on `email.send` per 00 §3.

Every connector declares its tools with input schemas, required scopes, and sensitivity per FR-008. New connectors add tools without touching the endpoint or policy engine (FR-009).

### 2.3 Representative tool schemas

JSON Schema (draft 2020-12) as MCP requires. `snake_case` parameters throughout.

**email.search** (routine)
```json
{
  "name": "email.search",
  "description": "Search the mailbox. Returns message metadata and snippets, not full bodies.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "query":       { "type": "string", "description": "Search text." },
      "mailbox":     { "type": "string", "enum": ["inbox", "sent"], "default": "inbox" },
      "since":       { "type": "string", "format": "date-time" },
      "limit":       { "type": "integer", "minimum": 1, "maximum": 50, "default": 10 }
    },
    "required": ["query"]
  }
}
```

**email.send** (sensitive — requires step-up approval)
```json
{
  "name": "email.send",
  "description": "Send an email. SENSITIVE: execution pauses for human approval in the admin console.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "to":      { "type": "array", "items": { "type": "string", "format": "email" }, "minItems": 1 },
      "cc":      { "type": "array", "items": { "type": "string", "format": "email" } },
      "bcc":     { "type": "array", "items": { "type": "string", "format": "email" } },
      "subject": { "type": "string", "maxLength": 200 },
      "body":    { "type": "string", "maxLength": 100000 }
    },
    "required": ["to", "subject", "body"]
  }
}
```

**email.draft** (routine — a draft permission never authorizes send)
```json
{
  "name": "email.draft",
  "description": "Create an email draft. Routine. Sending the draft always requires its own step-up approval (email.send).",
  "inputSchema": {
    "type": "object",
    "properties": {
      "to":      { "type": "array", "items": { "type": "string", "format": "email" }, "minItems": 1 },
      "subject": { "type": "string", "maxLength": 200 },
      "body":    { "type": "string", "maxLength": 100000 }
    },
    "required": ["to", "subject", "body"]
  }
}
```

**email.settings.read** (routine — read-only recovery-settings visibility)
```json
{
  "name": "email.settings.read",
  "description": "Read mailbox recovery-relevant settings (forwarding addresses, filter rules). Read-only; for console review (FR-PAA02-005).",
  "inputSchema": {
    "type": "object",
    "properties": {
      "section": { "type": "string", "enum": ["forwarding", "filters", "all"], "default": "all" }
    }
  }
}
```

**email.settings.write** (sensitive — recovery-affecting changes)
```json
{
  "name": "email.settings.write",
  "description": "Change mailbox recovery-relevant settings (forwarding, filter rules, recovery address). SENSITIVE: execution pauses for human approval in the admin console (protected flow, FR-PAA02-002/003).",
  "inputSchema": {
    "type": "object",
    "properties": {
      "section":  { "type": "string", "enum": ["forwarding", "filters", "recovery_address"] },
      "settings": { "type": "object", "description": "New settings for the section." }
    },
    "required": ["section", "settings"]
  }
}
```
**calendar.list** (routine)
```json
{
  "name": "calendar.list",
  "description": "List calendar events in a time range.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "start":       { "type": "string", "format": "date-time" },
      "end":         { "type": "string", "format": "date-time" },
      "calendar_id": { "type": "string" },
      "limit":       { "type": "integer", "minimum": 1, "maximum": 100, "default": 25 }
    },
    "required": ["start", "end"]
  }
}
```

**calendar.create** (conditional sensitivity)
```json
{
  "name": "calendar.create",
  "description": "Create a calendar event. Requires approval when attendees include external addresses.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "title":       { "type": "string" },
      "start":       { "type": "string", "format": "date-time" },
      "end":         { "type": "string", "format": "date-time" },
      "attendees":   { "type": "array", "items": { "type": "string", "format": "email" } },
      "description": { "type": "string" },
      "location":    { "type": "string" },
      "calendar_id": { "type": "string" }
    },
    "required": ["title", "start", "end"]
  }
}
```

**code.file.read** (routine)
```json
{
  "name": "code.file.read",
  "description": "Read a file from a repository at a ref (branch, tag, or commit).",
  "inputSchema": {
    "type": "object",
    "properties": {
      "repo": { "type": "string", "description": "owner/name" },
      "path": { "type": "string" },
      "ref":  { "type": "string", "default": "HEAD" }
    },
    "required": ["repo", "path"]
  }
}
```

**code.pr.open** (sensitive — write action)
```json
{
  "name": "code.pr.open",
  "description": "Open a pull request. SENSITIVE: execution pauses for human approval in the admin console.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "repo":  { "type": "string", "description": "owner/name" },
      "title": { "type": "string" },
      "head":  { "type": "string" },
      "base":  { "type": "string" },
      "body":  { "type": "string" }
    },
    "required": ["repo", "title", "head", "base"]
  }
}
```

### 2.4 Parameter conventions

- `snake_case` names everywhere.
- Listing tools accept `limit` (bounded, documented max). No cursor pagination in MVP; `limit` plus time-range filters are enough for personal use.
- Date-times are RFC 3339 strings (`format: date-time`).
- No tool accepts credentials, tokens, or secrets as parameters. Ever. (FR-012, FR-022.)
- Descriptions state the sensitivity in the first line for sensitive tools, so a model reading `tools/list` knows approval is involved before it calls.

### 2.5 Agent-visible meta tool

**`gateway.approval_status`** — the only non-connector tool an agent may call.

```json
{
  "name": "gateway.approval_status",
  "description": "Check the status of a pending step-up approval request.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "approval_request_id": { "type": "string", "description": "From an approval_required error." }
    },
    "required": ["approval_request_id"]
  }
}
```

Response (success): `{ "approval_request_id", "status": "pending|approved|denied|expired", "decided_at", "expires_at", "result_summary?" }`. `result_summary` is present only when the approved call was executed server-side via the execute-on-approval fallback (2.8, below): it carries a short, PII-redacted summary of the executed result, so a polling agent receives the result through the same schema. In the normal poll-and-reinvoke path there is no `result_summary` — the agent re-invokes the original tool and the gateway matches the active grant by (agent, tool, argument-hash) (see 2.8 step 9). There is no agent-visible grant identifier: internal grant IDs never cross the agent boundary. This tool is routine and reveals nothing about policy rules — only the status of the agent's own request.

**Caller binding (Fix B, MF-5):** `approval_request_id` lookups are bound to the authenticated caller's agent identity. An `approval_request_id` belonging to another agent returns **not-found**, never "denied" (a denial would confirm the request exists). Request IDs are 128-bit CSPRNG values with the `apr_` prefix.

**Rate budget:** `gateway.approval_status` has its own rate budget, separate from the agent's tool-call budget (default 60 polls/min per agent, tunable) — polling for a decision never consumes the budget for real tool calls.

**Audit carve-out:** routine status polls are exempt from FR-030's per-call audit row (polling every few seconds would flood the log). Polls that return `denied`, `expired`, or not-found ARE audit-logged; each approval record itself (decision, approver, scope) is always logged per FR-031.

### 2.6 Admin-only control surface (NOT MCP tools)

Design choice, forced by FR-018 and FR-022: **agents must have no tool that evaluates or grants policy.** Two capabilities the task brief named are therefore console HTTP API endpoints, not MCP tools:

- `POST /api/policy/evaluate` — dry-run one hypothetical call against a policy version. Body: `{agent_id, tool, arguments, policy_version?}`. Returns `{decision, matched_rule_id, requires_approval}`. Admin console only. (An agent-callable `policy.evaluate` would let agents probe policy boundaries; rejected.)
- `POST /api/policy/dry-run` — replay a policy version against history. Body: `{policy_version, window_days}`. Returns `{counts: {would_allow, would_deny, would_require_approval}, changed_calls: [...], corpus: "history"|"synthetic"}`. Changed calls list which calls' outcomes would change. Cold start: when audit history is empty, the corpus is hand-written synthetic calls (one per tool), labeled `"synthetic"` in the output (DQ-2). Admin console only. (MF-12)
- `POST /api/approvals/{request_id}/decision` — approve or deny. Body: `{decision: "approve|deny", scope: "one_time", note?}`. MVP grants are one-time only; windowed grants are deferred post-MVP (00 §3). Admin console only, admin-authenticated. **Anti-CSRF:** all state-changing console API routes require anti-CSRF tokens (or `SameSite=Strict` cookies plus a custom-header check); this endpoint gets both belt and braces — token plus per-decision confirmation. Decisions on destructive scopes (e.g., `calendar.delete`, recovery-affecting settings) additionally require re-authentication or a per-decision confirmation token (FR-042). Decision handling is idempotent: a retried POST against an already-decided request returns the existing decision, never a second grant. (An agent-callable `policy.approve` would defeat step-up entirely; rejected.)
- `POST /api/admin/login` and `POST /api/admin/logout` — the admin authentication endpoints (FR-036, MF-10). Every login attempt, success or failure, emits an audit event (FR-039). Login is rate-limited with lockout and exponential backoff (FR-040).

This split is the load-bearing security decision of the surface design. The MCP surface is for agents. The control surface is for Ken.

### 2.7 Error shapes

All tool-call failures return MCP `isError: true` with a single JSON payload in `content[0].text`. One envelope, machine-readable codes, human-readable messages, and the audit correlation ID.

```json
{
  "error": {
    "code": "approval_required",
    "message": "email.send is sensitive. Approval requested (apr_9f2k…). Poll gateway.approval_status or wait for the admin.",
    "request_id": "req_01J…",
    "retryable": false,
    "details": {
      "approval_request_id": "apr_9f2k…",
      "expires_at": "2026-10-12T19:30:00Z",
      "tool": "email.send"
    }
  }
}
```

Error codes (stable, documented):

| Code | Meaning | Retryable | Requirement |
|---|---|---|---|
| `policy_denied` | no allow rule, or explicit deny (default-deny) | no | FR-016, FR-017 |
| `approval_required` | sensitive; step-up approval created | poll, then re-invoke | FR-018 |
| `approval_denied` | approver denied the request | no | FR-018, FR-031 |
| `approval_expired` | approval window lapsed; default-deny | re-request | OQ-8 (15-min default target) |
| `approval_queue_full` | per-agent pending-approval cap hit (default 5) | after a request resolves | FR-028 |
| `cooldown_active` | identical call denied during the post-denial refusal cooldown; no approval request is created and no notification is sent. Denial-streak escalation also applies: after 3 denied sensitive requests for the same (agent, tool) within 24 hours (design targets, tunable), ALL sensitive calls for that pair return `cooldown_active` regardless of arguments until 24 hours after the most recent denial (FR-PAA09-003; 2.8 steps 3 and 10) | after the cooldown lapses | FR-PAA09-003 |
| `already_executed` | the grant for this identical (agent, tool, argument-hash) call was already consumed; re-invoking does not re-execute and creates no new approval request | no — the call already ran | 2.8 steps 3 and 9 |
| `agent_paused` | agent identity is paused (temporary, resumable) | no — resume is an admin action | FR-PAA10-002, FR-PAA10-004 |
| `agent_canceled` | agent's pending work was canceled | no — re-request is a new call | FR-PAA10-002, FR-PAA10-004 |
| `invalid_input` | schema validation failed | fix args | FR-025 |
| `rate_limited` | per-agent rate limit hit | after `retry_after` | FR-028 |
| `budget_exceeded` | *deferred — post-MVP; code reserved, not emitted in MVP (FR-029)* | — | FR-029 |
| `injected_output_blocked` | tool output contained prompt-injection; blocked/redacted per policy | no | FR-026 |
| `upstream_failure` | connector or downstream system failed | per `details` | NFR-REL-002 |
| | Unknown-outcome rule (FR-PAA06-003): after a timeout or ambiguous response, automatic retry is blocked until a status check via the connector's status-check capability confirms non-execution. Where the connector exposes no status-check capability, the retry is denied pending console approval. | | |
| `auth_failed` | agent authentication failed | no | FR-011 |
| `agent_revoked` | agent identity revoked | no | FR-015 |

**Safe reason vocabulary for `policy_denied`:** the agent-visible `reason` field is drawn only from a fixed vocabulary — `no_allow_rule`, `explicit_deny`, `mandate_scope_exceeded`, `mandate_expired`, `mandate_paused`, `mandate_withdrawn`, `policy_superseded`, `approval_denied`, `approval_expired`, `approval_queue_full`, `cooldown_active`, `rate_limited`, `invalid_input`, `agent_paused`, `agent_canceled`, `agent_revoked`. It carries no rule text, no matched-rule ID, no time windows, no domain lists, and no rule IDs. Rule structure never leaks through denials.

**`invalid_input` never echoes offending arguments:** the error names the offending field (e.g., `"to"`), never its value. No PII or injected content is returned to the agent in error paths (04 NH-2).

`request_id` is present on every error and matches the audit row. `details.retry_after` (seconds) accompanies `rate_limited`. Nothing in any error leaks vault contents, policy rule text, or other agents' data (FR-022, NFR-SEC-003).

**Destructive-action registry (in-MVP).** The tools whose approval flow uses the destructive treatment — 5-minute approval window (00 §7 parameter 3) and per-decision re-authentication or confirmation token (FR-042):

| Tool | Why destructive |
|---|---|
| `calendar.delete` | deletes events; no undo at the service |
| `email.settings.write` | recovery-affecting changes (forwarding, filters, recovery address); protected flow (FR-PAA02-003) |

FR-042's "destructive scopes" and 00 §7 parameter 3 reference this registry.

### 2.8 Approval suspend/resume across stateless HTTP

MCP over Streamable HTTP is request/response: the server cannot push a result into a closed request later. The design therefore **suspends by reference, not by holding the connection**. Sequence:

1. Agent calls `email.send`. The gateway authenticates the session (Fix A; one credential per agent). Lifecycle state is checked at entry and named distinctly: a paused agent gets `agent_paused`, a canceled agent gets `agent_canceled`, a revoked agent gets `agent_revoked` (FR-PAA10-002, FR-PAA10-004). `tools/list` and `initialize` require the same credential — unauthenticated callers get `auth_failed` (2.1, 2.7).
2. **Validate first.** The gateway validates arguments against the tool's declared schema (FR-025) **before** anything approval-related is created. Schema validation failure returns `invalid_input` (naming the offending field, never its value — 2.7) and **never creates an approval request**. (Fix B, MF-4.)
3. **Idempotent lookup before the cap check (MINOR-9).** Arguments are canonicalized (canonical JSON serialization per FR-PAA06-002) and hashed with HMAC-SHA256 keyed with the gateway-held key (the same HMAC rule as the evidence subset in step 4). Then, in order: (a) **Pending dedupe** — if an identical request, same (agent, tool, argument-hash), is already pending, the gateway returns the existing `apr_…` ID instead of creating a duplicate. (b) **Already-executed check** — if the identical call's grant was already consumed (step 9), the call returns `already_executed`: no new approval request, no re-execution, no notification. (c) **Refusal-cooldown check (FR-PAA09-003):** if an identical request (agent, tool, argument-hash) is inside the refusal cooldown from a denial (step 10), the call is denied with `cooldown_active` — no approval request is created and no notification fires. (d) **Denial-streak escalation (FR-PAA09-003):** if this (agent, tool) pair has 3 or more denied sensitive requests in the last 24 hours (design targets, tunable), the pair-level cooldown engages: ALL sensitive calls for that (agent, tool) return `cooldown_active` regardless of arguments, until 24 hours after the most recent denial. This bounds the deny→mutate→request loop that a one-character argument change would otherwise open.
4. **Queue-cap check, then creation.** If the agent already has the maximum concurrent pending approvals (default 5, tunable — FR-028), the call returns `approval_queue_full` and the event is audit-logged. No request is created. (The step-3 lookups run first, so an at-cap agent re-submitting an identical pending request gets the existing `apr_…` ID, a call whose grant was already consumed gets `already_executed`, and a cooled-down request gets `cooldown_active` — never `approval_queue_full`.) Otherwise the gateway creates the approval request (`apr_…`, 128-bit random) for a sensitive call — a call the policy denies outright gets `policy_denied` and never reaches this step — stores per the evidence-subset rule below, writes an audit row with `decision: approval_required`, and returns the `approval_required` error (2.7) with `request_id` and `expires_at`. The HTTP request ends here. Nothing is held open.

   **Evidence-subset rule (BLOCKER-2).** The card must show recipients, full rendered message as inert text, and counterparty delta (4.4, FR-PAA07-002), but the redaction catalog removes exactly those fields — so the approvals record stores a per-field evidence subset, defined once: (a) an **evidence subset** in cleartext, LIMITED to the approver-visible decision fields the card must show — recipient/payee, amount and currency, audience (to/cc/bcc), and the rendered content preview (subject line / message body / term sheet). **Code-like secrets are redacted even here:** verification codes, OTPs, and API-key-shaped strings are redacted in the rendered preview per FR-PAA02-001 (see 4.4); only recipient/payee, amount and currency, and audience stay cleartext; (b) the full argument set in **redacted** form per the redaction catalog (NFR-DATA-001); (c) an **HMAC-SHA256** of the canonical full arguments, keyed with a gateway-held key — the key lives in the platform secret store per 03 §5, NOT in the backed-up config SQLite, with rotation support — never plain SHA-256, which is brute-forceable offline by anyone with config-DB read access (MINOR-8). Full arguments are never stored in plaintext in the approvals table (04 NH-4). The evidence subset is the minimum needed for the card; everything else stays redacted. The cleartext exception applies to the approvals record only — never to the audit log or agent delivery (NFR-DATA-001 note).
5. The request appears in the console approvals queue in near real time (FR-037). An email-to-Ken notification fires over a **dedicated system notification path** — a documented exempt system path with its own audit record, NOT the policy-gated `email.send` connector (so M3's notification does not depend on M4's vault-backed email connector). **Notifier credential (MAJOR-3):** the path authenticates with a bootstrap deploy-time secret held in the platform secret store (Fly secrets or GCP Secret Manager per hosting choice) — NOT the M4 gateway vault, which holds connector credentials only — encrypted at rest per NFR-SEC-002 with a key managed outside app config (see 03 §5). **Content limits:** the notifier builds the message from a fixed field allowlist — agent name, tool name, timestamp, and a console link ONLY. There is no free-text passthrough of tool arguments: no PII, no argument values. **Provisioning:** the sending service and sender identity are chosen at deploy time and recorded in the console configuration. **Failure semantics:** a bounced or delayed notification falls back to the in-console queue — the request is always visible there. The 15-minute approval window runs from request creation regardless of notification delivery; a notification failure never extends or shortens the window. **Rate limits:** notification volume is bounded by the per-agent pending-approval cap (default 5); per-agent notification digests or a short notification cooldown blunt attention-DoS (T5). **Notification channel is DECIDED:** in-console plus email-to-Ken on each new approval request for MVP (00 §7 parameter 7; 00 §9 decision 3 closed; DQ-1 decided).
6. The agent polls `gateway.approval_status` (caller-bound per 2.5). (Polling is the agent's choice; a well-behaved agent polls with backoff. The gateway does not notify agents.)
7. Ken approves in the console with a **one-time grant** bound to the exact argument hash (story 10; windowed grants are deferred post-MVP). The grant is valid 30 minutes from approval (design target, configurable), independent of the approval window — the approval window (default 15 min, OQ-8) is how long Ken has to decide; the grant TTL is how long the agent has to re-invoke after approval.
8. `approval_status` flips to `approved`.
9. The agent **re-invokes the original tool call**. The policy engine checks active grants for (agent, tool, argument-hash) **before** rule evaluation. **Live-mandate check at consumption (BLOCKER-1, FR-PAA01-004):** a matching grant is NOT enough on its own — the gateway verifies the mandate is still live. A withdrawn mandate denies the call with reason `mandate_withdrawn`, an expired mandate with reason `mandate_expired`, a paused mandate with reason `mandate_paused` (an audit event is recorded in each case); grant invalidation applies to all three — the gateway invalidates all remaining unconsumed grants under that mandate. Approved-but-unconsumed grants therefore die with the mandate; a dead mandate can never authorize a call. **Policy-supersession check (FR-PAA04-003):** each grant records the policy version it was issued under. If a MATERIAL change to the standing instruction or mandate was saved since issuance (02 §5 change classification), the call is denied with reason `policy_superseded` and flagged for re-approval. Non-material changes preserve grants. A matching, unexpired, un-superseded grant with a live mandate short-circuits to `allowed_via_approval` (Fix B, MF-7). Grant consumption is **atomic** (compare-and-consume / single-flight): two concurrent re-invocations cannot both consume a one-time grant — the first consumes it, the second finds the grant already consumed and gets `already_executed`. **Replay after consumption is terminal:** an identical re-invoke after its grant was consumed returns `already_executed` — no new approval request, no re-execution, no notification (step 3 check (b)). A call with no matching grant, no pending request, no consumed grant, and no active cooldown is a fresh call: it re-enters the standard flow (step 4: cap check, then a new `apr_…` + `approval_required` for a sensitive call, or `policy_denied` per policy). Agent revocation kills grants immediately. The executed call logs `decision: allowed_via_approval` on the same `approval_request_id`.
10. If Ken denies, or the window lapses (default 15 min, OQ-8), `approval_status` returns `denied`/`expired`. **Refusal cooldown (FR-PAA09-003):** on a deny, the gateway records (agent, tool, argument-hash) → cooldown until timestamp (default 24 hours, design target, tunable per policy). An identical call inside the cooldown hits the step-3 check: `cooldown_active`, no new request, no notification. Refusal ends solicitation. Each denial also increments the (agent, tool) denial counter feeding the step-3 denial-streak escalation. A call with no grant, no pending request, and outside the cooldown is a new sensitive call: it is processed per step 4 (new `apr_…` + `approval_required`, subject to the cap) or `policy_denied` per policy — never a silent re-execution.

Three audit rows share one `approval_request_id`: the paused call, the approval decision (approver, scope, window — FR-031), and the executed call. The audit viewer renders them as one timeline (see 7).

**Fallback: execute on approval (MF-11).** If a platform's agent cannot complete the poll-and-retry loop (M0 spike fails), the console gets an "execute on approval" path: Ken's approval triggers the approved call server-side immediately. **Grant consumption at approval time:** in execute-on-approval mode, the approval action itself consumes the grant atomically at approval time — nothing is left to consume later. Any subsequent agent re-invoke of the identical call therefore hits the `already_executed` rule (step 3): no double execution is possible. **Coherent result delivery:** the executed result reaches the human through the console approval record — that is the delivery path — and `result_summary` (PII-redacted) on `approval_status` is its machine-readable mirror of the same delivery, present ONLY in execute-on-approval mode (2.5), not a second path. Ken stays the sender back to the agent. The fallback is required before MVP is declared done for any platform whose agent cannot poll.

Rejected alternative (designer judgment): holding the HTTP stream open until Ken decides. The rationale — proxies, timeouts, and agent SDKs all break long-held streams, and it couples gateway availability to human response time — is the designer's judgment; the team has not tested long-held streams against Muse/Grok clients.

---

## 3. Admin console information architecture

### 3.1 Navigation

Left sidebar, nine sections, one level deep. Top bar shows gateway status, pending-approval count badge, and the admin identity. No nested menus in MVP — nine pages are few enough to show all at once.

### 3.2 Page list

| Page | Purpose | Key requirement |
|---|---|---|
| Dashboard | One-screen security posture: agents, calls, approvals, policies, audit tail; global "stop everything" control | FR-038, story 5, FR-PAA10-001 |
| Agents | Register, inspect, pause, revoke agent identities; session/token status; per-item work status | FR-011, FR-015, FR-038, stories 1–5, FR-PAA10-003 |
| Connectors | Connector registry: tools exposed, health checks, credential binding | FR-007–FR-010, FR-038 |
| Policies | Rule list, rule builder, dry-run, version history | FR-016–FR-020, stories 6–8 |
| Approvals | Pending queue; approve/deny with bounded scope; decision history; counterparty-record review/correction (diffed, audit-logged) | FR-018, FR-031, FR-037, stories 9–10, FR-PAA05-001, 03 AOQ-12 |
| Audit Log | Searchable, filterable, append-only log; export | FR-030–FR-034, stories 18–20 |
| Vault & Settings | Credential entries, rotation, global settings (token lifetime, rate-limit defaults, retention); recorded decision criteria per domain | FR-021–FR-024, stories 11–12, FR-PAA09-004, 03 AOQ-13 |
| Mandates | Standing instructions per agent: list, one-action pause/narrow/end; mandate history | FR-PAA01-001, FR-PAA01-006 |
| Context boundaries | Purpose registry, data-label classes, cross-context leakage events | FR-PAA03-001…004 |

### 3.3 Role model

MVP: **single admin = Ken.** One strong admin credential (FR-036; OIDC later, explicitly out of MVP). No per-page permissions in MVP. The data model still keys every policy, grant, and audit row to `admin_id` so team RBAC (P3, later phase) does not require a schema rewrite — a seam, not a feature.

---

## 4. Key screens (described)

### 4.1 Dashboard
- **Purpose:** answer "is anything wrong right now?" in under ten seconds (story 5).
- **Key elements:** status cards (agents connected, tool calls today, denied today, pending approvals); connected-agents table (name, platform, status, last call, scopes held); recent tool calls (time, agent, tool, decision badge); pending-approvals queue preview; policy summary (rule count, default-deny indicator); audit tail (last ~10 rows). Global **"stop everything"** control (FR-PAA10-001): one action pauses all agents and cancels pending approvals; the acknowledgment distinguishes "received" from "enforced" and names what was paused, canceled, or left in-flight (per-item status, FR-PAA10-003/004). A visible "mock data" label applies only to the mockup, not the product.
- **Primary action:** jump to the approvals queue (the only time-critical action).

### 4.2 Agent detail + connect flow
- **Purpose:** register a new agent identity and verify its first connection (stories 1–5); inspect or revoke later.
- **Key elements:** agent identity summary (`agent_muse_main`, platform, created date, status); credential panel (client ID; secret/bearer shown **once** at issuance, then never again — FR-022; exactly one credential per agent per FR-011); scopes granted; live sessions and token status (FR-038); per-item work status for queued, delegated, and in-flight work under pause/revoke (FR-PAA10-003); "first connection" checklist: session established → which auth method was verified (OAuth 2.1 or conditional fallback bearer) with the verification test date recorded in the console → `tools/list` received → test `calendar.list` call → audit row present (AC-01/AC-02); danger zone: **Pause agent** (temporary, resumable — FR-PAA10-001) and **Revoke access** (one action, immediate — FR-015, AC-08).
- **Primary action:** issue the single credential, then verify first connection.

### 4.3 Policy editor
- **Purpose:** write allow/deny/require-approval rules without learning a DSL (story 6).
- **Key elements:** rule list ordered by evaluation priority (drag to reorder); the implicit default-deny shown as a pinned, non-deletable final row (FR-017 made visible); rule builder form (see 5); raw JSON/YAML toggle; dry-run panel; version history with diff and rollback.
- **Primary action:** save a new policy version (every save is a version; nothing is edited in place).

### 4.4 Approval card
- **Purpose:** decide a sensitive action fast, with enough context to decide well (stories 9–10, FR-037).
- **Key elements:** agent, tool, timestamp, mandate purpose + remaining duration (FR-PAA01-006). **Evidence source:** the arguments and previews shown on the card come from the evidence subset stored at creation (2.8 step 4: recipient/payee, amount/currency, audience, rendered content preview in cleartext); everything outside the evidence subset stays redacted, and the stored HMAC lets the card verify the subset against the original arguments. Code-like secrets are redacted even in the preview: verification codes, OTPs, and API-key-shaped strings render as redacted tokens per FR-PAA02-001 — recipient/payee, amount/currency, and audience stay cleartext. Arguments render **inert**: preformatted monospace text, no rich rendering, no clickable links. A static **"untrusted content"** label marks every argument block. A structured **consequence summary** (tool, recipient count, size, computed from structured fields — not from free text) appears **before** any free text. No urgency language appears anywhere on the card (FR-PAA09-001). **Cap state:** the card shows the agent's pending-approval slot usage (e.g., "3 of 5 pending approvals used", FR-028). **Expiry-countdown interplay:** the countdown (default 15 min, OQ-8) and the cap interact — an expired or decided request frees its slot immediately; while the cap is hit, that agent's new sensitive calls get `approval_queue_full` (2.8 step 4) until a slot frees. Then, conditional sections by action class:
  - **Term sheet** (commitment-adjacent): payee, total amount + currency, fees, dates, recurring terms, cancellation consequences (FR-PAA06-001).
  - **Counterparty evidence** (commitment-adjacent): recipient, claim source (the message/document that triggered the call), delta vs. the recorded independent record, detected urgency or relationship-claim language (FR-PAA05-003). Agent-supplied legitimacy assertions render as untrusted content, never evidence.
  - **Incentives** (FR-PAA09-001): detected sponsor/placement signals in the trigger content, how the action compares to the recorded criteria, the trigger source.
  - **Audience + content preview** (send actions): recipients and the full rendered message as inert text; the approval binds (audience-hash, content-hash) (FR-PAA07-002).
  The matched policy rule and why it triggered; note field; Approve / Deny buttons; expiry countdown (default 15 min, OQ-8); scope is **one-time (this exact call)** in MVP — windowed grants deferred post-MVP.
- **Primary action:** approve with the one-time bounded scope, or deny.

### 4.5 Audit viewer
- **Purpose:** reconstruct any incident in minutes (stories 18–20).
- **Key elements:** filter bar (agent, connector/tool, decision, time presets + custom range, text search); results table (time, agent, tool, decision badge, latency, expandable redacted arguments); row click opens a detail drawer with the full redacted payload and, for approvals, the three-row timeline (paused call → decision → executed call) linked by `approval_request_id`; export button (JSON/CSV, time range).
- **Primary action:** filter to the incident, then export the slice.

---

## 5. Policy-configuration UX

No DSL. Ken builds rules from a structured form; raw JSON/YAML is an escape hatch, not the default.

**Rule builder form fields:**

1. **Name** (free text, e.g. "Muse can read email").
2. **Applies to — agent:** all agents, or pick one/more.
3. **Applies to — tool:** pick connector, then tool, or "all tools".
4. **Effect:** Allow / Deny / Require approval (FR-016–FR-018).
5. **Conditions (optional):** time window (e.g. weekdays 09:00–18:00); argument constraints (e.g. `email.send` only when every `to` address is in `…@kenhuangus.com`… — Ken's own domain; example only); per-agent rate-limit override for this rule.
6. **Priority:** rules evaluate top-down, first match wins. The list is draggable. The final row is always the pinned default-deny (FR-017) — visible, not implied.

**Raw mode:** a toggle switches the form to a JSON/YAML editor with schema validation and a "back to form" button that re-parses into fields when possible. Both modes produce the same stored rule.

**Dry-run / preview (FR-019, AC-12):** beside every unsaved rule, a **Preview** button runs the rule set against (a) the last 7 days of audit history and reports counts: would-allow / would-deny / would-require-approval, plus the list of calls whose outcome would change; and (b) a handful of synthetic sample calls (one per tool) for the "no history yet" case. Nothing is enforced during preview. Enforcement only happens on **Save as new version**.

**Version history:** every save creates an immutable version (v1, v2, …) with timestamp, author, and note. The history view shows a diff between any two versions. Rollback creates a *new* version copying the old content — history is never rewritten, matching the append-only audit philosophy (FR-032).

**Change classification.** Every save records a change classification — material or non-material — alongside the version. A MATERIAL change to a standing instruction or mandate (scope widened, new allow rule, allowed classes changed, expiry extended, purpose text changed) invalidates affected unconsumed grants and flags pending approvals referencing it for review (FR-PAA04-003; enforced at 2.8 step 9 via the policy-supersession check, reason `policy_superseded`). Non-material changes (notes, display names, ordering with identical semantics) preserve grants. **Admin-action audit:** every policy save, rollback, revocation, and credential rotation emits an audit event as an admin action (FR-041).

**Template-bound notice rule (FR-PAA07-005).** A standing policy-rule type — not an approval grant (see DQ-3 below). It binds an audience list, a template id, and a schedule (for example, a weekly status email to a fixed list with a fixed template). Each execution is allowed only if the rendered content matches the template within the declared constraints (fields, recipients, timing); any deviation requires a normal step-up approval. Every execution is audit-logged. One-off sends always need their own approval; a notice rule never authorizes them.

---

## 6. Agent-onboarding flow per platform

Each flow is split into **platform-UI steps** (in the agent's own interface) and **console steps** (in the gateway). Uncertain steps are flagged, not papered over.

### 6.1 Meta Muse

| # | Where | Step |
|---|---|---|
| 1 | Console | Create agent identity (`agent_muse_main`). Assign scopes and an initial policy set. |
| 2 | Console | Issue exactly one credential: an OAuth 2.1 client ID + secret by default. The long-lived bearer fallback is issued **only** if the platform has demonstrably failed OAuth verification, recorded in the console with the test date; fallback is never the default and never issued alongside OAuth credentials (FR-011, Fix A). |
| 3 | Muse UI | Register the gateway's public HTTPS URL as a Custom Connector (per the brief: user supplies the URL; Muse builds the integration in its VM). |
| 4 | Muse UI | Store the issued credential in Muse's Secure Credentials Store (per the brief). ⚠️ Exact field mapping unverified (OQ-1). |
| 5 | Console | Verify first connection: checklist shows session established, client-reported identity + transport logged (FR-006), `tools/list` received, test `calendar.list` call succeeds, audit row present (AC-01). Record **which** auth method was verified (OAuth 2.1 or conditional fallback bearer) with the verification test date. |
| 6 | Console | If Muse presents no stable client identity, the gateway-assigned identity is the source of truth (OQ-2 recommendation). Document what was observed. |

**Revocation:** Agents page → Revoke. Sessions dropped, tokens revoked immediately, subsequent calls denied (FR-015, AC-08, story 4).

### 6.2 Grok Bot

| # | Where | Step |
|---|---|---|
| 1 | Console | Create agent identity (`agent_grok_main`). Assign scopes/policies. |
| 2 | Console | Issue exactly one credential: OAuth 2.1 client ID + secret by default; the conditional bearer fallback only after a failed OAuth verification test, recorded with the test date (FR-011, Fix A). |
| 3 | Grok UI | Add the gateway in Plugins settings (name + public HTTPS URL) or ask the bot in chat (per the brief). ⚠️ Exact fields and auth support unverified (OQ-3). |
| 4 | Console | Verify first connection: same checklist as Muse (AC-02), recording which auth method was verified with the test date. |
| 5 | Console | If several Bots share the account, issue one gateway identity per Bot and record the mapping visibly in the console (OQ-4 recommendation). Per-Bot distinguishability is unverified — flag, don't assume. |

**Revocation:** same one-action revoke as Muse.

### 6.3 OpenAI Dots (provisional — no MVP build)

Per the requirements, the Dots-via-ChatGPT-plugins path is the thinnest-documented claim (OQ-5) and explicitly out of MVP. The design therefore specifies **no Dots onboarding flow** — only a verification spike to run before any design work:

1. Connect a custom MCP plugin in ChatGPT.
2. Check whether a Dot sees and can invoke it.
3. Record what identity the Dot presents to the server.

If the spike fails, Dots stays out. The endpoint is kept generic (FR-INT-004) so no Dots-specific protocol work is needed either way.

---

## 7. Audit-log viewer UX

**Filters** (FR-034, story 20): agent (multi-select), connector, tool, decision (allowed / denied / allowed_via_approval / approval_required / approved / denied-by-approver / expired / injection-blocked / upstream-failure), time (presets: 1h / 24h / 7d / 30d / custom range), free-text search over tool names and redacted argument text. Filters combine with AND. Result count shown before export.

**Redaction display conventions** (FR-030, NFR-DATA-001): redaction happens *before* the row is written — the viewer never has raw values to leak. Redacted values render as monospace tokens: `[redacted:email]`, `[redacted:phone]`, `[redacted:account-number]`, with a tooltip naming the rule that removed them. No partial masking in MVP (open question DQ-6 below asks whether Ken wants last-4 style hints for debugging).

**Approval linkage:** the three rows sharing an `approval_request_id` (paused call → approval decision → executed call) render as one expandable timeline in the detail drawer. Each row links to the others. The approval decision row shows approver, scope granted, and time window (FR-031).

**Export UX** (FR-033, story 19, AC-09): Export button → dialog with time-range picker (defaults to current filter range), format choice (JSON or CSV), and field list. Produces a download. The export itself is written to the audit log (who exported what range, when) — reading the log is an audited action.

**Append-only:** no edit or delete controls exist in the UI (FR-032). Retention default 90 days, configurable (NFR-DATA-002, OQ-10).

---

## 8. Traceability: requirements → design

| Requirement | Design section |
|---|---|
| FR-001–FR-004 (endpoint, Streamable HTTP, multi-agent) | 2.1–2.2, 2.8 |
| FR-005 (SDK pin) | build-time constraint; console Settings shows pinned SDK version |
| FR-006 (client identity logging) | 6.1/6.2 verification checklist, agent session panel |
| FR-007–FR-010 (connector registry) | 2.2 inventory, Connectors page (3.2) |
| FR-011–FR-015 (identity, tokens, revocation) | 2.6, 4.2, 6.x |
| FR-016–FR-020 (policy engine, dry-run) | 2.7, 2.8, 4.3, 5 |
| FR-021–FR-024 (vault) | Vault & Settings page (3.2); secrets never in UI |
| FR-025–FR-029 (inspection, guardrails) | 2.4 (schemas), 2.7 (error codes) |
| FR-030–FR-034 (audit) | 4.5, 7 |
| FR-035–FR-038 (console) | 3, 4 |
| FR-039–FR-041 (admin auth audit, login rate-limit, admin-action audit) | 2.6 (admin auth endpoints), 5 (policy-versioning admin-action audit) |
| FR-042 (CSRF; per-decision re-auth for destructive scopes) | 2.6 (decision endpoint), 2.7 (destructive-action registry) |
| FR-INT-001–004 (platform reachability) | 6.x |
| AC-01, AC-02 | 6.1, 6.2 verification checklists |
| AC-03–AC-08 | 2.7, 2.8, 4.4, 7 |
| AC-09 | 7 export UX |
| AC-10 | build-time; surfaced in Settings |
| AC-11 | design target noted in 1; load-test hook in Settings |
| AC-12 | 5 dry-run/preview, 2.6 dry-run endpoint |
| OQ-1–OQ-5 | 6.x (flagged; OQ-1/OQ-3 resolved to the Fix A single-credential rule) |
| OQ-6–OQ-10 | passed to architect/Ken; see DQ list below |
| FR-PAA01-001 (MVP) | 3.2 (Mandates page), 6.1/6.2 onboarding (session binding) |
| FR-PAA01-002 (MVP) | 6.1/6.2 onboarding, 2.8 (grant check requires live mandate) |
| FR-PAA01-003 (MVP) | 3.2 (Mandates page), 2.8 (deny path) |
| FR-PAA01-004 (MVP) | 4.2 (pause/end), 2.8 steps 9–10 (queued requests canceled as denied; approved-but-unconsumed grants invalidated; live-mandate check at grant consumption) |
| FR-PAA01-005 (MVP) | 3.2 (Mandates page — delegation chain) |
| FR-PAA01-006 (MVP) | 3.2 (Mandates page), 4.4 (card shows purpose + duration) |
| FR-PAA01-007 (MVP) | 7 (audit viewer) |
| FR-PAA01-008 (MVP) | 3.2 (Mandates page), 4.4 (card) |
| FR-PAA02-001 (MVP) | 2.2 inventory, 4.4 (card) |
| FR-PAA02-002 (MVP) | 2.2 (`email.settings.write` sensitive), 4.4 (protected-flow card) |
| FR-PAA02-003 (MVP) | 2.6 (decision endpoint), 4.4 |
| FR-PAA02-004 (MVP) | 2.2, 4.4 (untrusted-content label) |
| FR-PAA02-005 (MVP cond.) | 2.2 (`email.settings.read`), 3.2 (Connectors page review surface) |
| FR-PAA03-001 (MVP cond.) | 3.2 (Context boundaries page) |
| FR-PAA03-002 (MVP) | 5 (purpose-bound rules), 3.2 (Context boundaries page) |
| FR-PAA03-003 (MVP) | 3.2 (Context boundaries page), 4.4 (card flags) |
| FR-PAA03-004 (MVP) | 4.4 (exact-content preview), 2.8 (approval flow) |
| FR-PAA04-001 (MVP) | 3.2 (Mandates, Policies pages), 4.3 |
| FR-PAA04-002 (MVP) | 4.3 (rule builder), 3.2 (Mandates page) |
| FR-PAA04-003 (MVP) | 4.3 (version history), 4.4 (flagged pending approvals) |
| FR-PAA04-004 (MVP) | 4.3 (confirm + diff), 7 (audit entry) |
| FR-PAA05-001 (MVP) | 3.2 (Approvals page — counterparty records), 4.4 (delta display) |
| FR-PAA05-002 (MVP) | 2.8 (new-payee auto-sensitive), 4.4 |
| FR-PAA05-003 (MVP) | 4.4 (counterparty-evidence section) |
| FR-PAA05-004 (MVP) | 4.4 (untrusted-content rendering) |
| FR-PAA05-005 (MVP cond.) | 4.4 ("no independent record available" state) |
| FR-PAA06-001 (MVP) | 4.4 (term-sheet section), 7 (audit record) |
| FR-PAA06-002 (MVP) | 2.8 (argument-hash grant matching, canonicalization) |
| FR-PAA06-003 (MVP cond.) | 2.7 (retry semantics), 4.4 |
| FR-PAA06-004 (MVP) | 7 (receipt against approval) |
| FR-PAA07-001 (MVP) | 2.2 (`email.draft` vs `email.send`), 2.3 schemas |
| FR-PAA07-002 (MVP) | 4.4 (audience + content preview), 2.8 (hash-bound grant) |
| FR-PAA07-003 (MVP) | 2.8 (grant invalidation on material change), 4.4 |
| FR-PAA07-004 (MVP cond.) | 4.4 (auth fact vs authorization) |
| FR-PAA07-005 (MVP) | 5 (template-bound notice rule — a standing policy rule, not a grant); every execution audit-logged (7) |
| FR-PAA08-001 (MVP) | 4.2 (household role on agent identity), 5 (role-scoped rules) |
| FR-PAA08-002 (MVP) | 4.4 (audience expansion escalates) |
| FR-PAA08-003 (MVP) | 4.2 (separate identities) |
| FR-PAA08-004 (MVP) | 7 (data owner + role on access rows) |
| FR-PAA09-001 (MVP) | 4.4 (incentives section, no urgency language) |
| FR-PAA09-002 (MVP) | 4.4 (flag display) |
| FR-PAA09-003 (MVP) | 2.8 steps 3 and 10 (refusal cooldown: `cooldown_active` on identical re-invoke inside the cooldown; 24h default, tunable) |
| FR-PAA09-004 (MVP) | 3.2 (Vault & Settings — recorded criteria), 4.1 (one-action cancel) |
| FR-PAA10-001 (MVP) | 4.1 (global stop), 4.2 (per-agent pause) |
| FR-PAA10-002 (MVP) | 4.2 (lifecycle states), 3.2 (Agents page) |
| FR-PAA10-003 (MVP) | 4.1/4.2 (per-item status) |
| FR-PAA10-004 (MVP) | 4.1 (received-vs-enforced acknowledgments), 2.7 (state-naming errors) |
| FR-PAA10-005 (MVP) | 7 (irreversible marker on audit row) |

---

## 9. Design open questions

Things the designer needs from Ken or the architect before implementation. Numbered DQ to distinguish from the requirements' OQ list.

- **DQ-1 — Approval delivery channel. DECIDED:** in-console plus email-to-Ken on each new approval request for MVP (implemented in §2.8 step 5; 00 §7 parameter 7, 00 §9 decision 3 closed). Mobile push is explicitly out of MVP. The design above stands as decided; no further Ken input needed on the channel.
- **DQ-2 — Dry-run data source.** AC-12 specifies the last 7 days of audit history. For a fresh install with no history, are synthetic sample calls (one per tool, hand-written) acceptable as the preview corpus? Architect confirms feasibility.
- **DQ-3 — Approval grant semantics. RESOLVED:** MVP ships one-time exact-call grants only; windowed grants are deferred post-MVP. The proposed third option — standing scoped grants — is rejected as redundant: it overlaps with policy allow rules, so no third grant type exists. Template-bound recurring notices (FR-PAA07-005) are implemented as a standing POLICY RULE type (the template-bound notice rule in §5), not a grant — the tension with a third grant type is resolved by not creating one.
- **DQ-4 — Argument constraints in policies.** The rule builder supports `to`-domain allowlists as an example. Which real constraints does Ken want at MVP: recipient domains for `email.send`, repo allowlist for `code.*`, attendee rules for `calendar.create`? Ken picks the set; the form only builds fields for what exists.
- **DQ-5 — Admin credential strength.** FR-036 requires "at minimum a strong admin credential." Is password + TOTP required for MVP, or password alone with a forced-rotation policy? Ken decides; the login screen differs.
- **DQ-6 — Redaction display.** MVP shows full `[redacted:type]` tokens. Does Ken want partial hints (e.g. last 4 of a phone number) for debugging, accepting the small data-exposure tradeoff? Ken decides.
- **DQ-7 — Default rate limits.** FR-028 requires configurability but no values. Proposed design targets: 60 calls/min and 1,000/day per agent default, plus the per-agent pending-approval cap (default 5, FR-028). Cost budgets are post-MVP (FR-029) and take no value. Ken confirms or adjusts.
- **DQ-8 — Connector health semantics.** What counts as "healthy": credential valid + API reachable, checked every 5 minutes? Architect confirms cost/latency; Ken confirms the cadence shown in the UI.
- **DQ-9 — Dashboard windows.** "Today" counters: calendar day in which timezone (Ken's local vs UTC)? Ken picks; default to his local timezone.

---

## 10. Explicit non-decisions

Deferred to the architect (Phase 3) or later phases, deliberately not designed here:

- Hosting and TLS termination (OQ-6), vault KMS choice (NFR-SEC-002), database selection for audit storage.
- OAuth 2.1 grant flows and token format internals — decided; see 03 §2 (two token layers, lifetimes, revocation). The earlier non-decision was stale after Phase 3.
- Prompt-injection detection technique (patterns in MVP; semantic judge later — out of MVP per requirements).
- Multi-user admin roles, Dots support, scanner integration, HA — all out of MVP per requirements §8.

---

*Mockup: `mockups/dashboard.html` — static HTML mock of the admin dashboard (mock data, clearly labeled).*
