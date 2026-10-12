# Personal Agent Security Gateway — Architecture

**Document:** `docs/03-architecture.md`
**Phase:** 2 of 4 (Systems Architecture) — planning only, no implementation
**Requirements baseline:** `docs/01-requirements.md`
**Status:** Draft for review. Implementation is gated on Ken's go-ahead.

Conventions: every claim about a third-party platform, SDK, or hosting
service is either from the brief/requirements or stated as the architect's
own judgment. Anything unverifiable is flagged, not asserted. Numbers are
design targets, never benchmarks. No prices are quoted as facts; pricing
statements are qualitative and marked where unverified.

---

## 1. System architecture

### 1.1 Components

The gateway is one deployable service with nine logical components.
MVP runs them as a single stateful process (NFR-REL-001); the boundaries
are drawn so the process can be split later without re-design.

| Component | Responsibility | Trust posture |
|---|---|---|
| MCP server | Public Streamable-HTTP endpoint. Handles `initialize`, `tools/list`, `tools/call`, session management, transport-level auth. | Internet-facing. Treats every connected client as untrusted until verified (NFR-SEC-003). |
| Connector registry + adapters | Pluggable adapters to real systems. Each adapter declares tools, input schemas, required scopes, sensitivity labels (FR-007, FR-008). MVP: email (send/read), calendar (read/write), one code host (read-first; writes sensitive, per OQ-7 recommendation). | Trusted code, untrusted data. Adapters parse upstream responses; their outputs enter the inspection pipeline. |
| Identity service | Registers agent identities. Runs OAuth 2.1 flows for agents. Issues short-lived scoped tokens per tool call (FR-011–FR-015). Holds revocation state. | Trusted. Its signing keys are the gateway's root of trust. |
| Policy engine | Evaluates every tool call against per-agent/per-tool/per-action allow/deny rules. Default-deny (FR-016–FR-018). Supports dry-run evaluation (FR-019). | Trusted. Must be deterministic and fast (FR-020, NFR-PERF-001). |
| Credential vault | Stores upstream credentials (OAuth refresh tokens, API keys) encrypted at rest (FR-021). Releases them only to the connector adapter that needs them, never to agents or the console (FR-022). Logs every internal read (FR-024). | Highest-trust zone. Narrowest possible API surface. |
| Inspection pipeline | Validates tool-call inputs against schemas (FR-025). Scans tool outputs for prompt-injection patterns (FR-026). Redacts configured PII (FR-027). Enforces rate limits and the per-agent pending-approval cap (FR-028). | Trusted. Sits between untrusted upstream data and untrusted agents. |
| Audit store | Append-only log of every tool call, decision, inspection event, and approval (FR-030–FR-032). Search + JSON/CSV export (FR-033, FR-034). | Trusted. Append-only enforced at the application layer and (where supported) at the storage layer. |
| Approval service | Holds pending sensitive-action requests. Notifies the admin console (FR-037). Default-deny on timeout (OQ-8 recommendation: configurable window, default 15 min). | Trusted. Timeout semantics are part of the fail-closed design. |
| Admin console | Web UI for agent registration/revocation, policy editing, approval decisions, audit browsing, connector health (FR-035–FR-038). Authenticated with a strong admin credential in MVP (FR-036). | Internet-facing admin surface. Hardened per NFR-SEC-005. |

### 1.2 Data flow for a single tool call

Numbered steps. Each step names the component and the trust boundary
being crossed.

**Ordering note (Fix B, MF-4):** this section's step order was changed
from the original draft: input validation now runs before policy
evaluation, and mandate validity is checked at session binding. The
order below is authenticate → validate inputs → check mandate liveness → evaluate policy →
approval → mint token → execute → inspect output → audit. Schema
validation failure on a sensitive tool returns `invalid_input` and
never creates an approval request. No other reordering was made.

1. **Agent → MCP server.** The agent's platform opens a Streamable-HTTP
   session to the public HTTPS endpoint (FR-001, FR-002, FR-INT-001/003/004).
   Transport auth is presented (see §2). The agent credential (Fix A) is
   required on every request — including `tools/list` and `initialize`;
   there is no anonymous surface enumeration, and unauthenticated callers
   get `auth_failed` (02 §2.1, 02 §2.7). Identity checks include lifecycle
   state: a paused agent gets `agent_paused`, a canceled agent gets
   `agent_canceled`, distinct from `agent_revoked` (FR-PAA10-002).
2. **MCP server → Identity service.** The session is bound to a registered
   agent identity AND to an active mandate (FR-PAA01-001, FR-PAA01-002).
   Unknown or revoked identity → reject before any tool logic runs
   (FR-004, FR-006, FR-015). Expired, paused, ended, or withdrawn mandate
   → deny before any tool logic runs (FR-PAA01-004).
3. **MCP server → Inspection pipeline: input validation.** Arguments are
   validated against the tool's declared schema (moved ahead of policy
   evaluation per MF-4). Malformed → structured error, logged (FR-025);
   a schema-failed sensitive action never creates an approval request.
4. **Inspection pipeline → Policy engine.** The `tools/call` request
   (agent, tool, action, arguments) is evaluated. Mandate scope is checked
   before rules: an action class outside the mandate's allowed classes is
   denied (`mandate_scope_exceeded`), and no allow rule can rescue an
   invalid mandate (FR-PAA01-002, FR-PAA01-003). Active one-time grants for
   (agent, tool, argument-hash) are checked before rule evaluation; a
   matching unexpired grant short-circuits to `allowed_via_approval`
   (Fix B, MF-7). **Grant consumption requires a live mandate (BLOCKER-1):**
   a matching grant alone is not enough — the gateway verifies the mandate
   is still live at consumption time. A withdrawn mandate denies the call with
   reason `mandate_withdrawn`, an expired mandate with reason `mandate_expired`,
   a paused mandate with reason `mandate_paused` (an audit event is recorded in
   each case), and the gateway invalidates all remaining unconsumed grants under
   that mandate (FR-PAA01-004 covers approved-but-unconsumed grants, not just
   queued approval requests). A dead mandate can never authorize a call — this
   keeps the §1.4 PAA01 row's "grant check requires live mandate" true.
   **Policy-supersession check (FR-PAA04-003):** each grant records the policy
   version it was issued under; a MATERIAL change to the standing instruction
   or mandate since issuance (02 §5 change classification) denies the call with
   reason `policy_superseded` and flags it for re-approval; non-material changes
   preserve grants. Grant consumption is atomic (compare-and-consume /
   single-flight): two concurrent re-invocations cannot both consume a
   one-time grant — the first consumes it, the second finds the grant already
   consumed and gets `already_executed`. Agent revocation kills grants
   immediately. No matching allow rule → deny and log
   (FR-016, FR-017).
5. **Policy engine → Approval service (only for sensitive actions).** If
   the action is marked sensitive (FR-018), execution pauses. Approval
   requests are created idempotently per the 02 §2.8 step-3 lookup order:
   pending dedupe returns the existing `apr_…` ID, a consumed grant returns
   `already_executed`, an identical denied request inside the cooldown (or a
   pair under denial-streak escalation) returns `cooldown_active` — all before
   the per-agent pending-approval cap check, so an at-cap agent re-submitting
   an identical pending request gets the existing `apr_…` ID, not
   `approval_queue_full`. The argument hash is HMAC-SHA256 of the canonicalized
   arguments with the gateway-held key (02 §2.8 step 3). The approvals table stores the evidence
   subset in cleartext — the approver-visible decision fields per the
   02 §2.8 step 4 evidence rule (recipient/payee, amount/currency,
   audience, rendered content preview) — plus the redacted full argument
   set, plus an HMAC-SHA256 (gateway-held key) of the canonical full
   arguments: never plaintext full arguments (04 NH-4, NFR-DATA-001, with
   the evidence-subset exception). The approval service notifies the console
   (FR-037)
   and the email-to-Ken notification fires over the dedicated exempt
   system notification path (not the policy-gated `email.send`
   connector). If the platform's agent cannot poll, the console's
   "execute on approval" path executes the approved call server-side
   (MF-11).
   The `approval_status` lookup is bound to the caller's agent identity
   (MF-5); cards render arguments as inert preformatted text with a
   structured consequence summary and a static "untrusted content" label
   (MF-6); a per-agent pending-approval cap applies (default 5, MF-9).
   Approve → continue. Deny or timeout → deny and log (AC-04).
6. **Identity service → token minting.** The gateway mints a short-lived
   token scoped to exactly this agent, tool, and action (FR-012, FR-013).
   The raw vault credential is never exposed outside the vault boundary.
7. **Connector adapter → upstream system.** The adapter exchanges the
   short-lived token for upstream access (or uses the vault credential
   server-side, per connector design — see §2) and performs the call.
   Upstream failure → structured error, gateway stays up (NFR-REL-002).
8. **Connector adapter → Inspection pipeline.** The upstream response
   re-enters the gateway. Prompt-injection scan runs (FR-026): detection →
   block or redact per policy, log the event (AC-06). PII redaction runs
   per policy (FR-027); redaction happens before the response reaches the
   agent AND before anything is written to audit (NFR-DATA-001, AC-07).
   PAA10 hooks also fire here: code-artifact redaction, label-aware
   filtering, trigger-content flagging (see §1.4).
9. **Inspection pipeline → rate accounting.** Per-agent rate counters
   update (FR-028). Limit exceeded → deny with structured error. Cost
   budgets are out of MVP (MF-13); the budget row in §7 is superseded.
10. **Audit store ← everything.** The call record (agent, tool, action,
    timestamp, decision, redacted arguments), the inspection events, and
    any approval record are appended (FR-030–FR-032, NFR-OBS-001).
    PAA10 fields (mandate_id, term sheets, counterparty deltas, irreversible
    markers, data-owner labels) ride on the same row (see §1.4).
11. **MCP server → Agent.** The redacted, validated tool result is
    returned over the Streamable-HTTP session.

### 1.3 Trust boundaries

In MVP all nine components run in one process (NFR-REL-001). Every
boundary below is therefore logical-in-MVP, physical later — e.g.,
vault↔adapter separation is code discipline, not a process or
network boundary, until the components are split.

- **Public internet ↔ MCP server (logical in MVP).** TLS 1.2+ only (NFR-SEC-001). All
  client-supplied data (identities, arguments, session headers) is
  untrusted input.
- **MCP server ↔ internal components (logical in MVP).** Internal only; never exposed.
  The MCP server is the sole ingress for agent traffic.
- **Vault ↔ everything else (logical in MVP).** The vault has no network ingress of its
  own. The only caller is the connector-adapter layer (via a narrow
  internal API), and the only data it returns is short-lived derived
  credentials, never stored secrets (FR-022).
- **Upstream systems ↔ connector adapters (logical in MVP).** Upstream responses are
  untrusted data (prompt-injection risk). They always pass through the
  inspection pipeline before reaching an agent or the audit log.
- **Admin console ↔ everything else (logical in MVP).** Authenticated admin surface.
  The console can read redacted audit data and manage policy, but it
  cannot read vault secrets (FR-022) or modify audit entries (FR-032).

### 1.4 PAA10 enforcement points in the tool-call flow

Each entry names the §1.2 step(s) in Fix-B order, the intercepting
component(s), and the check or mechanism that fires. All mechanisms are
grounded in `05-paa10-mapping.md`; its ⚠️ flags carry over. The
provider-side sub-controls in mapping §(i) are not gateway features and
are not claimed here.

Supporting state (additive to the config SQLite DB in §5; no new
infrastructure): mandate records, counterparty records, recorded
decision criteria, lifecycle state. All new stores are admin-readable
and audit-logged.

| PAA | Step(s) | Intercepting component(s) | Check / mechanism |
|---|---|---|---|
| PAA01 mandate drift | 2, 4, 5, 10 | Identity service (session bound to active mandate); Policy engine (mandate scope before rules; grant check requires live mandate); Approval service (card shows purpose + remaining duration; withdrawal cancels queued requests); Audit store (`mandate_id` on every row) | Deny on expired/paused/ended/withdrawn mandate; deny `mandate_scope_exceeded` outside allowed classes; read-only mandate never authorizes communicate/transact actions; delegated calls need a parent `mandate_id` with equal-or-narrower scope (FR-PAA01-001…007) |
| PAA02 account/recovery takeover | 3, 4, 5, 8, 10 | Inspection pipeline (code/OTP/reset-link patterns redacted before delivery AND before audit write; event logged); Policy engine (recovery-affecting actions sensitive by default); Approval service (console-only protected flow; agent-supplied confirmations are not evidence); Connector registry (read-only forwarding/filter visibility) | Familiar name, thread, or identity never authorizes code disclosure; `email.send`/`forward` carrying a redacted artifact is blocked or escalated with the untrusted-content label (FR-PAA02-001…004) |
| PAA03 context exposure | 4, 5, 7/8, 10 | Connector adapters (label `work`/`private`/`family` on returned data; filter per agent clearance); Policy engine (purpose-bound rules; purpose registry); Inspection pipeline (cross-context leakage flagged + redacted, logged); Approval service (external-disclosure preview of exactly what would leave) | Tool outputs carry label metadata into redaction and audit; secondary use needs a purpose-matched rule; no silent repurposing (FR-PAA03-001…004) |
| PAA04 memory corruption | 8 (store boundary), console | Admin console (all standing-instruction changes need explicit confirm + before/after diff + provenance); Inspection pipeline (tool outputs labeled untrusted; no pipeline writes extracted content into mandate/policy/grant stores — auto-promotion is architecturally absent); Policy engine/Approval service (provenance on stored rules; inferred vs explicit distinguished) | Corrections propagate to dependent grants and pending approvals; audit records change scope and retention limits (FR-PAA04-001…004) |
| PAA05 counterparty deception | 4, 5, 8, 10 | Policy engine (new-payee auto-sensitive for commitment-adjacent actions; changed-details escalation); Approval service (evidence card: recipient, claim source, delta vs recorded record, urgency/relationship flags); Inspection pipeline (extracts claim-source metadata at output time; flags time-pressure/authority-claim language); Connector registry (read-only directory lookup where supported ⚠️) | Agent-supplied legitimacy assertions rendered as untrusted content, never evidence; spending limits never presented as counterparty verification (FR-PAA05-001…004) |
| PAA06 unauthorized spending | 4, 5, 6/7, 10 | Approval service (approval record = term sheet: payee, amount/currency, fees, dates, recurring, cancellation); Policy engine (duplicate/parallel commitment gating); Grant layer (argument-hash re-check at execution; material mismatch → deny pending re-approval); Connector registry (status-check tools; retry-after-unknown blocked until status verified) | Unparseable economic effect → deny (FR-PAA06-001…004) |
| PAA07 social representation | 3, 4, 5, 7 | Policy engine (draft vs send are distinct actions; send always sensitive); Approval service (approval binds audience-hash + content-hash; inert full-message and recipient preview); Inspection pipeline (step 3 validates send args match the approval; step 7 invalidates the grant on audience/content change); Connector adapters (origin disclosure where the service supports it — conditional) | Audience expansion, message edits, or onward representation each need a new approval; verified identity shown as auth fact, not authorization (FR-PAA07-001…004) |
| PAA08 household/bystander | 2, 4, 5, 8, 10 | Identity service (household role on the agent identity); Policy engine (role-scoped rules — one member's agent cannot satisfy another member's private-labeled rules); Inspection pipeline (recipient-list expansion checks; escalation names new recipients); Audit store (every access records data owner + role; retention minimized per label) | Distinct or distrusted roles get separate identities, never shared credentials (FR-PAA08-001…004) |
| PAA09 manipulation of choice | 5, 8, 10 | Approval service (incentives section on card: sponsor/placement signals, comparison to recorded criteria, trigger source; no urgency language on the card; refusal cooldown suppresses re-presentation); Inspection pipeline (flags false-urgency and deceptive relationship claims in trigger content); Policy engine (recorded-criteria store); Admin console (one-action cancel denies pending approvals immediately) | Flags ride with the approval record into audit (FR-PAA09-001…004) |
| PAA10 loss of control | 1–2, 5, 10 | Identity service (revoke kills identity; sessions, derived tokens, grants invalidated; fallback bearer gets the immediate-revocation path); Admin console (global stop; per-agent pause/revoke; inventory; per-item status for queued/delegated/in-flight work; received-vs-enforced acknowledgments); Approval service (queued requests show lifecycle; cancellation denies immediately); Audit store (irreversible markers with pending obligations; export as continuity) | Agent-facing errors name the state (paused/revoked/canceled), never a silent hang (FR-PAA10-001…005) |

### 1.5 Traceability to the PAA10-derived requirements

**Realized by the mechanisms in §1.4:** FR-PAA01-001…007,
FR-PAA02-001…004, FR-PAA03-002/003, FR-PAA04-001…004, FR-PAA05-001…004
(gateway parts), FR-PAA06-001/002/004, FR-PAA07-001…003, FR-PAA08-001…004,
FR-PAA09-001…004 (trigger-content scope), FR-PAA10-001…005.

**Conditionally realizable — flagged, not asserted.** No mechanism is
invented for these; each is an open question for the M0 connector spikes:
- FR-PAA03-001/004 and FR-PAA08 label filtering need upstream
  sensitivity/ownership metadata at usable granularity → mapping AQ-1.
- FR-PAA05-003's evidence section: the read-only directory/address-book
  lookup exists only where a connector supports it; when absent the card
  says "no independent record available" rather than inventing one →
  mapping AQ-4 adjacent, provider-side sub-control 9.
- FR-PAA06-003 status-check gating needs per-connector
  transaction-status endpoints → mapping AQ-4.
- FR-PAA07-004 origin disclosure is unrealizable for any connector whose
  service does not support adapter-settable origin markers; flagged per
  connector rather than silently dropped.
- FR-PAA09-001 platform incentive metadata: assume no platform exposes it
  (mapping AQ-3); the gateway covers trigger content visible in tool
  calls only.
- FR-PAA06 aggregate ceilings stay out of MVP with FR-029 (MF-13);
  mapping AQ-8 is not re-opened.

**Not gateway features by design.** The 14 provider-side sub-controls in
`05-paa10-mapping.md` §(i) (mandate propagation into platform subagents,
bypass-path elimination, stable client identity, recovery channels,
platform memory provenance and deletion, session/worker termination,
etc.) are outputs for the OWASP PAA10 project, not gateway scope. The
gateway enforces only what crosses its own boundary; the doc states
this limit rather than claiming more (mapping AQ-5).

---

## 2. AuthN/Z design

### 2.1 Gateway ↔ upstream systems (email, calendar, code host)

- The gateway acts as an OAuth 2.1 client to each upstream system.
  Upstream OAuth flows (authorization code + PKCE) are completed once by
  Ken in the admin console; the resulting refresh tokens and API keys go
  straight into the vault (FR-021).
- At call time, the connector adapter asks the vault for a derived,
  short-lived access token scoped to the connector's needs, uses it for
  the upstream call, and discards it. The agent never sees it (FR-012,
  AC-05).
- Where an upstream system only supports long-lived API keys, the key
  stays in the vault and is injected into the upstream request
  server-side. Same guarantee: never leaves the gateway.

### 2.2 The two token layers (Fix A)

There are exactly two token layers. Every token in the system is one of
them; no token exists outside this table.

| Layer | Name | Minter | Consumer | Scope semantics |
|---|---|---|---|---|
| 1 | Session credential | Identity service (OAuth authorization-server role; or the gateway itself when the conditional fallback bearer is issued) | Agent — presented on every MCP request | Carries the gateway-assigned agent identity and the policy claims the agent may invoke (FR-013a). Never contains upstream secrets. |
| 2 | Derived call token | Identity service — minted per authorized tool call | Connector adapter only, inside the gateway (vault-side) | Live bearer at the upstream API, bounded by the connector's registered upstream OAuth scopes (FR-013b). Minutes-long TTL. Never exposed to the agent in raw form. |

- The identity service attaches (agent, tool, action) claims to each
  derived call token as gateway bookkeeping. Upstream providers do not
  mint per-tool tokens, so these claims are NOT a cryptographic
  binding: a stolen derived token is valid for any upstream API within
  the connector's scopes until expiry (see T2).
- Derived call token lifetime: design target 5 minutes (FR-014);
  configurable. Session credential: 60-minute OAuth access tokens, or
  the fallback bearer with max age 90 days and mandatory rotation
  (00 §7, parameter 1).
- Revocation (FR-015): the agent's identity is marked revoked, which
  immediately denies all new calls and invalidates its sessions;
  in-flight derived tokens expire within their 5-minute window (AC-08).

### 2.3 Gateway authenticates the calling agent (MVP recommendation)

Three options were considered:

| Option | Fit | Problem |
|---|---|---|
| **OAuth 2.1 against the gateway** (gateway as authorization server; agent presents client credentials / auth code) | Strongest: standard, scoped, auditable (FR-011). | The brief cannot verify whether Muse or Grok MCP clients support OAuth 2.1 toward a custom server (OQ-1, OQ-3). |
| **Mutual TLS** | Strong, no token management. | Requires the platform to present a client certificate the gateway can verify. No evidence in the brief that either platform supports this. **REJECTED — considered and rejected: Fix A allows exactly one credential per agent (OAuth 2.1 primary, conditional bearer fallback only) and no third auth path.** |
| **Registration token (long-lived bearer per agent)** | Simple. Works with any client that can send an HTTP header. | Weaker than OAuth: bearer tokens are exfiltration-prone; needs rotation discipline. |

**Rule for MVP: single credential per agent (Fix A).** OAuth 2.1 is
the default. The gateway issues a long-lived per-agent bearer
fallback only for an agent whose platform has demonstrably failed
OAuth verification, recorded in the admin console with the test date
(FR-011). The fallback is never the default and never issued
alongside OAuth credentials. The gateway refuses agent connections
that cannot present at least a per-agent secret over TLS; there is
no third rung (no IP-allowlist downgrade — AOQ-1 marks it REJECTED).
The gateway-assigned agent identity is the source of truth for
authorization, not any platform-supplied client string (OQ-2
recommendation, FR-006).

### 2.4 Per-agent scoping

- Gateway-scope (FR-013a): the identity service attaches least-privilege
  policy claims (agent, tool, action) to the session credential and
  mints no derived call token outside them. A "token for
  `calendar.read`" cannot invoke `email.send` because the gateway
  refuses to mint it — enforcement is gateway bookkeeping, not a
  cryptographic property of the token.
- Upstream-scope (FR-013b): each connector registers with
  least-privilege upstream OAuth scopes; a derived call token's reach
  at the upstream API is bounded by those scopes.
- Sensitive actions are not in any token's scope by default; they
  require a live approval record from the approval service (FR-018).

### 2.5 Credential isolation guarantees

- **Where secrets live:** only in the vault, encrypted at rest with a
  key managed outside application config (KMS or equivalent at deploy
  time, NFR-SEC-002).
- **Who can read them:** only the connector-adapter layer, through a
  narrow internal API, and only at call time. Not the MCP server, not
  the policy engine, not the admin console, not the audit store, and
  never the agents (FR-022, FR-024).
- **Rotation:** the vault supports rotation with graceful expiry of
  derived tokens (FR-023, user story 12). Rotation is an admin-console
  action; in-flight calls finish on their short-lived tokens.
- **Audit:** every internal vault read is logged (FR-024) — but the log
  records *that* a credential was read and by which adapter, never the
  credential value.

---

## 3. MCP protocol specifics

### 3.1 Streamable HTTP transport requirements

- Public HTTPS with a valid public certificate (FR-001, FR-INT-001/003/004).
- The gateway must maintain MCP sessions per connected agent: session
  IDs bound to agent identities (FR-004). Session state lives
  server-side so revocation is immediate.
- No Server-Sent Events fallback is required for MVP; Streamable HTTP
  is the single transport. Plaintext HTTP from the internet is refused
  (NFR-SEC-001).
- **Session-auth semantics:** the agent credential (Layer-1 session
  credential) is validated on every request — the MCP session ID alone
  is never sufficient authentication. Session IDs are 128-bit random
  values bound to the validated agent identity at session
  establishment; agent revocation invalidates its sessions immediately
  (FR-015). See T2 for the session-ID-theft threat.

### 3.2 SDK comparison: Python FastMCP vs TypeScript MCP SDK

| Criterion | Python (FastMCP / MCP Python SDK) | TypeScript (MCP TS SDK) |
|---|---|---|
| Maturity | FastMCP's server-framework ecosystem is the strongest of the two in the architect's assessment: the most worked server examples and the most adapter-style code the architect could find. | Official SDK, mature, but a smaller server-framework ecosystem than Python's in the architect's assessment. |
| OAuth support | The OAuth account-takeover flaw was in the Python SDK; the fix line (≥1.30.0/2.2.0) is the known-good floor (FR-005). Python OAuth helper surface is, in the architect's judgment, the most documented of the two. | TS SDK also ships OAuth support and received the corresponding fixes; a smaller body of worked examples in the architect's assessment. |
| Streamable HTTP | Verify against named SDK versions in the M0 spike (00 §4 M0); claimed at "current versions" in the brief but no version numbers were supplied. | Verify against named SDK versions in the M0 spike. |
| Ecosystem | In the architect's assessment, the strongest connector-adapter ecosystem for this shape of work: email/calendar/code-host client libraries, HTTP tooling, and data-validation libraries are all available in Python. | Strong for web-facing services; thinner for the sysadmin-style integrations in MVP scope in the architect's assessment. |
| Team fit | Ken teaches AI engineers; Python is the lingua franca of that audience and of his existing scanner-adjacent work. A Python gateway is easier for him to audit, extend with new connectors, and hand to contributors. | TypeScript fits if the admin console were the dominant surface, but the gateway's core is protocol and policy logic, not UI. |

**Recommendation: Python, built on FastMCP.** Rationale (architect's
judgment): strongest connector library ecosystem for the three MVP
connectors, most worked OAuth examples (important given the OQ-1/OQ-3
unknowns), and best fit for Ken and his audience to read and extend.
The admin console can still be a separate small web app in any stack.

### 3.3 SDK version floor (hard)

**The MCP SDK the gateway builds on MUST be ≥ the fixed releases:
Python SDK 1.30.0 / 2.2.0 lineage or later (FR-005, AC-10).** This is a
hard floor, not a suggestion: the pre-fix versions carry the OAuth
account-takeover flaw where a malicious server could exfiltrate client
secrets, auth codes, and PKCE verifiers. The dependency manifest is
checked in CI, and a dependency scan must show no HIGH+ CVEs in the MCP
path before MVP is declared done (NFR-SEC-004, AC-10).

---

## 4. Deployment topology

Requirement: a single stateful service, publicly reachable over HTTPS
(FR-002, NFR-REL-001). Four options:

| Option | TLS termination | Cost profile | Operational burden | Secret management | MVP fit |
|---|---|---|---|---|---|
| **Fly.io** | Managed: automatic certificates per app/hostname. | Qualitative: a free allowance exists for small apps; a single small always-on instance is typically low single-digit dollars per month. Exact pricing unverified — confirm on their pricing page before committing. | Low. `fly deploy` from CI; built-in health checks; volumes for state. | Fly secrets (encrypted env at deploy); external KMS via cloud APIs if needed. | Good. Built for exactly this shape: one small always-on HTTPS service. |
| **Google Cloud Run** | Managed: automatic HTTPS on the provided domain; custom domains with managed certs. | Qualitative: generous free tier for low traffic; pay-per-request beyond that. A personal-use gateway would plausibly sit inside the free tier, but this is unverified — confirm before committing. | Low. Container deploy; scales to zero (note: cold starts; keep min-instances=1 for an approval-latency-sensitive gateway). | Google Secret Manager integration is native and clean — the best KMS story of the four for NFR-SEC-002. | Good, especially if Ken already lives in GCP. Cold-start behavior needs the min-instance setting. |
| **Plain VPS (Hetzner / DigitalOcean)** | Self-managed: Caddy or nginx with automatic Let's Encrypt. Well-trodden, but it is your job. | Qualitative: small VPS instances are typically a few dollars per month. Exact pricing unverified. | Highest of the four. OS patching, firewall, backups, and TLS renewal are all yours. | Self-managed: encrypted volume + a local key file, or wire in an external KMS. No native secret manager. | Acceptable. Maximum control, maximum chores. Fine if Ken wants one box he fully owns. |
| **Always-on machine + Cloudflare Tunnel** (e.g., a home server or mini-PC) | Tunnel egress: Cloudflare terminates public TLS; no inbound ports, no public IP needed. Origin TLS between cloudflared and the app is still configured. | Qualitative: the tunnel itself is free; the machine is sunk cost. Pricing of paid Cloudflare features unverified. | Medium. No port-forwarding or dynamic-DNS pain; but the machine must stay on, and you depend on Cloudflare's edge. | Same as VPS (self-managed), unless paired with a cloud KMS. | Reasonable for personal use. Removes the "public IP" problem entirely; adds a hard dependency on one vendor's edge and on home power/network. |

**Recommendation: Fly.io for MVP.** Rationale: lowest operational
burden for a single always-on HTTPS service, managed TLS with zero
ceremony, and a cost profile that fits personal use. Cloud Run is the
close second — pick it instead if Ken prefers GCP-native Secret
Manager for the vault key (NFR-SEC-002) or already deploys there. The
VPS and Tunnel options stay valid if he wants full ownership or has an
always-on machine; they trade chores for control.

This answers OQ-6 (hosting) with a default and a conditional.

---

## 5. Storage

What stores what, and why:

| Data | Technology (MVP) | Rationale |
|---|---|---|
| Agent registrations, policies, approvals state, connector configs, revocation lists | **SQLite** (single file, e.g., via SQLAlchemy) | Single stateful service (NFR-REL-001); zero operational burden; ACID; trivially backed up as a file. Postgres is overkill for one admin and 10 concurrent sessions (NFR-PERF-002). Migration path to Postgres is kept open via the ORM layer. |
| Audit log (hot, searchable) | **SQLite**, separate database file from config | Same rationale; keeps the append-only audit store physically separate from mutable config. Append-only enforced at the application layer (FR-032); the retention job archives expired rows to object storage past the configured window (NFR-DATA-002, default 90 days). |
| Audit exports | **Object storage** (e.g., S3/GCS-compatible bucket, or local files synced off-box) for JSON/CSV exports (FR-033) | Exports are bulk, infrequently accessed, and potentially large. Object storage is the right shape; local-disk staging with manual download is the MVP fallback. |
| Secrets (upstream OAuth refresh tokens, API keys) | **Vault component backed by encrypted-at-rest storage**: SQLite file or OS keyring equivalent, encrypted with a data key from a KMS (NFR-SEC-002) | Secrets must never sit in plaintext next to config. On Fly.io: Fly secrets hold the KMS/data-key reference; on Cloud Run: Secret Manager natively. Envelope encryption (KMS-held key encrypts a local data key) keeps the design portable across the hosting options in §4. |
| System-notification credential (M3 email-to-Ken notifier) | **Platform secret store (Fly secrets / GCP Secret Manager per hosting choice):** bootstrap deploy-time secret, held OUTSIDE the gateway vault | The M4 vault holds connector credentials only; the notifier must not transit the policy-gated `email.send` path (02 §2.8 step 5). Encrypted at rest per NFR-SEC-002 (key managed outside app config). Used only by the dedicated exempt notification path, whose content is limited to agent name, tool name, timestamp, and a console link. |
| Short-lived tokens, session state, rate-limit counters | **In-process memory + SQLite** | Token lifetimes are minutes (FR-014); loss on restart is acceptable because clients re-establish sessions. Rate counters persist in SQLite so a restart does not reset limits. |

**Encryption at rest (MVP):** the secrets store is encrypted with
envelope encryption; the KMS key lives outside application config
(NFR-SEC-002). The SQLite files for config and audit live on an
encrypted volume. No plaintext secrets in environment dumps, logs, or
backups.

**HMAC key lifecycle:** the gateway-held HMAC key used for argument
hashing (02 §2.8 steps 3–4) lives in the platform secret store (Fly
secrets or GCP Secret Manager per hosting choice) — NOT in the config
SQLite that gets backed up. Rotation is supported: stored hashes are
tagged with the key id, and a retired key is kept for verifying in-flight
lookups until no pending request references it.

**Notifier bootstrap secret rotation:** the exempt system-notification
credential (the M3 email-to-Ken notifier path) rotates via the platform
secret store on a documented schedule — max age 90 days (design target).
Rotation replaces the secret in the platform secret store and is
audit-logged as an admin action (FR-041). Reads of the secret are
audit-logged per FR-024.

**Backup (MVP):** nightly file-level backup of the three SQLite files
(config, audit, encrypted secrets) to object storage, with the KMS key
*not* in the backup. Backup blobs are encrypted at rest in object
storage (object-store server-side encryption), independent of the
encrypted volume for live files. Restore is a documented manual procedure.
Point-in-time recovery is out of scope for MVP.

---

## 6. Threat model (STRIDE-style)

Each row: threat → impact → mitigation → residual risk.

| # | Threat | Impact | Mitigation | Residual risk |
|---|---|---|---|---|
| T1 | **Malicious tool output / prompt injection via connector results.** An upstream email, calendar invite, or repo file contains injected instructions; the agent acts on them. | Agent performs unauthorized actions with the gateway's authority. | Inspection pipeline scans all tool outputs for injection patterns before delivery (FR-026); block-or-redact per policy; detection events logged (AC-06). Input schemas validated so injected content cannot smuggle extra parameters (FR-025). | Pattern-based detection misses novel phrasing. LLM-judge semantic detection is explicitly out of MVP (§8 of requirements). Residual: sophisticated injections may pass. |
| T2 | **Compromised agent credential.** Attacker holds the agent's Layer-1 session credential, a stolen session ID, or (host-side) a derived call token. | Attacker invokes tools as that agent, within its policy claims, until expiry or revocation. | Fix A splits the mitigation by token type, with the real blast radius stated honestly. The (agent, tool, action) claims on a derived token are gateway bookkeeping, not cryptographic (FR-013b): the gateway refuses to mint outside granted claims, but a stolen derived call token is a live bearer for **any upstream API within the connector's registered scopes** until its 5-minute expiry. Mitigations: 5-minute derived-token TTL; vault-side use only — derived tokens are never exposed to the agent in raw form (FR-012b); rotation of the underlying vault credential; the agent credential is validated on every request and session IDs are 128-bit random bound at establishment, with immediate session invalidation on revocation (§3.1). A stolen long-lived fallback bearer gets the immediate-revocation path, rotation discipline, and a console-visible "fallback auth in use" flag (MF-14). Per-agent rate limits cap damage (FR-028); cost-budget capping is out of MVP (MF-13). One-action revocation kills the identity immediately (FR-015, AC-08); every call is audited (FR-030). | Between theft and detection, the attacker has the agent's legitimate permissions. **Anomaly alerting (feasibility decision recorded):** OUT of MVP. Automated anomaly detection on agent behavior is not built in MVP — with per-agent rate limits, the pending-approval cap, and Ken reviewing the dashboard directly, alerting adds tuning burden without MVP payoff. Revisit post-MVP. Residual: detection speed depends on Ken watching audit anomalies. |
| T3 | **Malicious MCP client impersonation.** A rogue client claims another agent's identity. | Unauthorized tool calls billed to the wrong identity; audit misattribution. | Gateway-assigned identity is the source of truth, verified via OAuth 2.1 or per-agent registration token — never via client self-report (OQ-2 recommendation, FR-006, FR-011). Session details and transport metadata are logged per session. | If the underlying platform (Muse/Grok) does not provide a verifiable client identity (OQ-2, OQ-4 open), impersonation *within* a shared platform credential cannot be distinguished server-side. Residual until platforms expose stable client identities. |
| T4 | **Credential theft from the vault.** Attacker reads stored upstream credentials. | Full upstream account takeover (email, calendar, code host). | Secrets encrypted at rest with KMS-held keys (NFR-SEC-002); vault has no network ingress and the narrowest internal API; only the adapter layer can request derived short-lived credentials, never raw secrets (FR-022); every internal read is audited (FR-024); admin console cannot display secrets. | A full host compromise (root on the gateway box) defeats application-layer controls. Residual: host hardening and minimal attack surface are the backstop; HSM-backed keys are a later phase. |
| T5 | **Approval fatigue / social engineering of the approver.** Flood of approval requests trains Ken to click "approve"; or a request's context is misleading — including injected content aimed at the human approver, not the agent (e.g., "URGENT — approve immediately" in an email body). | Sensitive action executes that should not have. | Approvals are bounded one-time grants (FR-031); full context with redacted arguments shown per request (FR-037); default-deny on timeout so silence is safe (OQ-8 recommendation); every approval logged with approver identity. **Approver-targeted injection (MF-6):** card arguments render inert (preformatted text, no clickable links), with a structured consequence summary before any free text, a static "untrusted content" label, and no urgency language on the card. **Queue cap (MF-9):** per-agent pending-approval cap (default 5) returns `approval_queue_full`, blunting queue-flooding as a denial-of-attention attack. | Human factors remain. Residual: fatigue is a UI/UX problem — batching, risk-ranked presentation, and quiet hours are later-phase work. |
| T6 | **SSRF via connector adapters.** A tool argument (e.g., a URL to fetch, a webhook target) makes the gateway's server call an internal address. | Internal network probing, cloud-metadata credential theft. | Adapters validate and allowlist outbound destinations; no open-ended "fetch this URL" tool in MVP; egress from the gateway is restricted to the known upstream API hosts. Metadata endpoints are blocked at the network layer. | A new connector with a URL parameter reintroduces the risk. Residual: the SSRF review checklist is REQUIRED for every MVP adapter as part of FR-009 acceptance (not a nice-to-have) — no adapter ships without passing it. |
| T7 | **Log injection / PII leakage into audit.** Malicious tool output contains newlines/control characters or PII; it lands in the audit log unredacted. | Forged log entries; PII stored where it should not be. | PII redaction runs *before* the audit write, not after (NFR-DATA-001, AC-07); structured (JSON) log encoding neutralizes control characters; arguments stored are the redacted form (FR-030). | Redaction patterns are configured, not exhaustive. Residual: novel PII formats leak until patterns are updated. |
| T8 | **MCP-ecosystem trust: rogue server consent / client credential exfiltration.** The known SDK flaw class: a malicious MCP server tricks a client into leaking secrets, auth codes, PKCE verifiers. | Account takeover of the agent platform's OAuth identity. | SDK pinned ≥ the fixed releases (FR-005, AC-10, §3.3); client credential hygiene — never echo secrets/auth codes/verifiers to untrusted parties, strict redirect-URI validation, treat connected clients as untrusted until verified (NFR-SEC-003, FR-006); server verification to the extent the protocol allows. | The ecosystem is young and the flaw class is protocol-adjacent, not fully protocol-fixed. Residual: stay pinned to current SDKs and re-audit on every MCP spec change. |
| T9 | **Mandate replay / delegation-chain abuse.** A queued or previously valid call is replayed after the mandate was withdrawn or expired; or a broader-scope call is presented as delegated from a valid parent mandate. | Execution with revoked or exceeded authority. | Mandate validity checked at session binding and again before rule evaluation — no allow rule or grant rescues an invalid mandate (FR-PAA01-002); scope-class containment denies `mandate_scope_exceeded` (FR-PAA01-003); withdrawal cancels queued approvals as denied (FR-PAA01-004); delegated calls need a parent `mandate_id` with equal-or-narrower scope (FR-PAA01-005); `mandate_id` on every audit row (FR-PAA01-007). | Platform-spawned subagents invisible to the gateway cannot be chained (mapping AQ-2); any platform action path that bypasses the gateway voids the control (mapping sub-control 2). |
| T10 | **Claim-source deception / changed payment details.** Tool content carries a plausible-but-edited invoice, or a compromised familiar sender, with an attacker-controlled destination. Pattern scanning (T1) does not catch plausible business data. | Commitment or send to an attacker. | Counterparty records derived from audited calls; changed-details and new-payee escalation to approval; evidence-bearing approval cards with delta-vs-record display; agent legitimacy assertions rendered as untrusted content, never evidence; term-bound grants with argument-hash re-check at execution (FR-PAA05-001…004, FR-PAA06-001/002). | Truly independent verification (account-name APIs, sender authentication) is provider-side (mapping sub-control 9); a first-contact payee has no record to compare against, so the first commitment always needs console approval. |
| T11 | **Verification-code / recovery-artifact extraction.** Codes, OTPs, or reset links in tool output are read by the agent and forwarded, or used to take over recovery channels. | Account or recovery takeover through the agent. | Code-artifact patterns redacted before agent delivery AND before audit write; the redaction event is logged (FR-PAA02-001, FR-027 catalog); recovery-affecting actions are sensitive by default with a console-only protected approval flow (FR-PAA02-002/003); sends carrying redacted artifacts are blocked or escalated with the untrusted-content label (FR-PAA02-004). | Platform built-in tools that bypass the gateway are outside this control (mapping sub-control 5); upstream recovery-change events are not guaranteed API-visible (mapping AQ-1). |
| T12 | **Cross-context and bystander-data disclosure.** Private-labeled or bystander-incidental facts cross purpose or audience boundaries at output or send time. | Personal-data exposure to the wrong audience. | Label-aware retrieval filtering and purpose-bound rules; cross-context leakage flagged and redacted per policy; outbound disclosure gating with an exact-content preview; recipient-scope limits; retention minimization per label class; every access records the data owner and role (FR-PAA03-001…004, FR-PAA08-001/002/004). | Upstream label/ownership metadata is unverified at the needed granularity (mapping AQ-1); the platform mixing contexts inside its own memory is outside the gateway (mapping sub-control 7). |
| T13 | **Exempt notification-path abuse.** The M3 email-to-Ken notification path: a spoofed notifier message phishes Ken (the MF-6 attack class aimed at the approver); the bootstrap secret is compromised and used to send unauthenticated emails; tool arguments are injected into notification content; a request flood turns notifications into attention-DoS. | Ken acts on a forged approval prompt; the exempt path sends unauthenticated mail; injected content reaches Ken's inbox; attention-DoS degrades approval quality. | The notifier builds messages from a fixed field allowlist (agent name, tool name, timestamp, console link) — no free-text passthrough of tool arguments (02 §2.8 step 5); the bootstrap secret is held in the platform secret store, encrypted at rest per NFR-SEC-002, rotates on a documented schedule (max age 90 days, §5), and every read is audit-logged (FR-024); notification volume is bounded by the per-agent pending-approval cap (default 5), with per-agent notification digests or a short notification cooldown blunting attention-DoS; the sending service and sender identity are chosen at deploy and recorded in console config; a bounced or delayed notification falls back to the in-console queue, and the 15-minute approval window runs from request creation regardless of notification delivery. | The path is still email — sender-identity spoofing depends on the chosen sending service's authentication (SPF/DKIM/DMARC). Residual: phishing remains possible; Ken must verify approvals in the console, never from the email alone. |

---

## 7. Scalability and failure modes

**Fail-closed principle (explicit):** every failure, timeout, or
unavailable dependency defaults to *deny*. A tool call that cannot be
fully evaluated, approved, or audited does not execute. This principle
governs every row below.

| Failure | Behavior |
|---|---|
| **Gateway down** | All tool calls fail because there is no path to upstream systems except through the gateway. Agents receive transport errors. This is fail-closed by construction: no bypass path exists. Recovery is restart; sessions re-establish. |
| **Upstream API outage** (email/calendar/code host down) | Connector health check goes red in the console (FR-010, FR-038). In-flight calls return structured errors; the gateway stays up (NFR-REL-002). No retry storms: adapters use bounded retries with backoff. |
| **Approval service unreachable / approver silent** | Default-deny. Pending sensitive requests expire denied after the configured window (default 15 min per OQ-8 recommendation). The agent gets a structured "approval expired" error, not a hang. |
| **Audit store full / unwritable** | Fail-closed: if a call cannot be audited, it is denied. Rationale: an unaudited allow is worse than a denied call (FR-030 is unconditional). Disk-space monitoring and the retention job (NFR-DATA-002) make this a should-never-happen; the behavior is defined anyway. |
| **Rate-limit exhaustion** | Deny with a structured error naming the exhausted limit (FR-028). Counters persist across restarts so limits cannot be reset by crashing the service. (Cost budgets are post-MVP, FR-029; no budget-exhaustion path in MVP.) |
| **Vault / KMS unavailable** | No credential can be derived → all upstream calls denied. The gateway stays up for policy reads and audit browsing. |
| **Policy engine error** (rule misconfiguration) | Default-deny (FR-017). Dry-run mode (FR-019, AC-12) exists precisely to catch bad rules before enforcement. |

Scalability notes: MVP targets 10 concurrent sessions without degraded
decision latency (NFR-PERF-002) and <100 ms p95 policy+inspection
overhead (NFR-PERF-001, AC-11) — both are design targets to be measured
in the AC-11 load test. The single-process design (§1.1) means scaling
beyond MVP is vertical first; the component boundaries (§1.1) and the
ORM-backed storage (§5) are the seams for a later multi-instance split
(stateless MCP/policy workers + shared Postgres + externalized sessions).

---

## 8. Tech-stack recommendation

| Layer | Choice | Rationale |
|---|---|---|
| Language/runtime | **Python 3.12+** | SDK comparison in §3.2; strong connector libraries in the architect's assessment; Ken's audience reads Python. |
| MCP server framework | **FastMCP** (on MCP Python SDK ≥ the §3.3 floor) | In the architect's assessment, the most mature server framework for this shape of work; Streamable HTTP support verified against named SDK versions in the M0 spike; the best worked-example base for the OAuth unknowns (OQ-1, OQ-3). |
| Web framework (admin console + health endpoints) | **FastAPI** | Same process, same language; standard CSRF/XSS/session mitigations available (NFR-SEC-005); health/readiness endpoints are trivial (NFR-OBS-002). |
| Policy engine | **Hand-rolled rule evaluator** (JSON rules, default-deny) over a policy library | MVP rule shape (per-agent/per-tool/per-action allow/deny + sensitivity flags) does not justify OPA/Rego operational weight. Keep the evaluator dependency-free and auditable; dry-run is a second evaluation pass over stored audit rows (FR-019, AC-12). |
| Database | **SQLite via SQLAlchemy** | §5 rationale: zero-ops, ACID, file backup. ORM keeps the Postgres migration path open. |
| Secret management | **Envelope encryption; KMS-held key** (Fly secrets / GCP Secret Manager per hosting choice, §4) | Satisfies NFR-SEC-002 on every hosting option without tying the design to one cloud. |
| Inspection | **Regex/pattern rules + JSON-schema validation** (Python `jsonschema`) | Deterministic, fast (<100 ms budget, NFR-PERF-001), no LLM in the hot path. |
| Hosting | **Fly.io** (Cloud Run as conditional alternate) | §4 recommendation: least ops for one always-on HTTPS service. |
| CI/CD | **GitHub Actions**: lint + typecheck, dependency CVE scan (blocks HIGH+), SDK-floor assertion (AC-10), AC-11 load test, `fly deploy` on merge to main | Every acceptance criterion that can be automated is automated; the SDK floor is enforced in CI, not by convention. |

**Deliberately NOT chosen for MVP, and why:**

- **Postgres** — operational weight with no MVP payoff at 10 sessions; SQLite suffices, migration seam kept.
- **OPA/Rego or Cedar** — policy shape is simple; an external policy engine adds deployment and learning cost.
- **LLM-judge prompt-injection detection** — latency, cost, and nondeterminism in the hot path; pattern scanning now, semantic detection later (requirements §8).
- **Kubernetes / multi-instance** — NFR-REL-001 says single stateful service; HA is a later phase.
- **Admin-console OIDC** — requirements defer it; strong admin credential for MVP (FR-036).
- **A separate frontend framework (React etc.)** — the console is functional admin UI; server-rendered pages or minimal JS keep the codebase small. A richer UI is later-phase polish.
- **HSM-backed vault keys** — residual risk in T4 is accepted for MVP; KMS envelope encryption is the proportionate control.

---

## 9. Architecture open questions

Dependencies on the requirements' open questions first, then new ones.

- **AOQ-1 (depends on OQ-1, OQ-3): agent auth method.** The
  single-credential design (§2.3) assumes at least one of OAuth 2.1 or
  the conditional bearer fallback is usable from Muse and Grok clients.
  *Recommendation:* verify with a live connection test per platform
  (M0 spike) before finalizing the identity service. **REJECTED (Fix
  A):** IP allowlisting plus a shared secret header as a further
  downgrade. If a platform cannot present at least a per-agent secret
  over TLS, the gateway refuses the connection — there is no condition
  under which the floor is lowered further; platform connectivity that
  requires weakening below the bearer-token fallback is out of scope
  until the platform adds auth.
- **AOQ-2 (depends on OQ-2, OQ-4): per-agent identity strength.** If a
  platform multiplexes several bots behind one client identity, the
  gateway cannot distinguish them server-side (T3 residual).
  *Recommendation:* one gateway identity per platform connection as
  registered; document the mapping; do not claim finer granularity
  than the platform proves.
- **AOQ-3 (depends on OQ-5): Dots.** No Dots-specific architecture work
  until the plugin-inheritance claim is verified. The generic endpoint
  imposes no Dots constraint. *Recommendation:* verification spike only.
- **AOQ-4 (depends on OQ-6): hosting confirmation.** §4 recommends
  Fly.io (Cloud Run conditional). *Recommendation:* Ken confirms before
  the design phase wires in the KMS and deploy pipeline.
- **AOQ-5 (depends on OQ-7): code-host connector.** MVP assumes GitHub
  with write actions sensitive-gated from day one. *Recommendation:*
  confirm GitHub; the adapter interface (FR-009) makes a later swap
  cheap.
- **AOQ-6 (depends on OQ-8): approval timeout default.** 15 minutes is
  the recommended default (fail-closed). *Recommendation:* confirm, or
  set per-connector (shorter for destructive actions like `calendar.delete`
  or `email.settings.write` — not `code.pr.merge`, which is deferred out
  of MVP).
- **AOQ-7 (new): admin console exposure.** Should the console live on
  the same public host as the MCP endpoint (simpler, one TLS cert) or
  be restricted (VPN, IP allowlist, separate hostname)? *Recommendation:*
  same host for MVP with strong credential auth + rate-limited login
  (FR-036); revisit restriction when team access arrives.
- **AOQ-8 (new): SQLite concurrency under the AC-11 load test.** 10
  concurrent sessions with audit writes on every call — SQLite in WAL
  mode handles this comfortably in the architect's judgment, but AC-11
  is the proof. *Recommendation:* run AC-11 early; if p95 exceeds the
  100 ms design target, the first lever is write batching, the second
  is Postgres.
- **AOQ-9 (new): upstream OAuth app ownership.** The gateway needs
  OAuth app registrations (client IDs/secrets) at Google/Microsoft for
  email+calendar and at GitHub for the code host. These are Ken-owned
  developer apps with their own verification/branding steps.
  *Recommendation:* start the app registrations early — platform
  verification lead times are the likeliest schedule risk, and they
  are outside the codebase.
- **AOQ-10 (new): PII pattern catalog ownership.** Redaction is only as
  good as its patterns (T7 residual). *Recommendation:* ship a default
  catalog (email, phone, common account/SSN shapes) and make it
  console-editable from day one; treat pattern updates as a routine
  admin task, not a code change.
- **AOQ-11 (new): mandate lifecycle and default mandate.** FR-PAA01-001
  requires a mandate for every session — does each session need an
  explicitly created mandate, or does registration create a default
  standing mandate? *Recommendation:* registration creates a default
  standing mandate (Ken-visible, scope-limited); Ken narrows, pauses, or
  ends it from the Mandates page. Mandate records live in the config
  SQLite DB (§1.4); the no-mandate case is an explicit denial, never an
  implicit pass.
- **AOQ-12 (new): counterparty-record bootstrap.** A first-contact payee
  has no audited record, so "changed details" comparison is vacuous
  (T10 residual). *Recommendation:* the first commitment-adjacent call
  to a new payee always requires console approval (FR-PAA05-002); the
  counterparty record is written from that approved audited call; Ken
  corrects records in the console with a diffed change, audit-logged.
- **AOQ-13 (new): recorded-criteria vocabulary (PAA09).** The criteria
  comparison on the approval card (FR-PAA09-001/004) is empty without
  Ken's decision criteria per domain. Same Ken-input class as AQ-7.
  *Recommendation:* seed criteria in console settings before M3; an
  empty criteria section on the card is a visible gap, not an error.
- **AOQ-14 (new): in-flight interruption semantics (PAA10).** Pause and
  revoke are checked at session binding and at execution (steps 2, 6/7),
  but a call already executing upstream when revocation lands cannot be
  recalled. *Recommendation:* state this in the lifecycle spec; the
  audit row carries the irreversible marker (FR-PAA10-005) and the
  agent-facing error names the state (paused/revoked/canceled), never a
  silent hang.
