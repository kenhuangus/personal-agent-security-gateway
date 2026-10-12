# Personal Agent Security Gateway — Requirements

**Document:** `docs/01-requirements.md`
**Phase:** 1 of 4 (Functional Analysis) — planning only, no implementation
**Product owner:** Ken
**Status:** Draft for review

---

## 1. Problem Statement

Ken runs AI agents that touch his real systems: email, calendar, code repos, databases, internal APIs. Today each agent platform connects to those systems its own way. Each path stores credentials differently, applies policy differently (or not at all), and logs differently (or not at all). There is no single place that answers: which agent touched which system, with whose authority, and was it allowed?

This solves that for Ken first, and later for power users and small teams with the same problem.

The gateway is a centralized security control plane that sits between personal AI agents and real enterprise/personal systems. It exposes one public MCP endpoint over Streamable HTTP. Agents connect to it once through their custom-connector paths. The gateway then brokers every tool call: identity and token exchange, runtime authorization, credential isolation, request/response inspection, and audit logging. The agents never hold raw credentials. The gateway never runs inside an agent's VM — it is a separate server the agents reach over the public internet.

Why now: three agent platforms now offer custom MCP server connections (Meta Muse, Grok Bot, and, provisionally, OpenAI Dots via ChatGPT plugins), so a single public endpoint can serve all of them. MCP is also accumulating trust problems — the MCP Python SDK had an OAuth account-takeover flaw (a malicious server could exfiltrate client secrets, auth codes, and PKCE verifiers), fixed in versions 1.30.0/2.2.0 — GitHub advisory GHSA-qx49-fqc8-xw99, published 2026-09-28 (https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-qx49-fqc8-xw99; affected 1.9.1–1.29.1 and 2.0.0–2.1.1; no CVE assigned as of 2026-09-29) — so a gateway that brokers, verifies, and logs connections addresses a concrete gap. See FR-005/AC-10 for the version floor this enforces.

Synergy note: Ken is already building an AI agent security scanner SaaS (OWASP-mapped attack scenarios) at `~/workspace/agent-scanner/`. The scanner finds agent vulnerabilities before deployment; this gateway controls runtime access after deployment. Scanner findings can become gateway policy rules later (out of MVP scope).

---

## 2. Personas

### P1 — Ken, builder/admin (primary)
Builds and deploys the gateway. Connects his own agents (Muse, Grok Bot, Dots) to it. Writes policies, approves sensitive actions, reviews audit logs. Wants minimal hands-on labor: finished artifacts, single copy-paste steps, plan-before-implementation.

### P2 — Power user (future)
A technical user who connects their own agents to their own systems through a self-hosted or hosted gateway. Comfortable editing JSON policy files but wants a working default configuration.

### P3 — Small team admin (future)
Manages agents for a small team: onboards agents per person, sets per-agent and per-team policies, reviews audit logs for compliance. Needs multi-user admin roles, which MVP does not provide.

---

## 3. User Stories

### Agent onboarding
1. As Ken, I register a Muse Custom Connector pointing at my gateway's public URL, so my agent calls real systems through the gateway instead of holding credentials itself.
2. As Ken, I register a Grok Bot custom MCP server (name + public HTTPS URL in Plugins settings or in chat), so the bot's tool calls route through the gateway.
3. As Ken, I connect an OpenAI Dot to the gateway (provisional path: ChatGPT plugin ecosystem → Dots inherit account-connected plugins), so the Dot's tool calls route through the gateway.
4. As Ken, I revoke an agent's access with one action in the admin console, so a compromised or retired agent can no longer reach any system.
5. As Ken, I can see which agents are connected, when each last called a tool, and which connector scopes each holds, so I know the current attack surface at a glance.

### Policy management
6. As Ken, I define per-agent, per-tool, per-action allow/deny rules, so a read-only research agent can never trigger a write tool.
7. As Ken, I mark specific actions (e.g., send email, merge PR, delete records) as sensitive, requiring step-up approval before execution.
8. As Ken, I can test a policy change against recent audit history (dry-run mode) before enforcing it, so I don't break working agents with a bad rule.

### Approvals
9. As Ken, I receive a push/notification in the admin console when an agent requests a sensitive action, so I can approve or deny it within seconds.
10. As Ken, I can approve a sensitive action with a bounded scope (this action, this agent, this time window), so approval doesn't become a permanent privilege.

### Credential management
11. As Ken, I store real-system credentials (API keys, OAuth refresh tokens) in the gateway's server-side vault once, so agents never see or store raw secrets.
12. As Ken, I rotate a stored credential and have in-flight short-lived tokens expire gracefully, so rotation doesn't break running agents.
13. As Ken, the gateway exchanges my stored credentials for short-lived, scoped tokens per agent call, so a leaked token is useless outside its narrow scope and lifetime.

### Inspection and guardrails
14. As Ken, the gateway validates every tool-call input against the tool's schema and rejects malformed calls, so bad or malicious inputs never reach real systems.
15. As Ken, the gateway scans tool outputs for prompt-injection patterns before returning them to the agent, so a poisoned tool output can't hijack the agent.
16. As Ken, the gateway redacts PII (e.g., emails, phone numbers, account numbers) from tool outputs by policy, so the agent only sees data it's allowed to see.
17. As Ken, I can set per-agent rate limits, so a runaway agent can't hammer an API. (Cost budgets are post-MVP per FR-029.)

### Audit
18. As Ken, every tool call is recorded — who (agent identity), what (tool, action), when (timestamp), with redacted arguments — so I can reconstruct any incident.
19. As Ken, I can export the audit log (JSON/CSV) for a time range, so I can analyze it or hand it to an auditor.
20. As Ken, I can search the audit log by agent, tool, time, and outcome (allowed/denied/approved), so incident review takes minutes, not hours.

### Admin console
21. As Ken, I have a single web console to connect agents, manage policies, approve sensitive actions, and browse audit logs, so I don't manage the gateway through config files alone.

---

## 4. Functional Requirements

### 4.1 MCP server endpoint (Streamable HTTP)
- **FR-001** The gateway SHALL expose a single public HTTPS endpoint serving MCP over Streamable HTTP.
- **FR-002** The endpoint SHALL be reachable from the public internet (no localhost-only assumption); it MUST NOT require the agent platform's cloud to reach a private network.
- **FR-003** The gateway SHALL implement MCP tool listing (`tools/list`) and tool invocation (`tools/call`) for every connector-exposed tool.
- **FR-004** The gateway SHALL support multiple concurrently connected agents from different platforms (Muse, Grok, Dots) against the same endpoint, with each session bound to a distinct agent identity.
- **FR-005** The gateway SHALL pin or constrain the MCP SDK version it builds on to ≥ the fixed releases (Python SDK 1.30.0 / 2.2.0 or later — GitHub advisory GHSA-qx49-fqc8-xw99), so the known OAuth account-takeover flaw is not reintroduced by dependency drift.
- **FR-006** The gateway SHALL verify the identity/origin of connected MCP clients to the extent the protocol allows, and SHALL log every session's client-reported identity and transport details.

### 4.2 Connector registry
- **FR-007** The gateway SHALL provide a connector registry: pluggable adapters to real systems (MVP: at least email send/read, calendar read/write, and one code-host connector), each exposing scoped MCP tools.
- **FR-008** Each connector SHALL declare its tools with input schemas, required scopes, and a sensitivity classification (routine vs. sensitive).
- **FR-009** Connectors SHALL be addable without modifying the MCP endpoint or the policy engine (plugin interface). Every connector adapter SHALL pass an SSRF review checklist (egress allowlist, no open-ended URL fetch, cloud-metadata endpoints blocked) before acceptance.
- **FR-010** The registry SHALL support per-connector health checks visible in the admin console.

### 4.3 Identity & token exchange
- **FR-011** The gateway SHALL authenticate each agent session using OAuth 2.1 as the primary method, issuing exactly one credential per agent. A long-lived per-agent bearer fallback SHALL be issued only for an agent whose platform has demonstrably failed OAuth verification, recorded in the admin console with the test date. Fallback issuance is never the default and never alongside OAuth credentials. The gateway SHALL refuse agent connections that cannot present at least a per-agent secret over TLS; there is no third rung (no IP-allowlist downgrade).
- **FR-012a** The gateway SHALL issue each agent a single agent-facing session credential: an OAuth 2.1 access token, or, when the conditional fallback is active, a long-lived per-agent bearer with mandatory rotation. The agent presents it on every request. It carries no upstream secrets.
- **FR-012b** For each authorized tool call, the gateway SHALL mint a per-call derived upstream token server-side: short-lived, scoped to agent/tool/action, used only by the connector adapter inside the gateway, and never exposed to the agent in raw form. The raw vault credential is never exposed outside the vault boundary.
- **FR-013a** Gateway-scope least privilege: the policy claims attached to the agent-facing session credential SHALL grant only the agent/tool/action permissions the policy engine allows. The gateway SHALL NOT mint or honor a call token outside the granted claims.
- **FR-013b** Upstream-scope least privilege: each connector SHALL register with least-privilege upstream OAuth scopes. A derived call token's power at the upstream API is bounded by those connector scopes — upstream providers do not mint per-tool tokens, so the (agent, tool, action) binding is gateway bookkeeping, not cryptographic.
- **FR-014** Token lifetime SHALL be configurable, with a default short enough that a leaked token is useful only briefly (design target; exact value set at implementation).
- **FR-015** The gateway SHALL support revocation of an agent's sessions and tokens with immediate effect (FR revocation from user story 4).

### 4.4 Policy engine
- **FR-016** The gateway SHALL evaluate every tool call against per-agent, per-tool, per-action allow/deny rules before execution.
- **FR-017** The default posture SHALL be deny: a tool call with no matching allow rule is denied and logged.
- **FR-018** Rules SHALL support marking actions as sensitive, triggering step-up approval instead of automatic allow.
- **FR-019** The policy engine SHALL support dry-run (audit-only) evaluation of rule changes against live or historical traffic before enforcement.
- **FR-020** Policy evaluation MUST complete fast enough not to dominate tool-call latency (design target: single-digit milliseconds at p50).

### 4.5 Credential vault
- **FR-021** Real-system credentials (API keys, OAuth refresh tokens, passwords) SHALL be stored server-side only, encrypted at rest.
- **FR-022** No API or tool output SHALL return a raw stored credential to an agent or admin-console client.
- **FR-023** The vault SHALL support credential rotation with graceful expiry of derived short-lived tokens.
- **FR-024** Vault access SHALL itself be audited: every read of a credential by the gateway internals is logged. This covers reads of the exempt system-notification bootstrap secret too — that secret lives in the platform secret store per NFR-SEC-002 (not the vault), and its reads are logged the same way.

### 4.6 Inspection & guardrails
- **FR-025** The gateway SHALL validate every tool-call input against the tool's declared schema and reject malformed calls with a structured error.
- **FR-026** The gateway SHALL scan tool outputs for prompt-injection patterns before returning them to the agent; on detection, it SHALL block or redact per policy and log the event.
- **FR-027** The gateway SHALL redact configured PII patterns from tool outputs per policy (per-agent, per-tool rules).
- **FR-028** The gateway SHALL enforce per-agent rate limits (calls per minute/hour, configurable). The gateway SHALL ALSO enforce a per-agent cap on concurrent pending approval requests (default 5, tunable per agent); breaching the cap returns the `approval_queue_full` error and the event is audit-logged.
- **FR-029 (post-MVP)** Per-agent cost budgets where the underlying system reports cost. No MVP connector reports cost, so MVP enforcement is a no-op; implementation waits for a cost-reporting connector (see MF-13).

### 4.7 Audit log
- **FR-030** The gateway SHALL record every tool call: agent identity, tool name, action, timestamp, policy decision (allow/deny/approve), and redacted arguments.
- **FR-031** The gateway SHALL record every sensitive-action approval: approver, scope granted, time window, and outcome.
- **FR-032** The audit log SHALL be append-only; entries MUST NOT be editable or deletable through the admin console.
- **FR-033** The gateway SHALL support export of audit entries (JSON and CSV) for a requested time range.
- **FR-034** The gateway SHALL support search/filter of the audit log by agent, tool, time range, and decision outcome.

### 4.8 Admin console
- **FR-035** The gateway SHALL provide a web admin console for: connecting/revoking agents, managing policies, approving sensitive actions, and browsing/searching the audit log.
- **FR-036** The admin console SHALL require authentication (at minimum a strong admin credential; OIDC in a later phase).
- **FR-037** Sensitive-action approval requests SHALL surface in the admin console in near real time with full context (agent, tool, arguments redacted per policy).
- **FR-038** The admin console SHALL display connector health and per-agent session/token status.
- **FR-039** All admin authentication attempts (success and failure) SHALL be audit-logged.
- **FR-040** Admin login SHALL be rate-limited with lockout or exponential backoff.
- **FR-041** Policy version saves, rollbacks, agent revocations, and credential rotations SHALL be audit-logged as admin actions.
- **FR-042** Admin console state-changing endpoints SHALL require anti-CSRF protection (anti-CSRF tokens, or `SameSite=Strict` cookies plus custom-header checks); approval decisions for destructive scopes additionally require per-decision re-authentication or a per-decision confirmation token.

---

## 5. Non-Functional Requirements

### Security
- **NFR-SEC-001** All traffic to the public endpoint SHALL use TLS 1.2+; the gateway SHALL NOT accept plaintext MCP traffic from the internet.
- **NFR-SEC-002** Stored credentials SHALL be encrypted at rest with a key managed outside the application config (KMS or equivalent at deploy time). Scope note: this covers the vault's upstream credentials AND the gateway's bootstrap deploy-time secrets, including the exempt system-notification credential used by the M3 approval-notification path (02 §2.8 step 5). That notifier credential is held in the platform secret store (Fly secrets or GCP Secret Manager per hosting choice) — never in the M4 vault, which holds connector credentials only — and is encrypted at rest per this requirement (key managed outside app config). See 03 §5 for the storage split.
- **NFR-SEC-003** The gateway SHALL follow client credential hygiene per the MCP OAuth flaw lessons: never echo client secrets, auth codes, or PKCE verifiers to untrusted parties; validate redirect URIs strictly; treat connected MCP servers/clients as untrusted until verified.
- **NFR-SEC-004** Dependencies with known CVEs at or above HIGH severity SHALL be patched or pinned within the project's dependency policy; the MCP SDK floor from FR-005 is the first instance.
- **NFR-SEC-005** The admin console SHALL be protected against CSRF, XSS, and session fixation using standard framework mitigations.

### Latency & performance
- **NFR-PERF-001** Policy evaluation + inspection overhead per tool call SHALL target < 100 ms at p95 (design target; excludes downstream system latency and LLM inference).
- **NFR-PERF-002** The gateway SHALL support at least 10 concurrent agent sessions in MVP without degraded decision latency (design target).

### Availability & reliability
- **NFR-REL-001** The gateway SHALL be deployable as a single stateful service (MVP); multi-instance/HA is a later phase.
- **NFR-REL-002** A failed connector call SHALL NOT crash the gateway; failures return structured errors and are logged.

### Observability
- **NFR-OBS-001** Every policy decision and inspection event SHALL emit a structured log entry correlatable with its audit record.
- **NFR-OBS-002** The gateway SHALL expose health and readiness endpoints for the hosting environment.

### Compliance & data handling
- **NFR-DATA-001** PII redaction rules SHALL apply before data is written to the audit log (FR-030's "redacted arguments" is mandatory, not optional). Exception: the approvals record stores the narrow evidence subset in cleartext per the 02 §2.8 step 4 evidence rule (approver-visible decision fields only — recipient/payee, amount/currency, audience, rendered content preview). The exception applies to the approvals record only, never to the audit log or agent delivery.
- **NFR-DATA-002** Audit log retention SHALL be configurable (default: 90 days in MVP; design target).
- **NFR-DATA-003** The gateway SHALL NOT send tool-call contents to any third party except the configured downstream system for that tool.

---

## 6. Per-Platform Integration Requirements

Only the brief's claims are asserted here. Anything about a platform's UI or API not stated in the brief is flagged, not invented.

### 6.1 Meta Muse
- **What the brief establishes:** Muse supports Custom Connectors. The user provides a public MCP server URL (or OpenAPI/API docs); Muse builds the integration inside its VM; credentials are stored in Muse's Secure Credentials Store. Localhost does not work; the endpoint must be publicly reachable from Meta's cloud.
- **Gateway-side requirements:**
  - **FR-INT-001** The gateway's public endpoint MUST be reachable from Meta's cloud over HTTPS with a valid public certificate.
  - **FR-INT-002** The gateway SHOULD present a clean `tools/list` surface (names, descriptions, schemas) since Muse builds the integration from what the endpoint advertises.
- **Agent-UI steps (per the brief, inside Muse's UI):** user registers the gateway URL as a Custom Connector; Muse builds the integration in its VM; credentials (if any are needed on the Muse side) live in Muse's Secure Credentials Store.
- **Gateway-console steps:** register the Muse agent identity, assign scopes/policies, issue the agent's OAuth credentials.
- **⚠️ Cannot verify from the brief:** the exact screens/fields in Muse's Custom Connector setup; whether Muse's MCP client sends a stable client identity the gateway can verify; whether Muse supports OAuth 2.1 against a custom MCP server or only API-key style credentials. → Open questions OQ-1, OQ-2.

### 6.2 Grok Bot
- **What the brief establishes:** Grok Bot supports custom MCP servers, added via Plugins settings (name + public HTTPS URL) or by asking the bot in chat. The server must be publicly reachable. Once added, it's available to Bots on the account.
- **Gateway-side requirements:**
  - **FR-INT-003** Same public-HTTPS reachability requirement as FR-INT-001.
- **Agent-UI steps (per the brief, inside Grok):** add the gateway in Plugins settings with a name + public HTTPS URL, or ask the bot in chat to add it.
- **Gateway-console steps:** register the Grok Bot agent identity, assign scopes/policies.
- **⚠️ Cannot verify from the brief:** the exact Plugins settings fields; what authentication (if any) Grok's MCP client supports toward the server; whether per-Bot identities are distinguishable server-side. → Open questions OQ-3, OQ-4.

### 6.3 OpenAI Dots (provisional)
- **What the brief establishes:** Dots consume the ChatGPT plugin ecosystem; ChatGPT supports custom MCP servers as plugins; Dots inherit the account's connected plugins. Enterprise/specialist Dots add tighter admin controls and identity boundaries. **The brief explicitly marks this claim as the thinnest-documented of the three — treat as provisional.**
- **Gateway-side requirements:**
  - **FR-INT-004** Public-HTTPS reachability, same as above. No Dots-specific protocol work until the path is verified.
- **⚠️ Cannot verify from the brief:** whether Dots actually inherit account-level MCP plugins; whether a plugin connection made in ChatGPT is visible to a Dot; what identity a Dot presents to the MCP server. → Open question OQ-5 (verify before any Dots-specific build).

---

## 7. Acceptance Criteria for MVP

Observable, testable — each must pass before MVP is declared done:

1. **AC-01** A Muse Custom Connector registered against the gateway's public URL lists the gateway's tools and invokes a read-only tool (e.g., calendar read); the call appears in the audit log with agent identity, tool, timestamp, and redacted args.
2. **AC-02** A Grok Bot with the gateway added as a custom MCP server invokes a gateway tool; the call is authorized per that agent's policy and logged.
3. **AC-03** An agent with no allow rule for a tool is denied (default-deny), and the denial is logged with the reason.
4. **AC-04** A tool call for a sensitive action (e.g., send email) pauses for step-up approval; it executes only after approval in the admin console, and the approval (approver, scope, window) is logged. Live-agent extension: using the actual Muse Custom Connector and Grok Bot clients, demonstrate a sensitive call completing the full error → poll → approve → re-invoke → execute loop. If a platform's agent cannot poll (M0 spike fails), the console SHALL provide an "execute on approval" path that executes the approved call server-side; this fallback is required before MVP is declared done.
5. **AC-05** No vault-stored upstream credential is retrievable agent-side: inspecting agent-side traffic and tool outputs shows only the agent-facing session credential (short-lived OAuth access tokens; the fallback bearer only when fallback auth is active for that agent), never vault contents.
6. **AC-06** A tool output containing a planted prompt-injection string is blocked or redacted per policy, and the detection event is logged.
7. **AC-07** A tool output containing a configured PII pattern (e.g., a phone number) is redacted before reaching the agent and before being written to the audit log.
8. **AC-08** Revoking an agent in the admin console immediately stops its subsequent tool calls (existing short-lived tokens expire within the configured window; new calls are denied).
9. **AC-09** The audit log exports to JSON and CSV for a chosen time range, and search by agent/tool/outcome returns correct results.
10. **AC-10** The gateway runs on MCP SDK ≥ the fixed versions (1.30.0/2.2.0 lineage — GitHub advisory GHSA-qx49-fqc8-xw99), verified by dependency manifest, and a dependency scan shows no HIGH+ CVEs in the MCP path.
11. **AC-11** Policy + inspection overhead per tool call stays under the 100 ms p95 design target: a local load test (10 concurrent sessions) runs as a CI gate (build fails if local p95 > 100 ms), and the same measurement is repeated against the deployed endpoint before MVP sign-off with the production number recorded. The 100 ms figure is a design target, not a promise. **Isolation method:** p95 is computed on gateway-internal timing spans (policy evaluation + inspection), which exclude downstream system latency per NFR-PERF-001. For the deployed-endpoint measurement, the adapter's upstream-call timer is subtracted from end-to-end timing; the recorded production number is the isolated gateway overhead, not end-to-end latency.
12. **AC-12** A dry-run policy change is evaluable via `POST /api/policy/dry-run` with `{policy_version, window_days}`, returning per-call would-allow/would-deny/would-require-approval counts plus the changed call list (last 7 days of audit history; synthetic per-tool corpus, labeled as such, when history is empty) — without changing enforcement.

---

## 8. MVP Scope vs. Later Phases

Realistic for one person + an agent team. MVP is: one public endpoint, a handful of connectors, core policy/approval/vault/inspection/audit, and a functional admin console.

### In MVP
- MCP server over Streamable HTTP, public HTTPS endpoint (FR-001–FR-006)
- Connector registry with 3 connectors: email (send/read), calendar (read/write), one code-host connector (read-first; write actions classified sensitive)
- OAuth 2.1 agent identities, short-lived scoped tokens, revocation (FR-011–FR-015)
- Policy engine: per-agent/per-tool/per-action allow/deny, default-deny, sensitive actions, dry-run (FR-016–FR-020)
- Server-side encrypted credential vault with rotation (FR-021–FR-024)
- Input validation, tool-output prompt-injection scanning, PII redaction, per-agent rate limits, per-agent pending-approval caps (FR-025–FR-028). Cost budgets are post-MVP (FR-029).
- Append-only audit log with search + JSON/CSV export (FR-030–FR-034)
- Web admin console: agents, policies, approvals, audit browsing, connector health (FR-035–FR-038)
- Muse and Grok Bot integration paths verified end-to-end (AC-01, AC-02)

### Explicitly out of MVP (later phases)
- **Multi-user / team admin roles** (P3 persona): MVP is single-admin (Ken). Team RBAC, per-user agent identities, and org-level policy inheritance come later.
- **OpenAI Dots path**: provisional per the brief — verify the plugin-inheritance claim (OQ-5) before building anything Dots-specific. No Dots work in MVP beyond keeping the endpoint generic.
- **Scanner integration**: feeding `~/workspace/agent-scanner/` findings into gateway policy rules. Adjacent, valuable, later.
- **HA / multi-instance deployment**: MVP is a single stateful service (NFR-REL-001).
- **Advanced guardrails**: semantic prompt-injection detection via LLM judge, data-loss-prevention beyond pattern redaction, anomaly detection on agent behavior.
- **Admin console OIDC login**: MVP uses a strong admin credential; OIDC later.
- **Mobile approvals**: step-up approvals happen in the web console; push-to-phone approval is later.
- **Usage metering/billing**: no billing in MVP (personal use).
- **Cost budgets (FR-029)**: no MVP connector reports cost; implementation waits for a cost-reporting connector (MF-13).
- **Connector marketplace / third-party connector signing**: connectors are first-party in MVP; verification/signing of third-party connectors is later.

---

## 9. Open Product Questions for Ken

1. **OQ-1 — Muse auth method.** The brief doesn't say whether Muse's Custom Connector MCP client supports OAuth 2.1 against our server or only API-key-style credentials. *Resolution (Fix A):* the gateway issues exactly one credential per agent — OAuth 2.1 by default. The long-lived per-agent bearer fallback is issued only for an agent whose platform has demonstrably failed OAuth verification, recorded in the admin console with the test date; it is never issued by default or alongside OAuth credentials. Confirm Muse's behavior during the M0 live spike.
2. **OQ-2 — Muse client identity.** Can the gateway distinguish one Muse Custom Connector from another server-side (stable client ID)? *Recommendation:* assume the gateway-assigned agent identity (registered in the admin console) is the source of truth, not the platform's client string, until proven otherwise.
3. **OQ-3 — Grok auth method.** Same unknown as OQ-1 for Grok's MCP client. *Resolution (Fix A):* same single-credential rule as OQ-1 — OAuth default, gated bearer fallback only after a failed OAuth verification test with the test date recorded.
4. **OQ-4 — Grok per-Bot identity.** If several Bots on the account use the gateway, can we tell them apart? *Recommendation:* issue one gateway agent identity per Bot at registration; document the mapping in the console.
5. **OQ-5 — Dots plugin inheritance (provisional).** The brief flags the Dots-via-ChatGPT-plugins path as the thinnest-documented claim. *Recommendation:* do not build for Dots in MVP; run a verification spike (connect a plugin in ChatGPT, check visibility from a Dot) before any Dots-specific work.
6. **OQ-6 — Hosting.** Where does the public endpoint live? (VPS, Cloud Run, home server with tunnel?) This drives TLS, vault KMS, and availability answers. *Recommendation:* a small VPS or Cloud Run with managed TLS; decide before the architecture phase.
7. **OQ-7 — Connector priority.** MVP proposes email, calendar, and one code-host connector. Is the code-host connector GitHub, and should its write actions (merge, push) be sensitive-gated from day one? *Recommendation:* yes to both.
8. **OQ-8 — Approval latency expectation.** Step-up approvals pause agent execution. What's your tolerance — seconds (you're watching the console) or minutes/hours (async)? *Recommendation:* design for async with a default-deny timeout (unapproved requests expire denied after a configurable window, default 15 min).
9. **OQ-9 — Product shape.** Is this a personal-use tool, or the second SaaS line next to the AgentSec scanner? *Recommendation:* build MVP as personal-use with clean multi-tenancy seams (agent identities, per-agent policies already imply them); decide SaaS packaging after MVP proves the control plane.
10. **OQ-10 — Audit retention vs. cost.** Default 90-day retention is a design target. Longer retention for compliance, or is 90 days right? *Recommendation:* keep 90 days in MVP; make it configurable from day one.

---

## 10. PAA10-Derived Functional Requirements

Added 2026-10-12 from `docs/05-paa10-mapping.md`. Additive only: all existing FRs, NFRs, ACs, and OQs above stand unchanged, and these requirements build on the Fix A / Fix B corrected behavior in `docs/00-build-plan.md` (single-credential auth, validate-first approval ordering, caller-bound `approval_status`, inert card rendering, grant-before-rule evaluation). The review amendments from `docs/04-review.md` (FR-011 rewrite, FR-012 split, AC-05 amendment, FR-029 scope change, new admin-surface FRs) were applied to the canonical text on 2026-10-12 — see §10.11 for the full tracked list.

Milestone convention: each FR below carries its milestone — **(MVP)** or **(MVP — conditional)** where enforcement depends on unverifiable upstream/provider support (03 §1.5); there are no post-MVP PAA10 FRs in this round. "Conditional" means the gateway enforces where the capability exists and degrades visibly (never silently) where it does not.

Conventions: SHALL = mandatory for the milestone named; short sentences; no invented provider capabilities — platform claims traceable to §6 or flagged ⚠️.

### 10.1 PAA01 — Personal Mandate Drift

- **FR-PAA01-001 (MVP)** The gateway SHALL record a mandate for every agent session: `mandate_id`, agent, purpose, allowed tool/action classes, expiry timestamp, delegation chain (parent `mandate_id`), and status (active/paused/ended/withdrawn).
- **FR-PAA01-002 (MVP)** The gateway SHALL evaluate mandate validity before policy-rule evaluation on every tool call: an expired, paused, ended, or withdrawn mandate denies the call regardless of matching allow rules.
- **FR-PAA01-003 (MVP)** The gateway SHALL deny any tool call whose action class falls outside the mandate's allowed tool/action classes, with reason `mandate_scope_exceeded`; read-only mandates SHALL NOT silently authorize communicate or transact actions.
- **FR-PAA01-004 (MVP)** Withdrawal or expiry of a mandate SHALL take effect immediately: subsequent calls are denied, queued approval requests under that mandate are canceled as denied, and every approved-but-unconsumed grant under that mandate is invalidated. At grant-consumption time (02 §2.8 step 9, 03 §1.2 step 4) the gateway SHALL verify the mandate is still live; a withdrawn, expired, or paused mandate denies the call with an audit event and invalidates the remaining unconsumed grants under it.
- **FR-PAA01-005 (MVP)** Calls presented as delegated work (child agent or sub-task) SHALL reference a parent `mandate_id` and carry equal-or-narrower scope; broader or unchained delegated calls are denied.
- **FR-PAA01-006 (MVP)** The admin console SHALL list standing instructions per agent with one-action pause, narrow, and end; approval cards SHALL display the mandate purpose and remaining duration.
- **FR-PAA01-007 (MVP)** Every audit row SHALL carry the `mandate_id` and the scope rule that authorized the call.
- **FR-PAA01-008 (MVP)** Read-only-to-transact mandate transitions SHALL require a new mandate; silent escalation is denied. (05 §PAA01, responsibility split (b).)

### 10.2 PAA02 — Personal Account and Recovery Takeover

- **FR-PAA02-001 (MVP)** The gateway SHALL scan tool outputs for verification-code, OTP, and password-reset-link patterns, redact matches before agent delivery and before the audit write, and log the redaction event.
- **FR-PAA02-002 (MVP)** Recovery-affecting actions (external email forwarding/filter rules, recovery-address changes, session exports — see the `email.settings.write` tool in the design inventory) SHALL be classified sensitive by default and require step-up approval. Any future tool with recovery-affecting semantics inherits this classification.
- **FR-PAA02-003 (MVP)** Approval for recovery-affecting actions SHALL use a protected flow: the decision is confirmed in the admin console only. A familiar name, thread, or identity presented by the agent or by tool content SHALL NOT authorize code disclosure.
- **FR-PAA02-004 (MVP)** Any `email.send`/`email.forward` carrying a redacted code artifact SHALL be blocked or escalated to console approval with the untrusted-content label, and the attempt SHALL be audit-logged.
- **FR-PAA02-005 (MVP — conditional)** Connectors SHALL expose read-only visibility into recovery-relevant settings (e.g., Gmail forwarding/filter rules) for review in the admin console, where the upstream API supports it. (05 §PAA02 concrete mechanism; flagged ⚠️ in the mapping.)

### 10.3 PAA03 — Private Life Context Exposure

- **FR-PAA03-001 (MVP — conditional)** Connectors SHALL declare data-label classes on returned data (e.g., `work`, `private`, `family`); adapters SHALL filter or tag results per the calling agent's clearance before the inspection pipeline runs. Depends on upstream sensitivity/ownership metadata at usable granularity (03 §1.5, mapping AQ-1); where unavailable the adapter declares "unlabeled" rather than guessing.
- **FR-PAA03-002 (MVP)** Policy rules SHALL bind to a declared purpose; a tool call outside the agent's allowed purpose is denied even when the tool and action are otherwise allowed.
- **FR-PAA03-003 (MVP)** The gateway SHALL flag and redact cross-context leakage (e.g., `private`-labeled facts inside a `work`-purpose response) per policy before delivery, and log the event.
- **FR-PAA03-004 (MVP)** Sending or summarizing `private`-labeled content to an external audience SHALL pause for console approval with a preview of exactly what would leave; sensitive inferences SHALL be protected like their source information.

### 10.4 PAA04 — Personal Memory and Preference Corruption

- **FR-PAA04-001 (MVP)** Every stored mandate, policy rule, and approval grant SHALL carry provenance: source, created-by, and timestamp, visible in the admin console; inferred entries SHALL be distinguished from explicit instructions.
- **FR-PAA04-002 (MVP)** No gateway pipeline SHALL write content extracted from tool outputs into mandate, policy, or grant stores; untrusted tool content SHALL NOT silently become authority.
- **FR-PAA04-003 (MVP)** Corrections to a standing instruction SHALL propagate to dependent artifacts: grants issued under the old instruction are re-validated or invalidated, and pending approvals referencing it are flagged for review.
- **FR-PAA04-004 (MVP)** Every standing-instruction change SHALL require explicit console confirmation with a before/after diff, and the audit entry SHALL record scope and retention limits of the change.

### 10.5 PAA05 — Counterparty Deception and Agent Mediated Scams

- **FR-PAA05-001 (MVP)** The gateway SHALL maintain per-payee counterparty records from audited calls; a destination or account detail differing from the record SHALL escalate to approval with the delta displayed.
- **FR-PAA05-002 (MVP)** A recipient with no prior audited history (new payee) SHALL be classified sensitive automatically for commitment-adjacent actions.
- **FR-PAA05-003 (MVP)** Approval cards for commitment-adjacent actions SHALL include a counterparty-evidence section: recipient, claim source (the message/document that triggered the call), delta vs. the recorded independent record, and detected urgency or relationship-claim language.
- **FR-PAA05-004 (MVP)** Agent-supplied assertions of legitimacy SHALL be rendered as untrusted content and SHALL NOT count as evidence; spending limits SHALL NOT be presented as a substitute for counterparty verification.
- **FR-PAA05-005 (MVP — conditional)** Where a connector supports it, the gateway SHALL provide a read-only directory/address-book lookup so the approval card can compare against an independent record. When the connector does not support it, the card states "no independent record available" rather than inventing one. (05 §PAA05 concrete mechanism.)

### 10.6 PAA06 — Unauthorized Spending and Personal Commitments

- **FR-PAA06-001 (MVP)** Approval records for commitment-adjacent actions SHALL bind the exact terms: payee, total amount and currency, fees, dates, recurring terms, and cancellation consequences (a term sheet).
- **FR-PAA06-002 (MVP)** If the tool arguments at execution differ materially from the approved terms, the grant SHALL NOT match and the call SHALL be denied pending renewed approval. Argument equality is decided on canonical JSON serialization before hashing; immaterial diffs (key order, insignificant whitespace) do not force re-approval.
- **FR-PAA06-003 (MVP — conditional)** A call whose outcome is unknown (timeout, ambiguous response) SHALL block automatic retry; retry is permitted only after a status check via the connector, where the connector exposes a transaction-status endpoint (03 §1.5), and the retry itself requires approval when the action is sensitive.
- **FR-PAA06-004 (MVP)** Commitment receipts SHALL be recorded in the audit log against the approval that authorized them; when the gateway cannot determine the economic effect of a call, the default SHALL be deny.

### 10.7 PAA07 — Unauthorized Social Representation

- **FR-PAA07-001 (MVP)** Draft and send SHALL be distinct actions with distinct sensitivity: send is always sensitive; a draft permission SHALL NOT authorize a send. Any future tool with draft/send semantics inherits this classification.
- **FR-PAA07-002 (MVP)** Send approvals SHALL bind `(audience-hash, content-hash)`; the approval card SHALL show recipients and the full rendered message as inert text per the Fix B rendering rules.
- **FR-PAA07-003 (MVP)** Audience expansion, material message changes, or onward representation (another agent sending) SHALL each require a new approval; the prior grant SHALL NOT transfer.
- **FR-PAA07-004 (MVP — conditional)** The gateway SHALL mark agent-originated messages with an origin disclosure wherever the connected service supports adapter-settable origin markers; verified agent identity SHALL be shown on the card as authentication fact, separate from the authorization decision. Unrealizable where the service does not support it; flagged per connector, never silently dropped.
- **FR-PAA07-005 (MVP)** Narrow recurring notices (e.g., a weekly status email to a fixed list with a fixed template) SHALL be authorized via a template-bound notice rule — a standing POLICY RULE (02 §5), not an approval grant: the rule binds the audience list, the template, and the schedule; each execution is allowed only if the rendered content matches the template within declared constraints; every execution is audit-logged. (05 §PAA07 concrete mechanism.)

### 10.8 PAA08 — Household and Bystander Consent Violations

- **FR-PAA08-001 (MVP)** Household roles SHALL be first-class policy scopes: an agent registered for one member's role SHALL NOT satisfy rules for another member's private-labeled data.
- **FR-PAA08-002 (MVP)** Recipient lists SHALL be constrained to the approved audience; expansion beyond it escalates to approval with the new recipients named.
- **FR-PAA08-003 (MVP)** Distrusted or distinct household roles SHALL use separate agent identities with separate access boundaries, not shared credentials.
- **FR-PAA08-004 (MVP)** Retention SHALL be minimized per label class: bystander-incidental data SHALL be redacted or dropped per policy rather than stored; every access SHALL record whose data was touched and under which role.

### 10.9 PAA09 — Manipulation of Personal Choice

- **FR-PAA09-001 (MVP)** Approval cards SHALL include an incentives section: detected sponsor/placement signals in the trigger content, how the action compares to the recorded criteria, and the trigger source; cards SHALL NOT use urgency language.
- **FR-PAA09-002 (MVP)** The inspection pipeline SHALL flag false-urgency patterns and deceptive relationship claims in content that triggers a sensitive call, and surface the flags on the approval card.
- **FR-PAA09-003 (MVP)** A denied approval request SHALL enter a refusal cooldown during which the same request is not re-presented; refusal ends solicitation. The cooldown key is (agent, tool, argument-hash). Default cooldown duration is 24 hours (design target, tunable per policy). An identical call inside the cooldown is denied with the `cooldown_active` error code — no approval request is created and no notification is sent to Ken (02 §2.8 steps 3 and 10, 02 §2.7). Denial-streak escalation: after 3 denied sensitive requests for the same (agent, tool) within 24 hours (design targets, tunable), a per-(agent, tool) cooldown engages (24 hours default, tunable) under which ALL sensitive calls for that pair return `cooldown_active` regardless of arguments. This bounds the deny→mutate→request loop while the per-request cooldown covers first denials.
- **FR-PAA09-004 (MVP)** The gateway SHALL record Ken's decision criteria per domain for reference in evaluations; cancellation or disconnection of a workflow SHALL be one action, deny pending approvals immediately, and never require justification.

### 10.10 PAA10 — Loss of Personal Control and Continuity

- **FR-PAA10-001 (MVP)** The admin console SHALL provide a global "stop everything" control that pauses all agents and cancels pending approvals, plus per-agent pause and revoke.
- **FR-PAA10-002 (MVP)** Pause, cancel, revoke, delete, and close SHALL be distinct lifecycle states with distinct effects: pause is temporary and resumable; cancel drops pending approvals and queued work; revoke kills the identity and invalidates sessions, tokens, and grants; delete removes the identity while audit is retained per retention; close completes offboarding with export.
- **FR-PAA10-003 (MVP)** The console SHALL report per-item status for queued, delegated, and in-flight work under each lifecycle action — never a single undifferentiated "done."
- **FR-PAA10-004 (MVP)** Agent-facing errors and console acknowledgments SHALL distinguish "received" from "enforced" and name the state (paused/revoked/canceled), never a silent hang.
- **FR-PAA10-005 (MVP)** Irreversible actions SHALL carry an explicit irreversible marker in the audit row with their pending obligations (e.g., sent email, no recall available).

### 10.11 Tracked amendments from the adversarial review (applied 2026-10-12)

- **FR-011** rewritten: OAuth 2.1 primary, exactly one credential per agent; long-lived bearer fallback only after demonstrably failed OAuth verification, recorded in the console with the test date; auth floor refuses connections below a per-agent secret over TLS (no third rung).
- **FR-012** split into **FR-012a** (agent-facing session credential) and **FR-012b** (per-call derived upstream token, never agent-visible).
- **FR-013** split into **FR-013a** (gateway-scope policy claims) and **FR-013b** (upstream-scope connector OAuth scopes; the (agent, tool, action) binding is gateway bookkeeping, not cryptographic).
- **AC-04** extended with the live-agent poll→approve→re-invoke criterion and the console "execute on approval" fallback. **AC-05** amended (no vault credential retrievable agent-side). **AC-11** amended (CI gate + production measurement). **AC-12** amended (`POST /api/policy/dry-run` endpoint shape).
- **FR-028** extended with the per-agent pending-approval cap (default 5) and `approval_queue_full`.
- **FR-029** moved to post-MVP.
- **FR-039–FR-041** added (admin auth audit, admin login rate limiting/lockout, admin-action audit logging). **FR-042** added (CSRF on state-changing console endpoints; per-decision re-auth for destructive scopes).
- **OQ-1/OQ-3** rewritten to the Fix A single-credential rule.
