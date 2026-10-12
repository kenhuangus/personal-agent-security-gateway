# Personal Agent Security Gateway — Build Plan

**Document:** `docs/00-build-plan.md`
**Phase:** 4 of 4 (Consolidation) — planning only, no implementation
**Product owner:** Ken
**Status:** Draft for Ken's review. Implementation is gated on his explicit go-ahead.
**Baseline:** `docs/01-requirements.md`, `docs/02-design.md`, `docs/03-architecture.md`, `docs/04-review.md`

Conventions: numbers are design targets, not promises, unless labeled otherwise. Every third-party platform claim is traceable to the project brief or flagged as unverified. Short sentences, no marketing language.

---

## 1. Vision

One public MCP endpoint (Streamable HTTP over HTTPS) that Ken's personal AI agents — Meta Muse (Custom Connectors), Grok Bot (custom MCP servers), and OpenAI Dots (provisional, via ChatGPT plugins) — register once. The gateway mediates every tool call: agent identity, short-lived scoped tokens, per-agent/per-tool allow/deny policies, step-up human approval for sensitive actions, server-side credential vault, input validation, tool-output prompt-injection scanning, PII redaction, rate limits, and a full redacted audit log. Agents never hold raw credentials. The gateway never runs inside an agent's VM.

The reviewer (04) rejected all three planning artifacts — not the vision, but the details. This plan folds all 16 must-fix items (MF-1–MF-16) into the build as required corrections. The three artifacts need the named edits before they are final; the plan below states the corrected behavior so implementation planning can proceed on a consistent base.

---

## 2. The two load-bearing fixes (from the review)

The reviewer grouped the must-fix items into two connected fixes. They are not independent tickets.

### Fix A — The auth wall (MF-1, MF-2, MF-3, MF-14, MF-15)

- Exactly one credential per agent. OAuth 2.1 is primary. A long-lived per-agent bearer fallback exists only for an agent whose platform has demonstrably failed OAuth verification, recorded in the console with the test date. Fallback issuance is never the default and never alongside OAuth credentials. (MF-1, MF-15)
- The auth floor: the gateway refuses agent connections that cannot present at least a per-agent secret over TLS. There is no third rung (no IP-allowlist downgrade). (MF-2)
- Two token layers, named separately: the agent-facing session credential (OAuth access token, or the fallback bearer when active) and the per-call derived upstream token (short-lived, scoped to agent/tool/action, never agent-visible in raw form). FR-012 is split accordingly; AC-05 is amended to assert that no vault-stored upstream credential is retrievable agent-side, with the fallback bearer as the only permitted long-lived agent-side secret. (MF-3)
- The threat model splits credential theft by token type: short-lived derived tokens vs. long-lived fallback bearers, with rotation discipline, a console-visible "fallback auth in use" flag, and an immediate revocation path for the latter. (MF-14)

### Fix B — The approval workflow (MF-4, MF-5, MF-6, MF-7, MF-8, MF-9, MF-11, MF-12)

- Validate-first ordering: authenticate → validate inputs → check mandate liveness → evaluate policy → approval if sensitive → mint token → execute → inspect output → audit. Schema validation failure on a sensitive tool returns `invalid_input` and never creates an approval request. (MF-4)
- `gateway.approval_status` lookups are bound to the caller's agent identity; another agent's request ID returns not-found (not "denied"). Request IDs are 128-bit random (`apr_` prefix for approvals, `req_` for calls). (MF-5)
- Approval cards render arguments as inert preformatted text (no rich rendering, no clickable links), show a structured consequence summary before free text, and carry a static "untrusted content" label. (MF-6)
- Grant evaluation order is specified: active grants for (agent, tool, argument-hash) are checked before rule evaluation; a matching unexpired grant short-circuits to `allowed_via_approval` — provided the mandate is still live (grant consumption re-checks mandate liveness; withdrawal, expiry, or pause invalidates approved-but-unconsumed grants, each named with its own reason — FR-PAA01-004). Grants survive non-material policy version changes; a material change to a standing instruction/mandate invalidates affected unconsumed grants and flags pending approvals for review (FR-PAA04-003; the save records a material/non-material classification). Agent revocation kills grants immediately. (MF-7)
- Anti-CSRF tokens (or SameSite=Strict cookies plus custom-header checks) on all state-changing console API routes, named explicitly for the approval-decision endpoint. (MF-8)
- Per-agent cap on concurrent pending approvals (default 5, tunable); breaching it returns a structured error and logs the event. (MF-9)
- AC-04 is extended with a live-agent criterion: using the actual Muse Custom Connector and Grok Bot clients, demonstrate a sensitive call completing the full error → poll → approve → re-invoke → execute loop. If a platform's agent cannot poll, the design gets a console-side "execute on approval" fallback for that platform before MVP is declared done. (MF-11)
- The history dry-run operation is a specified console endpoint (e.g. `POST /api/policy/dry-run` with `{policy_version, window_days}`), returning per-call would-allow/would-deny/would-require-approval counts plus the changed call list, with a synthetic corpus for cold start. (MF-12)

### Other must-fix items folded in

- Admin-surface requirements added: all admin authentication attempts audit-logged, admin login rate-limited with lockout/backoff, policy saves/rollbacks/revocations/rotations audit-logged as admin actions. All MVP. (MF-10)
- FR-029 (cost budgets) moved out of MVP: no MVP connector reports cost. (MF-13)
- AC-11 kept as a CI gate (local p95 > 100 ms fails the build) plus a post-deploy production measurement recorded before MVP sign-off. (MF-16)

---

## 3. MVP scope

### In MVP

- Public HTTPS MCP endpoint over Streamable HTTP; multiple concurrent agents with distinct identities (Fix A auth).
- Connector registry (plugin interface, FR-009) with 3 connectors: email (search/read/send), calendar (list/create/update/delete), one code-host connector (GitHub, pending Ken's confirmation; read-first, `pr.open` sensitive-gated from day one; `pr.merge` deferred until the approval loop proves itself on `email.send`).
- Policy engine: per-agent/per-tool/per-action allow/deny, visible pinned default-deny, sensitive actions, one-time approval grants only (windowed grants deferred), dry-run with history endpoint (MF-12).
- Server-side encrypted vault (envelope encryption, KMS-held key), rotation, audited internal reads; secrets never in UI, errors, or audit.
- Inspection pipeline: JSON-schema input validation (runs before policy/approval per MF-4), pattern-based prompt-injection scan, PII redaction before audit write and before agent delivery, per-agent rate limits, per-agent pending-approval caps (MF-9). Cost budgets: out (MF-13).
- Append-only audit log: search/filter, JSON/CSV export (exports audit-logged), admin-auth events logged (MF-10).
- Web admin console (nine pages: Dashboard, Agents, Connectors, Policies, Approvals, Audit Log, Vault & Settings, Mandates, Context boundaries): agent registration with single-credential issuance and first-connection verification checklist, one-action revocation, policy builder + raw JSON/YAML + version history with diff/rollback, approval queue with inert rendering (MF-6) and CSRF protection (MF-8), connector health (credential-valid + API-reachable, every 5 min).
- PAA10-derived controls (01 §10, all MVP per the milestone assignments there): mandate records bound at session binding with mandate-scoped evaluation, inert approval cards with mandate/term-sheet/counterparty-evidence/incentives/audience-preview sections, global stop + per-agent pause with per-item work status, code-artifact redaction, cross-context leakage flagging, purpose-bound rules, household-role scoping.
- Muse and Grok Bot integration verified end-to-end, including the live approval loop (extended AC-04).

### Explicitly out of MVP

- OpenAI Dots build (verification spike only; provisional path).
- Cost budgets (MF-13), windowed approval grants (one-time only in MVP).
- Multi-user/team admin roles (single admin = Ken; `admin_id` seams in the schema).
- `code.pr.merge` and other code-host write actions beyond PR open.
- HA/multi-instance, Postgres (SQLite + migration seam), OPA/Cedar, LLM-judge injection detection, console OIDC (password + TOTP for admin), mobile/push approvals (email-to-Ken notification), usage metering/billing, connector marketplace/signing, scanner-findings-to-policy integration.

---

## 4. Milestones with exit criteria

Build order is sliced end-to-end per the reviewer's sequencing. Each milestone is independently testable.

### M0 — Spikes and registrations (before any component work)

- Live platform spikes: (a) can the Muse Custom Connector client do OAuth 2.1 against a test server, or only bearer headers? (b) same for Grok Bot. (c) Does each platform's agent complete a poll-and-retry loop (error → poll status → re-invoke)? (d) Dots verification spike: connect a custom MCP plugin in ChatGPT, check Dot visibility and presented identity. Each spike has a written pass/fail; failures pick the auth path (Fix A) or trigger the approval-loop redesign (MF-11) before M3.
- Start upstream OAuth app registrations: Google and/or Microsoft (email + calendar), GitHub (code host). Platform verification lead times (days to weeks) are the top schedule risk and sit outside the codebase — start on day one.
- Ken confirms hosting (Fly.io default, Cloud Run conditional) and the code-host choice.

Exit criteria: spike results recorded per platform; auth method per platform decided; OAuth apps submitted; hosting confirmed.

### M1 — Endpoint, identity, audit

- MCP server (Streamable HTTP, TLS), single auth path per platform per M0 results, agent registration/revocation, session binding, SQLite config + separate audit DB (WAL), append-only audit with search.

Exit criteria: AC-01, AC-02 (read-only test tool through the real Muse connector and Grok Bot), AC-03 (default-deny), AC-08 (revocation), AC-09 (export + search), mandate records bound at session binding with mandate-validity checked before any tool logic (FR-PAA01-001/002).

### M2 — Email-read connector, policy engine, minimal console

- Email connector (read-only: search/read), hand-rolled JSON rule evaluator with default-deny, console pages: Agents, Audit Log.

Exit criteria: allow/deny end-to-end per agent/tool; denial rows logged with reasons; dry-run single-call endpoint working; purpose-bound rule evaluation (FR-PAA03-002); household-role scoping on agent identities (FR-PAA08-001).

### M3 — Approval workflow (Fix B, complete)

- Validate-first ordering, caller-bound `approval_status`, inert argument rendering, grant-before-rule evaluation, grant semantics, CSRF on the decision endpoint, per-agent approval caps, one-time grants only, Approvals page, email-to-Ken notification on new requests.

Exit criteria: extended AC-04 — the full approval loop demonstrated with the actual Muse and Grok agents, not just the spec. Minimal schema validator ships here (JSON Schema draft 2020-12: type/enum/required/format/maxLength — sufficient to demonstrate `invalid_input` vs `approval_required`; M5 hardens it). One-time grants only. Approval cards carry the 02 §4.4 sections (inert rendering, mandate purpose/duration, term sheet, counterparty evidence, incentives, audience+content preview). Email-to-Ken notification uses the dedicated exempt system notification path, not M4's policy-gated `email.send` connector — M3 does not wait for M4. If a platform's agent cannot poll (M0 spike failed), the console "execute on approval" fallback is in place for that platform.

### M4 — Vault and credential-backed connectors

- Encrypted vault (envelope encryption, KMS key per hosting choice), rotation with graceful token expiry, audited internal reads; email.send, calendar write, GitHub read + `pr.open` (sensitive-gated).

Exit criteria: amended AC-05 (no vault credential retrievable agent-side), AC-08 re-verified with credential-backed calls, rotation drill passes.

### M5 — Inspection pipeline

- Input validation in the hot path (already ordered per MF-4; hardened here), prompt-injection pattern scanning, PII redaction catalog (console-editable from day one), rate limits.

Exit criteria: AC-06 (planted injection blocked/logged), AC-07 (PII redacted before agent and before audit write). Input validation hardened here beyond the M3 minimal validator: format validators (date-time/email), `additionalProperties` rejection, canonicalization before hashing, injection-oriented constraints, per-tool stricter patterns. Code-artifact redaction (FR-PAA02-001), cross-context leakage flagging (FR-PAA03-003), and trigger-content false-urgency flagging (FR-PAA09-002) live in the inspection pipeline.

### M6 — Console completion and hardening

- Remaining pages (Dashboard, Connectors with health checks, Policies with version history + history dry-run endpoint, Vault & Settings), admin-auth audit + login rate limiting (MF-10), admin password + TOTP, AC-10 dependency scan + SDK-floor CI assertion, AC-12 history dry-run, AC-11 production p95 measurement recorded.

Exit criteria: all acceptance criteria green, including the production AC-11 measurement and the live-agent AC-04. Console ships all nine pages (02 §3.2): Mandates page, Context boundaries page, counterparty-record review/correction (AOQ-12), recorded-criteria settings (AOQ-13), global stop control with per-item work status (FR-PAA10-001/003), per-agent pause in the agent danger zone (FR-PAA10-001). History dry-run endpoint per AC-12.

---

## 5. Tech stack (from the architecture, with review corrections)

| Layer | Choice |
|---|---|
| Language/runtime | Python 3.12+ |
| MCP server framework | FastMCP on the MCP Python SDK, pinned ≥ the fixed releases (FR-005/AC-10; exact release citations added to the requirements before build) |
| Admin console + health endpoints | FastAPI (server-rendered pages or minimal JS; no React in MVP) |
| Policy engine | Hand-rolled JSON rule evaluator (no OPA/Cedar) |
| Database | SQLite via SQLAlchemy (separate files for config, audit, encrypted secrets; WAL mode; Postgres migration seam via ORM) |
| Secret management | Envelope encryption; KMS-held key (Fly secrets or GCP Secret Manager per hosting choice) |
| Inspection | JSON-schema validation + regex/pattern rules (no LLM in the hot path) |
| Hosting | Fly.io (default); Cloud Run if Ken prefers GCP-native Secret Manager |
| CI/CD | GitHub Actions: lint + typecheck, CVE scan (blocks HIGH+), SDK-floor assertion, AC-11 load test as CI gate, deploy on merge to main |
| Backup | Nightly file-level backup of the three SQLite files to object storage; KMS key excluded; documented manual restore |

Review corrections applied: the "most widely used / largest example base" superlatives are dropped — the FastMCP choice stands on the architect's stated judgment (connector library ecosystem, OAuth worked examples, team fit). Trust boundaries in the architecture are labeled logical-in-MVP (single process), physical later. Streamable HTTP support is verified against named SDK versions at implementation.

---

## 6. Acceptance criteria (amended per review)

AC-01 (Muse end-to-end), AC-02 (Grok end-to-end), AC-03 (default-deny), AC-04 (approval loop — extended with the live-agent demonstration), AC-05 (amended: no vault-stored upstream credential retrievable agent-side; fallback bearer the only permitted long-lived agent-side secret), AC-06 (injection blocked/logged), AC-07 (PII redacted pre-write and pre-delivery), AC-08 (revocation), AC-09 (export/search), AC-10 (SDK floor + CVE scan), AC-11 (CI gate locally + recorded production p95 measurement), AC-12 (history dry-run via the specified endpoint).

---

## 7. Parameters to set (reviewer's 20, with recommendations)

Owner is Ken unless noted. Set before or during the named milestone.

1. Agent session credential lifetime — 60 min OAuth access tokens; fallback bearer max age 90 days with mandatory rotation and a console-visible age indicator. (M1)
2. Derived per-call token lifetime — 5 minutes. (M1)
3. Approval timeout default — 15 minutes; 5 minutes for destructive actions (destructive-action registry in 02 §2.7: `calendar.delete`, `email.settings.write`). (M3)
4. Default rate limits — 60 calls/min, 1,000/day per agent, tunable; plus the pending-approval cap of 5 per agent (MF-9). (M3/M5)
5. Audit retention — 90 days, configurable; expired rows archived to object storage (pick archive over delete). (M1)
6. Admin authentication strength — password plus TOTP for MVP. (M6)
7. Approval notification channel — in-console plus email-to-Ken on each new request for MVP. (M3)
8. Hosting confirmation — Ken picks before M0 exits. (M0)
9. Code-host connector — confirm GitHub; start its OAuth app registration in M0. (M0)
10. Upstream OAuth app registrations — start in M0; verification lead time is the top schedule risk. (M0)
11. Grant vs policy-version semantics — grants survive non-material version changes; a material change to a standing instruction/mandate invalidates affected unconsumed grants and flags pending approvals for review (FR-PAA04-003; every save records a material/non-material classification, 02 §5). Revocation kills grants immediately. (M3)
12. Request-ID format — 128-bit CSPRNG, `apr_` / `req_` prefixes. (M1)
13. Redaction catalog — ship email/phone/SSN-shaped/account-number patterns; console-editable from day one; full `[redacted:type]` tokens, no last-4 hints until Ken accepts the tradeoff. (M5)
14. Conditional-sensitivity definitions — Ken supplies his domain list ("external" attendees) and `email.send` recipient-domain constraints at build time. (M2)
15. Dashboard timezone — UTC in storage, Ken's local timezone in display. (M6)
16. Connector health checks — credential-valid + API-reachable, every 5 minutes, console banner on failure. (M6)
17. Dry-run cold-start corpus — hand-written synthetic calls (one per tool), labeled in output. (M2)
18. Grant types — one-time grants only in MVP; "always allow" is a policy rule, not an approval. (M3)
19. Audit export staging — local-disk staging with manual download for MVP. (M6)
20. Build sequencing — the M0–M6 order above. (Plan)
21. One-time grant TTL — 30 minutes from approval (design target). The approval window (default 15 min, parameter 3) is how long Ken has to decide; the grant TTL is how long the agent has to re-invoke after approval. (M3)

Nice-to-haves to consider if room appears: hash-chained audit entries (NH-1), `invalid_input` without arg echo (NH-2), approval-decision idempotency (NH-3), redacted-plus-hash storage for paused calls (NH-4), NTP/chrony note (NH-5), SSE-vs-poll labeling (NH-6), secret zeroization note (NH-7), retry-loop rate limiting after deny/expire (NH-8), default-deny row in dry-run output (NH-9), approval-card blast-radius line (NH-11). (NH-10 — the SSRF review checklist — is now required for every MVP adapter as part of FR-009 acceptance, not a nice-to-have.)

---

## 8. Risks

1. **Upstream OAuth app verification lead time** (Google/Microsoft/GitHub) — outside the codebase, blocks end-to-end testing (AC-01/AC-02). Mitigation: start registrations in M0, day one.
2. **Platform agent behavior** — whether Muse/Grok clients support OAuth 2.1 and whether their agents complete the poll-and-retry approval loop is unverified. Mitigation: M0 spikes with written pass/fail; Fix A and MF-11 fallbacks ready.
3. **Approval fatigue** — the human is the weakest link (T5). Mitigation: bounded scopes, queue caps, default-deny timeout, inert rendering; batching and risk-ranked presentation are later-phase work.
4. **Pattern-based injection detection** — misses novel phrasing (T1 residual). Accepted for MVP; semantic detection is a later phase.
5. **Single stateful service** — no HA in MVP (NFR-REL-001); gateway-down means fail-closed for all agents. Accepted; documented.

---

## 9. Open decisions needing Ken's call

1. **Hosting: Fly.io or Cloud Run?** Drives the KMS story and the deploy pipeline. (M0)
2. **Product shape: personal-use tool or second SaaS line next to the AgentSec scanner?** MVP builds personal-use with multi-tenancy seams (agent identities, per-agent policies); a SaaS decision later changes team RBAC, billing, and hosting posture. (Before M6)
3. **Approval notification channel: DECIDED** — in-console plus email-to-Ken on each new approval request for MVP (see 02 §2.8 step 5). Admin credential strength (password + TOTP for the console) still needs Ken's confirmation. (M3/M6)
4. Confirm GitHub as the code-host connector and that its write actions beyond `pr.open` stay out of MVP. (M0)
5. Supply the domain/attendee lists for conditional-sensitivity rules and recipient-domain constraints. (M2)
6. Start the Google/Microsoft/GitHub OAuth app registrations — needs Ken's developer accounts; cannot be delegated to an agent. (M0)

---

## 10. Role mapping for the build

- **Functional analyst** — owns FR/NFR amendments from the review (FR-011 rewrite, FR-012 split, AC-05 amendment, FR-029 move, new admin-surface FRs, MF-16 AC-11 correction) and the traceability of each milestone's exit criteria back to requirements.
- **Designer** — owns the Fix B approval-flow redesign (validate-first, caller-bound status, inert rendering, grant semantics, CSRF, queue caps, dry-run endpoint spec) and the console page builds.
- **Architect** — owns Fix A (auth wall, token layers, threat-model split), the M0 spike definitions with pass/fail criteria, hosting/KMS wiring, and the CI gates (SDK floor, CVE scan, AC-11 load test).
- **Reviewer** — re-reviews the amended artifacts against the must-fix list and signs off each milestone's exit criteria, starting with M0's spike results.

---

*Planning complete. Nothing here is built. Implementation begins only on Ken's explicit go-ahead, after he reviews this plan and answers the open decisions in §9.*
