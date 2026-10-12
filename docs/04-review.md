# Personal Agent Security Gateway — Adversarial Review

**Document:** `docs/04-review.md`
**Phase:** 3 of 4 (Adversarial Review) — planning only, no implementation
**Reviewer role:** senior adversarial reviewer
**Baseline:** `docs/01-requirements.md`, `docs/02-design.md`, `docs/03-architecture.md`
**Status:** Draft for review. Implementation remains gated on Ken's go-ahead.

This review is blunt on purpose. Praise is omitted. Every item below is a
problem to fix or a decision to make.

---

## 1. Verdict per artifact

### 01-requirements — REJECT

The requirements are internally inconsistent on the single most
security-critical decision in the document: how agents authenticate.
FR-011 says agent sessions SHALL use OAuth 2.1/OIDC, while OQ-1
recommends building an API-key fallback and the later documents run
with it. AC-05 then asserts agent-side traffic shows "only short-lived
scoped tokens," which is false the moment a long-lived fallback bearer
exists. FR-029 (cost budgets) is unimplementable against the MVP
connectors — email, calendar, and GitHub do not report per-call cost,
so the requirement can never be exercised in MVP. Three admin-surface
requirements are missing entirely: audit of admin authentication
events, login rate limiting/lockout, and a cap on pending approvals per
agent. Blockers: rewrite FR-011, amend AC-05, scope FR-029 out of MVP,
add the three missing FRs. These are small edits, but they must be
edits, not carried ambiguity.

### 02-design — REJECT

The approval suspend/resume flow has four defects that block build
planning. First, the data flow creates an approval request before
input validation runs (architecture §1.2 orders approval at step 4,
validation at step 5), so malformed calls can spam Ken's approval
queue — a fail-open-shaped hole in a fail-closed design. Second,
`gateway.approval_status` is specified without binding the lookup to
the caller's agent identity, making request IDs a cross-agent oracle
until proven otherwise. Third, the approval card displays tool
arguments to Ken with no defense against prompt injection aimed at the
human approver — the threat model covers injection against the agent
(T1) but not against the approver. Fourth, the flow depends on the
agent polling with backoff and re-invoking, which is assumed platform
behavior the plan cannot verify; AC-04 does not require proving the
real agent completes the loop. Also missing: the console API endpoint
for history-based dry-run (FR-019/AC-12 names the capability, design
§2.6 only specifies single-call evaluate), CSRF protection on the
approval-decision endpoint, and pending-approval caps. Blockers are
named in the MUST-FIX list.

### 03-architecture — REJECT

The architecture is the strongest of the three, and most of its open
questions are honestly flagged. It is still not ready for build
planning for one reason: the authentication fallback ladder has no
floor. Section 2.3 recommends OAuth 2.1 primary with registration
tokens as fallback, and AOQ-1 then proposes a further downgrade to "IP
allowlisting plus a shared secret header" if neither works — with no
stated point at which the answer becomes "this platform cannot be
connected securely." Each fallback is weaker than the last, and the
fallback becomes the attack path (the architect's own §2.3 table calls
bearer tokens "exfiltration-prone"). The threat model (T2) does not
differentiate stolen long-lived fallback tokens from stolen
short-lived derived tokens, though the blast radius differs by orders
of magnitude. Blockers: define the auth floor, forbid issuing both
credentials by default, and split T2 by token type. Secondary: AC-11's
"local load test" is presented as evidence for a production p95 claim
it cannot support.

---

## 2. MUST-FIX items

**MF-1 — Rewrite FR-011 to admit the fallback honestly.**
Problem: FR-011 (01 §4.3) states agents SHALL authenticate using OAuth
2.1/OIDC. OQ-1 (01 §9), design §6.1/§6.2, and architecture §2.3 all
proceed on dual-auth with a bearer-token fallback. A SHALL that the
design knowingly violates is not a requirement; it is a lie the build
plan will inherit.
Affects: 01-requirements (FR-011), 02-design (§6.1, §6.2), 03-architecture (§2.3).
Fix: rewrite FR-011 as "OAuth 2.1/OIDC is the primary agent-auth
method; a per-agent long-lived bearer fallback is permitted only when
the platform demonstrably lacks OAuth support, must be flagged
visibly in the console, and is subject to mandatory rotation." Add an
FR that fallback credentials are issued only after a failed OAuth
verification test — never by default alongside OAuth credentials.

**MF-2 — Define the authentication floor; delete the third rung.**
Problem: architecture AOQ-1 proposes that if neither OAuth nor bearer
tokens work, the fallback is "IP allowlisting plus a shared secret
header," described as a "documented downgrade." There is no stated
condition under which a platform is refused connection. A security
control plane with no refusal condition will eventually connect an
insecure platform and call it documented.
Affects: 03-architecture (AOQ-1, §2.3).
Fix: specify the floor in the architecture doc — e.g., "the gateway
refuses agent connections that cannot present at least a per-agent
secret over TLS; platform connectivity that requires weakening below
the bearer-token fallback is out of scope until the platform adds
auth." Remove the IP-allowlist rung or mark it explicitly as
rejected, not deferred.

**MF-3 — Amend AC-05; define the two token layers.**
Problem: AC-05 (01 §7) claims agent-side traffic shows "only
short-lived scoped tokens, never vault contents." Under the fallback
auth path, agent-side traffic shows a long-lived registration bearer
by design. The acceptance criterion contradicts the approved auth
design. Related: FR-012's "short-lived, scoped tokens for each tool
call" conflates two different tokens — the agent-facing session
credential and the per-call derived upstream token.
Affects: 01-requirements (AC-05, FR-012), 03-architecture (§2.2).
Fix: split FR-012 into FR-012a (agent-facing session credential:
OAuth access token or, under fallback, a long-lived per-agent bearer
with rotation) and FR-012b (per-call derived upstream token,
short-lived, scoped to agent/tool/action, never agent-visible in raw
form). Rewrite AC-05 to assert: no vault-stored upstream credential
is retrievable agent-side; the only long-lived agent-side secret is
the gateway-issued fallback bearer, and only when fallback is active.

**MF-4 — Validate inputs before creating approval requests.**
Problem: architecture §1.2 orders the flow as policy evaluation (step
3) → approval (step 4) → input validation (step 5). A malformed or
adversarial call to a sensitive tool therefore creates an approval
request and an audit row before its arguments are even checked. An
agent (or attacker holding its credential) can flood Ken's approval
queue with garbage at zero cost. This inverts the fail-closed order:
cheap checks must run before expensive human-involving ones.
Affects: 03-architecture (§1.2), 02-design (§2.8).
Fix: reorder to authenticate → validate inputs (FR-025) → evaluate
policy → approval if sensitive → mint token → execute → inspect
output → audit. State explicitly that schema validation failure on a
sensitive tool returns `invalid_input` and never creates an approval
request.

**MF-5 — Bind `gateway.approval_status` to the caller's identity.**
Problem: design §2.5 specifies the meta tool and claims it "reveals
nothing about policy rules — only the status of the agent's own
request." Nothing in the design binds the `request_id` lookup to the
authenticated agent identity. If request IDs are guessable or leak
(e.g., via a shared log), one agent can poll another agent's approval
status — an oracle that reveals when sensitive actions are pending,
approved, or denied for other agents.
Affects: 02-design (§2.5).
Fix: require that `approval_status` filters by the caller's
`agent_id`; a request ID belonging to another agent returns
not-found (not "denied," to avoid confirming existence). Specify
request-ID entropy (e.g., 128-bit random, `apr_` prefix).

**MF-6 — Defend the human approver against prompt injection.**
Problem: the threat model covers injected tool output hijacking the
agent (T1) but not injected content hijacking Ken. The approval card
(design §4.4) shows an "argument summary" — for `email.send`, that is
attacker-influenceable text (subject, body) rendered to the person
holding the approve button. "URGENT — approve immediately, your boss
asked" in an email body is a prompt-injection attack against the
approver, and no mitigation is specified.
Affects: 02-design (§4.4), 03-architecture (§6, T5).
Fix: add to the design — approval arguments render as inert
preformatted text (no rich rendering, no clickable links); the card
shows a structured summary (tool, agent, recipient count, size)
before any free text; a static warning label marks arguments as
untrusted content. Add the attack to T5's mitigation column.

**MF-7 — Specify grant-evaluation order and grant/policy-version interaction.**
Problem: design §2.8 says the re-invoked call finds the active grant
and is allowed, but never states evaluation order: grants must be
checked before rule evaluation, or the re-invoked sensitive call
would spawn a second approval request. Unspecified: what happens if
the policy version changes between approval and re-invocation — does
a human grant survive a rule change?
Affects: 02-design (§2.8).
Fix: specify — on `tools/call`, the policy engine checks active
grants for (agent, tool, argument-hash) before evaluating rules; a
matching unexpired grant short-circuits to allow with decision
`allowed_via_approval`. Specify that grants reference the policy
version active at approval time and remain valid across versions
(human decision outranks rule edits), or the opposite — but decide
and write it down. Recommended: grants survive version changes;
revocation of the agent kills its grants immediately.

**MF-8 — Require CSRF protection on the approval-decision endpoint.**
Problem: `POST /api/approvals/{request_id}/decision` (design §2.6) is
the single most sensitive endpoint in the system — it authorizes
actions. NFR-SEC-005 names CSRF in passing, but nothing specifies the
mechanism, and AOQ-7 puts the console on the same public host as the
MCP endpoint. Threat: an attacker who controls an agent creates a
pending request, then CSRFs Ken's browser into approving it.
Affects: 02-design (§2.6), 01-requirements (NFR-SEC-005).
Fix: require anti-CSRF tokens (or `SameSite=Strict` cookies plus
custom-header check) on all state-changing console API routes, named
explicitly for the approval-decision endpoint. Add an FR: admin
console state-changing endpoints SHALL require CSRF protection;
approval decisions additionally SHOULD require re-authentication or a
per-decision confirmation token for destructive scopes.

**MF-9 — Cap pending approvals per agent.**
Problem: no limit exists on how many approval requests an agent can
create. A compromised or runaway agent can flood the queue — a
denial-of-attention attack that feeds directly into T5 approval
fatigue. Rate limits (FR-028) count tool calls; approval requests are
a separate scarce resource (human attention).
Affects: 01-requirements (FR-028), 02-design (§2.8, §4.4), 03-architecture (§6, T5).
Fix: add a per-agent cap on concurrent pending approval requests
(recommended default: 5; tunable per agent). Breaching the cap
returns `approval_required` with code `approval_queue_full` (or
denies with `rate_limited`) and logs the event. Document in T5
mitigations.

**MF-10 — Add the missing admin-surface requirements.**
Problem: the gateway is a security control plane, but the
requirements never require auditing admin authentication events,
rate-limiting admin login, or recording policy-version saves as
audited admin actions. Design §7 audits audit-log *exports* but not
logins; design §5 versions policies without saying the save is
audited. An attacker brute-forcing the single admin credential
(FR-036) would leave no required trace.
Affects: 01-requirements (§4.8, §5), 02-design (§7).
Fix: add FRs — (a) all admin authentication attempts (success and
failure) SHALL be audit-logged; (b) admin login SHALL be rate-limited
with lockout or exponential backoff; (c) policy version saves,
rollbacks, agent revocations, and credential rotations SHALL be
audit-logged as admin actions. These are MVP, not later-phase.

**MF-11 — Prove the approval loop against the real agent, not the spec.**
Problem: design §2.8 assumes the agent polls `approval_status` with
backoff and re-invokes the original call. Whether Muse's or Grok's
MCP client surfaces the `approval_required` error content to the
model, and whether the model will actually perform a multi-step
poll-then-retry loop inside its tool budget, is unverified platform
behavior — the exact class of assumption design principle 5 forbids.
AC-04 tests that approval gates execution, not that any real agent
can traverse the loop.
Affects: 02-design (§2.8), 01-requirements (AC-04).
Fix: extend AC-04 with a live-agent criterion — "using the actual
Muse Custom Connector and Grok Bot clients, demonstrate an
`email.send` (or equivalent) completing the full
error → poll → approve → re-invoke → execute loop." If a platform's
agent cannot or will not poll, the design needs a fallback (e.g.,
console-side 'execute on approval' for that platform) before MVP is
declared done.

**MF-12 — Specify the history dry-run console endpoint.**
Problem: FR-019/AC-12 require dry-run evaluation against the last 7
days of audit history. Design §2.6 specifies `POST
/api/policy/evaluate` for a single hypothetical call only. The
history-replay operation — the one AC-12 actually tests — has no
specified interface, request shape, or result shape.
Affects: 02-design (§2.6, §5), 01-requirements (FR-019, AC-12).
Fix: specify the endpoint (e.g., `POST /api/policy/dry-run` with
`{policy_version, window_days}` returning per-call
would-allow/would-deny/would-require-approval counts plus the changed
call list). Note the cold-start behavior per DQ-2 (synthetic corpus
when history is empty).

**MF-13 — Scope FR-029 out of MVP or define the no-op.**
Problem: FR-029 requires per-agent cost budgets "where the underlying
system reports cost." None of the MVP connectors (email, calendar,
GitHub) report per-call cost. An untestable SHALL in MVP is dead
weight that will either be skipped silently or gold-plated.
Affects: 01-requirements (FR-029, §8).
Fix: move FR-029 to "later phases" in §8, or keep the FR with an
explicit MVP note: "no MVP connector reports cost; enforcement is a
no-op until a cost-reporting connector exists." Do not leave it as a
bare SHALL.

**MF-14 — Split T2 by token type.**
Problem: threat model T2 ("compromised agent / stolen registration
token") treats all credential theft uniformly. A stolen short-lived
derived token (minutes of life, bound to one tool/action) and a
stolen long-lived fallback bearer (full agent permissions until
revocation) differ in blast radius by orders of magnitude, and the
fallback bearer is the more exfiltration-prone of the two by the
architect's own admission (§2.3).
Affects: 03-architecture (§6, T2).
Fix: split into T2a (short-lived derived token theft — mitigations as
written) and T2b (fallback bearer theft — mitigations: rotation
discipline with a defined maximum age, console-visible "fallback
auth in use" flag per agent, anomaly alerting on first use from a new
network origin if feasible in MVP, immediate revocation path).

**MF-15 — Forbid dual credential issuance by default.**
Problem: design §6.1 step 2 and §6.2 step 2 instruct the console to
issue "OAuth 2.1 client ID + secret AND an API-key fallback" for every
agent, because the platform's capability is unknown. Issuing both by
default doubles the credential exposure surface and guarantees the
weaker path is always available to attack — the fallback becomes the
attack path by issuance policy.
Affects: 02-design (§6.1, §6.2).
Fix: issue exactly one credential per agent. Default to the OAuth
pair; enable the fallback bearer only for an agent whose platform has
demonstrably failed OAuth verification, recorded in the console with
the test date. The onboarding checklist (§6.1 step 5) must record
which method was verified, not just that "a" session was established.

**MF-16 — Correct AC-11 from "proof" to "smoke test."**
Problem: AC-11 (01 §7) requires policy+inspection overhead "< 100 ms
at p95 in a local load test (10 concurrent sessions), excluding
downstream latency." A local test cannot establish the production p95
on Fly.io/Cloud Run — different CPU, noisy neighbors, TLS
termination, and SQLite on a network volume all change the number.
As written, AC-11 lets MVP be declared done on evidence that does not
support the claim.
Affects: 01-requirements (AC-11), 03-architecture (§7).
Fix: keep the local load test as a CI gate (fail if p95 > 100 ms
locally), and add a post-deploy measurement requirement: the same
measurement repeated against the deployed endpoint before MVP
sign-off, with the production number recorded. Label the 100 ms
figure a design target in both places, which the docs mostly do but
AC-11 does not.

---

## 3. NICE-TO-HAVE items

**NH-1 — Tamper-evidence for the audit log.** FR-032 makes the log
append-only at the application layer. For a product whose value is
"which agent touched which system," hash-chained audit entries (each
row commits to the previous row's hash) would make tampering
detectable. Cheap to add with SQLite; do it if the build plan has
room, defer otherwise.

**NH-2 — Structured `invalid_input` errors without arg echo.** Design
§2.7 does not say whether `invalid_input` echoes the offending
arguments. Echoing risks returning PII or injected content to the
agent. Recommend: error names the offending field, never its value.

**NH-3 — Idempotency on the approval-decision endpoint.** Double-clicks
and retried POSTs to `/api/approvals/{request_id}/decision` should not
create duplicate windowed grants. An idempotency key or
check-then-act on request state is a small addition.

**NH-4 — Redaction-before-display for the paused-call audit row.**
Design §2.8 stores the approval request with the "exact call."
Confirm the stored form is the redacted argument set plus a hash of
the full arguments for grant matching — the full arguments should not
sit in the approvals table in plaintext.

**NH-5 — Clock discipline.** Audit ordering, approval expiry, and
token lifetimes all assume a sane clock. Add an NFR or a deploy note:
the host SHALL run NTP/chrony; timestamps are UTC (ties to DQ-9 —
answer "UTC in storage, Ken's local tz in display").

**NH-6 — SSE vs poll for console approval notifications.** DQ-1 asks
the channel question; whatever Ken picks, the "no SSE" statement in
design §2.8 is about the MCP transport and should say so explicitly
to avoid confusion with console notifications.

**NH-7 — Secret zeroization note.** The vault decrypts credentials
into memory at call time. A line in the architecture doc stating the
intent (zero buffers after use where the language allows; no secrets
in tracebacks or error paths) costs nothing at planning time.

**NH-8 — `approval_denied` vs silent re-poll.** After Ken denies, an
agent that keeps polling gets `denied` — fine. Consider documenting
that repeated re-invocation after `denied`/`expired` without changed
arguments is itself rate-limited, to blunt retry loops.

**NH-9 — Default-deny visibility in dry-run output.** Design §5's
dry-run reports would-allow/would-deny/would-require-approval. Add an
explicit row for "denied by pinned default-deny (no rule matched)" so
Ken can distinguish "my rules denied it" from "nothing allowed it."

**NH-10 — Connector review checklist.** T6's residual risk notes that
every new connector needs SSRF review. Write the checklist now (egress
allowlist, no open URL-fetch parameters, metadata-endpoint blocks,
timeout/bounded-retry defaults) and attach it to FR-009's plugin
interface, so the second connector does not reintroduce what the first
avoided.

**NH-11 — Approval-card "blast radius" line.** The card shows agent,
tool, and arguments. Adding the one-line consequence ("this will send
an email to N recipients" / "this will merge PR #x into main")
computed from structured fields — not from free text — would do more
against approval error than any warning label.

---

## 4. Contradictions found

| # | Doc A says | Doc B says | Resolution |
|---|---|---|---|
| C-1 | 01 FR-011: agents SHALL authenticate with OAuth 2.1/OIDC | 01 OQ-1, 02 §6.1/§6.2, 03 §2.3: build and issue a bearer-token fallback | Rewrite FR-011 per MF-1: OAuth primary, fallback conditional and flagged. The SHALL as written is false. |
| C-2 | 01 AC-05: agent-side traffic shows only short-lived scoped tokens | 03 §2.3 + 02 §6.1/§6.2: fallback agents hold a long-lived bearer | Amend AC-05 and split FR-012 into session-credential vs derived-token layers per MF-3. |
| C-3 | 03 §1.2 data flow: approval (step 4) precedes input validation (step 5) | 01 FR-025: validate every call, reject malformed; 03 §7 fail-closed principle | Reorder: validate before policy/approval per MF-4. Malformed calls never reach the approval queue. |
| C-4 | 02 §6.1/§6.2: issue OAuth credentials AND fallback API key for every agent | 03 §2.3: "each registered agent is configured for the strongest method its platform demonstrably supports" | MF-15: issue exactly one credential; the architect's sentence is the correct rule, the designer's table is wrong. |
| C-5 | 02 §10: "OAuth 2.1 grant flows and token format internals" deliberately not designed | 03 §2: token exchange, lifetimes, and revocation semantics specified in detail | 02 §10 is stale after Phase 3. Update it to point at 03 §2 as the decided design instead of a non-decision. |
| C-6 | 02 §2.5: `approval_status` reveals "only the status of the agent's own request" | 02 §2.5 (same section): no caller-identity binding on the lookup | Add the binding per MF-5; the claim is currently unearned. |
| C-7 | 01 §8: MVP includes "policy/approval/vault/inspection/audit, and a functional admin console" of 7 pages plus 3 connectors | 01 §8 (same section): "Realistic for one person + an agent team" (asserted, not shown) | See §6 honest-claims and §5 sequencing: the scope sentence needs a phased build order, not just an assertion. |
| C-8 | 02 §2.8: re-invoked call "finds the active grant" and is allowed | 02 §2.7/§2.8: sensitive rule would re-trigger `approval_required` on any call | Specify grant-check-before-rule-evaluation order per MF-7, or the flow loops forever. |
| C-9 | 03 §1.3: trust boundaries drawn between nine components | 03 §1.1: MVP runs all nine as a single stateful process | Label the §1.3 boundaries "logical in MVP, physical later." In one process, vault↔adapter separation is code discipline, not a boundary. Honest labeling, not a redesign. |
| C-10 | 01 NFR-SEC-002: vault key "managed outside the application config (KMS or equivalent)" | 03 §5: "On Fly.io: Fly secrets hold the KMS/data-key reference" | Watch item, not a flat contradiction: confirm at implementation that a Fly secret reference satisfies "outside application config" under envelope encryption, and document the answer. |

---

## 5. Missing decisions / numbers

Parameters the team must set before or during implementation. Owner in
parens. Recommendations are the reviewer's, not Ken's — he decides.

1. **Agent session credential lifetime** (OAuth access token TTL).
   Recommendation: 60 minutes, refresh via the platform's OAuth flow;
   fallback bearer maximum age 90 days with mandatory rotation and a
   console-visible age indicator.
2. **Derived per-call token lifetime** (FR-014). Recommendation: 5
   minutes — long enough to survive one upstream call plus retries,
   short enough to bound theft.
3. **Approval timeout default** (OQ-8/AOQ-6). Recommendation: 15
   minutes default; per-tool override shorter for destructive actions
   (merge, delete: 5 minutes).
4. **Default rate limits** (DQ-7). The proposed 60 calls/min and
   1,000/day per agent are sane starting points. Recommendation:
   accept, make per-agent tunable, and add the pending-approval cap
   from MF-9 (default 5).
5. **Audit retention default** (OQ-10). Recommendation: keep 90 days,
   configurable; decide whether expired rows are deleted or archived
   to object storage (arch §5 says "prunes or archives" — pick one).
6. **Admin authentication strength** (DQ-5/FR-036). Recommendation:
   password plus TOTP for MVP. A security control plane with
   password-only admin login in 2026 is a finding waiting to happen.
7. **Approval notification channel** (DQ-1). Recommendation: in-console
   polling for MVP plus email-to-Ken on each new approval request —
   cheap, no new infrastructure, covers the "not watching the console"
   case. SMS/push stays out.
8. **Hosting confirmation** (OQ-6/AOQ-4). Architect recommends Fly.io,
   Cloud Run conditional. Recommendation: Ken picks before the build
   plan is finalized; the KMS story (NFR-SEC-002) differs by host.
9. **Code-host connector choice** (OQ-7/AOQ-5). Assumed GitHub.
   Recommendation: confirm; start the GitHub OAuth app registration
   early per AOQ-9 (platform verification lead time is the likeliest
   schedule risk and is outside the codebase).
10. **Upstream OAuth app registrations** (AOQ-9). Google and/or
    Microsoft for email+calendar. Recommendation: start immediately;
    verification can take days to weeks and blocks end-to-end testing
    (AC-01/AC-02).
11. **Grant vs policy-version semantics** (from MF-7). Recommendation:
    grants survive policy version changes; agent revocation kills
    grants immediately. Write it down either way.
12. **Request-ID format and entropy** (from MF-5). Recommendation:
    128-bit CSPRNG, `apr_` prefix for approvals, `req_` for calls.
13. **Redaction catalog contents** (AOQ-10) and DQ-6 partial hints.
    Recommendation: ship email/phone/SSN-shaped/account-number
    patterns; console-editable from day one; default to full
    `[redacted:type]` tokens (no last-4 hints) until Ken explicitly
    accepts the tradeoff.
14. **Conditional-sensitivity definitions.** `calendar.create` is
    "sensitive when external attendees are included" (02 §2.2) —
    "external" needs a domain list. `email.send` recipient-domain
    constraints (DQ-4) need Ken's actual domain set. Recommendation:
    Ken supplies both lists at build time; the rule builder ships
    with exactly the fields these lists require, no more.
15. **Dashboard timezone** (DQ-9). Recommendation: UTC in storage,
    Ken's local timezone in display (see NH-5).
16. **Connector health-check cadence and definition** (DQ-8).
    Recommendation: credential-valid plus API-reachable, every 5
    minutes, failure surfaced as a console banner — cheap enough to
    keep.
17. **Dry-run cold-start corpus** (DQ-2). Recommendation: accept
    hand-written synthetic calls (one per tool) when history is empty;
    label dry-run output with which corpus was used.
18. **Approval semantics beyond one-time/windowed** (DQ-3). Standing
    scoped grants overlap policy allow-rules. Recommendation: do not
    add a third grant type in MVP; if Ken wants "always allow,"
    that is a policy rule, not an approval.
19. **Export storage for audit exports** (03 §5). Object storage vs
    local-disk staging. Recommendation: local-disk staging with
    manual download for MVP; object storage when retention archiving
    (decision 5) needs it.
20. **MVP build sequencing.** The scope as listed (8 components, 3
    connectors, approvals, 7-page console) is too large to build as
    one undifferentiated block. Recommendation — build in this order,
    each slice end-to-end testable: (a) MCP endpoint + identity
    (single auth path per platform, decided by live spike) + SQLite +
    audit; (b) email connector (read-only first) + policy engine +
    minimal console (Agents, Audit); (c) approval workflow + Approvals
    page; (d) vault + credential-backed connectors (email send,
    calendar, code host); (e) inspection pipeline (validation,
    injection scan, redaction, rate limits); (f) remaining console
    pages, dry-run, export. Defer to post-MVP: windowed grants (ship
    one-time grants only), cost budgets (MF-13), code-host write
    actions beyond PR open (merge can wait for the approval loop to
    prove itself on email send).

---

## 6. Honest-claims audit

Fluff, unsourced numbers, and overconfident platform claims, by
section, with corrections.

- **01 §1 — "fixed in versions 1.30.0/2.2.0."** The version pairing is
  unusual (two version lines for one SDK) and is asserted without a
  changelog link. Correction: cite the exact SDK releases and the
  advisory in FR-005/AC-10 before the build plan treats the floor as
  verified. The requirement is right to exist; the citation is
  missing.
- **01 §1 — "a gateway that brokers, verifies, and logs connections
  is timely, not speculative."** Marketing-adjacent filler.
  Correction: delete the sentence; the flaw citation above it already
  makes the case.
- **01 §8 — "Realistic for one person + an agent team."** Asserted,
  not argued. Correction: replace with the phased build order (§5,
  item 20) so the realism claim is demonstrated by sequencing, not
  asserted by adjective.
- **02 §2.1 — "Tool names stay within the MCP-allowed character
  set."** No spec section is cited, and the allowed set is stated as
  fact. Correction: cite the MCP spec's tool-naming rule (or mark it
  "to be verified against the spec at implementation") before
  depending on dots in tool names.
- **02 §2.8 — "Rejected alternative: holding the HTTP stream open."**
  The rejection rationale (proxies, timeouts, SDK behavior) is sound
  but presented as settled engineering fact. Correction: label it the
  designer's judgment — the team has not tested long-held streams
  against Muse/Grok clients.
- **03 §3.2 — "FastMCP is the most widely used server framework in
  the MCP ecosystem," "largest example base," "richest
  connector-adapter ecosystem."** Three unsourced superlatives in one
  table. Correction: downgrade to labeled judgment ("in the
  architect's assessment") or cite ecosystem evidence (GitHub stars,
  download counts, with dates). The recommendation can stand on team
  fit and connector-library availability without the superlatives.
- **03 §3.2 — "Streamable HTTP supported in both SDKs at current
  versions."** Asserted without version numbers. Correction: name the
  SDK versions where Streamable HTTP support was verified, or mark
  unverified.
- **03 §4 — cost lines for Fly.io, Cloud Run, VPS, Tunnel.** The
  architect correctly marks each as qualitative/unverified — this is
  the honest pattern the rest of the docs should follow. No
  correction; held up as the standard. Pricing must still be confirmed
  on the providers' pages before the hosting decision (see §5,
  item 8).
- **03 §9 AOQ-8 — "SQLite in WAL mode handles this comfortably in
  the architect's judgment."** Labeled as judgment with AC-11 named
  as the proof. Acceptable. Correction: none, but AC-11's proof value
  is limited per MF-16.
- **01 AC-11 / 03 §7 — the 100 ms p95 figure.** Mostly labeled a
  design target, which is honest. AC-11's wording ("measures < 100 ms
  at p95 in a local load test") is the one place it reads as a
  pass/fail bar on non-representative evidence. Correction per MF-16.
- **02 §1 — "Latency and scale targets are design targets, not
  promises."** Good. This sentence should be the template for every
  number in all three documents.
- **General — platform capability claims.** 01 §6 is careful to flag
  OQ-1–OQ-5 as unverified, and 02 §6 carries the flags forward. The
  gap is that 02 §2.8's approval loop and 03 §2.3's auth design both
  depend on platform behavior (agent polling discipline; OAuth
  support) that the flags do not cover. Correction: extend the
  unverified-behavior list to include "will the agent actually
  poll-and-retry" (MF-11) and "does the platform's MCP client speak
  OAuth 2.1 to a custom server" as explicit spike criteria with
  pass/fail definitions, not just open questions.

---

## Reviewer notes for the build-plan phase

1. The auth design is the load-bearing wall. MF-1, MF-2, MF-3, MF-14,
   and MF-15 are one connected fix: single credential per agent,
   OAuth primary, fallback conditional and visibly flagged, no third
   rung, threat model split by token type. Do not let the build plan
   treat these as five independent tickets.
2. The approval loop is the load-bearing workflow. MF-4, MF-5, MF-6,
   MF-7, MF-8, MF-9, and MF-11 are one connected fix: validate first,
   bind status to caller identity, render arguments as untrusted,
   define grant semantics, protect the decision endpoint, cap the
   queue, and prove a real agent walks the loop. A live spike against
   Muse and Grok belongs at the front of the build plan, not the
   back — if the agents will not poll, the workflow needs redesign
   before anything downstream is built.
3. The single most under-appreciated schedule risk in all three
   documents is AOQ-9: upstream OAuth app registrations and platform
   verification lead times. It is outside the codebase and therefore
   invisible to a build plan organized by component. Put calendar
   time, not just task order, around it.
4. Nothing in this review requires new platform facts. Every
   uncertainty above is flagged as uncertainty with a named test
   (live spike, AC-04 extension, AC-11 production measurement) that
   resolves it. That is the standard the build plan should keep.
