# Pillar 2 — AI Security Agents: Product/UX Design

**Status:** design only. Nothing here is built. Implementation is gated on Ken's approval.
**Baseline:** `docs/00-build-plan.md`, `docs/build-log.md` (M1–M6, judge module, hackathon readiness), `docs/pillar1-finance-design.md`.
**Applies to:** branch `pillars/two-pillars`.

The security agents are gateway clients, not gateway components. Each runs with an agent identity, a scoped mandate, and the same policy/approval/audit pipeline as any other agent. They dogfood the product: every scan they run, every issue they file, every policy they draft passes through the enforcement they are testing. An agent that cannot pass through the gateway has no business judging it.

Stealth note: any user-facing text in this pillar refers to the candidate OWASP project only as "candidate OWASP project." No announced/official wording, no formal project title, no lead-role references.

## 0. Shared rules for all four agents

1. **Scoped mandates, least privilege.** Each agent's mandate lists exactly the tools it may call. None gets `policy.save`, `vault.read`, agent revocation, or global stop. Those are console-only, human-only, always.
2. **Default-off.** No security agent runs until the operator creates its mandate and starts its schedule. There is no ambient scanning.
3. **Fail-closed.** If a security agent's mandate expires, pauses, or its calls start denying, the agent stops — it does not escalate its own privileges, widen its own scope, or file issues about its own denial. Its failures are audit rows like anyone else's.
4. **Judge stays advisory-only.** The judge cascade may annotate these agents' findings; it never makes their decisions for them, and their outputs never override a Rego deny.
5. **Kill switches.** Per-agent pause (existing Agents page danger zone) and the global stop (existing Dashboard control) halt every security agent immediately. Their schedules do not resume automatically after a global stop; the operator restarts each one.

## 1. Agent fleet dashboard

### What the operator sees

New console page: **Security Agents** (nav, after Approvals). One row per security agent:

- **Identity & mandate:** agent id, mandate name + scope summary ("read audit + run demo tools; no writes"), mandate state (live / checkpoint-due / paused / expired), expiry countdown.
- **Recent verdicts:** the agent's own last 20 calls through the gateway as allow/ask/deny chips. This is the dogfood view: a red-team agent that suddenly collects denials is itself misbehaving or mis-scoped, and the operator sees it here first.
- **Findings count:** open findings attributed to the agent (red-team issues, sentinel escalations), with severity breakdown. Clicking jumps to the finding.
- **Health:** last run time, last heartbeat, schedule state (next run in…), connector health for the tools it uses. Stale heartbeat (>2 missed runs) → amber; >5 → red with a console banner.
- **Spend/latency:** calls in the last 24h, p95 decision latency on its calls (reuses the Latency page data), judge annotations count.

The page also shows a **fleet summary strip**: agents live/total, findings opened this week, escalations unacknowledged, any agent paused.

### What each agent experiences

Nothing special. They call tools; the pipeline evaluates; they get allow/deny/approval_required like any agent. The dashboard is read-only observability — it changes no behavior.

### Failure modes

- **Dashboard becomes a second approval surface.** It must not. Findings are informational; actions (acknowledge, assign, close) happen on the finding itself or in the existing Approvals queue. The dashboard links; it does not decide.
- **An agent's mandate silently widens via ontology drift.** The dashboard shows the mandate's scope hash; any change (new version, material classification) is flagged on the row until the operator acknowledges it.

## 2. Red-team agent

### What it does

A scheduled agent (`agent/redteam`) with a mandate scoped to: read-only audit and policy inspection tools, the demo/sandbox tool set, and `codehost.issue_open` (sensitive-gated: filing an issue needs approval until the operator grants a standing rule for it — default is approval-per-issue for the first month, then a bounded standing grant the operator can revoke).

Attack catalog (each is a scenario with setup, execution, and expected-control assertion):

1. **Prompt injection via tool output.** Plants injection strings in sandbox tool outputs; asserts the inspection pipeline blocks or redacts them. Reports misses.
2. **Jailbreak / role-play against agent-facing errors.** Probes error envelopes for information leakage (do denied calls reveal rule text, amounts, counterparties?).
3. **Secret extraction.** Attempts to get the agent to surface vault-backed credential material through crafted tool args; asserts nothing retrievable agent-side (the amended AC-05 property, continuously re-proven).
4. **Counterparty spoofing.** Submits payments (sandbox adapter) to near-miss payee names ("IRS" vs "1RS"); asserts the counterparty assessment flags them.
5. **Approval fatigue probing.** Opens sequences of low-value approval requests; asserts the per-agent cap (5 pending) holds and the cooldown/streak escalation fires.
6. **Mandate boundary probing.** Calls tools just outside its own mandate; asserts deny with the right reason codes. (It tests the wall by leaning on it.)
7. **Event-injection.** Sends spoofed inbound events to the event receiver; asserts quarantine verdicts.

Out of scope for the agent: anything outside the sandbox tool set and read APIs. It never touches real connectors, real credentials, or other agents' mandates.

### How findings surface: the GitHub issue format

Findings become GitHub issues in the gateway repo (via `codehost.issue_open`; `pr.open` is NOT in its mandate — it files issues, never code). Issue format is fixed by template:

```markdown
## [redteam] <short title>
**Severity:** critical | high | medium | low (scored by the agent, reviewed by human)
**Scenario:** <catalog id, e.g. RT-04-counterparty-spoof>
**First seen:** <utc> · **Agent run:** <run id>

### What happened
<2–4 sentences: what the agent attempted, what the gateway did>

### Evidence (redacted)
- request_id: `req_…`
- audit rows: <ids or query>
- verdict received: <allow|deny|approval_required|quarantined + reason code>
- expected control: <what should have happened>

### Blast radius
<what an attacker could have done if the control had failed>

### Suggested control change
<concrete: rule text, threshold, or detector — never applied by the agent>

### Reproduction
<exact steps against the sandbox; no real credentials involved>
```

Labels: `redteam-finding`, severity label, scenario label. The issue body never contains secret material, full account numbers, or unredacted args — the agent's mandate denies it the tools to obtain them, and the issue template is validated before filing (a pre-file check rejects bodies matching the redaction catalog).

Duplicate suppression: a finding matching an open issue (same scenario + same control point) comments on the existing issue with the new run id instead of opening a new one.

### Operator tuning: scope and rate

**Security Agents → redteam → Configure:**

- **Scope:** checkboxes for the scenario catalog (run all / subset), target tool set (sandbox only, fixed — not editable), excluded scenarios with reason.
- **Rate:** max attempts per hour (default 60), max per day (default 500), concurrent scenario limit (default 2). These are enforced by the agent's own rate limiter *and* the gateway's per-agent limits — belt and suspenders.
- **Schedule:** cron expression (default: nightly 02:00 ET, plus on-demand "Run now").
- **Finding threshold:** minimum severity to auto-file (default: medium; lows go to the run log only).
- **Kill switch:** pause agent (existing), which also cancels its schedule.

### Failure modes

- **The red-team agent finds a real hole and keeps exploiting it.** Scenarios are single-attempt with assertion: once a control fails, the agent records the finding and stops that scenario. It does not pivot, escalate, or retry variants. "One miss, one issue, move on" is in its system prompt and enforced by its mandate (no tool allows iterative exploitation loops — each attempt is a discrete audited call).
- **Issue spam.** Duplicate suppression + severity threshold + daily issue cap (default 10; overflow goes to the run log, surfaced on the dashboard).
- **The agent is compromised and files false findings.** Every finding links to audit rows the operator can verify independently. The operator trusts the evidence, not the agent. False-finding rate is a dashboard metric; a lying agent gets its mandate revoked.
- **Red-team vs production.** The agent's mandate cannot address production connectors. If it tries, it gets `policy_denied` — which is itself a passing test of the boundary.

## 3. Sentinel agent

### What it watches

A continuously-running agent (`agent/sentinel`) with read-only access to the audit stream (a new read tool, `audit.search`, scoped to its mandate; it cannot export). It evaluates sliding windows of audit rows against pattern detectors:

1. **Probing:** ≥N denials from one agent within M minutes (defaults 10/15), especially `policy_denied` with varied tools — someone mapping the policy surface.
2. **Approval fatigue:** approval requests to the same approver spiking above baseline (default: 3× the 7-day median in an hour), or many low-value requests in sequence — the pattern that precedes a rubber-stamp.
3. **Velocity anomalies:** an agent's call rate or spend rate deviating from its mandate baseline (uses the same counters as the money pack, read-only).
4. **Drift clusters:** multiple `drift_suspected` flags on one mandate in a day.
5. **Quorum stalls:** quorum requests sitting `partially_approved` past 50% of timeout — nudge before expiry, not after.
6. **Injection uptick:** `injected_output_blocked` or quarantine verdicts rising week over week.

Detectors are deterministic thresholds first (shipped), judge-annotated second (opt-in, advisory). The deterministic layer must work with the judge off.

### What an escalation looks like in the console

Sentinel findings are **not** GitHub issues — they are operational and time-sensitive. They surface in three places:

1. **Dashboard banner** (existing banner pattern): "Sentinel: probing pattern from agent/wealth-1 — 14 denials in 12 min." Clicking opens the finding.
2. **Security Agents → sentinel → Findings:** the finding detail shows the pattern, the window, the rows (linked audit ids), the detector and threshold that fired, and the recommended action ("pause agent", "review approvals", "dismiss"). Actions are console buttons the *operator* clicks — sentinel never pauses anyone itself.
3. **Approvals queue annotation:** if the pattern touches pending approvals (fatigue case), the affected requests carry a "sentinel: fatigue risk" tag so the approver sees it on the card before deciding.

Acknowledgment is explicit: each finding needs an operator ack (ack / ack-with-action / false-positive). Unacknowledged high-severity findings re-notify via the exempt notifier path (email to Ken) every 4 hours, max 3 times, then stay bannered. Sentinel never pages anyone itself; the notifier path is the existing M3 exempt channel.

### Failure modes

- **Alert fatigue from sentinel itself.** Per-detector cooldowns (a detector cannot re-fire on the same agent for 1 hour after ack), severity-gated notification, and the false-positive button which tunes that detector's threshold for that agent (operator-confirmed, audit-logged).
- **Sentinel goes blind.** If its audit reads start failing or its heartbeat stalls, the dashboard shows it red — "sentinel unhealthy, patterns unwatched since <time>." Fail-visible, not fail-silent.
- **Adversarial audit evasion.** Sentinel reads the same append-only audit the gateway writes; agents cannot write or delete audit rows. An attacker who compromises the gateway host is outside this pillar's threat model (noted, not solved).

## 4. Policy assistant

### The loop

A conversational agent (`agent/policy-assistant`) that helps the operator write policy. Its mandate: read policy versions, run dry-run evaluation, read the Rego files, and open PRs. Explicitly NOT in its mandate: `policy.save` (no such tool exists for it — version saves are console-only), `policy.rollback`, mandate edits, vault access.

The loop, each step visible:

1. **Natural language in:** the operator describes the intent in the console's policy-assistant panel (or in chat, pasted): "Require quorum approval for any payment over $25k to a new payee."
2. **Draft out:** the agent produces (a) the JSON rule dict(s) in the existing rule schema, (b) a plain-English reading of what the rules do ("this asks for 2 approvals when…; it denies when…"), and (c) `opa test` cases for the new behavior.
3. **Machine check:** the draft goes through `opa check` + `opa test` (the same save-time gate, run pre-save) and the history dry-run endpoint (`POST /api/policy/dry-run`) showing would-allow / would-deny / would-require-approval counts against the last 30 days. The operator sees the blast radius before anything is saved.
4. **PR:** the agent opens a PR against the policies directory (`code.pr.open`, sensitive-gated — the operator approves the PR-open action, seeing the exact diff). The PR contains the rule JSON, the Rego tests, and the dry-run summary.
5. **Human gate:** Ken reviews and merges. Merge triggers the normal policy-save path (material classification, version immutability, audit log). The agent cannot merge, cannot push to main, cannot save a version.

### Where the human approval gate sits

In two places, both non-bypassable:

- **PR open is approval-gated.** The agent's `code.pr.open` call halts for human approval showing the full diff. No silent PRs.
- **Policy application is human-only.** There is no tool path from the agent to a live policy version. Even a merged PR applies through the console's existing save flow (or the repo's merge-to-main deploy), which is a human action with MFA.

The agent is a drafter with a test harness, not a policy author. The design states this bluntly in the agent's mandate description so no future tuning accidentally grants it write access.

### Failure modes

- **Plausible-but-wrong rules.** The dry-run blast-radius view is the control: a rule that would have denied last week's legitimate payroll shows up as a changed-call list before merge. The operator reads it.
- **The agent drafts rules that widen access.** The material-change classifier flags widening; the PR template requires the agent to state "this widens/narrows/keeps" and the dry-run numbers must agree. Disagreement blocks the PR-open approval card with a warning.
- **Prompt injection in the NL input.** The operator's own NL is trusted (it's the admin), but the agent's draft is still machine-checked. `opa check` does not care who wrote the rule.
- **Version skew:** the agent drafts against policy v12 while v13 ships. The PR-open approval card shows "drafted against v12, current is v13" and the dry-run re-runs against current before the operator approves.

## 5. Incident agent

### What triggers it

- Operator clicks "Open incident" from a sentinel finding, a denied/quarantined event, or an audit row.
- Automatic: global stop engaged, or a `critical` red-team finding filed.

The incident agent (`agent/incident`) has a mandate for: audit search/read, approval-request read, mandate read, and `incident.write` — a scoped tool that writes to an incident record store (new, console-surfaced). It cannot change policy, pause agents, or approve anything.

### What a generated incident timeline looks like

**Security Agents → Incidents → INC-2026-1043** (or the Dashboard incident banner):

```
INC-2026-1043 · opened 2026-10-13 09:14 ET by operator (from sentinel finding S-881)
Status: open · Severity: high · Linked mandate: mnd_chen_wealth

09:02:11  agent/wealth-1  email.search            allow        req_9f2…
09:07:44  agent/wealth-1  events.receive          quarantined  req_a41…  "sender-auth-failure"
                                          ↳ inspection: dkim=fail, urgency flag, counterparty mismatch
09:07:45  agent/wealth-1  gateway.approval_status poll         allow        (stub: withheld by policy)
09:11:03  agent/wealth-1  payment.initiate        approval_required  apr_77c…  "new payee, over soft threshold"
                                          ↳ quorum: false (single approval sufficed at $18k)
09:13:58  ken (admin)     approval.decision       denied       apr_77c…  "payee not verified — spoof suspected"
09:14:02  system          counterparty.update     blocked      payee "CHEN CUSTODIAN NEW"

Summary (agent-written, human-editable):
  A spoofed custodian email was quarantined at 09:07. The agent could not
  see its content. At 09:11 the agent nevertheless attempted an $18,000
  payment to the spoofed payee (payee details likely from an earlier,
  unquarantined thread — see linked rows). The approval was denied.
  No money moved. Payee blocked.

Linked: audit rows (6) · approval apr_77c… · event req_a41… · sentinel S-881
Actions: [export timeline] [open follow-up] [close incident]
```

Properties:

- **Every line links to the underlying audit row.** The timeline is a view over the audit log, not a separate story. If a row is missing, the timeline shows the gap ("no rows 09:08–09:10 — agent idle or denied polls unlogged per 02 §2.5 carve-out").
- **The summary is marked agent-written.** The operator can edit or replace it. The original is kept as a version.
- **Export** produces the timeline as markdown + the linked rows as JSON, with the same manifest/hash treatment as the compliance export (§6 of the Pillar 1 doc).
- **Close** requires a resolution note (resolved / false-positive / accepted-risk) and is audit-logged.

### Failure modes

- **Timeline gaps.** Denied `approval_status` polls are intentionally unlogged (02 §2.5 carve-out). The timeline says so explicitly instead of implying continuous coverage.
- **The incident agent hallucinates a causal link.** Links are by id correlation (request ids, approval ids, time windows), never by narrative inference. The agent may *suggest* a link ("possibly related"); suggested links render dashed and unlabeled until the operator confirms.
- **Incident during global stop.** The agent keeps read access (timeline building is read-only); its `incident.write` still works so the stop itself is documented.

## Non-goals (Pillar 2)

- Autonomous response. No security agent pauses agents, blocks payees, revokes credentials, or engages global stop. They observe, draft, and escalate. Humans act.
- Self-improvement loops. The agents do not retrain, rewrite their own prompts, or modify their own mandates. Their configuration is operator-owned.
- Coverage of the gateway host itself (OS, network, supply chain). The agents test the gateway's policy behavior, not its infrastructure. Host hardening is a separate track.
- A general-purpose SOC. Four agents with narrow jobs, not an open-ended analyst. If Ken wants a fifth agent, it gets its own mandate and its own design section.
- Replacing the existing test suite. The red-team agent complements `pytest` + `opa test`; it does not substitute for them. Deterministic tests remain the gate; the agent is the explorer.

## Open decisions for Ken

1. Red-team issue filing: approval-per-issue for the first month, then standing grant — or standing grant from day one with a daily cap?
2. Sentinel notification: email-to-Ken on high-severity only, or also medium? (Default proposed: high only.)
3. Policy assistant surface: console panel vs chat — where does the NL input live?
4. Second admin for quorum (from Pillar 1) also affects who acks sentinel findings — same person or a different delegate?
5. Schedule for red-team runs: nightly 02:00 ET default acceptable?
