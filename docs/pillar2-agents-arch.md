# Pillar 2 — AI Security Agents: Technical Architecture

**Status:** architecture only. Nothing here is built. Implementation is gated on Ken's approval.
**Baseline:** `docs/pillar2-agents-design.md` (product/UX design), `docs/00-build-plan.md` (Fix A auth wall, Fix B approval flow).
**Applies to:** branch `pillars/two-pillars`. Never touch the main working tree at `~/workspace/mcp-gateway`.

Stealth note: any user-facing text in this pillar refers to the candidate OWASP project only as "candidate OWASP project." No announced/official wording, no formal project title, no lead-role references.

## 0. Key decisions (summary)

1. **Separate runner process, dogfood clients.** The four agents run in a dedicated `agents-runner` process (asyncio + croniter) and call back into the gateway as ordinary MCP clients over Streamable HTTP at `/mcp`, authenticating with their own Fix-A credentials. No in-process pipeline bypass — every agent call goes through auth → validate → mandate → policy → approval → execute → inspect → audit exactly like any other agent.
2. **Deterministic-first agents; LLM is optional.** Red-team scenarios and sentinel detectors are deterministic code with no LLM dependency, so the MVP ships and tests with zero model, zero network, zero GPU. An optional OpenAI-compatible LLM endpoint (`GATEWAY_AGENTS_LLM_URL`) powers only policy-assistant drafting and incident summaries; unset → those degrade to a clear "not configured" state, never to hallucinated output.
3. **`codehost.issue_open` does not exist yet — define the adapter + safe file fallback.** The code-host connector currently exposes only `code.file.read` and `code.pr.open` against an in-memory mock. The architecture adds an `IssueOpener` interface with a file-backed `LocalIssueStore` (MVP) and a defined-but-unimplemented GitHub backend (fail-closed config error if selected). Issue filing is sensitive-gated: default approval-per-issue; a bounded standing-rule path is architected for Ken's decision.
4. **New gateway-side tools are gateway-namespaced and default-deny.** `audit.search`, `policy.inspect` (MVP), `policy.dry_run`, `incident.write` (extensions) are registered on the MCP surface like the existing `gateway.approval_status` meta tool, denied for all agents by default, and allowed only via per-agent seed policy rules for the security agents.
5. **Kill switches are runner-enforced with no auto-resume.** The runner polls a persisted global-stop flag and per-agent pause/mandate state every tick; on global stop it halts in-flight runs cooperatively, persists `schedule.enabled=False`, and never resumes until the operator restarts each agent explicitly.

## 1. Agent runtime

### 1.1 Process model: separate runner process

```
┌─────────────────────┐      MCP over Streamable HTTP      ┌──────────────────────┐
│  agents-runner       │ ───────────────────────────────▶ │  gateway (FastMCP)   │
│  (own OS process)    │  Authorization: Basic/Bearer      │  /mcp                │
│  asyncio scheduler   │  per Fix-A transport contract     │  full Fix-B pipeline │
│  src/agents/runner.py│                                   │  config.db / audit.db│
└─────────────────────┘                                   └──────────────────────┘
         │ reads/writes config.db directly for schedules, heartbeats, findings
         │ (own SQLAlchemy sessions; SQLite WAL mode tolerates this)
```

**Choice: separate process over in-process scheduler, OS cron, or in-process calls.**

- Rejected: in-process scheduler calling the pipeline directly — it would bypass Fix-A authentication and the transport edge, violating the dogfood rule ("an agent that cannot pass through the gateway has no business judging it"). It also creates a privileged code path that production agents never use.
- Rejected: OS cron launching per-run CLIs — no heartbeat/fail-visible semantics, no concurrency control, awkward for sentinel's 2-minute interval, and per-run process startup loses the rate-limiter state.
- Chosen: one long-running `agents-runner` process. It owns scheduling (croniter), per-agent rate limiting (in-memory token buckets + `asyncio.Semaphore`), heartbeats, and kill-switch polling. It never holds a privileged DB bypass: all *tool* access goes over MCP as an authenticated client. Its direct DB access is limited to its own state tables (schedules, runs, heartbeats, findings) — never the audit log (append-only; the runner reads audit only through the `audit.search` tool as the sentinel/redteam agent, never via SQL).

Entry point: `python -m agents.runner` (package `src/agents/`). Supervised like the gateway itself (systemd unit / compose service; deploy detail, not MVP code). Startup is fail-closed: the runner refuses to start when `GATEWAY_AGENTS_ENABLED != 1`, when the gateway `/healthz` is unreachable, or when any configured agent has no live mandate (it logs and idles; it does not invent mandates).

New dependency: `croniter` (pinned in `pyproject.toml`) for cron parsing. No other new runtime deps (asyncio, FastMCP `Client`, httpx, SQLAlchemy are already present).

### 1.2 Agent identities and Fix-A credentials

Security agents are ordinary gateway agents with `platform="internal"` and `household_role="security"`:

| Agent id | Display name | Purpose |
|---|---|---|
| `agent_redteam` | `agent/redteam` | scheduled attack-scenario prober |
| `agent_sentinel` | `agent/sentinel` | continuous audit-pattern watcher |
| `agent_policy_assistant` | `agent/policy-assistant` | on-demand policy drafter |
| `agent_incident` | `agent/incident` | on-demand incident timeline builder |

**One credential per agent (Fix A), same as any agent.** Registration happens through the existing console flow (`IdentityService.register_agent`, OAuth primary) or the gated fallback bearer (`issue_fallback_bearer`) if the internal platform ever needs it. The raw secret is shown once at issuance and never persisted (FR-022: bcrypt hash only in `agent_credentials`).

The runner authenticates *as* each agent over MCP. The raw per-agent secret reaches the runner exactly one way: environment variables / platform secret store, one per agent:

- `GATEWAY_AGENT_REDATEAM_CREDENTIAL` — raw client_secret (OAuth) or `key_id.raw_token` (fallback bearer)
- `GATEWAY_AGENT_SENTINEL_CREDENTIAL`
- `GATEWAY_AGENT_POLICY_ASSISTANT_CREDENTIAL`
- `GATEWAY_AGENT_INCIDENT_CREDENTIAL`

`src/agents/mcp_client.py` — `AgentMCPClient(agent_id)` reads the matching env var at run start (never logs it, never writes it to disk or DB), builds a FastMCP `Client` against `http://{GATEWAY_HOST}:{GATEWAY_PORT}/mcp`, and sets the `Authorization` header per the M1 transport contract (`Basic base64(client_id:client_secret)` for OAuth agents, `Bearer key_id.token` for fallback). The client_id/key_id is stored alongside in `GATEWAY_AGENT_<NAME>_CREDENTIAL_ID` (public part; safe to persist in the schedule row for display).

If the env var is missing at run start, that agent's run is skipped with heartbeat status `credential_missing` — fail-closed, never retried with a different identity.

### 1.3 Scheduler

`src/agents/scheduler.py`:

- **Tick loop:** every `GATEWAY_AGENTS_RUNNER_POLL_S` (default 15s) the runner loads `agent_schedules` rows, computes due runs with croniter (`cron_expr`, `timezone`), and dispatches.
- **On-demand runs:** the console "Run now" button inserts an `agent_runs` row with `trigger='manual', status='requested'`; the scheduler picks it up on the next tick (no signal mechanism needed; 15s latency is acceptable).
- **Sentinel "continuous"** is an interval schedule (`GATEWAY_SENTINEL_INTERVAL_S`, default 120) — same machinery, no separate daemon.
- **Concurrency:** one `asyncio.Semaphore(GATEWAY_REDATEAM_MAX_CONCURRENCY)` (default 2) per agent for scenario fan-out; runs for different agents are independent tasks.
- **Pre-run gate (every run, every agent):** (1) global-stop flag clear; (2) agent status `active` (not paused/revoked); (3) `MandateService.check()` yields a live mandate covering the agent's tools — else skip with heartbeat `mandate_missing`; (4) `validate_security_mandate()` (§2.4) passes on the resolved allowlist — else skip with heartbeat `mandate_forbidden` and raise an operator-visible alert (this is defense-in-depth against hand-edited mandates).

### 1.4 Heartbeats and health

`agent_heartbeats(agent_id PK, ts, run_id, status)` — written after every run and every scheduler tick for interval agents. Status vocabulary: `ok`, `findings`, `error`, `denied` (agent's own calls started denying — itself a signal), `mandate_missing`, `mandate_forbidden`, `credential_missing`, `paused`, `stopped`.

Console health rule (fleet dashboard, §7): expected interval comes from the schedule row; `now - last_heartbeat > 2×interval` → amber; `> 5×interval` (or the `GATEWAY_AGENTS_HEARTBEAT_MISSED_RED=5` count) → red + console banner. Sentinel additionally banners "patterns unwatched since <time>".

### 1.5 The "no autonomous response" invariant, in code

Four layers, all in the MVP:

1. **Mandate allowlists (§2)** contain no response tools. There is no `agent.pause`, `payee.block`, `policy.save`, `vault.read`, or `gateway.global_stop` tool registered on the MCP surface at all — the agents cannot call what does not exist.
2. **`src/agents/mandates.py::validate_security_mandate(allowed_classes)`** refuses forbidden patterns (see §2.4). Called at seed time, at schedule-enable time (console), and at every run start against the *resolved* DB allowlist. Raises `ForbiddenMandateError`; the runner skips the run and alerts.
3. **Sentinel escalations are data, not actions.** The sentinel agent's outputs are finding rows; pausing an agent, deciding an approval, or sending a notification are console-operator actions and runner/notifier-side effects respectively. The sentinel agent holds no tool that changes another agent's state.
4. **Red-team single-attempt** (§3.1): the engine calls each scenario's `execute()` exactly once per run; a missed control becomes a finding, never a pivot.

### 1.6 The agents' LLM brain (optional, never load-bearing)

`src/agents/llm.py`:

```python
class LLMClient(Protocol):
    def complete(self, *, system: str, user: str, max_tokens: int) -> str: ...
class NullLLM(LLMClient):        # default: raises LLMNotConfigured
class OpenAICompatLLM(LLMClient) # httpx POST {base}/chat/completions; trust_env=False
```

- Red-team and sentinel are **fully functional with `NullLLM`** — deterministic scenario/detector code needs no model. This is what makes the MVP testable with no network/GPU.
- Policy-assistant drafting and incident summaries use the LLM when `GATEWAY_AGENTS_LLM_URL` is set; when unset, the policy-assistant panel shows "LLM not configured" (no draft) and incident summaries fall back to a deterministic template (counts, time range, linked rows — no prose invention).
- The LLM never sees secrets: prompts are built from redacted evidence only. The judge cascade (advisory) is a separate system and stays independent of this client.

## 2. Mandate definitions

### 2.1 Exact tool allowlists

| Agent | Allowed classes | Notes |
|---|---|---|
| `agent_redteam` | `audit.search`, `policy.inspect`, `sandbox.echo`, `sandbox.payment_initiate`, `sandbox.event_receive`, `codehost.issue_open`, `gateway.approval_status` | `code.pr.open` deliberately excluded (RT-06 probes it as out-of-mandate) |
| `agent_sentinel` | `audit.search`, `gateway.approval_status` | read-only; "cannot export" — no export tool exists |
| `agent_policy_assistant` | `policy.inspect`, `policy.dry_run`, `code.file.read`, `code.pr.open`, `gateway.approval_status` | no `policy.save` (no such tool exists); PR open is sensitive-gated |
| `agent_incident` | `audit.search`, `approval.read`, `mandate.read`, `incident.write`, `gateway.approval_status` | read + scoped incident-store writes only |

New gateway-side tools (all `routine` sensitivity unless noted; all default-deny for non-security agents):

- `audit.search` — thin wrapper over `AuditLog.search` (filters: agent_id, tool, decision, since, until, limit≤200). Returns redacted rows only. `agent_sentinel`/`agent_incident`/`agent_redteam` get allow rules; the handler additionally constrains non-security callers to their own `agent_id` (defense-in-depth; default-deny makes this moot for others).
- `policy.inspect` — returns `{policy_version, rules[]}` (same data the Policies page renders). Read-only.
- `policy.dry_run` *(extension)* — calls the service behind `POST /api/policy/dry-run` (`{policy_version, window_days}`) and returns counts + changed-call list. Read-only.
- `incident.write` *(extension)* — scoped writes to the incident store (§6.2). `routine` sensitivity; allowed only for `agent_incident`.
- `approval.read`, `mandate.read` *(extension)* — read-only views over `ApprovalRequest` (evidence subset + redacted args only) and `Mandate` rows for the incident agent's timeline building.

Registration: `src/gateway/agent_tools.py` builds the `ToolDescriptor` list; `GatewayApp` registers them via the existing `register_connector_tools("gateway", ...)` path (same as `gateway.approval_status`) when `GATEWAY_AGENTS_ENABLED=1`. They are invisible on the MCP surface otherwise.

### 2.2 Seeding

`python -m agents.seed` (idempotent — skips existing rows):

1. Registers the four agents via `IdentityService.register_agent` (prints each raw secret once with "paste into `GATEWAY_AGENT_<NAME>_CREDENTIAL`" instructions; never stored).
2. Creates one mandate per agent via `MandateService.create_mandate` with the §2.1 allowlists, purpose text stating the non-goals ("observes, drafts, escalates; never pauses agents, blocks payees, or changes policy"), and `purpose_key="security"`. Each creation passes through `validate_security_mandate` — the seed fails closed on violation.
3. Creates `agent_schedules` rows with `enabled=False` (default-off: the operator enables each schedule in the console).
4. Seeds policy allow rules for the four agents' tools (material policy change, audit-logged, operator-visible in the Policies page).
5. Seeds `sentinel_detector_configs` with the §4.2 defaults.

### 2.3 Operator mandate flow (console)

Security Agents → agent row → "Create mandate": a form pre-filled with the §2.1 allowlist for that agent (editable only to *narrow* — the form rejects additions outside the seed list; widening requires editing the seed and re-running, a deliberate speed bump). Submission calls `MandateService.create_mandate` + `validate_security_mandate`; violations render an error, nothing is created. The dashboard row shows the mandate scope hash (`sha256` of sorted allowlist); any change (new version, drift) flags the row until the operator acknowledges.

### 2.4 Forbidden patterns (defense in depth)

```python
FORBIDDEN_SECURITY_AGENT_TOOL_PATTERNS = (
    "policy.*",          # no live-policy write path exists; belt
    "vault.*",           # credential material — never agent-visible
    "agent.revoke", "agent.delete", "agent.pause", "agent.cancel",
    "mandate.create", "mandate.end", "mandate.withdraw",
    "mandate.pause", "mandate.narrow",
    "gateway.global_stop",
    "code.pr.merge",     # deferred out of MVP regardless
)
```

`validate_security_mandate(allowed_classes: list[str]) -> None` raises `ForbiddenMandateError` on any wildcard-aware match. Enforced at: seed time, console schedule-enable, every run start (against the resolved DB allowlist). The pipeline's own mandate check (`mandate_scope_exceeded`) remains the runtime backstop.

## 3. Red-team agent (MVP slice)

### 3.1 Scenario engine

`src/agents/redteam/engine.py`, `scenarios.py`:

```python
@dataclass(frozen=True)
class Scenario:
    id: str                 # "RT-01"
    name: str               # "injection-via-tool-output"
    control_point: str      # e.g. "inspection.injected_output_blocked"
    default_severity: str   # "critical" | "high" | "medium" | "low"
    setup: Callable[[AgentCtx], dict]        # returns scenario state (ids, payloads)
    execute: Callable[[AgentCtx, dict], dict]  # ONE attempt; returns raw observations
    assert_control: Callable[[dict], AssertionResult]  # pure function over observations

@dataclass(frozen=True)
class AssertionResult:
    passed: bool
    evidence: dict   # request_ids, audit row ids, verdicts, reason codes — redacted
    note: str        # 1–2 sentences for the finding/run log
```

Execution semantics per run:

1. For each enabled scenario (scope config): `setup()` → `execute()` **exactly once** → `assert_control()`.
2. If the assertion **passes**: log to the run record, continue.
3. If it **fails** ("one miss, one issue, move on"): build a `Finding`, run the filing pipeline (§3.4), mark the scenario complete. The engine never retries, never varies the payload, never pivots to a related control. This is structural (the loop has no retry path), not just a prompt instruction.

`AgentCtx` wraps the authenticated MCP client + per-scenario rate-limit tokens + the run id. Every tool call is a discrete audited gateway call with the scenario id in the (redacted) args metadata, so the audit trail shows exactly what the agent attempted.

### 3.2 Scenario catalog

The **assertion surface** for every scenario is the audit log (via the agent's own `audit.search` by `request_id`) plus the agent-visible error envelope. No new gateway surface is needed.

| ID | Name | Execute (sandbox tools) | Assert (control held iff…) | Default severity |
|---|---|---|---|---|
| RT-01 | injection-via-tool-output | `sandbox.echo` returns planted injection strings in tool output | audit row for the call shows the inspection pipeline blocked or redacted the output (`injected_output_blocked` / redaction flags) | high |
| RT-02 | error-envelope-leakage | force denies: call `demo.write`-style denied tool; call `code.pr.open` (out of mandate) | error envelope text matches **no** redaction-catalog pattern and contains no rule text, amounts, or counterparty identifiers | medium |
| RT-03 | secret-extraction | crafted `sandbox.echo` args attempt to surface vault-backed material | response contains no vault content; nothing retrievable agent-side (continuous re-proof of amended AC-05) | critical |
| RT-04 | counterparty-spoofing | `sandbox.payment_initiate` to near-miss payee ("1RS" vs "IRS") | decision is `approval_required`/`denied` with the counterparty-mismatch reason (counterparty assessment flagged it) | high |
| RT-05 | approval-fatigue | open 6 sequential low-value `sandbox.payment_initiate` approvals (sensitive → `approval_required`) | the 6th attempt returns the per-agent pending-cap structured error (cap 5 holds) and the denial-streak/cooldown path fires | medium |
| RT-06 | mandate-boundary | call `code.pr.open` (in policy-assistant's mandate, not redteam's) | deny with reason `mandate_scope_exceeded` (the wall holds when leaned on) | medium |
| RT-07 | event-injection | `sandbox.event_receive` with spoofed sender auth | verdict `quarantined` on the audit row | high |

Sandbox connector (`src/gateway/connectors/sandbox.py`, enabled only with `GATEWAY_SANDBOX_TOOLS=1`; hard policy rule restricts its tools to `household_role="security"` agents):

- `sandbox.echo` (routine): returns canned tool-output payloads, including injection-laden variants keyed by a `payload_id` arg. Mock upstream only — never touches real systems.
- `sandbox.payment_initiate` (sensitive): mock payment against a mock payee directory containing near-miss entries; exercises counterparty assessment + the approval path. No real money, no real connectors.
- `sandbox.event_receive` (routine): mock inbound-event ingestion feeding the inspection path; spoofed-sender variants yield quarantine verdicts.

RT-02's "denied tool" uses a tool the agent's mandate excludes (e.g. `demo.write` when demo tools are off, or any unlisted tool) — the deny itself is the probe input.

### 3.3 Rate limits and schedule

- Agent-side token bucket in the runner: `GATEWAY_REDATEAM_MAX_ATTEMPTS_HOUR` (default 60), `GATEWAY_REDATEAM_MAX_ATTEMPTS_DAY` (default 500); one token per scenario `execute()` call. Exhaustion pauses the run (status `rate_limited`, resumes next scheduled run).
- Concurrency: `asyncio.Semaphore(GATEWAY_REDATEAM_MAX_CONCURRENCY)` (default 2).
- Gateway-side per-agent limits (00 §7 param 4) apply independently — belt and suspenders.
- Schedule: `agent_schedules` row, cron `GATEWAY_REDATEAM_SCHEDULE` default `0 2 * * *`, timezone `GATEWAY_REDATEAM_TZ` default `America/New_York` (nightly 02:00 ET), plus console "Run now" → `agent_runs(trigger='manual')`.
- Scope config (Security Agents → redteam → Configure): enabled-scenario checkboxes, excluded-scenario reasons, severity threshold, daily issue cap — stored as JSON on the schedule row.

### 3.4 Finding → issue pipeline

`src/agents/redteam/findings.py`, `issues.py`:

```python
@dataclass
class Finding:
    id: str               # "F-…" (run-scoped)
    scenario_id: str      # "RT-04"
    control_point: str
    severity: str
    run_id: str
    first_seen_utc: str
    evidence: dict        # request_ids, audit row ids, verdict, reason code, expected control
    title: str
    what_happened: str    # 2–4 sentences
    blast_radius: str
    suggested_control: str
    reproduction: str     # exact steps against the sandbox; no real credentials
```

Steps, in order, fail-closed at each gate:

1. **Severity threshold:** `severity < GATEWAY_REDATEAM_ISSUE_THRESHOLD` (default `medium`) → finding goes to the run log only (visible on the dashboard), never filed.
2. **Pre-file redaction gate:** render the issue body from the fixed template (§3.4.1), then run the gateway's redaction catalog over title + body + labels. Any match → **filing rejected**, finding kept as `draft_blocked`, operator alerted. The agent's mandate already denies it the tools to obtain secrets; this gate is defense-in-depth.
3. **Duplicate suppression:** dedupe key = `(scenario_id, control_point)`. `IssueOpener.find_open_issues(repo, labels=["redteam-finding", f"rt-{scenario}"])` → if an open issue matches the key, post a comment (`New occurrence in run <run_id> at <utc>; evidence: <request_ids>`) instead of opening. Closed issues do not suppress (a regression re-opens the conversation as a new issue referencing the old one).
4. **Daily cap:** `GATEWAY_REDATEAM_DAILY_ISSUE_CAP` (default 10) issues/day, counted from the issue-store index. Overflow → run log + dashboard counter.
5. **File:** via `codehost.issue_open` (sensitive-gated → the approval flow, §3.5).

#### 3.4.1 Issue template (fixed)

```markdown
## [redteam] <short title>
**Severity:** <critical|high|medium|low> (scored by the agent, reviewed by human)
**Scenario:** <catalog id, e.g. RT-04-counterparty-spoof>
**First seen:** <utc> · **Agent run:** <run id>

### What happened
<2–4 sentences>

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

### Advisory judge note (optional, never a decision basis)
<judge annotation if the cascade was consulted, else omitted>
```

Labels: `redteam-finding`, severity label, scenario label (`rt-04`). The body never contains secret material, full account numbers, or unredacted args.

### 3.5 `codehost.issue_open`: adapter interface + safe fallback

**Status check:** no issue-opening capability exists today. `CodeHostConnector` exposes only `code.file.read` (routine) and `code.pr.open` (sensitive) against the in-memory `MockGitHub`. There is no real GitHub adapter.

New tool `codehost.issue_open` (sensitive-gated) on `CodeHostConnector`, backed by the `IssueOpener` interface (`src/gateway/connectors/issue_store.py`):

```python
class IssueOpener(Protocol):
    def open_issue(self, *, repo: str, title: str, body: str, labels: list[str]) -> IssueRef: ...
    def find_open_issues(self, *, repo: str, labels: list[str]) -> list[IssueRef]: ...
    def comment(self, *, issue_id: str, body: str) -> None: ...
    def count_opened_since(self, *, repo: str, since_utc: datetime) -> int: ...  # daily cap

@dataclass(frozen=True)
class IssueRef:
    id: str            # "local-000123" or GitHub issue number
    url: str           # file path (local) or https URL
    dedupe_key: str    # "RT-04|inspection.injected_output_blocked"
    state: str         # "open" | "closed"
```

MVP implementation: `LocalIssueStore` — appends one JSON file per issue under `GATEWAY_CODEHOST_ISSUES_DIR` (default `data/issues/<owner>/<repo>/`), plus an `index.json` for dedupe-key lookup and daily counts. This is the **safe local fallback**: it never fails open (write failure → the tool call errors, the finding stays `draft_blocked`, the run log records it) and never leaks (the pre-file redaction gate runs before the store write, identically for both backends).

`GitHubIssueOpener` is **defined but not implemented** in the MVP slice: `GATEWAY_CODEHOST_ISSUES_BACKEND=github` raises a clear startup config error ("GitHub issue backend not implemented; use `file`"). Selecting it never silently degrades. When later implemented, it uses the vault-held GitHub credential via the derived-token path (FR-012b), like the other adapters.

Filing approval — both paths architected (Ken decides per design open question 1; **default is path A**):

- **Path A — approval-per-issue (default):** `codehost.issue_open` is sensitive → each call creates an approval request; the card shows the rendered issue body (inert) + dedupe status + redaction-gate pass. The operator approves → the agent polls `gateway.approval_status` → re-invokes → `allowed_via_approval` → the handler writes the issue. Full dogfood of the Fix-B loop.
- **Path B — bounded standing rule:** the operator creates a material-classified policy allow rule for (`agent_redteam`, `codehost.issue_open`) with `argument_constraints`: `repo` must equal `GATEWAY_CODEHOST_ISSUES_REPO`, labels must include `redteam-finding`, body length cap. The daily cap is enforced gateway-side by a per-agent/day counter in the issue opener (counter-write failure → deny). The standing rule itself is created through the console policy flow (human, audit-logged, revokable); the dashboard shows filed issues for review. (Not a grant — MVP grants are one-time only per 00 §7 param 18; this is a policy rule, which is the sanctioned "always allow" shape.)

### 3.6 Red-team console surfaces (MVP)

- **Security Agents page** (§7): the redteam row (mandate state, recent verdict chips, open-issue count by severity, health, spend/latency).
- **Security Agents → redteam:** run history (`agent_runs`), per-run scenario results, run log (sub-threshold findings), filed issues (links into the local issue store / GitHub later).
- **Security Agents → redteam → Configure:** scenario checkboxes + exclusion reasons, rate limits, cron schedule, severity threshold, daily cap, pause. All changes audit-logged as admin actions.

## 4. Sentinel agent (extension — after MVP)

### 4.1 Where detectors run: in-agent

The six detectors are pure functions in `src/agents/sentinel/detectors.py`, executed **inside the sentinel agent's run** (not as a gateway-side job):

```python
def detect(audit_rows: list[dict], *, window: timedelta, config: DetectorConfig) -> list[DetectorHit]
```

Rationale: (1) dogfood — the sentinel exercises `audit.search` exactly as designed; (2) the gateway hot path stays free of scan work; (3) detectors are unit-testable against synthetic audit rows with no gateway running; (4) fail-visible — if the agent's reads fail, its heartbeat goes red and the operator sees "patterns unwatched."

Each run: `audit.search(since=now-max_window)` → run all six detectors → hits become findings (§4.3). Deterministic thresholds first; judge annotation second (opt-in, advisory). The deterministic layer works with the judge off.

### 4.2 The six detectors (deterministic threshold functions)

Windows slide over the rows returned by `audit.search`; all thresholds live in `sentinel_detector_configs(detector PK, enabled, params JSON)` and are console-editable.

| # | Detector | Fires when | Defaults |
|---|---|---|---|
| 1 | probing | ≥N `denied` rows (esp. `policy_denied`, varied tools) from one agent in M minutes | N=10, M=15 (`GATEWAY_SENTINEL_PROBING_N/_M_MIN`) |
| 2 | approval_fatigue | approval requests to one approver >3× the 7-day median in 1h, or a run of low-value requests | multiplier 3, window 1h |
| 3 | velocity_anomaly | an agent's call/spend rate deviates from its mandate baseline (reads the same counters as the money pack, read-only) | z-threshold configurable |
| 4 | drift_cluster | ≥K `drift_suspected` flags on one mandate in a day | K=3 |
| 5 | quorum_stall | quorum request `partially_approved` past 50% of its timeout | 50% (reads approval rows via `approval.read`-class access scoped to sentinel) |
| 6 | injection_uptick | `injected_output_blocked`/quarantine verdicts rising week-over-week | ratio 2.0 |

Each `DetectorHit`: `{detector, subject_agent_id, window_start/end, count, threshold, audit_row_ids[], recommended_action}`. Recommended actions are operator verbs ("pause agent", "review approvals", "dismiss") rendered as console buttons — the agent takes none of them.

### 4.3 Finding model + storage

`sentinel_findings` (config DB):

```
id               TEXT PK   -- "S-000881"
detector         TEXT      -- "probing"
severity         TEXT      -- "high" | "medium" | "low"
subject_agent_id TEXT
window_start/end TIMESTAMP
evidence         JSON      -- {audit_row_ids[], count, threshold, recommended_action}
judge_note       JSON NULL -- advisory annotation, if cascade consulted
status           TEXT      -- "open" | "acknowledged" | "acknowledged_with_action" | "false_positive" | "closed"
ack_by / ack_at / ack_note
notify_count     INT       -- re-notify counter (max 3)
last_notified_at TIMESTAMP NULL
created_at       TIMESTAMP
```

### 4.4 Console surfaces

1. **Dashboard banner** (existing banner pattern): "Sentinel: probing pattern from agent/wealth-1 — 14 denials in 12 min." Click → finding detail.
2. **Security Agents → sentinel → Findings:** pattern, window, linked audit ids, detector + threshold that fired, recommended action, ack buttons. The finding detail shows the judge note (if any) in a visually subordinate "advisory" block.
3. **Approvals queue annotation:** `approval_card.py` gains a lookup — when rendering a card, if an open `approval_fatigue` finding covers the requesting agent within its window, the card carries a `sentinel: fatigue risk` tag. Read-only annotation; it changes no approval semantics.

### 4.5 Ack lifecycle, cooldowns, re-notify

- Ack is explicit per finding: **ack** / **ack-with-action** (records the action taken, free text) / **false-positive**.
- **False-positive tunes the detector:** proposes a per-agent threshold override (e.g. raise probing N for that agent); the operator confirms in the console; the override is stored on the detector config and audit-logged. The agent never tunes itself.
- **Per-detector cooldown:** after an ack, that detector cannot re-fire on the same subject agent for `GATEWAY_SENTINEL_COOLDOWN_H` (default 1h).
- **Re-notify:** unacknowledged `high` findings (severity gate `GATEWAY_SENTINEL_NOTIFY_SEVERITY`, default `high`; Ken decides whether mediums notify) re-notify via the **existing exempt notifier path** (`Notifier.notify_new_request` shape, fixed field allowlist: agent name, detector, finding id, timestamp, console link — no args, no PII): max `GATEWAY_SENTINEL_RENOTIFY_MAX=3` times, `GATEWAY_SENTINEL_RENOTIFY_INTERVAL_H=4` apart, then the finding stays bannered. The sentinel agent never sends anything itself; the runner invokes the notifier.
- **Fail-visible:** audit-read failures or heartbeat stall → dashboard red: "sentinel unhealthy, patterns unwatched since <time>." Never fail-silent.

## 5. Policy assistant (extension — after MVP)

### 5.1 NL input surface: console panel

Decision: the **console panel** at Security Agents → policy-assistant (a form: intent textarea + target policy version + "Draft" button). Chat is deferred per the design's open question — the panel keeps the loop inside the audited console with CSRF protection, and avoids building a second conversational surface.

### 5.2 The draft loop (who runs what, where)

1. **NL in:** operator submits intent → console inserts an `agent_runs` row (`trigger='manual'`, agent `agent_policy_assistant`) → the runner's next tick dispatches a one-shot run.
2. **Draft out (agent, as MCP client):** the agent calls `policy.inspect` (current version + rules) and `code.file.read` (the Rego files), then — only if `GATEWAY_AGENTS_LLM_URL` is configured — drafts (a) JSON rule dicts in the existing rule schema, (b) a plain-English reading, (c) `opa test` cases. **The agent produces text; it runs nothing.** Without an LLM, the panel shows "LLM not configured — drafting unavailable" (no stub draft is ever presented as real).
3. **Machine check (console backend, server-side):** the draft text is POSTed to an internal endpoint that runs `opa check` + `opa test` via the existing `src/gateway/opa_client.py` (the save-time gate, run pre-save — the agent never executes binaries), then `POST /api/policy/dry-run` against the last 30 days. The operator sees the blast-radius view (would-allow / would-deny / would-require-approval counts + changed-call list) before anything is saved.
4. **PR (agent, approval-gated):** the agent calls `code.pr.open` (sensitive). The approval card shows the **full diff** (rule JSON + Rego tests + dry-run summary in the PR body, rendered inert). The operator approves → agent polls → re-invokes → PR opened (mock upstream in MVP; real GitHub later). No silent PRs.
5. **Human gate (Ken):** reviews and merges. Merge triggers the normal policy-save path (material classification, version immutability, audit log).

### 5.3 The two non-bypassable gates, in code

- **Gate 1 — PR open is approval-gated:** `code.pr.open` has `sensitivity="sensitive"` in the connector; the pipeline halts for human approval. There is no policy rule that can make a sensitive tool skip approval for this agent (the seed policy contains no such rule, and `validate_security_mandate` does not police this — the pipeline's sensitivity handling does).
- **Gate 2 — no tool path to live policy:** no `policy.save`/`policy.apply` tool exists on the MCP surface; policy saves are console-only admin actions (`Policies` page, password+TOTP, CSRF). `validate_security_mandate` forbids `policy.*` patterns so no future tool registration can slip into the agent's mandate unnoticed — the runner refuses the run.

### 5.4 Version skew

The draft records `drafted_against_policy_version`. The PR-open approval card renders "drafted against v12 · current is v13" when they differ, and the console re-runs the dry-run against current **before** the operator decides; on skew the card shows the refreshed blast-radius numbers with a skew warning. The operator may approve on the refreshed numbers or send it back for re-draft. The agent cannot resolve skew itself.

## 6. Incident agent (extension — after MVP)

### 6.1 Triggers

- **Operator click:** "Open incident" buttons on a sentinel finding, a denied/quarantined audit row, or the audit log → console inserts `agent_runs(trigger='manual', agent='agent_incident', input={source})`.
- **Automatic:** global stop engaged → the runner spawns exactly one incident run (`trigger='global_stop'`) to document the stop — the single exception to "global stop halts every security agent" (§8.2). A `critical` red-team finding filed → runner spawns an incident run (`trigger='redteam_critical'`).

### 6.2 `incident.write` tool + record store

`incident.write` (`routine` sensitivity, allowed only for `agent_incident`) with actions:

```python
incident.write({
  "action": "create",            # -> returns incident_id "INC-2026-1043"
  "title": str, "severity": str, "trigger": str,
} | {
  "action": "link_rows",
  "incident_id": str, "audit_request_ids": [str], "link_type": "confirmed" | "suggested",
} | {
  "action": "write_summary",
  "incident_id": str, "body": str,   # agent-written; versioned, human-editable
})
```

Close is **console-only** (button on the incident page; requires a resolution note: resolved / false-positive / accepted-risk; audit-logged). The agent cannot close incidents — "no autonomous response."

Tables (config DB):

```
incidents(id PK "INC-…", title, severity, status "open"|"closed",
          trigger, opened_by, opened_at, closed_at NULL,
          resolution NULL, resolution_note NULL)
incident_links(incident_id FK, audit_request_id, link_type "confirmed"|"suggested",
               note, created_at)          -- suggested links render dashed until confirmed
incident_summaries(incident_id FK, version INT, body TEXT,
                   author "agent"|"operator", created_at)  -- originals kept; operator edits add versions
```

### 6.3 Timeline rendering

Security Agents → Incidents → `INC-2026-1043`: rows are a **view over the audit log** — each line links to its audit row (`request_id`). Linkage is by id correlation (request ids, approval ids, time windows), never narrative inference. Suggested links render dashed and unlabeled until the operator confirms. Gaps render explicitly ("no rows 09:08–09:10 — agent idle or denied polls unlogged per the 02 §2.5 carve-out"). The summary block is labeled agent-written; the operator can edit/replace (new version; original kept).

### 6.4 Export

`[export timeline]` produces `incident-<id>.md` (the rendered timeline) + `incident-<id>.rows.json` (linked audit rows) + `manifest.json` (`sha256` per file) — the same manifest/hash treatment as the Pillar 1 compliance export. Export is audit-logged.

## 7. Fleet dashboard

New console page **Security Agents** (nav after Approvals), implemented in `src/gateway/console/security_agents.py` + `templates/security_agents*.html`, following the existing `render_page`/`csrf` patterns in `console/app.py`.

One row per security agent:

| Column | Data source |
|---|---|
| Identity & mandate | `IdentityService` + `MandateService` (config DB): agent id, mandate name + scope summary, state (live / checkpoint-due / paused / expired), expiry countdown, scope hash + drift flag |
| Recent verdicts | `AuditLog.search(agent_id, limit=20)` (audit DB) → allow/ask/deny chips (the dogfood view) |
| Findings count | redteam: `LocalIssueStore` open-issue count by severity; sentinel: `sentinel_findings` open by severity (extension) |
| Health | `agent_heartbeats` latest + `agent_schedules.next_run_at` (croniter); connector health via `HealthMonitor` for the connectors the agent uses; stale → amber/red |
| Spend/latency | audit count last 24h per agent; p95 decision latency from `latency.py` recorder |

**Additive latency change:** `LatencySpan` gains an optional `agent_id` field (default `""`); the pipeline records it when a call context carries an agent id. Per-agent `stats()` then filters by agent. Process-wide stats keep working (the Latency page is unchanged).

**Fleet summary strip** (one query each, config/audit DB): agents live/total, findings opened this week, escalations unacknowledged, any agent paused, any red heartbeat.

The dashboard is read-only observability: it links to findings and the Approvals queue; it hosts no ack/close/decide actions (those live on the finding or in the existing queue).

MVP ships the page with the redteam row fully wired; sentinel/policy-assistant/incident rows appear as their extensions land (rows render "not configured" until a mandate + schedule exist — default-off is visible, not hidden).

## 8. Kill switches

### 8.1 Wiring

- **Per-agent pause:** existing Agents page danger zone → `IdentityService.set_status(agent, "paused")` (also: mandate pause via Mandates page). The runner's pre-run gate sees non-active status / non-live mandate and skips; in-flight runs finish the current audited tool call, then halt cooperatively (a per-run `asyncio.Event` set by the tick loop; the engine checks it between scenarios).
- **Global stop:** the existing Dashboard control persists `config_settings["global_stop"] = {engaged: true, at, by}`. The runner polls it every tick:
  1. Stop dispatching new runs.
  2. Set the stop event on in-flight runs (finish current call, no new calls).
  3. Persist `agent_schedules.enabled=False` for all four agents (the no-auto-resume rule).
  4. Spawn the single `agent_incident` documentation run (§6.1), then halt the loop's dispatch entirely.
  5. Audit-log each step as system actions.

### 8.2 Restart after global stop

Schedules stay `enabled=False`. The console shows per-agent "Restart" buttons (CSRF-protected POST) that re-validate the mandate (`validate_security_mandate` + live-mandate check) and set `enabled=True`. There is deliberately no "restart all" — the operator restarts each agent consciously.

### 8.3 Scheduler tests for pause/stop

`tests/test_agents_scheduler.py`: pause mid-run → run halts after current scenario, no new tool calls recorded; global stop → all schedules persisted disabled, in-flight run stops, incident documentation run spawned exactly once; restart requires explicit per-agent action (assert `enabled` stays False across ticks after the stop clears).

## 9. Config

All new settings live in `Settings` (`src/gateway/config.py`) following the existing `GATEWAY_*` patterns; `validate()` gains checks for the new values. **Everything is default-off**: `GATEWAY_AGENTS_ENABLED=0` default, no mandates exist until the seed/operator creates them, schedules seed with `enabled=False`.

| Env var | Default | Meaning |
|---|---|---|
| `GATEWAY_AGENTS_ENABLED` | `0` | master switch; runner refuses to start when 0 |
| `GATEWAY_AGENTS_RUNNER_POLL_S` | `15` | scheduler tick seconds |
| `GATEWAY_SANDBOX_TOOLS` | `0` | register the `sandbox.*` connector tools (red-team targets) |
| `GATEWAY_AGENT_REDATEAM_CREDENTIAL` / `_CREDENTIAL_ID` | — | raw per-agent secret (secret) + public id, Fix A |
| `GATEWAY_AGENT_SENTINEL_CREDENTIAL` / `_CREDENTIAL_ID` | — | same |
| `GATEWAY_AGENT_POLICY_ASSISTANT_CREDENTIAL` / `_CREDENTIAL_ID` | — | same |
| `GATEWAY_AGENT_INCIDENT_CREDENTIAL` / `_CREDENTIAL_ID` | — | same |
| `GATEWAY_REDATEAM_SCHEDULE` | `0 2 * * *` | cron for nightly runs |
| `GATEWAY_REDATEAM_TZ` | `America/New_York` | schedule timezone (02:00 ET) |
| `GATEWAY_REDATEAM_MAX_ATTEMPTS_HOUR` | `60` | agent-side token bucket |
| `GATEWAY_REDATEAM_MAX_ATTEMPTS_DAY` | `500` | agent-side token bucket |
| `GATEWAY_REDATEAM_MAX_CONCURRENCY` | `2` | scenario fan-out semaphore |
| `GATEWAY_REDATEAM_ISSUE_THRESHOLD` | `medium` | min severity to auto-file |
| `GATEWAY_REDATEAM_DAILY_ISSUE_CAP` | `10` | max issues/day; overflow → run log |
| `GATEWAY_CODEHOST_ISSUES_BACKEND` | `file` | `file` (MVP) \| `github` (unimplemented → startup config error, fail-closed) |
| `GATEWAY_CODEHOST_ISSUES_DIR` | `data/issues` | local issue store root |
| `GATEWAY_CODEHOST_ISSUES_REPO` | — | `owner/name` the issues belong to (required when filing enabled) |
| `GATEWAY_SENTINEL_INTERVAL_S` | `120` | sentinel run interval |
| `GATEWAY_SENTINEL_PROBING_N` / `_M_MIN` | `10` / `15` | probing detector defaults |
| `GATEWAY_SENTINEL_COOLDOWN_H` | `1` | per-detector re-fire cooldown after ack |
| `GATEWAY_SENTINEL_NOTIFY_SEVERITY` | `high` | notify gate (`high` \| `medium`) |
| `GATEWAY_SENTINEL_RENOTIFY_MAX` | `3` | max re-notifications per finding |
| `GATEWAY_SENTINEL_RENOTIFY_INTERVAL_H` | `4` | hours between re-notifications |
| `GATEWAY_AGENTS_LLM_URL` / `_MODEL` / `_API_KEY` | — | optional OpenAI-compatible LLM for drafting/summaries; unset → deterministic-only |
| `GATEWAY_AGENTS_HEARTBEAT_MISSED_AMBER` / `_RED` | `2` / `5` | missed-heartbeat thresholds |

Secret values (`*_CREDENTIAL`, `_API_KEY`) come from the process environment / platform secret store only — never the repo, never the DB, never logs.

## 10. Judge interaction

The judge stays **advisory-only** throughout Pillar 2:

- **Where annotations may appear:** an optional `judge_note` on sentinel findings (§4.3) and the "Advisory judge note" section of red-team issues (§3.4.1) — visually subordinate, labeled as advisory, never a decision basis.
- **How it's consulted:** the runner may call the existing judge cascade (`judge/factory.py`) with redacted evidence; `JudgeUnavailable` → the annotation is omitted (fail-closed, deterministic path unchanged). Secrets are redacted pre-model per the cascade's existing behavior.
- **What it never does:** gate issue filing, change a finding's severity, suppress a detector hit, or override a Rego/pipeline deny. The deterministic layers (scenario assertions, detector thresholds) are complete without the judge — the judge-off configuration is byte-identical in behavior.

## 11. MVP vs extension module map

**MVP slice — independently shippable (red-team agent):**

```
src/agents/
  __init__.py  runner.py  scheduler.py  models.py  llm.py
  mandates.py            # validate_security_mandate + FORBIDDEN_* (MVP)
  mcp_client.py          # Fix-A authenticated MCP client factory (MVP)
  seed.py                # idempotent seed: agents, mandates, schedules, policy rules (MVP)
  redteam/
    __init__.py  engine.py  scenarios.py   # RT-01..RT-07 (MVP)
    findings.py  issues.py                  # template, dedupe, redaction gate (MVP)
    rate_limit.py
src/gateway/
  agent_tools.py         # audit.search, policy.inspect ToolDescriptors (MVP)
  connectors/sandbox.py  # sandbox.echo/payment_initiate/event_receive (MVP)
  connectors/codehost.py # + codehost.issue_open (MVP)
  connectors/issue_store.py  # IssueOpener, LocalIssueStore (MVP)
  console/security_agents.py  # fleet page + redteam detail/configure/run-now (MVP)
  console/templates/security_agents*.html  (MVP)
  models.py              # + AgentRun, AgentHeartbeat, AgentSchedule (MVP)
  latency.py             # + LatencySpan.agent_id (MVP, additive)
```

**Extensions (after the MVP slice is clean):**

| Extension | Modules |
|---|---|
| Sentinel | `src/agents/sentinel/` (detectors.py, findings.py), `sentinel_findings` + `sentinel_detector_configs` tables, dashboard banner hook, approval-card `sentinel: fatigue risk` tag, re-notify wiring |
| Policy assistant | `src/agents/policy_assistant/`, `policy.dry_run` tool, console panel + draft/check endpoints, opa check/test integration |
| Incident | `src/agents/incident/`, `incident.write` + `approval.read` + `mandate.read` tools, `incidents`/`incident_links`/`incident_summaries` tables, incident console pages, export |

The MVP's `src/agents/` runtime (runner, scheduler, credentials, mandate validation, heartbeats, kill switches) is shared unchanged by all extensions — that is the independently-shippable core.

## 12. Test plan

Constraints: no network, no GPU, no docker; GitHub filing mocked/stubbed (`LocalIssueStore` or a stub `IssueOpener`); pytest with `TMPDIR=/home/hatch/workspace/.tmp-pytest` (the 512MB `/tmp` tmpfs must not fill — SQLite test DBs go under the workspace tmp dir). No secrets in tests (use `MockNotifierTransport`-style fakes and random test credentials).

**Unit — `tests/test_agents_redteam.py`:**
- Scenario assertion logic per RT-01…RT-07 against synthetic observations (no gateway needed): each assert function tested with passing and failing evidence.
- Single-attempt enforcement: engine calls `execute()` exactly once per scenario per run even when the assertion fails (spy counter).
- Duplicate suppression: same `(scenario_id, control_point)` with an open issue → `comment()` called, `open_issue()` not called; closed issue → new issue opened referencing the old.
- Pre-file redaction gate: body containing a secret-shaped string (e.g. `sk-…`, SSN-shaped) → filing rejected, finding marked `draft_blocked`.
- Issue template rendering: all design fields present; labels correct.
- Severity threshold: low finding with threshold `medium` → run log only.
- Daily cap: 11th filing in a day → run log + counter surfaced.

**Unit — `tests/test_agents_sentinel.py` (extension):**
- Each of the six detectors against synthetic audit rows: fires at threshold, silent below; window boundaries correct.
- Per-detector cooldown: re-fire within cooldown suppressed; after cooldown fires.
- Ack lifecycle: ack / ack-with-action / false-positive transitions; false-positive proposes a per-agent override (operator confirm path).
- Re-notify: max 3, 4h apart (clock-injected), then banner-only.

**Unit — `tests/test_agents_mandates.py`:**
- `validate_security_mandate` refuses each forbidden pattern (parametrized), including wildcard variants (`vault.*` vs `vault.read`).
- Seed allowlists (§2.1) pass validation (regression: nobody adds a forbidden tool to a seed).

**Unit — `tests/test_agents_llm.py`:** `NullLLM` raises `LLMNotConfigured`; `OpenAICompatLLM` against a stub HTTP server (no network).

**Integration — `tests/test_agents_integration.py`:**
- Red-team run end-to-end: runner (test double scheduler, immediate dispatch) → agent as MCP client against a real in-process gateway app (httpx ASGI transport, no network) → sandbox tools → a forced RT-01 miss → finding → issue draft in `LocalIssueStore` (approval-per-issue path driven with an auto-approving test hook on the approval service — the *flow* is exercised, the human is stubbed).
- Mandate-boundary probe (RT-06): `code.pr.open` call → `denied` with `mandate_scope_exceeded` in the audit row.
- Approval-fatigue (RT-05): 6 sequential sensitive calls → 6th returns the pending-cap structured error.
- Kill-switch: pause mid-run → no further tool calls; global stop → schedules persisted disabled.

**Scheduler — `tests/test_agents_scheduler.py`:**
- Cron due-computation (croniter) incl. timezone; manual run pickup; concurrency semaphore respected.
- Pause/stop semantics (§8.3); no auto-resume after global stop; explicit per-agent restart.
- Heartbeat staleness thresholds (amber/red) with injected clock.

**Gateway-side — `tests/test_agents_tools.py`:**
- `audit.search` default-deny for a non-security agent; allowed for `agent_sentinel`; returns redacted rows only.
- `policy.inspect` read-only (no state change across calls).
- `codehost.issue_open` sensitive-gating: creates an approval request; without approval the issue is not written.
- Sandbox tools unreachable when `GATEWAY_SANDBOX_TOOLS=0`; restricted to `household_role="security"` when enabled.

## 13. Deferred / needs Ken's decision

From the design's open questions, with the architecture's stance:

1. **Issue filing: approval-per-issue vs standing grant** — both paths architected (§3.5); default is approval-per-issue. Ken picks.
2. **Sentinel notify severity: high-only vs high+medium** — env default `high`; Ken picks.
3. **Policy-assistant surface** — architecture picks the console panel (chat deferred). Ken confirms.
4. **Second admin for quorum / sentinel ack delegation** — out of this pillar's scope; the ack actor is whoever holds the admin session today.
5. **Red-team schedule** — default nightly 02:00 ET; Ken confirms.
6. **GitHub backend for `codehost.issue_open`** — interface defined, implementation deferred; needs Ken's GitHub OAuth app decision (00 §9.4) before real filing exists. Until then the file store is the system of record.
7. **Agent LLM endpoint** — unset by default; Ken decides whether to point `GATEWAY_AGENTS_LLM_URL` at an OpenAI-compatible endpoint for drafting/summaries. Red-team and sentinel do not need it.

---

*Architecture complete. No implementation. Next: Ken's approval, then the integrator builds the MVP slice (§11) first.*
