# Pillar 1 — Finance-Grade Gateway: Technical Architecture

**Status:** architecture only. Nothing here is built. Implementation is gated on Ken's approval.
**Design input:** `docs/pillar1-finance-design.md` (product/UX; the what). This document is the how.
**Baseline:** `docs/00-build-plan.md` (Fix A auth wall, Fix B approval flow, stack: Python 3.12+, FastMCP, FastAPI console, hand-rolled JSON rules → OPA sidecar, SQLite via SQLAlchemy, envelope-encryption vault).
**Branch:** `pillars/two-pillars`. Never touch `~/workspace/mcp-gateway`.

The gateway is the policy layer, never the custodian. It does not hold money, clear payments, or operate real-money rails.

---

## 0. Module map: MVP slice vs extension

The integrator builds the **MVP slice** first: **money-movement pack + quorum approvals + finance demo scenario**. Everything else follows only if the slice is clean. The slice is independently shippable: with the money pack off (`GATEWAY_MONEY_ENABLED=0`, the default), the gateway behaves exactly as before — the existing approval loop for non-money tools is untouched.

### MVP slice (shippable alone)

| Piece | New modules / files | New tables (config DB) | Console |
|---|---|---|---|
| Payment connector family | `src/gateway/connectors/payment_sandbox.py` | — | Connectors health row |
| Money policy pack | `src/gateway/money/__init__.py`, `money/amounts.py`, `money/state.py`, `money/limits.py`, `money/allowlist.py` | `money_ledger`, `counterparty_allowlist`, `money_pair_cooldowns` | Policies → Money page (`money.html`), `register_money()` |
| Money pipeline stage | `MoneyStage` in `src/gateway/money/stage.py`, wired in `pipeline.py` step 3.5 | — | — |
| Quorum approvals | `src/gateway/quorum.py`; extensions to `approvals.py`, `approval_card.py` | columns on `approval_requests` (migration m001) | Quorum card in `approvals.html` |
| Finance demo | `scripts/seed_finance_demo.py`, `scripts/demo_finance.py` | seed data only | — |

### Extension (after MVP)

| Piece | New modules / files | New tables | Console |
|---|---|---|---|
| Long-horizon mandates | `mandates.py` additions, `src/gateway/drift.py`, `DriftStage` | columns on `mandates` (m003) | Mandates checkpoint UI, re-confirm route |
| Event interception | `src/gateway/events/` (`models.py`, `interception.py`, `webhooks.py`) | `inbound_events`, `webhook_nonces` (m004) | Event Inbox (`events.html`, `event_detail.html`) |
| Vault namespaces | `vault/models.py` + `vault/store.py` + `vault/minter.py` additions | `vault_namespaces`, `vault_entries.namespace_id` (m005, vault DB) | Namespaces tab |
| Compliance export | `src/gateway/compliance.py` | `audit_entries.namespace_id` (m006, audit DB) | Audit export profile selector |

Migration numbering is sequential (m001–m006); m001–m002 are MVP, m003–m006 are extension. See §9.

**Stealth wording:** all public-facing strings say only "candidate OWASP project". No formal project title, no announced/official status, no lead-role references anywhere in code, docs, or console copy.

---

## 1. Money-movement policy pack

### 1.1 Connector family: `payment.*`

New file: `src/gateway/connectors/payment_sandbox.py`, following the `connectors/mock_upstream.py` + `connectors/base.py` pattern.

Tools (registered via `ConnectorRegistry.register`, same as email/calendar):

| Tool | Sensitivity | Ledger effect |
|---|---|---|
| `payment.quote` | routine | none — read-only estimate |
| `payment.initiate` | money-gated (see §1.3) | appends `money_ledger` row on success |
| `payment.status` | policy-gated read | none |
| `payment.cancel` | always `require_approval` (single approver) | appends reversal marker row |

Canonical argument schema (`payment.initiate` / `payment.quote`):

```json
{
  "type": "object",
  "properties": {
    "amount_cents": {"type": "integer", "minimum": 1},
    "currency": {"type": "string", "const": "USD"},
    "payee_key": {"type": "string", "minLength": 1, "maxLength": 256},
    "memo": {"type": "string", "maxLength": 280},
    "dry_run": {"type": "boolean", "default": false},
    "idempotency_key": {"type": "string", "maxLength": 128}
  },
  "required": ["amount_cents", "currency", "payee_key"],
  "additionalProperties": false
}
```

- `additionalProperties: false` is load-bearing: there is **no `namespace` argument** — a namespace smuggled in args fails validation (`invalid_input`, MF-4 ordering, no approval created). Namespace resolution is mandate-side only (§5).
- Amounts are integers in cents, USD only. `money/amounts.py::canonicalize_amount(args)` runs in `ValidateInputsStage` and rejects: floats, numeric strings (`"12000"`), negative/zero, missing currency, `currency != "USD"`. Fail closed: any rejection → `invalid_input`, no approval request (Fix B MF-4).
- **Receipt contract** (adapter → gateway), enforced by `PaymentSandboxAdapter` and asserted in tests:

```python
@dataclass(frozen=True)
class PaymentReceipt:
    payment_id: str      # "pay_" + 32 hex chars (same CSPRNG discipline as req_/apr_/mnd_)
    amount_cents: int    # echoes the canonicalized request amount
    payee_key: str       # echoes the request payee_key
    status: str          # "settled" | "pending" | "failed" | "voided"
    dry_run: bool        # True when the adapter moved no synthetic funds
```

- `dry_run=True`: the adapter returns a receipt with `dry_run=True` and `status="settled"` without mutating sandbox balances; the gateway still writes the `money_ledger` row flagged `dry_run=1` (so dry-run replays exercise the full pipeline including velocity accounting) but the demo treats it as synthetic. Used by the demo and by dry-run replay.
- Unknown-outcome handling: an adapter timeout on `payment.initiate` → existing `UnknownOutcomeService.record_block` (keyed by `(agent, tool, argument_hash)`); the agent sees `unknown_outcome` and must wait; the console resolves the block via `payment.status` receipt or an explicit void. No blind retry.
- **Execute-on-approval is disabled for `payment.*`.** In `ApprovalService.decide()`: `if execute_on_approval and tool.startswith("payment."): raise ValueError(...)`. Rationale (design §1 failure mode 1): replaying redacted args could alter the payee; money calls use the agent re-invoke path only, where the grant's argument HMAC binds the exact amount + payee.

### 1.2 Receipt / grant binding vs amount tampering

The grant binds `HMAC(canonical args)` (existing MF-7 semantics in `GrantService.check`). A re-invoke with a different amount misses the grant. Existing behavior would fall through to rule evaluation and open a *new* approval request — for money that is a tamper-shaped event, so `MoneyStage` adds a payment-specific guard:

- `money/limits.py::detect_grant_mismatch(db, agent_id, tool, ctx)`: if a grant exists for `(agent_id, tool)` that is approved, unconsumed, unexpired, but the argument hash does not match → deny with new terminal code `grant_argument_mismatch` (add to `ERROR_CODES` in `errors.py`, retryable `False`, alongside `already_executed`). Safe-vocabulary: it names the mismatch, not the amounts.
- This check runs only for `payment.*` and only when the agent presents an `approval_request_id` on re-invoke (i.e., it is in the post-approval loop).

### 1.3 JSON rule schema extension: `conditions.money`

Money rules are ordinary `PolicyRule` rows whose `conditions` carry a `money` block. New module `src/gateway/money/limits.py` owns validation; `policy.validate_rule_dict` accepts the block structurally (unknown keys still rejected — FR-PAA04-002).

```json
"conditions": {
  "money": {
    "per_call_soft_cents": 2500000,
    "per_call_hard_cents": 25000000,
    "per_day_cents": 10000000,
    "per_month_cents": null,
    "max_payments_per_window": {"n": 10, "window_minutes": 60},
    "max_payments_per_day": 50,
    "max_new_counterparties_per_day": 3,
    "cooldown_after_deny_minutes": 15,
    "quorum": 2,
    "quorum_min_cents": 2500000
  }
}
```

Semantics:

- `per_call_soft_cents`: amount ≥ soft → `require_approval`. Below soft, a listed payee within velocity → allow.
- `per_call_hard_cents`: amount ≥ hard → `policy_denied`, reason `amount_over_hard_ceiling`. **New safe-vocabulary reasons** (added to `SAFE_REASONS` in `errors.py`): `amount_over_hard_ceiling`, `spend_cap_exceeded`, `velocity_limit_exceeded`, `counterparty_blocked`, `mandate_window_closed`, `mandate_budget_exhausted`, `mandate_checkpoint_overdue`. All name the *class*, never amounts, payees, or windows.
- `per_day_cents` / `per_month_cents`: rolling windows computed server-side from UTC `money_ledger.occurred_at`. Breach → `policy_denied` / `spend_cap_exceeded`. The approval card shows remaining budget (from evidence, never the reason string).
- `max_payments_per_window`, `max_payments_per_day`: velocity hard-stops → `policy_denied` / `velocity_limit_exceeded`. Counters key on `(agent_id, namespace_id)` **and** `(agent_id, namespace_id, counterparty_key)` independently — N small payments to the same payee trip the per-payee velocity even under the soft threshold (split-payment evasion, design §1 failure mode 3). The card shows "3 of 10 hourly payments used".
- `max_new_counterparties_per_day`: first-ever payment to a payee key counts as new (checked against `counterparty_allowlist` + ledger history). Breach → deny `velocity_limit_exceeded`.
- `cooldown_after_deny_minutes`: after a deny on `(agent_id, payee_key)`, no new approval request for that pair until expiry → `cooldown_active` (existing code, extended key). New table `money_pair_cooldowns(agent_id, counterparty_key, expires_at)` — separate from `RefusalCooldown` because the key is the *payee*, not the argument hash.
- `quorum` (default 1) + `quorum_min_cents`: when the rule's outcome is `require_approval` and `amount_cents >= quorum_min_cents`, the approval request is created with `quorum_required = quorum`. Below the line, quorum collapses to 1 (single approval up to $25k; quorum of 2 at/above $25k — the demo's tiers in one rule).

### 1.4 Where the money state lives

**Decision: SQLite table, not in-memory.** Precedent: `RateCounter` persists in SQLite "so a restart does not reset limits" — spend limits have the same requirement, more so.

New table `money_ledger` (config DB, migration m002):

```python
class MoneyLedger(Base):
    __tablename__ = "money_ledger"
    id: Integer pk
    agent_id: String(64), FK agents.id, index
    namespace_id: String(64), nullable, index        # set when namespaces land (§5); NULL = pre-namespace
    mandate_id: String(64), index
    counterparty_key: String(256), index
    amount_cents: Integer, nullable=False
    tool: String(64)                                 # payment.initiate | payment.cancel
    request_id: String(64)                           # req_ linkage to the audit row
    dry_run: Boolean, default False
    occurred_at: DateTime(tz=True), index
```

Rolling windows are `SUM(amount_cents)` / `COUNT(*)` over indexed `occurred_at` ranges. Personal-gateway volumes make per-event rows cheap and auditable; no separate counter table to drift out of sync. Retention: prune rows older than `GATEWAY_MONEY_LEDGER_RETENTION_DAYS` (default 90, aligned with audit retention) via the existing backup/retention job — windows never exceed 30 days, so pruning is safe.

`money/state.py::MoneyStateBuilder.build(db, agent_id, namespace_id, payee_key, now)` returns one snapshot per call:

```python
@dataclass(frozen=True)
class MoneyState:
    spent_today_cents: int
    spent_month_cents: int
    payments_last_hour: int
    payments_today: int
    payee_payments_last_hour: int
    new_counterparties_today: int
    is_new_counterparty: bool
```

Three indexed aggregate queries. AC-11 note: each is single-digit ms on SQLite at personal scale; the stage records a `money` timing span (§11).

**Why not in the OPA input document?** The OPA pivot (`policy.py`) deliberately keeps high-churn DB state (grants, mandate liveness) Python-side per the spike's recommendation — the sidecar stays stateless. Money state is the same class of state. Money rules are therefore evaluated Python-side in `MoneyStage`, and `rule_to_input_data` **filters out** rules carrying `conditions.money` so OPA never sees them (documented in `policy.py`; the Python money evaluator is the single authority — no Rego/Python dual maintenance for thresholds).

### 1.5 Evaluation order

New pipeline step 3.5, between `MandateStage` (3) and `PolicyStage` (4). Fix-B order is preserved; the money check is a policy specialization that needs mandate liveness first (a dead mandate must deny before any spend math).

`MoneyStage.run(ctx)`:

1. If `ctx.tool` is not in the `payment.*` family → return None (pass through; non-money tools untouched).
2. If `GATEWAY_MONEY_ENABLED=0` → return None (money pack default-off; falls through to the existing policy stage and the `spending_thresholds` preset).
3. Amount is already canonicalized by `ValidateInputsStage` (MF-4 ordering: schema failure → `invalid_input`, no approval created).
4. Grant-mismatch guard (§1.2) when re-invoking post-approval.
5. Find the first matching money rule: `PolicyRule` rows in `rule_order` with tool selector matching `payment.*` and `conditions.money` present. **No money rule → return None** → the normal policy stage runs → the shipped `spending_thresholds` preset (`policies/v1/spending.rego`: `payment.*` → `require_approval`) applies its blanket ask. This is the design's preset-refinement rule: *explicit numeric rules override the preset's blanket ask; the preset remains the backstop.*
6. Evaluate thresholds in fixed order (hard stops before soft):
   a. `amount >= per_call_hard_cents` → `policy_denied` / `amount_over_hard_ceiling`
   b. payee `blocked` → `policy_denied` / `counterparty_blocked`
   c. `spent_today + amount > per_day` or monthly equivalent → `policy_denied` / `spend_cap_exceeded`
   d. velocity breach → `policy_denied` / `velocity_limit_exceeded`
   e. `amount >= per_call_soft_cents` **or** payee unlisted → `require_approval` (set `ctx.needs_approval=True`, `ctx.quorum_required` from the rule, `ctx.money_state`, `ctx.money_rule_id`); the existing `ApprovalStage` then creates the request — quorum-aware (§2).
   f. else → allow: set `ctx.policy_short_circuited=True`, `ctx.scope_rule=f"money_rule:{rule_id}"`; the policy stage is skipped for this call (same short-circuit shape as the grant path, MF-7).
7. `payment.cancel` bypasses amount thresholds: always `require_approval` (single approver), amount resolved from the referenced receipt at card-render time.

On **successful** `payment.initiate`/`payment.cancel` execution, `ExecuteStage` appends the `money_ledger` row (post-execute hook in `money/state.py::record_movement`). Denied/failed calls write no ledger row — only moved money consumes budget. `dry_run` calls write a `dry_run=1` row (excluded from budget sums, included in velocity counts — a dry-run flood is still a flood).

`dry_run` (the policy dry-run endpoint, MF-12 / AC-12) supports money rules: `PolicyEngine.dry_run` evaluates the `MoneyStage` logic with an as-of timestamp against historical ledger rows. The synthetic cold-start corpus gains per-`payment.*` entries.

### 1.6 Counterparty allowlist model

New table `counterparty_allowlist` (config DB, migration m002) — **distinct from** the existing `counterparty_records` (which are auto-built from audited calls, FR-PAA05-001). The allowlist is operator-curated:

```python
class CounterpartyAllowlist(Base):
    __tablename__ = "counterparty_allowlist"
    id: Integer pk
    namespace_id: String(64), nullable, index      # per-client allowlist (design §1); NULL until §5
    payee_key: String(256), nullable=False         # account fingerprint, e.g. "ach:schwab:xxxx1234"
    label: String(256), nullable=False             # "Schwab brokerage"
    details_snapshot: JSON, default dict           # {routing_tail_last4, account_tail_last4, ...}
    verification_state: String(16), default "pending"   # verified | pending | blocked
    verified_by: String(64), nullable              # admin_id
    verified_at: DateTime(tz=True), nullable
    record_version: Integer, default 1              # bumped on every edit; feeds quorum context freeze (§2.5)
    notes: Text, default ""
    # unique: (namespace_id, payee_key) — NULL namespace handled via coalesce in service layer
```

- `money/allowlist.py::AllowlistService`: `lookup(namespace_id, payee_key)`, `set_verification(...)` (admin-only, audit-logged as admin action, bumps `record_version`).
- Last-4 display: the design explicitly permits last-4 of *the operator's own* routing/account tails on the card — the single exception to the no-last-4 rule (00 §7 param 13). Full numbers are never stored: the operator enters last-4 only.
- Behavior matrix (enforced in `MoneyStage` step 6): listed+verified+within limits → allow-or-step-up per thresholds; unlisted → always `require_approval` with card flag "new counterparty"; `blocked` → hard deny `counterparty_blocked`; `pending` → `require_approval` (never silent allow).
- `extract_payee_key("payment.initiate", args)` → `args["payee_key"]`; add `payment.initiate`/`payment.cancel` to `counterparty.COMMITMENT_ADJACENT_TOOLS` so the existing counterparty assessment (`assess`) also sees payment calls.

### 1.7 Approval card: money evidence

Extend `approval_card.py::build_evidence_subset` with a `payment.*` branch (new function `build_money_evidence(args, money_state, allowlist_record, rule)`):

- consequence summary first: "Pay $48,000.00 to IRS (verified payee, 14 prior payments)" — amount rendered from integer cents, never floats.
- term sheet: mandate scope, remaining daily/monthly budget, velocity usage ("3 of 10 hourly payments used").
- counterparty evidence: verification state, verified-by/at, details snapshot (last-4 only), delta vs snapshot if changed.
- quorum header (§2), drift note if `ctx.drift_suspected` (§3.4), judge advisory (flags only — advisory, never the decision basis).
- `approval_required` details gain `"quorum": true` when `quorum_required > 1` (design §1: the agent's poll loop is unchanged; it just waits longer).

### 1.8 Policy-version material classification

`conditions.money` is inside the rule dict that `_rule_semantic_signature` hashes — **any** money-field change (limits, quorum, velocity, thresholds) is automatically `material_change=True` on save. No code change needed; the architecture documents the guarantee and the Money page save flow surfaces the classification to the operator before confirm. Counterparty allowlist edits are *data*, not rules: they do not create policy versions; instead they bump `record_version`, which freezes/expires in-flight quorum requests via the context check (§2.5).

---

## 2. Quorum approvals

### 2.1 State machine

New module `src/gateway/quorum.py`. ApprovalRequest gains (migration m001):

```python
quorum_required: Integer, default 1                 # approvers needed; 1 = existing single-approver path
approvals: JSON, default list                       # per-approver slots, append-only
# [{"admin_id": "admin_ken", "session_id": "sess_…", "decided_at": iso,
#   "approver_index": 0, "auth_method": "password+totp"}]
evidence_hash: String(128), nullable                # HMAC(canonical evidence_subset) at creation
context_fingerprint: JSON, nullable                 # {mandate_status, policy_version, counterparty_record_version}
request_type: String(16), default "tool_call"       # "tool_call" | "event_release" (§4)
```

Status transitions: `pending → partially_approved → (approved | denied | expired)`. `canceled` (existing, mandate-death path) remains terminal. Terminal states immutable; re-opening is a new `apr_` id.

`quorum.py` public functions (all transactional, all under the existing `_MUTEX` single-flight + conditional-UPDATE discipline):

```python
def validate_quorum_satisfiable(db: Session, quorum: int) -> None
    # Count AdminUser rows. quorum > count → ValueError(
    #   "quorum unsatisfiable — register a second admin").
    # Called on money-rule save (console) AND defensively at request creation.

def record_approval(db, apr_id, *, admin_id, session_id, auth_method, note="") -> ApprovalRequest
    # 1. sweep_expired first (a lapsed request cannot collect approvals).
    # 2. status must be pending|partially_approved, else return existing decision (idempotent).
    # 3. context check (§2.5) — stale context → expire(context_changed), raise.
    # 4. duplicate_approver: any slot with admin_id → ValueError("duplicate_approver").
    # 5. distinct session: any slot with session_id → ValueError("duplicate_session").
    #    (Blocks one person approving from two tabs on a shared login.)
    # 6. mandate liveness re-check at EACH decision (withdrawn/paused/expired → expire request).
    # 7. no-self-approval on delegated mandates: if mandate.parent_mandate_id is not None
    #    and admin_id == delegator admin → ValueError("delegator_cannot_approve").
    #    The card shows the delegation chain (parent_mandate_id → created_by).
    # 8. append slot {approver_index: len(slots)}; audit row decision="approved",
    #    redacted_args={approver_index, quorum_progress: "1/2", session_id, content_hash}.
    # 9. len(slots) == quorum_required → status="approved", mint grant (MF-7, one-time, 30-min TTL).
    #    else → status="partially_approved".

def record_denial(db, apr_id, *, admin_id, session_id, note="") -> ApprovalRequest
    # One-denial-kills: ANY eligible approver's deny → status="denied" immediately,
    # refusal-cooldown recorded, audit row decision="denied_decision".
    # A quorum denial needs only one no.
```

`ApprovalService.decide()` becomes quorum-aware: when `apr.quorum_required > 1` it delegates to `quorum.record_approval/record_denial`; the `quorum == 1` path keeps the exact existing behavior (additive; the non-money approval loop is untouched).

### 2.2 Distinct-session enforcement

`session_id` comes from the console admin session store (`console/admin_auth.py` — the session id issued at password+TOTP login, FR-036). The decision endpoint (`console/approvals.py`) already knows the admin; it now also passes `request.session` id. Enforcement is in the decision **transaction**, not the UI (design anti-gaming rule 1/3).

### 2.3 Unsatisfiable-quorum validation on rule save

`validate_quorum_satisfiable` runs in the Money page save handler: saving a money rule with `quorum: 2` on a single-admin install fails with "quorum unsatisfiable — register a second admin." The design does not fake quorum with double-clicks. (Also enforced at request-creation time as defense in depth — fail closed if an admin was removed after the rule was saved.)

### 2.4 Grant minting after quorum

Identical to the single-approver grant (MF-7): one-time, 30-min TTL, bound to `(agent, tool, argument_hash)`, live-mandate re-check + policy-supersession check at consumption, atomic compare-and-consume. Grant minting happens only on the transition to `approved` (all slots filled). `partially_approved` mints nothing — the request is not executable at 1/2.

### 2.5 Evidence freeze + `context_changed` expiry

At request creation: `evidence_hash = ring.digest(canonical(evidence_subset))`; `context_fingerprint = {mandate_status, policy_version: current, counterparty_record_version: allowlist.record_version}`.

`quorum.check_context(db, apr)` runs (a) inside `sweep_expired`, (b) before each `record_approval`:

- mandate not live (withdrawn/paused/expired) → `expired`, reason `context_changed`
- current policy version > `apr.policy_version` with a **material** change → `expired` / `context_changed` (non-material changes do not expire — matches MF-7 grant semantics)
- allowlist `record_version` for the payee != fingerprinted version → `expired` / `context_changed`

(c) At grant consumption, `GrantService.check` re-verifies money grants via `money.limits.reverify_money_grant`: spend caps against the fresh ledger plus committed reservations, and allowlist blocked/record-version — stale or blocked → deny, fail-closed. (This is the consumption-time enforcement; `check_context` itself is not called on the grant path.)

Expiry audit-logs both approver slots' admin ids and notifies in-console. Approvers never sign stale context.

### 2.6 Timeout

Unchanged default: 15-min approval window for money (design §2; the 5-min destructive registry is for `calendar.delete`/`email.settings.write`). `partially_approved` does not extend the clock — if the second approver never arrives, `sweep_expired` → `expired`; the agent's poll returns `expired` and must start a new request.

### 2.7 Collusion note

Two admins colluding is out of scope (design §2 failure modes). The control is the audit trail: who (`admin_id`), when, what (`evidence_hash`), which session — all in the compliance export (§6).

---

## 3. Long-horizon mandates (extension)

### 3.1 Schema changes (migration m003)

```python
# additions to mandates table
valid_from: DateTime(tz=True), nullable
# valid_until reuses the existing expires_at column.
allowed_windows: JSON, default list
# [{"days": ["mon","tue","wed","thu","fri"], "start": "09:00", "end": "17:00",
#   "tz": "America/New_York"}]  — same shape/semantics as policy time_window
max_actions: Integer, nullable
actions_used: Integer, default 0          # incremented in the audit stage per executed call
checkpoint_every_days: Integer, nullable
checkpoint_every_money_actions: Integer, nullable
last_reconfirmed_at: DateTime(tz=True), nullable
last_reconfirmed_by: String(64), nullable  # admin_id
client_principal_id: String(128), nullable # ontology person principal — also feeds §5 namespace resolution
revision: Integer, default 1              # bumped on narrow/pause/resume/re-confirm/duplicate; cited in §6 export
intent_summary: JSON, default dict
# {"tool_classes": {"payment.initiate": 41}, "amount_median_cents": 1200000,
#  "amount_max_cents": 4800000, "counterparties": ["ach:schwab:xxxx1234"],
#  "windows": ["mon-fri 09-17 America/New_York"], "updated_at": iso}
```

### 3.2 Enforcement points (all in `MandateStage`, step 3 — fail-closed by position)

`mandates.py::MandateService.check_temporal(mandate, db, now)` runs after the existing liveness check:

1. `valid_from`/`expires_at` bounds → outside → `mandate_expired` (existing reason; absolute bounds are expiry).
2. `allowed_windows`: reuse `policy.time_window_matches` semantics per window; a call outside all windows → `policy_denied` / `mandate_window_closed`, with a `retry_after` hint naming the next window in the error **details** (never the reason string).
3. `max_actions`: `actions_used >= max_actions` → `policy_denied` / `mandate_budget_exhausted`.
4. Checkpoint: `checkpoint_status()` (§3.3) → `overdue` → `policy_denied` / `mandate_checkpoint_overdue`. **In-flight grants are not consumed**: `GrantService.check` calls `check_temporal` on the grant's mandate too — an overdue mandate invalidates approved-but-unconsumed grants with reason `mandate_checkpoint_overdue` (same pattern as the existing `_mandate_dead_reason`).

`actions_used` increments in the pipeline audit stage (one indexed UPDATE per executed call — acceptable; the audit stage already writes per call).

### 3.3 Checkpoint countdown derivation

`mandates.py::checkpoint_status(mandate, db, now) -> {state, due_in_days, due_in_money_actions}`:

- Anchor: `last_reconfirmed_at or created_at`.
- Time axis: `due_at = anchor + checkpoint_every_days`; `due_in_days = (due_at - now).days`.
- Money-action axis: `money_actions_since_anchor = COUNT(money_ledger WHERE mandate_id AND occurred_at >= anchor AND dry_run=0)`; `due_in_money_actions = checkpoint_every_money_actions - money_actions_since_anchor`.
- `state`: `ok` → `due_soon` at ≤25% remaining on either axis → `overdue` at ≤0 on either axis. "Whichever comes first."
- At `due_soon`: the agent's next call carries `mandate_checkpoint_soon` in the call **metadata** (not an error — the call proceeds) and the console shows a banner. Metadata, not denial: the design is explicit.
- At `overdue`: `MandateStage` denies (fail-closed — an unattended agent cannot keep spending because nobody looked).

### 3.4 Re-confirmation

- Console-only: `POST /mandates/{id}/reconfirm` (admin-only, CSRF per MF-8). **There is no tool for it** — an agent asking for re-confirmation gets `policy_denied`.
- The route renders the mandate's term sheet (purpose, scope, limits, allowlist version, drift summary) exactly as at creation; the operator reviews and signs (password+TOTP session, existing FR-036).
- Service: `mandates.py::reconfirm(mandate_id, admin_id)` — asserts `allowed_classes` unchanged (re-confirmation cannot widen scope; widening is a new mandate — the UI offers "duplicate as new mandate", which calls `create_mandate` with a fresh id and `parent_mandate_id` unset). Sets `last_reconfirmed_at=now`, `last_reconfirmed_by=admin_id`, `revision += 1`, resets the countdown anchor.
- The signature (admin id + timestamp + content hash of the term sheet) is a **new audit row**: `tool="mandate.reconfirm"`, `decision="approved"`, `redacted_args={mandate_id, revision, term_sheet_hash}`. The audit log then shows denial → re-confirmation signature → resumed calls — the complete story for the compliance export.

### 3.5 Drift detection

New module `src/gateway/drift.py`:

- **Where the per-mandate intent summary lives:** `mandates.intent_summary` (JSON, §3.1). Updated post-execution from the audit stage via `drift.update_intent_summary(mandate, call_record)` — rolling medians/counts, cheap JSON rewrite, no extra tables.
- **What the drift check computes** (`drift.assess_drift(mandate, ctx) -> DriftResult`): compares the current call against the summary —
  - `new_tool_class`: tool class never seen under this mandate
  - `amount_spike`: `amount_cents >= 10 × amount_median_cents` (order of magnitude above history)
  - `new_payee`: payee key never seen under this mandate
  - `off_window`: call far outside the mandate's usual windows
- **How `drift_suspected` forces step-up:** new `DriftStage` between `PolicyStage` (4) and `ApprovalStage` (5). If `assess_drift` fires any signal: `ctx.needs_approval=True`, `ctx.drift_suspected=True`, `ctx.drift_notes=["drift: first payment to a new payee class", …]`. Drift alone never denies. The approval card renders the drift note plus an operator action "accept as new normal" → creates a new mandate revision (material-classified) rather than editing the baseline in place.
- Drift signals feed the existing ontology feedback loop (`ontology/feedback.py::record_decision_outcome`) so repeated false positives are tuned down by the operator, never by the agent.

---

## 4. Event-driven interception (extension)

Default: **off**. `GATEWAY_EVENT_INTERCEPTION=off|monitor|enforce` (default `off`). `monitor` computes verdicts and logs them but delivers everything (the inbox shows what *would* have been quarantined). Operators run monitor before flipping to enforce. Everything that changes production paths is default-off (§8).

### 4.1 Intake model

New package `src/gateway/events/`:

- `models.py::InboundEvent` (config DB, migration m004): `id` (`evt_` prefix — add to `ids.py::_PREFIXES`), `source` (`email` | `webhook`), `external_id` (message-id / webhook delivery id, dedupe), `claimed_sender`, `sender_auth` (JSON: `{spf, dkim, dmarc}` or `{hmac: ok/fail}`), `payload` (JSON raw event — **admin-only**, never agent-visible), `verdict`, `reason_class`, `findings` (JSON), `agent_id` (addressee), `created_at`, `released_at`, `released_by`.
- `interception.py::evaluate_event(db, event) -> (verdict, reason_class, findings)` — the chain, in fixed order:
  1. **schema validation** — malformed event → `deny` (fail closed)
  2. **injection scan** — reuse `inspection/injection_scan.py` → hit → `quarantine`, reason `injection-detected`
  3. **false-urgency scan** — reuse `inspection/urgency_flags.py` → hit is a *signal*, not a verdict alone
  4. **sender authentication** — email: SPF/DKIM/DMARC results from the email adapter metadata; webhook: HMAC (see §4.3). Failure → `quarantine`, reason `sender-auth-failure`
  5. **counterparty match** — `counterparty.assess` on the claimed sender: unknown sender, or details differing from the verified allowlist record → `quarantine`, reason `counterparty-mismatch`
  6. **policy decision** — any hard signal → verdict; else `deliver`
- Verdicts: `deliver` | `deliver_redacted` (secrets/links stripped via the redaction catalog, links rendered inert) | `quarantine` | `deny` (dropped, logged).
- Intake-time evaluation with caching: verdicts are computed once per `(source, external_id)` and stored; the email connector's `search`/`read` handlers consult the verdict — quarantined messages are replaced by the stub. This keeps interception off the agent's per-read hot path after first sight (AC-11).

### 4.2 The quarantine stub

The agent never sees quarantined content. Stub format (the *only* thing the agent receives):

```json
{
  "event_id": "evt_…",
  "status": "withheld_by_policy",
  "reason_class": "sender-auth-failure",
  "appeal": "operator review via console Event Inbox"
}
```

No sender text, no links, no amounts. A spoofed instruction cannot reach the agent's context — this is the point.

### 4.3 Webhook HMAC receiver + replay protection

`events/webhooks.py`, mounted in `mcp_server.py`: `POST /v1/events/webhook/{source}`.

- Per-sender secret stored in the **vault** (never env, never repo). HMAC-SHA256 over `(timestamp + "." + nonce + "." + raw_body)`, compared with `hmac.compare_digest`.
- Replay protection: `webhook_nonces(nonce, sender, seen_at)` table (migration m004); reject reused nonce or `|now - timestamp| > GATEWAY_WEBHOOK_NONCE_WINDOW_S` (default 600). Failed auth → `deny`, logged, sender rate-limited.
- Per-sender rate limits (event-flood DoS): reuse the `RateCounter` pattern keyed `event_sender:{sender}`; bulk patterns auto-quarantine; the inbox groups by sender.

### 4.4 Event Inbox console

- `GET /events` — table: time, source, claimed sender, verdict, reason class, linked agent(s). (`events.html`)
- `GET /events/{id}` — raw event rendered **inert** (admin-only), scan findings (which detector fired and why), counterparty assessment ("claimed sender matches no allowlist entry; routing details differ from the verified record"), actions.
- `POST /events/{id}/release` — creates an `ApprovalRequest` with `request_type="event_release"`; releasing follows the same approval flow (quorum-capable) — the releaser sees the full raw event first. On approval, verdict → `deliver`, audit-logged.
- `POST /events/{id}/release-redacted`, `POST /events/{id}/block-sender` (adds to `counterparty_allowlist` as `blocked`, audit-logged). All POST routes CSRF-protected (MF-8).
- Defense in depth (design Act 3): even after release, the subsequent `$30,000` payment to an unlisted payee still needs quorum approval under the money rules — two independent gates.

---

## 5. Per-client vault namespaces (extension)

### 5.1 Model

Vault DB (migration m005, `VaultBase`):

```python
class VaultNamespace(VaultBase):
    __tablename__ = "vault_namespaces"
    id: String(64), pk            # "ns_" + 32 hex (same CSPRNG discipline)
    client_principal_id: String(128), unique, nullable=False  # ontology person principal
    label: String(256), nullable=False                        # "the Chens"
    policy_ref: String(64), nullable                          # optional policy pointer
    created_at: DateTime(tz=True)
```

`VaultEntry.namespace_id: String(64), nullable, index` — NULL = pre-namespace legacy entries; **new entries require a namespace**. Each entry keeps its own random DEK (envelope encryption unchanged): Client A's entries and Client B's entries use different keys — no shared client secret.

### 5.2 Binding and resolution

- `vault/minter.py::VaultTokenMinter.mint(ctx)`: resolves `namespace_id` from **`ctx.mandate.client_principal_id → VaultNamespace`** (one namespace per client principal, unique constraint). The derived token is stamped with `(agent_id, tool, action, namespace_id)`; the adapter validates the stamp. A token minted for Client A cannot be presented for a Client B call.
- The pipeline resolves the namespace in `MandateStage` — **never from agent args** (§1.1: schemas forbid a namespace field; `additionalProperties: false` → `invalid_input`).
- An agent with mandates for two clients gets two separate token paths; each call is evaluated under exactly one mandate. Ambiguity (a call plausibly under two mandates) → the most specific matching mandate wins; residual ambiguity → `require_approval` with the namespace shown on the card.
- `Mandate.client_principal_id` is set at mandate creation (console Mandates page; migration m003 adds the column, backfilled NULL = unscoped).

### 5.3 Namespace-scoped audit + console

- `AuditEntry.namespace_id` (audit DB, migration m006), set from `ctx.namespace_id` in the audit stage — a client's activity is exportable in isolation (§6).
- Console **Vault & Settings → Namespaces** tab: one row per namespace (client label, entry count by connector, rotation status — oldest credential age, any expired — last used, owning mandate refs). Drill-in shows entry **metadata only** (connector, label, created, rotated, status) — never secret values (existing metadata-only rule).
- Actions (POST + CSRF): **rotate namespace** (rotates all entries, audit-logged; derived tokens live out their ≤5-min TTL — graceful expiry, existing M4 semantics), **revoke namespace** (kills all entries and derived tokens; in-flight approved money calls fail at the next mint with `upstream_failure` — fail closed).

---

## 6. Compliance export (extension)

New module `src/gateway/compliance.py`. Builds on the existing export (`GET /audit/export`, FR-033 — the export action itself is audit-logged with the filter used, so the export is reproducible).

### 6.1 Profile

`GET /audit/export?profile=compliance&namespace_id=ns_…&from=…&to=…&format=json|csv`. The Audit page Export panel gains profile select + namespace/date/agent/decision filters + preview row count. Large exports stage to local disk (existing 00 §7 param 19) with a progress row; filenames: `gateway-audit-<profile>-<from>-<to>-<shorthash>.{json,csv,manifest.json}` — the manifest is a separate small JSON file.

### 6.2 Exact field list (all present, none optional)

Per row: `event_id`, `timestamp_utc`, `request_id` (`req_`/`apr_` linkage), `agent_id`, `agent_binding` (credential *type* from `Agent.auth_method` — never the secret), `principal_on_whose_behalf` (client label via namespace), `namespace_id`, `mandate_ref` + `mandate_revision`, `tool`, `action_class`, `args_redacted`, `decision` (+ reason code), `rule_id` + `policy_version`, `data_snapshot_id`, `ontology_snapshot_ref`, `grant_ref` (via `Grant.approval_request_id` join), `approval_request_id` + `approver_admin_ids[]` + `approval_session_ids[]` + `quorum` flag (from `ApprovalRequest.approvals`), `counterparty_key` + `counterparty_verification_state`, `event_verdict` (for intercepted events, via `inbound_events` join), `judge_advisory` (flags only — never the decision basis), `export_proof` (per-row chain hash, §6.3).

Implementation note: the audit table stays narrow. `compliance.py` does **application-side enrichment** (joins in Python across the config/audit DB files — no cross-DB SQL): approval/grant/counterparty/event context is pulled from the config DB by id. Volumes are personal-scale; this avoids bloating the hot audit write path. The one new stored column is `AuditEntry.namespace_id` (first-class filter).

Identity bindings: every human decision chains to `admin_id` + auth method (`password+totp`) + session id + timestamp. Agent actions chain to agent identity + mandate revision. No anonymous rows.

### 6.3 Hash-chained manifest

Application-level chain over the exported row set (ordered by `event_id`):

```
h_0 = sha256("gateway-compliance-chain-v1")
h_i = sha256(h_{i-1} || canonical_json(row_i))   # canonical_json from hmac_util (FR-PAA06-002)
export_proof(row_i) = h_i
```

Manifest: `{profile, filters, row_count, sha256_rows, chain_head: h_n, chain_algorithm: "sha256-canonical-json-v1", exported_by, exported_at, retention_note}`. If the date range exceeds retention (90 days default), the manifest states the actual covered range and archive location — no silent truncation. (NH-1 hash-chained audit *entries* remain a separate nice-to-have; this chain covers the export.)

Exported args are the redacted args, always. There is no "include plaintext" toggle — plaintext is never retained (NFR-DATA-001); the approval evidence subset is the authoritative human-visible record.

---

## 7. Console

All new pages follow the existing `register_*` pattern in `console/pages.py` (server-rendered, no React) and the `CsrfProtector` on every state-changing route (Fix B MF-8, named explicitly for the approval-decision endpoint already; extended to all new POST routes).

| Page / change | Routes (in `create_console_app` / `pages.py`) | Template |
|---|---|---|
| **Policies → Money** (new) | `GET /policies/money`, `POST /policies/money` (`register_money()`) | `money.html` — per-agent/client selectors, limit fields (cents), velocity, quorum + quorum_min, allowlist table (payee key, label, last-4, verification state, verified-by/at), save shows material classification before confirm |
| **Quorum card** (Approvals page) | existing decision endpoint extended with `session_id` | `approvals.html` — quorum header ("Needs 2 of 2 distinct approvers", `1 / 2 approvals`), per-slot admin id / decision time / auth method, frozen-evidence note, delegation chain |
| **Event Inbox** (new) | `GET /events`, `GET /events/{id}`, `POST /events/{id}/release`, `/release-redacted`, `/block-sender` (`register_events()`) | `events.html`, `event_detail.html` — inert raw rendering, findings, counterparty assessment |
| **Mandates checkpoints** | `POST /mandates/{id}/reconfirm` (admin-only); countdown column on existing page | `mandates.html` — "Re-confirmation due in 3 days / 12 money actions", green→amber→red, term-sheet review modal |
| **Vault Namespaces** tab | `GET /vault/namespaces`, `POST /vault/namespaces/{id}/rotate`, `/revoke` | namespaces section — metadata-only rows, rotation status |
| **Audit export** | `GET /audit/export` extended (`profile`, `namespace_id`, `from`, `to`) | `audit.html` — profile select, filters, preview count, staged-download progress |

The Money page save path: build rule dict → `validate_rule_dict` → `validate_quorum_satisfiable` → `opa_check_rules` (money rules are excluded from the OPA input, but the save-time gate still runs over the non-money rules) → `save_version` (material auto-classification) → audit-logged admin action.

---

## 8. Config

New `Settings` fields, all `GATEWAY_*`, following the existing `_env`/`_env_int` patterns in `config.py`. **Everything that changes production paths defaults off.**

| Env var | Default | Effect |
|---|---|---|
| `GATEWAY_MONEY_ENABLED` | `0` | Master switch for the money pack (`MoneyStage`, `payment.*` tools). Off = gateway behaves exactly as before. |
| `GATEWAY_EVENT_INTERCEPTION` | `off` | `off` \| `monitor` \| `enforce` (§4). |
| `GATEWAY_WEBHOOK_NONCE_WINDOW_S` | `600` | Webhook timestamp acceptance window (§4.3). |
| `GATEWAY_MONEY_LEDGER_RETENTION_DAYS` | `90` | Ledger pruning horizon (aligned with audit retention). |
| `GATEWAY_CHECKPOINT_DEFAULT_DAYS` | `14` | Console default for `checkpoint_every_days` on new mandates. |
| `GATEWAY_COMPLIANCE_EXPORT_DIR` | `data/exports` | Staging dir for large compliance exports (param 19). |
| `GATEWAY_MONEY_DRY_RUN` | `0` | Force `dry_run=True` on all `payment.initiate` calls (demo safety). |

Money *thresholds* live in versioned policy rules, not env — they are material-classified, audited, and rollback-able; env vars are the wrong home for them.

---

## 9. Migration

**Decision: hand-rolled versioned migrations, not Alembic.**

Rationale: the codebase has no migration infrastructure today (`Database.create_all()` only); the deploy target is a single stateful process with three SQLite files; Alembic would add a dependency and autogenerate churn for a schema that changes in small, reviewable steps. A `schema_version` table + numbered, idempotent, forward-only migration modules keeps every schema change visible in review — which matters for a security gateway. The Postgres seam is preserved: migrations are written with SQLAlchemy DDL constructs (portable), and `models.py` remains the ORM source of truth. Rollback = restore from the nightly backup (documented); migrations themselves are forward-only.

New package `src/gateway/migrations/`:

```
migrations/__init__.py      # MIGRATIONS registry; migrate(engine) -> applied versions
m001_quorum.py              # MVP: approval_requests += quorum_required, approvals JSON,
                            #   evidence_hash, context_fingerprint, request_type
m002_money.py               # MVP: money_ledger, counterparty_allowlist, money_pair_cooldowns
m003_mandate_temporal.py    # EXT: mandates += valid_from, allowed_windows, max_actions,
                            #   actions_used, checkpoint_*, last_reconfirmed_*, client_principal_id,
                            #   revision, intent_summary
m004_events.py              # EXT: inbound_events, webhook_nonces
m005_vault_namespaces.py    # EXT: vault_namespaces; vault_entries += namespace_id (vault DB)
m006_audit_namespace.py     # EXT: audit_entries += namespace_id (audit DB)
```

- Each module exposes `upgrade(engine)` using `ALTER TABLE … ADD COLUMN` batches (SQLite) inside a transaction; new tables via the ORM metadata. Idempotent: `migrate()` records applied versions in `schema_version` and skips them.
- Applied at process boot by the launcher (MCP server + console + scripts) — single process, no lock contention (NFR-REL-001).
- Tests assert `create_all()` (fresh) and `migrate()` (from an empty/old schema) converge to the same schema — the migration path is tested, not just the fresh path.
- **Material classification of the new fields:** money rule fields live inside `conditions.money`, which `_rule_semantic_signature` already hashes — any limit/quorum/velocity change is automatically material. Counterparty allowlist edits are data (not rules): they bump `record_version` and expire in-flight quorum requests via the context freeze (§2.5) instead of creating policy versions.

---

## 10. Demo scenario: the Chens (MVP slice)

`scripts/seed_finance_demo.py` (idempotent, same pattern as `scripts/seed_demo.py`):

- **Agent** `agent/wealth-1` (platform `muse`, household role `owner`), one credential (Fix A).
- **Mandate** `mnd_chen_wealth`: purpose "portfolio management for the Chens", `purpose_key="wealth-management"`, `allowed_classes=["market.*", "payment.*", "email.read", "gateway.*"]`, `allowed_windows=[Mon–Fri 09:00–17:00 America/New_York]`, `checkpoint_every_days=14`, `client_principal_id` → the Chens' person principal.
- **Namespace** `ns_chen` (vault DB) with sandbox payment credential entries.
- **Money rule** (policy vNext): `per_call_soft_cents=2_500_000` ($25k), `per_call_hard_cents=25_000_000` ($250k), `quorum=2`, `quorum_min_cents=2_500_000`, `per_day_cents=10_000_000` ($100k), velocity 10/hour + 50/day, `max_new_counterparties_per_day=3`, `cooldown_after_deny_minutes=15`.
- **Allowlist**: Schwab brokerage (`verified`, verified 2026-09-30), IRS (`verified`), Chens' joint checking (`verified`) — payee keys are account fingerprints; last-4 only.
- **Second admin**: the seed creates `admin_delegate` in a must-reset-password state and prints setup instructions — quorum needs a person, not a second login for Ken (design open decision 2). No passwords in the seed output or repo.

`scripts/demo_finance.py` runs the four acts against a temp data dir (the demo story in design §7: routine rebalance → quorum payment → spoofed email → checkpoint week) and prints a console-readable transcript. It is the executable version of `tests/test_finance_demo.py` — the scripted test and the demo are the same code path.

Act 3 (spoofed email) in the MVP slice: the MVP demo exercises the money + quorum path; the spoofed-email act runs in `monitor` mode until the event-interception extension lands (the inbox shows what *would* have been quarantined). The demo script flags which acts are MVP vs extension.

---

## 11. Test plan

Conventions: `TMPDIR=/home/hatch/workspace/.tmp-pytest` (this VM: no docker, no GPU, 7 GB RAM, `/tmp` is a 512 MB tmpfs). No secrets in tests (sandbox adapter uses fake keys; HMAC ring uses a test key).

### Unit

- `tests/test_money_amounts.py` — `canonicalize_amount`: int cents accepted; floats, numeric strings, zero/negative, missing currency, `currency != "USD"`, extra `namespace` arg → `invalid_input`. Amount formatting (cents → `$48,000.00`) never uses floats.
- `tests/test_money_limits.py` — threshold ladder per §1.5 step 6: under-soft allow; ≥soft → `require_approval`; ≥hard → `amount_over_hard_ceiling`; daily/monthly breach → `spend_cap_exceeded`; velocity breach (per-payee and per-agent) → `velocity_limit_exceeded`; blocked payee → `counterparty_blocked`; unlisted payee → always `require_approval` ("new counterparty" flag). Split-payment: 11 × $1k to the same payee trips hourly velocity.
- `tests/test_quorum.py` — state machine: `pending → partially_approved → approved`; `record_denial` one-denial-kills from `partially_approved`; `duplicate_approver` rejected; same `session_id` rejected; `validate_quorum_satisfiable` fails on single-admin install; `context_changed` expiry on mandate pause / material policy change / allowlist `record_version` bump; grant minted only at `approved`; terminal states immutable.
- `tests/test_grant_hmac_binding.py` — post-approval re-invoke with altered amount/payee → `grant_argument_mismatch` (no new approval request, no execution).
- `tests/test_mandate_windows.py` (ext) — window math incl. overnight windows and tz handling (reuse `time_window_matches` semantics); `mandate_window_closed` with `retry_after` hint; `mandate_budget_exhausted`; `mandate_checkpoint_overdue` fail-closed; re-confirm resets countdown; re-confirm cannot widen scope.
- `tests/test_drift.py` (ext) — each signal (`new_tool_class`, `amount_spike` ≥10× median, `new_payee`, `off_window`) forces `require_approval` without denying; "accept as new normal" creates a new revision.
- `tests/test_webhook_hmac.py` (ext) — bad HMAC → deny; replayed nonce → deny; stale timestamp → deny.
- `tests/test_vault_namespaces.py` (ext) — mint binds `(agent, tool, action, namespace)`; cross-namespace presentation rejected; revoke kills future mints; metadata-only console view contains no secret material.

### Integration

- `tests/test_money_pipeline.py` — full pipeline per Fix-B order: limit breach → `policy_denied` (no approval request created, no notification); quorum flow `1/2 → 2/2 → execute` with receipt; ledger row written post-execute; `payment.status` gated; timeout → `unknown_outcome` block → console resolve → retry.
- `tests/test_event_interception.py` (ext) — spoofed "wire instructions changed" email (no DKIM, reply-to mismatch, urgency flags, unknown payee) → `quarantine`; agent receives only the stub (assert no sender text/links/amounts leak); `monitor` mode delivers with "would quarantine" logged; release requires the approval flow (`event_release` request type).
- `tests/test_compliance_export.py` (ext) — exact field list present on every row; manifest `sha256_rows` verifies; chain head recomputes; export audit-logged with filter; namespace filter isolates one client's rows.

### Scripted demo test

- `tests/test_finance_demo.py` — runs `scripts/demo_finance.py` end-to-end against temp DBs: asserts all four acts produce the expected decisions, audit rows link (`req_`/`apr_`/`pay_`), and both approver identities appear in the compliance export. This is the MVP acceptance artifact.

### AC-11 (p95 ≤ 100 ms) implications

- `MoneyStage` adds three indexed aggregate queries + allowlist lookup: record a `money` timing span; budget it inside the existing policy-path envelope. The ledger table stays small via retention pruning (§8).
- `DriftStage` (ext) is O(1) over the precomputed `intent_summary` JSON — no per-call history scan.
- Event interception (ext) is intake-time with verdict caching — off the tool-call hot path.
- Quorum decisions are console-side (human latency dominates); grant consumption adds one indexed lookup, same as today.
- The CI gate (`scripts/ac11_load.py`) gains `payment.initiate` cases at the soft-threshold boundary so the money path is measured, not assumed.

---

## 12. Hard-constraint compliance checklist

- **Fix A (auth wall):** untouched. Agent identity still flows from the Fix-A credential; `agent_binding` in the export names the credential *type* only.
- **Fix B:** validate-first ordering preserved (`MoneyStage` runs after `ValidateInputsStage`; amount-schema failure → `invalid_input`, never an approval). MF-7 grant semantics unchanged and extended (quorum grants mint only at full approval; grant consumption re-checks mandate liveness **and** checkpoint state). MF-8 CSRF on all new state-changing console routes. MF-9 caps: money approval requests count toward the existing per-agent pending cap; `money_pair_cooldowns` adds the (agent, payee) refusal cooldown.
- **Rego/JSON decision contract:** money rules are JSON, evaluated by the single Python authority (`MoneyStage`); they are filtered from the OPA input document so the sidecar never double-evaluates them. The `spending_thresholds` preset is untouched and remains the backstop.
- **Fail-closed everywhere:** every new check denies on error/ambiguity (schema fail, sidecar of money state, stale quorum context, overdue checkpoint, unauthenticated event, HMAC failure). `GATEWAY_MONEY_ENABLED=0` and `GATEWAY_EVENT_INTERCEPTION=off` defaults mean new production paths are inert until configured.
- **Judge advisory-only:** `judge_risk`/`judge_signals` ride the approval card as annotations (existing pattern); no money, quorum, event, or drift *decision* reads the judge.
- **No secrets in repo/tests:** sandbox adapter keys are fake; webhook secrets live in the vault; seed scripts never print secrets; HMAC test keys are test-only.
- **No weights.** **Stealth wording** per §0.

---

## 13. Deferred / needs Ken's decision

1. **Real custodian choice and timeline** (design open decision 1) — which sandbox first; whether a production ACH target exists at all in 2026. No production adapter ships in this pillar either way.
2. **Second admin identity** (design open decision 2) — quorum needs a person. The seed creates the account in must-reset state; Ken designates the human.
3. **Threshold numbers** (design open decision 3) — $25k quorum / $250k hard ceiling / $100k daily are demo defaults in the seed, not product decisions.
4. **Event interception default** (design open decision 4) — architecture ships `off`, supports `monitor`/`enforce`. Ken decides the rollout.
5. **Checkpoint cadence default** (design open decision 5) — 14 days is the demo/seed default (`GATEWAY_CHECKPOINT_DEFAULT_DAYS`).
6. **Money-in-Rego (deferred):** if a future phase wants `conditions.money` evaluated inside the OPA sidecar, `MoneyState` (§1.4) is the input-doc contract (`input.money_state`). Not pursued now — the stateless-sidecar rationale (§1.4) stands.
7. **Mandate versioning model (architect's call, flagged):** this doc uses a `revision` counter bumped on lifecycle events, cited in the export as `mandate_revision`. A full immutable mandate-version table (mirroring `PolicyVersion`) is the heavier alternative — recommended only if regulators ask for point-in-time mandate reconstruction.
8. **`payment.quote` before `payment.initiate` (not required):** the architecture does not require a quote before initiate; Ken may later want a rule (`conditions.money.require_quote`) — noted as a possible rule extension, not built.
