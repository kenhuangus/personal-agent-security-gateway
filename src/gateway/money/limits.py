"""Money rule schema + threshold ladder (Pillar 1 §1.3/§1.5).

Money rules are ordinary ``PolicyRule`` rows whose ``conditions``
carry a ``money`` block. ``money/limits.py`` owns the block's
structural validation (``validate_money_block``); the block lives
inside the rule dict that ``_rule_semantic_signature`` hashes, so ANY
money-field change is automatically ``material_change=True`` on save.

``evaluate`` implements the fixed evaluation order (hard stops before
soft):

a. amount >= per_call_hard_cents → policy_denied / amount_over_hard_ceiling
b. payee blocked → policy_denied / counterparty_blocked
c. per_day / per_month breach → policy_denied / spend_cap_exceeded
d. velocity breach → policy_denied / velocity_limit_exceeded
e. amount >= per_call_soft_cents OR payee unlisted → require_approval
   (quorum set from the rule; new-counterparty flag on the card)
f. else → allow (the policy stage is skipped for this call)

All safe-vocabulary reasons name the CLASS, never amounts, payees, or
windows. The approval card shows remaining budget from the evidence
(never the reason string).
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Any, Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import (
    ApprovalRequest,
    Grant,
    MoneyPairCooldown,
    PolicyRule,
    as_utc,
    utcnow,
)
from ..policy import rule_matches
from .allowlist import (
    STATE_BLOCKED,
    STATE_PENDING,
    STATE_VERIFIED,
    AllowlistService,
    canonicalize_payee_key,
)
from .amounts import format_cents
from .state import MoneyState, MoneyStateBuilder

#: The canonical money-block fields and their types. Unknown keys are
#: rejected (FR-PAA04-002); the block is otherwise structural.
_MONEY_FIELDS: dict[str, type | tuple[type, ...]] = {
    "per_call_soft_cents": int,
    "per_call_hard_cents": int,
    "per_day_cents": (int, type(None)),
    "per_month_cents": (int, type(None)),
    "max_payments_per_window": dict,
    "max_payments_per_day": (int, type(None)),
    "max_new_counterparties_per_day": (int, type(None)),
    "cooldown_after_deny_minutes": (int, type(None)),
    "quorum": (int, type(None)),
    "quorum_min_cents": (int, type(None)),
}

_MONEY_DEFAULTS: dict[str, Any] = {
    "per_call_soft_cents": 2_500_000,     # $25k
    "per_call_hard_cents": 25_000_000,    # $250k
    "per_day_cents": 10_000_000,          # $100k
    "per_month_cents": None,
    "max_payments_per_window": {"n": 10, "window_minutes": 60},
    "max_payments_per_day": 50,
    "max_new_counterparties_per_day": 3,
    "cooldown_after_deny_minutes": 15,
    "quorum": 2,
    "quorum_min_cents": 2_500_000,        # $25k
}


def validate_money_block(block: Any) -> dict[str, Any]:
    """Structural validation of ``conditions.money`` (raise on bad input).

    Returns the block with defaults filled. Rejects unknown keys,
    wrong types, non-positive thresholds, and hard < soft.
    """
    if not isinstance(block, dict):
        raise ValueError("conditions.money must be an object")
    unknown = set(block) - set(_MONEY_FIELDS)
    if unknown:
        raise ValueError(
            f"conditions.money: unknown keys {sorted(unknown)!r}"
        )
    out = dict(_MONEY_DEFAULTS)
    out.update({k: v for k, v in block.items() if v is not None})
    for key, value in out.items():
        want = _MONEY_FIELDS[key]
        if not isinstance(value, want):
            raise ValueError(
                f"conditions.money.{key} must be {getattr(want, '__name__', want)}"
            )
    for key in (
        "per_call_soft_cents", "per_call_hard_cents",
        "quorum_min_cents",
    ):
        if out[key] <= 0:
            raise ValueError(f"conditions.money.{key} must be positive")
    if out["per_call_hard_cents"] < out["per_call_soft_cents"]:
        raise ValueError(
            "conditions.money.per_call_hard_cents must be >= per_call_soft_cents"
        )
    window = out["max_payments_per_window"]
    if not isinstance(window.get("n"), int) or window["n"] <= 0:
        raise ValueError("conditions.money.max_payments_per_window.n must be a positive int")
    if not isinstance(window.get("window_minutes"), int) or window["window_minutes"] <= 0:
        raise ValueError(
            "conditions.money.max_payments_per_window.window_minutes must be a positive int"
        )
    quorum = out.get("quorum")
    if quorum is not None and quorum < 1:
        raise ValueError("conditions.money.quorum must be >= 1")
    return out


def find_money_rule(
    db: Session,
    agent: Any,
    tool: str,
    args: dict[str, Any],
    purpose: Optional[str],
    policy_version: Optional[int] = None,
    now: Optional[dt.datetime] = None,
) -> Optional[tuple[PolicyRule, dict[str, Any]]]:
    """First matching money rule (rule_order) + its validated block.

    None when no rule with ``conditions.money`` matches — the normal
    policy stage then runs and the shipped ``spending_thresholds``
    preset (``payment.*`` → ``require_approval``) is the backstop.
    """
    from ..policy import PolicyEngine  # local: keep import arrow one-way

    engine = PolicyEngine(db)
    row = engine._version_row(policy_version)
    if row is None:
        return None
    now = now or utcnow()
    rules = (
        db.execute(
            select(PolicyRule)
            .where(PolicyRule.policy_version_id == row.id)
            .order_by(PolicyRule.rule_order, PolicyRule.id)
        )
        .scalars()
        .all()
    )
    for rule in rules:
        conditions = rule.conditions or {}
        if "money" not in conditions:
            continue
        if not rule_matches(rule, agent, tool, args, purpose, now):
            continue
        try:
            block = validate_money_block(conditions["money"])
        except ValueError:
            continue  # fail closed: a bad block never matches silently
        return rule, block
    return None


@dataclass(frozen=True)
class MoneyDecision:
    """Outcome of the threshold ladder."""

    decision: str  # "allow" | "deny" | "require_approval"
    reason: Optional[str]  # safe-vocabulary reason on deny
    state: MoneyState
    block: dict[str, Any]
    quorum_required: int
    new_counterparty: bool
    # Card evidence (never the reason string): remaining budgets and
    # velocity usage, rendered from integer cents.
    card: dict[str, Any]


def _card_evidence(
    amount_cents: int,
    block: dict[str, Any],
    state: MoneyState,
    payee_key: str,
    allowlist_row: Any,
) -> dict[str, Any]:
    per_day = block.get("per_day_cents")
    per_month = block.get("per_month_cents")
    window = block["max_payments_per_window"]
    card: dict[str, Any] = {
        "amount": format_cents(amount_cents),
        "payee_key": payee_key,
        # Remaining budget nets out executed spend, committed
        # reservations (live grants), and this call — approvers see
        # the true headroom (HOLD fix #2).
        "remaining_daily": (
            format_cents(
                max(
                    0,
                    per_day
                    - state.spent_today_cents
                    - state.committed_cents
                    - amount_cents,
                )
            )
            if per_day is not None
            else None
        ),
        "remaining_monthly": (
            format_cents(
                max(
                    0,
                    per_month
                    - state.spent_month_cents
                    - state.committed_cents
                    - amount_cents,
                )
            )
            if per_month is not None
            else None
        ),
        "velocity_used": (
            f"{state.payments_last_hour} of {window['n']} "
            f"{window['window_minutes']}-minute payments used"
        ),
        "payments_today": state.payments_today,
        "payee_payments_last_hour": state.payee_payments_last_hour,
    }
    card["counterparty"] = AllowlistService.as_of(allowlist_row)
    return card


def evaluate(
    *,
    db: Session,
    agent: Any,
    tool: str,
    args: dict[str, Any],
    amount_cents: int,
    payee_key: str,
    rule: PolicyRule,
    block: dict[str, Any],
    now: Optional[dt.datetime] = None,
    namespace_id: Optional[str] = None,
    include_committed: bool = True,
) -> MoneyDecision:
    """Run the fixed threshold ladder (§1.5 step 6).

    ``include_committed``: count live (approved, unconsumed) money
    grants as budget reservations. True at approval-request time (the
    card's remaining budget and the ladder both see committed money);
    False for historical dry-run evaluation.
    """
    now = now or utcnow()
    allowlist = AllowlistService(db)
    allowlist_row = allowlist.lookup(namespace_id, payee_key)
    state = MoneyStateBuilder(db).build(
        agent.id, namespace_id, payee_key, now,
        allowlisted_keys=allowlist.keys(namespace_id),
        include_committed=include_committed,
    )

    def decide(decision: str, reason: Optional[str], new_cp: bool) -> MoneyDecision:
        quorum_required = 1
        if decision == "require_approval":
            quorum_min = block.get("quorum_min_cents")
            quorum = block.get("quorum") or 1
            if quorum_min is not None and amount_cents >= quorum_min:
                quorum_required = quorum
        return MoneyDecision(
            decision=decision,
            reason=reason,
            state=state,
            block=block,
            quorum_required=quorum_required,
            new_counterparty=new_cp,
            card=_card_evidence(amount_cents, block, state, payee_key, allowlist_row),
        )

    # (a) hard ceiling first (fail closed on size before identity).
    if amount_cents >= block["per_call_hard_cents"]:
        return decide("deny", "amount_over_hard_ceiling", state.is_new_counterparty)
    # (b) blocked payee.
    if allowlist_row is not None and allowlist_row.verification_state == STATE_BLOCKED:
        return decide("deny", "counterparty_blocked", False)
    # (c) rolling spend caps (executed + committed reservations +
    # this call — concurrent approvals cannot overshoot the cap).
    per_day = block.get("per_day_cents")
    if (
        per_day is not None
        and state.spent_today_cents + state.committed_cents + amount_cents > per_day
    ):
        return decide("deny", "spend_cap_exceeded", state.is_new_counterparty)
    per_month = block.get("per_month_cents")
    if (
        per_month is not None
        and state.spent_month_cents + state.committed_cents + amount_cents > per_month
    ):
        return decide("deny", "spend_cap_exceeded", state.is_new_counterparty)
    # (d) velocity hard-stops: per-agent window and per-payee window
    # independently (split-payment evasion), plus per-day and the
    # new-counterparty budget.
    window = block["max_payments_per_window"]
    if state.payments_last_hour >= window["n"]:
        return decide("deny", "velocity_limit_exceeded", state.is_new_counterparty)
    if state.payee_payments_last_hour >= window["n"]:
        return decide("deny", "velocity_limit_exceeded", state.is_new_counterparty)
    max_per_day = block.get("max_payments_per_day")
    if max_per_day is not None and state.payments_today >= max_per_day:
        return decide("deny", "velocity_limit_exceeded", state.is_new_counterparty)
    max_new = block.get("max_new_counterparties_per_day")
    if (
        max_new is not None
        and state.is_new_counterparty
        and state.new_counterparties_today >= max_new
    ):
        return decide("deny", "velocity_limit_exceeded", True)
    # (e) step-up: at/above the soft line, or an unlisted/pending payee.
    verified = (
        allowlist_row is not None
        and allowlist_row.verification_state == STATE_VERIFIED
    )
    if amount_cents >= block["per_call_soft_cents"] or not verified:
        return decide("require_approval", None, state.is_new_counterparty)
    # (f) allow.
    return decide("allow", None, False)


# ---------------------------------------------------------------------
# Money dry-run (Pillar 1 §9): evaluate the threshold ladder for a
# hypothetical payment call as-of a historical timestamp against the
# historical money ledger. Used by ``policy.dry_run`` for payment.*
# rows and the synthetic corpus. Redacted audit args are the
# acknowledged approximation (audit never holds plaintext).
# ---------------------------------------------------------------------

MONEY_DRY_RUN_TOOLS: frozenset[str] = frozenset(
    {"payment.initiate", "payment.cancel"}
)


def dry_run_decision(
    *,
    db: Session,
    agent: Any,
    tool: str,
    args: dict[str, Any],
    purpose: Optional[str],
    policy_version: int,
    as_of: dt.datetime,
) -> str:
    """Return the ladder's would-be decision ("allow" | "deny" |
    "require_approval") for a payment call as-of *as_of*."""
    if tool == "payment.cancel":
        # Matches MoneyStage: cancel always asks, amount thresholds
        # never apply.
        return "require_approval"
    amount_cents = args.get("amount_cents")
    payee_key = canonicalize_payee_key(str(args.get("payee_key") or ""))
    found = find_money_rule(
        db, agent, tool, args, purpose, policy_version=policy_version
    )
    if found is None or not isinstance(amount_cents, int) or amount_cents <= 0:
        # No money rule → the shipped spending_thresholds preset
        # (payment.* → require_approval) is the backstop; unusable
        # args → the safest answer.
        return "require_approval"
    rule, block = found
    decision = evaluate(
        db=db, agent=agent, tool=tool, args=args,
        amount_cents=amount_cents, payee_key=payee_key,
        rule=rule, block=block, now=as_of,
        # Historical evaluation: live grants *now* are irrelevant
        # as-of *as_of*.
        include_committed=False,
    )
    return decision.decision


# ---------------------------------------------------------------------
# Grant-mismatch guard (§1.2): amount tampering between approval and
# execution. Runs for payment.* on re-invoke (post-approval loop):
# a grant exists for (agent_id, tool) that is approved, unconsumed,
# unexpired, but the argument hash does not match → tamper-shaped →
# deny with the terminal code grant_argument_mismatch (no new
# approval request, no execution).
# ---------------------------------------------------------------------

def detect_grant_mismatch(
    db: Session,
    agent_id: str,
    tool: str,
    argument_hash: str,
    now: Optional[dt.datetime] = None,
) -> bool:
    """True when an unconsumed, unexpired grant exists for
    (agent_id, tool) with a DIFFERENT argument hash.

    A matching hash means this call is the approved one — the grant
    checker at the policy stage consumes it. No grant at all means the
    call is pre-approval (the ladder runs). Only a mismatched grant
    is tamper-shaped.
    """
    now = now or utcnow()
    rows = (
        db.execute(
            select(Grant).where(
                Grant.agent_id == agent_id,
                Grant.tool == tool,
                Grant.consumed.is_(False),
                Grant.invalidated.is_(False),
                Grant.expires_at > now,
            )
        )
        .scalars()
        .all()
    )
    for grant in rows:
        if grant.argument_hash != argument_hash:
            return True
    return False


def has_live_grant(
    db: Session,
    agent_id: str,
    tool: str,
    argument_hash: str,
    now: Optional[dt.datetime] = None,
) -> bool:
    """True when an unconsumed, unexpired, non-invalidated grant exists
    for (agent_id, tool) with exactly this argument hash — i.e. this
    call is the approved re-invoke. The grant checker (grant-before-
    rule) owns consumption; the money ladder must not re-decide."""
    now = now or utcnow()
    row = (
        db.execute(
            select(Grant).where(
                Grant.agent_id == agent_id,
                Grant.tool == tool,
                Grant.argument_hash == argument_hash,
                Grant.consumed.is_(False),
                Grant.invalidated.is_(False),
                Grant.expires_at > now,
            )
        )
        .scalars()
        .first()
    )
    return row is not None


# ---------------------------------------------------------------------
# Grant-consumption re-verification (HOLD fixes #2 and #3).
#
# The ladder decides on a ledger snapshot at approval-request time.
# Between approval and execution two things can invalidate it:
# concurrent approvals each passing against a stale snapshot (#2),
# and operator allowlist changes (block / verification / removal)
# after approval (#3). The grant checker calls
# ``reverify_money_grant`` at consumption — after the mandate and
# policy-supersession checks, before the atomic consume — and denies
# fail-closed when the world moved.
#
# Only the hard DENY conditions are re-checked (spend caps, blocked
# payee, allowlist staleness). Step-up conditions (unlisted payee,
# soft threshold) are NOT re-decided: the grant already carries its
# approval, and re-stepping-up at consumption would deny legitimate
# approved calls.
# ---------------------------------------------------------------------

#: Money tools re-verified at grant consumption. Only payment.initiate
#: carries an amount (payment.cancel reverses and has no thresholds).
REVERIFY_GRANT_TOOLS: frozenset[str] = frozenset({"payment.initiate"})


def reverify_money_grant(
    db: Session,
    grant: Grant,
    now: Optional[dt.datetime] = None,
) -> Optional[str]:
    """Re-verify a money grant at consumption. Returns a deny reason,
    or None when the grant may execute."""
    if grant.tool not in REVERIFY_GRANT_TOOLS:
        return None
    now = now or utcnow()

    apr = db.get(ApprovalRequest, grant.approval_request_id)
    if apr is None:
        return "grant_approval_missing"
    redacted = apr.redacted_args or {}
    amount_cents = redacted.get("amount_cents")
    payee_key = canonicalize_payee_key(str(redacted.get("payee_key") or ""))
    if (
        not isinstance(amount_cents, int)
        or isinstance(amount_cents, bool)
        or amount_cents <= 0
        or not payee_key
    ):
        # Cannot establish what the grant authorizes — fail closed.
        return "grant_args_unverifiable"

    # Current block: the rule may have tightened since approval. The
    # evidence pins the rule id; a deleted rule fails closed.
    rule_id = (apr.evidence_subset or {}).get("money_rule_id")
    rule = db.get(PolicyRule, rule_id) if rule_id is not None else None
    block = None
    if (
        rule is not None
        and isinstance(rule.conditions, dict)
        and "money" in rule.conditions
    ):
        try:
            block = validate_money_block(rule.conditions["money"])
        except ValueError:
            block = None
    if block is None:
        return "money_rule_unverifiable"

    # (fix #3) allowlist state since approval. The fingerprint carries
    # the payee's record_version at approval time (None when unlisted).
    fingerprint = apr.context_fingerprint or {}
    row = AllowlistService(db).lookup(None, payee_key)
    fingerprinted_version = fingerprint.get("counterparty_record_version")
    if row is None:
        if fingerprinted_version is not None:
            # Listed at approval, removed since → stale context.
            return "money_context_changed"
    else:
        if row.verification_state == STATE_BLOCKED:
            return "counterparty_blocked"
        if (
            fingerprinted_version is not None
            and row.record_version != fingerprinted_version
        ):
            return "money_context_changed"

    # (fix #2) spend caps against the fresh ledger plus other live
    # reservations (excluding this grant — it is still live and would
    # otherwise double-count its own amount).
    state = MoneyStateBuilder(db).build(
        grant.agent_id,
        None,
        payee_key,
        now,
        exclude_committed_request_id=grant.approval_request_id,
    )
    per_day = block.get("per_day_cents")
    if (
        per_day is not None
        and state.spent_today_cents + state.committed_cents + amount_cents > per_day
    ):
        return "spend_cap_exceeded"
    per_month = block.get("per_month_cents")
    if (
        per_month is not None
        and state.spent_month_cents + state.committed_cents + amount_cents > per_month
    ):
        return "spend_cap_exceeded"
    return None


# ---------------------------------------------------------------------
# (agent, payee) denial cooldowns (§1.3).
# ---------------------------------------------------------------------

def pair_cooldown_active(
    db: Session, agent_id: str, payee_key: str, now: Optional[dt.datetime] = None
) -> bool:
    now = now or utcnow()
    row = db.execute(
        select(MoneyPairCooldown).where(
            MoneyPairCooldown.agent_id == agent_id,
            MoneyPairCooldown.counterparty_key == payee_key,
        )
    ).scalars().first()
    return row is not None and (as_utc(row.expires_at) or row.expires_at) > now


def record_pair_cooldown(
    db: Session,
    agent_id: str,
    payee_key: str,
    minutes: int,
    now: Optional[dt.datetime] = None,
) -> None:
    """(Re)start the (agent, payee) cooldown after a deny."""
    now = now or utcnow()
    expires_at = now + dt.timedelta(minutes=minutes)
    row = db.execute(
        select(MoneyPairCooldown).where(
            MoneyPairCooldown.agent_id == agent_id,
            MoneyPairCooldown.counterparty_key == payee_key,
        )
    ).scalars().first()
    if row is not None:
        row.expires_at = expires_at
    else:
        db.add(
            MoneyPairCooldown(
                agent_id=agent_id,
                counterparty_key=payee_key,
                expires_at=expires_at,
            )
        )
    db.commit()
