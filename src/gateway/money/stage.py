"""Money pipeline stage (Pillar 1 §1.5): step 3.5.

Wired between ``MandateStage`` (3) and ``PolicyStage`` (4) in
``build_pipeline``. Fix-B order is preserved; the money check is a
policy specialization that needs mandate liveness first (a dead
mandate must deny before any spend math).

``MoneyStage.run(ctx)``:
1. Non-``payment.*`` tool → pass through (non-money tools untouched).
2. ``GATEWAY_MONEY_ENABLED=0`` → pass through (money pack default-off;
   falls through to the existing policy stage and the
   ``spending_thresholds`` preset).
3. Amount is canonicalized (MF-4 ordering: schema failure →
   ``invalid_input``, no approval created). The schema enforces the
   shape; ``canonicalize_amount`` is the defense-in-depth second check.
4. Grant-mismatch guard (§1.2) on re-invoke: a live grant for
   (agent, tool) with a different argument hash → deny
   ``grant_argument_mismatch`` (tamper-shaped; no new approval, no
   execution). A live grant with a MATCHING hash → pass through so the
   policy stage's grant checker consumes it (grant-before-rule).
5. First matching money rule (rule_order, tool selector matches
   ``payment.*``, ``conditions.money`` present). No money rule →
   pass through → the normal policy stage → the shipped
   ``spending_thresholds`` preset (``payment.*`` → ``require_approval``)
   is the backstop.
6. Threshold ladder (``limits.evaluate``) in fixed order: hard stops
   before soft; the approval card shows remaining budget from the
   evidence, never the reason string.
7. ``payment.cancel`` bypasses amount thresholds: always
   ``require_approval`` (single approver).

The stage records a ``money`` timing span (AC-11: three indexed
aggregate queries + allowlist lookup, budgeted inside the existing
policy-path envelope).
"""

from __future__ import annotations

from typing import Any, Optional

from sqlalchemy.orm import Session

from ..config import Settings
from ..errors import GatewayError, invalid_input, make_error, policy_denied
from ..pipeline import timing_span
from .amounts import AmountError, canonicalize_amount
from .limits import (
    detect_grant_mismatch,
    has_live_grant,
    evaluate,
    find_money_rule,
    pair_cooldown_active,
    record_pair_cooldown,
)

#: The money-pack tool family.
MONEY_TOOLS: frozenset[str] = frozenset(
    {"payment.quote", "payment.initiate", "payment.status", "payment.cancel"}
)


class MoneyStage:
    """Step 3.5: money-movement policy evaluation (Pillar 1)."""

    name = "money"

    def __init__(self, db: Session, settings: Settings) -> None:
        self.db = db
        self.settings = settings

    def run(self, ctx: Any) -> Optional[GatewayError]:
        if ctx.tool not in MONEY_TOOLS:
            return None
        if not self.settings.money_enabled:
            return None
        with timing_span(ctx, "money"):
            return self._run(ctx)

    def _run(self, ctx: Any) -> Optional[GatewayError]:
        # payment.quote / payment.status: policy-gated reads; the
        # normal policy stage handles them (the spending preset's
        # blanket ask is the backstop when no money rule matches).
        if ctx.tool in ("payment.quote", "payment.status"):
            return None

        # payment.cancel: always require_approval (single approver);
        # amount thresholds do not apply. The amount is resolved from
        # the referenced receipt at card-render time.
        if ctx.tool == "payment.cancel":
            found = find_money_rule(
                self.db, ctx.agent, ctx.tool, ctx.args,
                getattr(ctx.mandate, "purpose_key", None) if ctx.mandate else None,
            )
            ctx.needs_approval = True
            ctx.quorum_required = 1
            ctx.money_state = None
            ctx.money_rule_id = found[0].id if found else None
            ctx.money_new_counterparty = False
            ctx.policy_short_circuited = True
            return None

        # payment.initiate from here.
        try:
            amount_cents = canonicalize_amount(ctx.args)
        except AmountError as exc:
            # MF-4 ordering: schema failure → invalid_input, no
            # approval created. (ValidateInputsStage already enforced
            # the shape; this is the second check.)
            return invalid_input(ctx.request_id, "amount_cents", tool=ctx.tool)
        payee_key = str(ctx.args.get("payee_key") or "")

        # Grant-mismatch guard (§1.2): post-approval re-invoke with a
        # different amount/payee misses the grant's argument HMAC →
        # tamper-shaped. A live grant with a MATCHING hash means this
        # call is the approved re-invoke: the ladder does NOT re-decide
        # and the policy stage is NOT short-circuited, so the grant
        # checker (grant-before-rule) consumes the grant.
        if ctx.argument_hash is not None:
            if detect_grant_mismatch(
                self.db, ctx.agent_id, ctx.tool, ctx.argument_hash
            ):
                return make_error(
                    "grant_argument_mismatch",
                    f"{ctx.tool}: re-invoked arguments do not match the approved "
                    "grant (amount or payee changed); start a new approval request",
                    ctx.request_id,
                    {"tool": ctx.tool, "reason": "grant_argument_mismatch"},
                )
            if has_live_grant(self.db, ctx.agent_id, ctx.tool, ctx.argument_hash):
                return None

        found = find_money_rule(
            self.db, ctx.agent, ctx.tool, ctx.args,
            getattr(ctx.mandate, "purpose_key", None) if ctx.mandate else None,
        )
        if found is None:
            # No money rule → the normal policy stage runs → the
            # shipped spending_thresholds preset is the backstop.
            return None
        rule, block = found

        # (agent, payee) denial cooldown: after a deny on the pair, no
        # new approval request until expiry.
        if pair_cooldown_active(self.db, ctx.agent_id, payee_key):
            return make_error(
                "cooldown_active",
                f"{ctx.tool}: cooldown active for this agent and payee",
                ctx.request_id,
                {"tool": ctx.tool, "reason": "cooldown_active"},
            )

        decision = evaluate(
            db=self.db,
            agent=ctx.agent,
            tool=ctx.tool,
            args=ctx.args,
            amount_cents=amount_cents,
            payee_key=payee_key,
            rule=rule,
            block=block,
        )

        if decision.decision == "deny":
            # The pair cooldown starts on every money deny (§1.3).
            cooldown_minutes = block.get("cooldown_after_deny_minutes")
            if cooldown_minutes:
                record_pair_cooldown(
                    self.db, ctx.agent_id, payee_key, cooldown_minutes
                )
            assert decision.reason is not None  # safe-vocabulary, always set on deny
            return policy_denied(
                ctx.request_id, decision.reason,
                f"{ctx.tool}: denied by money policy ({decision.reason})",
                tool=ctx.tool,
            )
        if decision.decision == "require_approval":
            ctx.needs_approval = True
            ctx.quorum_required = decision.quorum_required
            ctx.money_state = decision.state
            ctx.money_rule_id = rule.id
            ctx.money_card = decision.card
            ctx.money_new_counterparty = decision.new_counterparty
            ctx.money_block = block
            # The money stage is the single authority for this call;
            # the normal policy stage must not re-evaluate it.
            ctx.policy_short_circuited = True
            return None
        # allow: same short-circuit shape as the grant path (MF-7).
        ctx.policy_short_circuited = True
        ctx.scope_rule = f"money_rule:{rule.id}"
        ctx.money_state = decision.state
        ctx.money_rule_id = rule.id
        return None


def build_money_stage(
    db: Session, settings: Settings
) -> Optional[MoneyStage]:
    """Build the MoneyStage when the money pack is enabled, else None."""
    if not settings.money_enabled:
        return None
    return MoneyStage(db, settings)
