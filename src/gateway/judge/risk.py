"""Intent risk scoring (judge advisory; allow→ask ONLY).

``score_intent_risk`` asks the judge to rate a normalized
:class:`gateway.intent.Intent`. The policy stage consults the result
through ``build_risk_scorer`` AFTER the Rego/policy decision: a
"high" rating on an ALLOWED call sets ``ctx.needs_approval`` (step-up
to the approval flow). It can never turn a deny into an allow, never
clears an existing ask, and never runs in front of policy evaluation.

The judge sees REDACTED SHAPES only — never raw secrets. Parameter
values are replaced by type/length shapes; secret-like values become
a fixed token. The state string is capped at ~2000 chars.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Optional

from ..intent import Intent
from .cascade import JudgeCascade
from .client import JudgeUnavailable, Question

#: Max chars of the intent state string sent to the judge.
INTENT_STATE_CHAR_CAP = 2000

RISK_LEVELS: tuple[str, ...] = ("low", "medium", "high")

#: Score weights for the expected-risk computation (low=0, medium=0.5, high=1).
_LEVEL_WEIGHTS: dict[str, float] = {"low": 0.0, "medium": 0.5, "high": 1.0}

# Keys whose values are never sent to the judge in any form.
_SECRET_KEY_RE = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|otp|pin|ssn|card|cvv|private)"
)
# Secret-like VALUES (verification codes, long base64-ish tokens).
_SECRET_VALUE_RE = re.compile(r"(?:\b[0-9]{4,8}\b|[A-Za-z0-9+/]{32,}={0,2})")


def _shape_value(value: Any, depth: int = 0) -> Any:
    """Replace a param value with its redacted shape (never raw secrets)."""
    if isinstance(value, str):
        if _SECRET_VALUE_RE.search(value):
            return "[redacted:secret-like]"
        if len(value) > 64:
            return f"<str {len(value)} chars>"
        return value
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, (list, tuple)):
        return f"<list of {len(value)}>"
    if isinstance(value, dict):
        if depth >= 2:
            return f"<dict of {len(value)}>"
        return {
            str(k): (
                "[redacted:secret-like]"
                if _SECRET_KEY_RE.search(str(k))
                else _shape_value(v, depth + 1)
            )
            for k, v in value.items()
        }
    return f"<{type(value).__name__}>"


def intent_state(intent: Intent) -> str:
    """Compact judge state for an intent: redacted shapes, ~2000 chars max."""
    shaped = {
        str(k): (
            "[redacted:secret-like]"
            if _SECRET_KEY_RE.search(str(k))
            else _shape_value(v)
        )
        for k, v in (intent.params or {}).items()
    }
    lines = [
        f"agent={intent.agent_id}",
        f"action={intent.action}",
        f"resource_type={intent.resource_type or '-'}",
        f"resource_id={intent.resource_id or '-'}",
        f"purpose={intent.purpose or 'undeclared'}",
        f"params={shaped}",
    ]
    return "\n".join(lines)[:INTENT_STATE_CHAR_CAP]


@dataclass(frozen=True)
class RiskScore:
    """The judge's risk rating for one intent."""

    score: float  # 0..1 (expected risk over the level distribution)
    level: str  # "low" | "medium" | "high"
    summary: str
    escalated: bool


def risk_question() -> Question:
    """The score question the judge answers about an intent."""
    return Question(
        name="intent_risk",
        kind="score",
        prompt=(
            "How risky is this intent? Weigh: irreversible or "
            "commitment-adjacent actions (send, delete, spend, publish), "
            "new or changed counterparties, recovery-affecting changes, "
            "and any scope beyond the declared purpose. Low = routine "
            "read or reversible action; high = irreversible commitment "
            "or broad blast radius."
        ),
        options=RISK_LEVELS,
    )


def score_intent_risk(intent: Intent, cascade: JudgeCascade) -> RiskScore:
    """Rate an intent's risk via the judge cascade.

    ``score`` is the expected risk over the level distribution
    (low=0, medium=0.5, high=1); ``level`` is the top label. Unknown
    or missing answers default to "low" (advisory: no friction without
    a signal). Raises JudgeUnavailable when no backend answers.
    """
    result = cascade.decide(intent_state(intent), [risk_question()])
    answer = result.answers.get("intent_risk")
    if answer is None or answer.top not in RISK_LEVELS:
        level = "low"
        probs = {}
    else:
        level = answer.top
        probs = answer.probabilities
    score = sum(
        probs.get(lvl, 0.0) * _LEVEL_WEIGHTS[lvl] for lvl in RISK_LEVELS
    )
    score = max(0.0, min(1.0, score))
    confidence = answer.confidence if answer is not None else 0.0
    summary = (
        f"judge {result.backend_path[-1] if result.backend_path else '?'} "
        f"rated intent {intent.action!r} {level} "
        f"(risk score {score:.2f}, confidence {confidence:.2f}"
        f"{', escalated' if result.escalated else ''})"
    )
    return RiskScore(score=score, level=level, summary=summary,
                     escalated=result.escalated)


# ---------------------------------------------------------------------
# Policy-path seam: the step-up advisor (allow→ask only).
# ---------------------------------------------------------------------

def apply_risk_step_up(ctx: Any, decision: str, risk: Optional[RiskScore]) -> bool:
    """Apply a risk score to the call context. Returns True when stepped up.

    HARD RULES (the advisory contract):
    - only an "allow" decision can be stepped up to ask;
    - "deny" / "require_approval" / grant paths pass through untouched;
    - a "low"/"medium" rating changes nothing;
    - never clears ``needs_approval`` (only sets it).
    The score rides on ``ctx.judge_risk`` for the approval record/card.
    """
    if risk is None or risk.level != "high":
        return False
    if decision != "allow":
        return False
    ctx.needs_approval = True
    ctx.judge_risk = risk
    return True


def build_risk_scorer(
    settings: Any, cascade: JudgeCascade
) -> Callable[[Intent, Any], Optional[RiskScore]]:
    """Build the ``PolicyStage(risk_scorer=...)`` callable.

    Returns None (judge off) unless ``settings.judge_enabled``.
    ``JudgeUnavailable`` (or any backend failure) maps to None — the
    deterministic policy decision stands unchanged.
    """

    def scorer(intent: Intent, ctx: Any) -> Optional[RiskScore]:  # noqa: ARG001
        if not getattr(settings, "judge_enabled", False):
            return None
        try:
            return score_intent_risk(intent, cascade)
        except JudgeUnavailable:
            return None
        except Exception:  # noqa: BLE001 — advisory: never break the policy path
            return None

    return scorer


def judge_risk_for_approval_record(ctx: Any) -> Optional[dict[str, Any]]:
    """Additive hook for the approval service (mirrors
    ``urgency_flags_for_approval_record``).

    Returns the judge risk assessment as plain data for the approval
    record's ``judge_risk`` key, or None when the judge did not score
    this call. Read-only; never modifies the context.
    """
    risk = getattr(ctx, "judge_risk", None)
    if risk is None:
        return None
    return {
        "level": risk.level,
        "score": round(risk.score, 3),
        "summary": risk.summary,
        "escalated": risk.escalated,
    }
