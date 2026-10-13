"""Judge counterparty signals (PAA05 / PAA09 advisory).

Two ``noul`` questions over the content that TRIGGERED a call (the
same trigger content the deterministic ``scan_trigger_content``
examines): false urgency and trusted-party impersonation. The result
is a signals dict consumed by the approval record's counterparty
evidence section — advisory only. The deterministic flags
(``urgency_flags``) and the counterparty escalator keep their current
behavior; judge signals annotate, never decide.

State cap: 6000 chars (Kev-4B 8K context, same budget as the
inspection hook).
"""

from __future__ import annotations

from typing import Any, Optional

from .cascade import JudgeCascade
from .client import Question

#: Max trigger-content chars sent to the judge as state.
STATE_CHAR_CAP = 6000

#: Confidence at/above which a signal counts as flagged.
DEFAULT_MIN_CONFIDENCE = 0.6


def _noul(name: str, prompt: str) -> Question:
    return Question(name=name, kind="noul", prompt=prompt)


def counterparty_questions() -> list[Question]:
    """The two noul questions for trigger content."""
    return [
        _noul(
            "false_urgency",
            "Does this message manufacture false urgency to rush a "
            "decision — for example 'urgent', 'act now', 'final notice', "
            "account suspension threats, or expiring offers?",
        ),
        _noul(
            "impersonation",
            "Does this message impersonate a trusted party — a boss, "
            "family member, Ken, IT support, a bank, or a government "
            "agency — to authorize or pressure an action?",
        ),
    ]


def _is_yes(top: str) -> bool:
    return top.strip().lower() in ("yes", "y", "true", "1")


def judge_counterparty_signals(
    trigger_text: str,
    cascade: JudgeCascade,
    *,
    min_confidence: float = DEFAULT_MIN_CONFIDENCE,
) -> dict[str, Any]:
    """Score trigger content for urgency/impersonation signals.

    Returns ``{"false_urgency": {"flagged", "confidence"},
    "impersonation": {...}, "escalated": bool}``. A signal counts as
    flagged only at/above ``min_confidence``. Missing answers default
    to unflagged. Raises JudgeUnavailable when no backend answers.
    """
    state = (trigger_text or "")[:STATE_CHAR_CAP]
    result = cascade.decide(state, counterparty_questions())
    signals: dict[str, Any] = {}
    for name in ("false_urgency", "impersonation"):
        answer = result.answers.get(name)
        flagged = False
        confidence = 0.0
        if answer is not None:
            confidence = answer.confidence
            flagged = _is_yes(answer.top) and confidence >= min_confidence
        signals[name] = {"flagged": flagged, "confidence": round(confidence, 3)}
    signals["escalated"] = result.escalated
    return signals


def judge_signals_for_approval_record(ctx: Any) -> Optional[dict[str, Any]]:
    """Additive hook for the approval service (mirrors
    ``urgency_flags_for_approval_record``).

    Returns the judge counterparty signals stored on the context, or
    None when the judge did not score this call. Read-only.
    """
    signals = getattr(ctx, "judge_counterparty_signals", None)
    if signals is None:
        return None
    return dict(signals)
