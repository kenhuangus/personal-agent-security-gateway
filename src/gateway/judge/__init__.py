"""Judge decision backends (JUDGE build).

Kev-4B (local or OpenRouter) and TypeSafe Jev both speak the
/v1/systemone contract. The judge is OPT-IN via ``GATEWAY_JUDGE_BACKEND``
(default ``"none"``); every backend is fail-closed — any failure
raises :class:`JudgeUnavailable` and the caller denies.
"""

from .client import (
    QUESTION_KINDS,
    Answer,
    DecisionBackend,
    DecisionResult,
    DisabledBackend,
    JudgeUnavailable,
    Question,
)
from .factory import BACKENDS, backend_from_settings
from .jev import JevBackend
from .kev import API_KEY_ENV, KevBackend

# Cascade + pipeline integration (advisory; default OFF — see
# GATEWAY_JUDGE_ENABLED). The judge can only ADD friction
# (allow→ask, flag, annotate): it never overrides a policy deny and
# never runs in front of policy evaluation.
from .cascade import CascadeResult, JudgeCascade, judge_async
from .counterparty_hook import (
    judge_counterparty_signals,
    judge_signals_for_approval_record,
)
from .inspection_hook import (
    JudgeInspectionHook,
    JudgeScanVerdict,
    judge_manipulation_scan,
    manipulation_question,
)
from .risk import (
    RiskScore,
    apply_risk_step_up,
    build_risk_scorer,
    intent_state,
    judge_risk_for_approval_record,
    risk_question,
    score_intent_risk,
)

__all__ = [
    "QUESTION_KINDS",
    "Answer",
    "DecisionBackend",
    "DecisionResult",
    "DisabledBackend",
    "JudgeUnavailable",
    "Question",
    "BACKENDS",
    "backend_from_settings",
    "JevBackend",
    "KevBackend",
    "API_KEY_ENV",
    # Cascade + pipeline integration.
    "CascadeResult",
    "JudgeCascade",
    "judge_async",
    "judge_counterparty_signals",
    "judge_signals_for_approval_record",
    "JudgeInspectionHook",
    "JudgeScanVerdict",
    "judge_manipulation_scan",
    "manipulation_question",
    "RiskScore",
    "apply_risk_step_up",
    "build_risk_scorer",
    "intent_state",
    "judge_risk_for_approval_record",
    "risk_question",
    "score_intent_risk",
]
