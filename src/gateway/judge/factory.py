"""Judge backend selection from Settings (JUDGE build).

The judge is OPT-IN: ``GATEWAY_JUDGE_BACKEND`` defaults to ``"none"``
(a :class:`DisabledBackend` whose ``decide()`` always raises
:class:`JudgeUnavailable`). This protects the AC-11 latency budget —
no judge call happens unless the operator explicitly enables one.

Misconfiguration is loud: an unknown backend name, or a ``jev``
backend with no URL/key, raises ``ValueError`` at construction time
rather than silently running without the judge.
"""

from __future__ import annotations

import os

from .client import DecisionBackend, DisabledBackend
from .jev import JevBackend
from .kev import API_KEY_ENV, KevBackend
from .llm_escalation import LlmEscalationBackend

#: Valid GATEWAY_JUDGE_BACKEND values.
BACKENDS: tuple[str, ...] = ("none", "kev", "jev")

#: Valid GATEWAY_JUDGE_ESCALATION values. "none" (default) builds no
#: escalation backend: the cascade returns low_confidence=True on
#: low-confidence primary answers and the caller falls back to the
#: deterministic ask path.
ESCALATIONS: tuple[str, ...] = ("none", "jev", "llm")


def backend_from_settings(settings) -> DecisionBackend:
    """Build the judge backend named by the settings.

    ``GATEWAY_JUDGE_TIMEOUT_S`` is NOT consumed here: it flows through
    ``decide(state, questions, timeout_s=...)`` at the call site (the
    cascade worker reads ``settings.judge_timeout_s``).
    """
    which = (settings.judge_backend or "none").strip().lower()
    if which == "none":
        return DisabledBackend()
    if which == "kev":
        return KevBackend(
            base_url=settings.judge_kev_url,
            api_key=os.environ.get(API_KEY_ENV),
        )
    if which == "jev":
        if not settings.judge_jev_url:
            raise ValueError(
                "GATEWAY_JUDGE_BACKEND=jev but GATEWAY_JUDGE_JEV_URL is empty"
            )
        if not settings.judge_jev_api_key:
            raise ValueError(
                "GATEWAY_JUDGE_BACKEND=jev but GATEWAY_JUDGE_JEV_API_KEY is empty"
            )
        return JevBackend(
            base_url=settings.judge_jev_url, api_key=settings.judge_jev_api_key
        )
    raise ValueError(
        f"unknown GATEWAY_JUDGE_BACKEND={settings.judge_backend!r} "
        f"(want one of {BACKENDS})"
    )


def escalation_from_settings(settings) -> DecisionBackend | None:
    """Build the cascade ESCALATION backend named by the settings.

    Returns None for ``"none"`` (default). The primary stays Kev;
    the escalation backend fires only when the primary is
    low-confidence or unavailable.

    Misconfiguration is loud: an unknown escalation name, or an
    ``llm`` escalation with no URL/model, raises ``ValueError`` at
    construction time — matching ``backend_from_settings`` behavior.
    """
    which = (
        getattr(settings, "judge_escalation", None) or "none"
    ).strip().lower()
    if which == "none":
        return None
    if which == "jev":
        if not settings.judge_jev_url:
            raise ValueError(
                "GATEWAY_JUDGE_ESCALATION=jev but GATEWAY_JUDGE_JEV_URL is empty"
            )
        if not settings.judge_jev_api_key:
            raise ValueError(
                "GATEWAY_JUDGE_ESCALATION=jev but GATEWAY_JUDGE_JEV_API_KEY is empty"
            )
        return JevBackend(
            base_url=settings.judge_jev_url, api_key=settings.judge_jev_api_key
        )
    if which == "llm":
        if not settings.judge_llm_escalation_url:
            raise ValueError(
                "GATEWAY_JUDGE_ESCALATION=llm but GATEWAY_LLM_ESCALATION_URL is empty"
            )
        if not settings.judge_llm_escalation_model:
            raise ValueError(
                "GATEWAY_JUDGE_ESCALATION=llm but GATEWAY_LLM_ESCALATION_MODEL is empty"
            )
        return LlmEscalationBackend(
            base_url=settings.judge_llm_escalation_url,
            model=settings.judge_llm_escalation_model,
            api_key=settings.judge_llm_escalation_api_key or None,
        )
    raise ValueError(
        f"unknown GATEWAY_JUDGE_ESCALATION={settings.judge_escalation!r} "
        f"(want one of {ESCALATIONS})"
    )
