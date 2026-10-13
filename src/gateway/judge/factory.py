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

#: Valid GATEWAY_JUDGE_BACKEND values.
BACKENDS: tuple[str, ...] = ("none", "kev", "jev")


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
