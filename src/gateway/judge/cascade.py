"""Judge cascade: primary decision model with low-confidence escalation.

The cascade runs the primary backend first. When the minimum
confidence across its answers falls below ``threshold`` and an
escalation backend exists, the escalation backend re-decides and its
answers win (``escalated=True``). Without an escalation backend, the
primary answers are returned with ``low_confidence=True`` — the
caller maps that flag to the deterministic ``ask`` path (step-up
approval), never to a silent allow.

Fail-closed: ``JudgeUnavailable`` from the primary tries the
escalation backend once; if that also fails (or no escalation backend
exists) the exception propagates and the caller falls back to the
deterministic path. The cascade never fabricates an answer.

Latency: every ``decide`` records wall-clock ``latency_ms`` spanning
both backends when escalation fires. The cascade is synchronous and
NOT on the hot path by default — the hooks gate it behind
``GATEWAY_JUDGE_ENABLED`` (see ``judge_async`` below for post-hoc,
off-hot-path enrichment).
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable, Optional

from .client import Answer, DecisionBackend, JudgeUnavailable, Question
from ..latency import record


def _judge_span_label(result: "CascadeResult") -> str:
    """Span label for a cascade result: the backend path in order.

    e.g. ``"kev"``, ``"kev|glimmer:escalated"``, ``"kev:low_confidence"``.
    """
    label = "|".join(result.backend_path)
    if result.escalated:
        label += ":escalated"
    if result.low_confidence:
        label += ":low_confidence"
    return label


@dataclass(frozen=True)
class CascadeResult:
    """The cascade's decision.

    ``answers``: the winning backend's answers (primary, or escalation
    when it fired). ``escalated``: the escalation backend decided.
    ``latency_ms``: wall clock across both attempts. ``backend_path``:
    backend names consulted, in order (provenance for the audit trail).
    ``low_confidence``: primary answered below threshold with no
    escalation backend — the caller maps this to deterministic ``ask``.
    """

    answers: dict[str, Answer]
    escalated: bool
    latency_ms: float
    backend_path: list[str]
    low_confidence: bool = False


class JudgeCascade:
    """Primary/escalation decision cascade.

    ``threshold``: minimum acceptable confidence (min over answers).
    ``timeout_s``: per-backend decide timeout, passed through to each
    backend's ``decide``.
    """

    def __init__(
        self,
        primary: DecisionBackend,
        escalation: Optional[DecisionBackend] = None,
        threshold: float = 0.75,
        timeout_s: float = 2.0,
    ) -> None:
        self.primary = primary
        self.escalation = escalation
        self.threshold = threshold
        self.timeout_s = timeout_s

    def decide(
        self, state: str, questions: list[Question]
    ) -> CascadeResult:
        """Run the cascade. Raises JudgeUnavailable when no backend answers.

        Records one ``judge`` latency span per successful cascade using
        the ``latency_ms`` already measured on the result (no second
        timer). Nothing is recorded when the judge is disabled or the
        cascade raises (the fail-closed path) — the span label is the
        backend path, observability only.
        """
        result = self._decide_inner(state, questions)
        record("judge", result.latency_ms, label=_judge_span_label(result))
        return result

    def _decide_inner(
        self, state: str, questions: list[Question]
    ) -> CascadeResult:
        """The cascade body. Raises JudgeUnavailable when no backend answers."""
        path = [self.primary.name]
        start = time.perf_counter()
        try:
            primary_result = self.primary.decide(state, questions, self.timeout_s)
        except JudgeUnavailable:
            # Fail-closed: one escalation attempt, then propagate.
            if self.escalation is None:
                raise
            path.append(self.escalation.name)
            esc = self.escalation.decide(state, questions, self.timeout_s)
            return CascadeResult(
                answers=esc.answers,
                escalated=True,
                latency_ms=(time.perf_counter() - start) * 1000.0,
                backend_path=path,
            )
        primary_ms = (time.perf_counter() - start) * 1000.0
        min_confidence = min(
            (a.confidence for a in primary_result.answers.values()),
            default=1.0,
        )
        if min_confidence >= self.threshold:
            return CascadeResult(
                answers=primary_result.answers,
                escalated=False,
                latency_ms=primary_ms,
                backend_path=path,
            )
        if self.escalation is None:
            return CascadeResult(
                answers=primary_result.answers,
                escalated=False,
                latency_ms=primary_ms,
                backend_path=path,
                low_confidence=True,
            )
        path.append(self.escalation.name)
        esc = self.escalation.decide(state, questions, self.timeout_s)
        return CascadeResult(
            answers=esc.answers,
            escalated=True,
            latency_ms=(time.perf_counter() - start) * 1000.0,
            backend_path=path,
        )


# ---------------------------------------------------------------------
# Off-hot-path helper: post-hoc audit enrichment.
# ---------------------------------------------------------------------

# Small bounded pool: enrichment traffic is advisory and must never
# starve the gateway's own threads.
_ASYNC_POOL = ThreadPoolExecutor(max_workers=2, thread_name_prefix="judge-async")


def judge_async(
    cascade: JudgeCascade,
    state: str,
    questions: list[Question],
    callback: Callable[[Optional[CascadeResult]], None],
) -> None:
    """Fire-and-forget judge call for post-hoc enrichment.

    Runs ``cascade.decide`` on a background threadpool and invokes
    ``callback`` with the :class:`CascadeResult`, or ``None`` when the
    judge was unavailable. Never raises: enrichment must not fail the
    call it annotates. Typical use: attach the result to the audit row
    after the response has been delivered (AC-11 hot path untouched).
    """

    def _run() -> None:
        try:
            result = cascade.decide(state, questions)
        except Exception:  # noqa: BLE001 — fire-and-forget: never raise
            result = None
        try:
            callback(result)
        except Exception:  # noqa: BLE001 — a bad callback must not kill the pool thread
            pass

    _ASYNC_POOL.submit(_run)
