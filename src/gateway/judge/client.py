"""FROZEN judge-backend interface (JUDGE build).

This module is the contract the cascade and pipeline-integration work
builds against. Do not change these shapes without a build-log entry.

A decision backend answers typed questions about a state in one shot
(TypeSafe ``/v1/systemone`` contract): ``noul`` (yes/no), ``choice``
(1-255 named options), ``score`` (ordered levels). The backend never
fabricates: any failure raises :class:`JudgeUnavailable` and the caller
fails closed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

#: The three question kinds, shared with the /v1/systemone wire "type".
QUESTION_KINDS: tuple[str, ...] = ("noul", "choice", "score")


@dataclass(frozen=True)
class Question:
    """One typed question for the decision model."""

    name: str
    kind: str  # "noul" | "choice" | "score"
    prompt: str
    options: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.kind not in QUESTION_KINDS:
            raise ValueError(
                f"unknown question kind {self.kind!r} (want one of {QUESTION_KINDS})"
            )
        if not self.name:
            raise ValueError("question name must be non-empty")
        if not self.prompt:
            raise ValueError("question prompt must be non-empty")
        object.__setattr__(self, "options", tuple(self.options))
        if self.kind == "noul":
            if self.options:
                raise ValueError("noul questions take no options")
        elif not self.options:
            raise ValueError(f"{self.kind} questions need at least one option")


@dataclass(frozen=True)
class Answer:
    """The model's calibrated answer to one question.

    ``top`` and ``confidence`` are DERIVED (never trusted from the
    wire): ``top`` is the highest-probability label and ``confidence``
    is its probability after normalizing the distribution to sum 1.0.
    """

    name: str
    kind: str
    probabilities: dict[str, float]
    top: str
    confidence: float

    def __post_init__(self) -> None:
        probs = {str(k): float(v) for k, v in self.probabilities.items()}
        if not probs:
            raise ValueError("answer probabilities must be non-empty")
        if any(v < 0 for v in probs.values()):
            raise ValueError("answer probabilities must be non-negative")
        total = sum(probs.values())
        if total <= 0:
            raise ValueError("answer probabilities must sum to a positive value")
        # Tolerate wire float error: normalize to a true distribution.
        probs = {k: v / total for k, v in probs.items()}
        top = max(probs, key=lambda k: probs[k])
        object.__setattr__(self, "probabilities", probs)
        object.__setattr__(self, "top", top)
        object.__setattr__(self, "confidence", probs[top])


@dataclass(frozen=True)
class DecisionResult:
    """One backend's answers for a state + question batch."""

    answers: dict[str, Answer]
    latency_ms: float
    backend: str
    model: str

    def __post_init__(self) -> None:
        for key, answer in self.answers.items():
            if key != answer.name:
                raise ValueError(
                    f"answer key {key!r} does not match answer name {answer.name!r}"
                )


class DecisionBackend(Protocol):
    """A decision-model backend. Fail-closed: raise, never fabricate."""

    name: str

    def decide(
        self, state: str, questions: list[Question], timeout_s: float
    ) -> DecisionResult: ...


class JudgeUnavailable(Exception):
    """The judge backend cannot serve a decision: the caller fails closed."""


class DisabledBackend:
    """The default backend ("none"): the judge is OPT-IN, so decide()
    always fails closed with JudgeUnavailable."""

    name = "none"

    def decide(
        self, state: str, questions: list[Question], timeout_s: float
    ) -> DecisionResult:
        raise JudgeUnavailable(
            "judge backend is disabled (GATEWAY_JUDGE_BACKEND=none): "
            "the judge is opt-in to protect the AC-11 latency budget"
        )
