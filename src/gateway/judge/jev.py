"""TypeSafe Jev hosted decision backend.

Jev speaks the same /v1/systemone wire contract as Kev-4B (state +
typed questions in, calibrated probabilities out), so this driver
shares the wire plumbing in ``_wire`` — the backend-swap test pins
that the two produce identical normalized shapes.

No real keys anywhere: the key comes from the constructor arg or the
environment at runtime only. Mocks only in tests.
"""

from __future__ import annotations

from ._wire import decide_once
from .client import DecisionBackend, DecisionResult, Question


class JevBackend(DecisionBackend):
    """DecisionBackend over TypeSafe's hosted Jev /v1/systemone API."""

    name = "jev"

    def __init__(self, base_url: str, api_key: str, model: str = "jev-latest") -> None:
        if not base_url:
            raise ValueError("base_url must be non-empty")
        if not api_key:
            raise ValueError("api_key must be non-empty: Jev is a hosted API")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model

    def decide(
        self, state: str, questions: list[Question], timeout_s: float
    ) -> DecisionResult:
        return decide_once(
            backend_name=self.name,
            model=self.model,
            base_url=self.base_url,
            api_key=self.api_key,
            state=state,
            questions=questions,
            timeout_s=timeout_s,
        )
