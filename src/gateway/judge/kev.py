"""Kev-4B decision backend (Jared Palmer, Apache-2.0).

Kev-4B is an open-weight DECISION model (LoRA + pointer head on
Qwen3.5-4B-Base) speaking TypeSafe's /v1/systemone wire contract: one
forward pass over a state + typed questions, calibrated probabilities
back, no text generation.

Local serving (from the Kev docs)::

    python -m kev.serve --run jaredpalmer/kev-4b --port 8009

binds 127.0.0.1 and serves POST /v1/systemone (optional ``KEV_API_KEY``).
Also hosted on OpenRouter as ``jaredpalmer/kev-4b``.

This client is original code reimplemented from the documented
contract — no code copied from the kev repository (repo is GPL-3.0;
kev is Apache-2.0).
"""

from __future__ import annotations

import os

from ._wire import decide_once
from .client import DecisionBackend, DecisionResult, Question

#: Default local-serve endpoint.
DEFAULT_BASE_URL = "http://127.0.0.1:8009"

#: Default model id (local serve + OpenRouter).
DEFAULT_MODEL = "jaredpalmer/kev-4b"

#: OpenRouter base URL (the /v1/systemone contract lives under it).
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

#: Env var holding the optional local-serve key / OpenRouter key.
API_KEY_ENV = "KEV_API_KEY"


class KevBackend(DecisionBackend):
    """DecisionBackend over a Kev-4B /v1/systemone endpoint."""

    name = "kev"

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        api_key: str | None = None,
        model: str = DEFAULT_MODEL,
    ) -> None:
        if not base_url:
            raise ValueError("base_url must be non-empty")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model

    @classmethod
    def openrouter(
        cls, api_key: str | None = None, model: str = DEFAULT_MODEL
    ) -> "KevBackend":
        """Kev-4B via OpenRouter. The key comes from the caller or the
        ``KEV_API_KEY`` env var ONLY — never hardcoded, never in tests."""
        key = api_key or os.environ.get(API_KEY_ENV)
        if not key:
            raise ValueError(
                f"{API_KEY_ENV} is not set: the OpenRouter backend needs an API key"
            )
        return cls(base_url=OPENROUTER_BASE_URL, api_key=key, model=model)

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
