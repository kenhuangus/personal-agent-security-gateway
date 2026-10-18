"""Optional LLM brain for the security agents (Pillar 2 §1.6).

Red-team and sentinel are fully functional with ``NullLLM`` —
deterministic scenario/detector code needs no model. This is what
makes the MVP testable with no network/GPU. Policy-assistant drafting
and incident summaries use the LLM when ``GATEWAY_AGENTS_LLM_URL`` is
set; when unset they degrade to a clear "not configured" state, never
to hallucinated output.

The LLM never sees secrets: prompts are built from redacted evidence
only.
"""

from __future__ import annotations

from typing import Protocol

import httpx


class LLMNotConfigured(RuntimeError):
    """No LLM endpoint configured (GATEWAY_AGENTS_LLM_URL unset)."""


class LLMClient(Protocol):
    def complete(self, *, system: str, user: str, max_tokens: int) -> str: ...


class NullLLM:
    """Default: raises LLMNotConfigured. Deterministic-only operation."""

    def complete(self, *, system: str, user: str, max_tokens: int) -> str:
        raise LLMNotConfigured(
            "GATEWAY_AGENTS_LLM_URL is not configured — drafting/summaries "
            "are unavailable (deterministic-only mode)"
        )


class OpenAICompatLLM:
    """OpenAI-compatible chat-completions client (httpx, trust_env=False)."""

    def __init__(
        self, base_url: str, model: str, api_key: str = "", timeout_s: float = 30.0
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout_s = timeout_s

    def complete(self, *, system: str, user: str, max_tokens: int) -> str:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "max_tokens": max_tokens,
        }
        with httpx.Client(trust_env=False, timeout=self.timeout_s) as client:
            resp = client.post(
                f"{self.base_url}/chat/completions", json=payload, headers=headers
            )
            resp.raise_for_status()
            data = resp.json()
        try:
            return str(data["choices"][0]["message"]["content"])
        except (KeyError, IndexError, TypeError) as exc:
            raise RuntimeError(f"unexpected LLM response shape: {exc}") from exc


def llm_from_settings(settings: object) -> LLMClient:
    """Build the agent LLM from settings; NullLLM when unconfigured."""
    url = str(getattr(settings, "agents_llm_url", "") or "").strip()
    if not url:
        return NullLLM()
    return OpenAICompatLLM(
        base_url=url,
        model=str(getattr(settings, "agents_llm_model", "") or "default"),
        api_key=str(getattr(settings, "agents_llm_api_key", "") or ""),
    )
