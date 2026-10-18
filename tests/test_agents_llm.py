"""Pillar 2 §2.3: the LLM seam.

NullLLM raises LLMNotConfigured (the runner surfaces
llm_unconfigured); OpenAICompatLLM posts a chat-completions-shaped
request; llm_from_settings returns the Null backend when no key is
configured (tests never touch the network — httpx is stubbed).
"""

from __future__ import annotations

import pytest

import agents.llm as llm_mod
from agents.llm import (
    LLMNotConfigured,
    NullLLM,
    OpenAICompatLLM,
    llm_from_settings,
)


class _Settings:
    agents_llm_url = ""
    agents_llm_model = ""
    agents_llm_api_key = ""


def test_null_llm_raises():
    with pytest.raises(LLMNotConfigured):
        NullLLM().complete(system="s", user="hello", max_tokens=10)


def test_llm_from_settings_null_when_unconfigured():
    assert isinstance(llm_from_settings(_Settings()), NullLLM)


def test_llm_from_settings_openai_compat_when_configured():
    s = _Settings()
    s.agents_llm_url = "http://127.0.0.1:9/v1"
    s.agents_llm_model = "test-model"
    s.agents_llm_api_key = "k"
    llm = llm_from_settings(s)
    assert isinstance(llm, OpenAICompatLLM)
    assert llm.model == "test-model"


class _FakeResp:
    def raise_for_status(self):
        pass

    def json(self):
        return {"choices": [{"message": {"content": "draft body"}}]}


class _FakeClient:
    def __init__(self, *a, **k):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def post(self, url, json=None, headers=None):
        self.calls.append({"url": url, "json": json, "headers": headers})
        return _FakeResp()


def test_openai_compat_posts_chat_completions(monkeypatch):
    clients = []

    def _factory(*a, **k):
        c = _FakeClient()
        clients.append(c)
        return c

    monkeypatch.setattr(llm_mod.httpx, "Client", _factory)
    llm = OpenAICompatLLM(base_url="http://x/v1", model="m", api_key="k")
    text = llm.complete(system="sys", user="summarize", max_tokens=50)
    assert text == "draft body"
    call = clients[0].calls[0]
    assert call["url"] == "http://x/v1/chat/completions"
    assert call["json"]["model"] == "m"
    assert call["json"]["messages"][0] == {"role": "system", "content": "sys"}
    # The key travels as a Bearer header, never in the body.
    assert call["headers"]["Authorization"] == "Bearer k"
    import json as _json

    assert '"k"' not in _json.dumps(call["json"])


def test_openai_compat_empty_content_raises(monkeypatch):
    class _Empty(_FakeResp):
        def json(self):
            return {"choices": []}

    class _C(_FakeClient):
        def post(self, url, json=None, headers=None):
            return _Empty()

    monkeypatch.setattr(llm_mod.httpx, "Client", lambda *a, **k: _C())
    llm = OpenAICompatLLM(base_url="http://x/v1", model="m")
    with pytest.raises(RuntimeError):
        llm.complete(system="s", user="hi", max_tokens=10)
