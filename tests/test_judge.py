"""JUDGE backend tests — Personal Agent Security Gateway.

Covers the frozen interface (client.py), the Kev/Jev drivers against
mocked httpx (exact wire body asserted), fail-closed behavior, the
factory, and the backend-swap interchangeability test.

Conventions: NO network, NO GPU. httpx is monkeypatched at
``gateway.judge._wire.httpx.Client``; API keys are fake literals.
"""

from __future__ import annotations

import httpx
import pytest

from gateway.config import Settings
from gateway.judge import (
    Answer,
    DecisionBackend,
    DecisionResult,
    DisabledBackend,
    JevBackend,
    JudgeUnavailable,
    KevBackend,
    Question,
    backend_from_settings,
)
from gateway.judge import _wire


# ---------------------------------------------------------------------------
# Fake HTTP transport
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self):
        if self._payload is None:
            raise ValueError("no JSON body")
        return self._payload


@pytest.fixture
def fake_http(monkeypatch):
    """Monkeypatch httpx.Client inside _wire. Returns (FakeClient, calls)."""
    calls = []

    class FakeClient:
        behavior = "ok"  # ok | timeout | conn_error | http500 | badjson
        payload = None

        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def post(self, path, json=None, headers=None):
            calls.append(
                {"path": path, "json": json, "headers": headers,
                 "kwargs": self.kwargs}
            )
            if FakeClient.behavior == "timeout":
                raise httpx.TimeoutException("timed out")
            if FakeClient.behavior == "conn_error":
                raise httpx.ConnectError("refused")
            if FakeClient.behavior == "http500":
                return _FakeResponse(500, None, "internal error")
            if FakeClient.behavior == "badjson":
                return _FakeResponse(200, None, "not json")
            return _FakeResponse(200, FakeClient.payload)

    monkeypatch.setattr(_wire.httpx, "Client", FakeClient)
    # Reset per-test class state.
    FakeClient.behavior = "ok"
    FakeClient.payload = None
    return FakeClient, calls


# ---------------------------------------------------------------------------
# Shared fixtures: one question of each kind + one wire response
# ---------------------------------------------------------------------------


@pytest.fixture
def questions():
    return [
        Question(name="risky", kind="noul", prompt="Is this call risky?"),
        Question(
            name="tier", kind="score", prompt="Risk tier?",
            options=("low", "medium", "high"),
        ),
        Question(
            name="action", kind="choice", prompt="Recommended action?",
            options=("allow", "ask", "deny"),
        ),
    ]


@pytest.fixture
def wire_payload():
    """Real kev.serve response shape (dict keyed by question id; noul
    carries the scalar p(true); score probabilities keyed by index)."""
    return {
        "model": "jaredpalmer/kev-4b",
        "answers": {
            "risky": {"type": "noul", "noul": 0.7},
            "tier": {
                "type": "score",
                "score": 1.6,
                "legend": {"0": "low", "1": "medium", "2": "high"},
                "probabilities": {"0": 0.1, "1": 0.2, "2": 0.7},
                "confidence": 0.4,
            },
            "action": {
                "type": "choice",
                "choice": "allow",
                "confidence": 0.5,
                "probabilities": {"allow": 0.6, "ask": 0.3, "deny": 0.1},
            },
        },
        "usage": {"input_tokens": 100, "output_tokens": 20},
        "latency_ms": 12.5,
    }


def expected_wire_body(model: str) -> dict:
    """Real kev.serve request shape (dict keyed by question id;
    instructions/criteria fields)."""
    return {
        "state": "STATE",
        "model": model,
        "questions": {
            "risky": {
                "type": "noul",
                "instructions": "Is this call risky?",
                "criteria": None,
            },
            "tier": {
                "type": "score",
                "instructions": "Risk tier?",
                "criteria": ["low", "medium", "high"],
            },
            "action": {
                "type": "choice",
                "instructions": "Recommended action?",
                "criteria": {"allow": "", "ask": "", "deny": ""},
            },
        },
    }


# ---------------------------------------------------------------------------
# Frozen interface: validation
# ---------------------------------------------------------------------------


class TestInterface:
    def test_bad_kind_rejected(self):
        with pytest.raises(ValueError):
            Question(name="q", kind="maybe", prompt="p")

    def test_empty_name_rejected(self):
        with pytest.raises(ValueError):
            Question(name="", kind="noul", prompt="p")

    def test_noul_with_options_rejected(self):
        with pytest.raises(ValueError):
            Question(name="q", kind="noul", prompt="p", options=("a",))

    def test_choice_without_options_rejected(self):
        with pytest.raises(ValueError):
            Question(name="q", kind="choice", prompt="p")

    def test_options_list_coerced_to_tuple(self):
        q = Question(name="q", kind="choice", prompt="p", options=["a", "b"])
        assert q.options == ("a", "b")

    def test_probabilities_normalized(self):
        # Wire float error: sums to 0.30000000000000004, not 1.0.
        a = Answer(
            name="q", kind="noul",
            probabilities={"yes": 0.1, "no": 0.2},
            top="???", confidence=-1.0,
        )
        assert abs(sum(a.probabilities.values()) - 1.0) < 1e-12
        assert a.probabilities["yes"] == pytest.approx(1 / 3)
        # top/confidence are DERIVED, never trusted from input.
        assert a.top == "no"
        assert a.confidence == pytest.approx(2 / 3)

    def test_probabilities_scaled_to_unit(self):
        a = Answer(
            name="q", kind="score",
            probabilities={"low": 20.0, "high": 80.0},
            top="", confidence=0.0,
        )
        assert a.probabilities == {"low": 0.2, "high": 0.8}
        assert a.top == "high" and a.confidence == 0.8

    def test_empty_probabilities_rejected(self):
        with pytest.raises(ValueError):
            Answer(name="q", kind="noul", probabilities={}, top="", confidence=0.0)

    def test_negative_probability_rejected(self):
        with pytest.raises(ValueError):
            Answer(name="q", kind="noul",
                   probabilities={"yes": -0.5, "no": 1.5}, top="", confidence=0.0)

    def test_result_key_name_mismatch_rejected(self):
        a = Answer(name="q", kind="noul",
                   probabilities={"yes": 1.0, "no": 0.0}, top="", confidence=0.0)
        with pytest.raises(ValueError):
            DecisionResult(answers={"other": a}, latency_ms=1.0,
                           backend="kev", model="m")

    def test_disabled_backend_always_fails_closed(self):
        b = DisabledBackend()
        assert b.name == "none"
        with pytest.raises(JudgeUnavailable):
            b.decide("s", [Question(name="q", kind="noul", prompt="p")], 1.0)

    def test_frozen_dataclasses(self):
        q = Question(name="q", kind="noul", prompt="p")
        with pytest.raises(Exception):
            q.name = "x"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# KevBackend wire mapping (mocked httpx)
# ---------------------------------------------------------------------------


class TestKevBackend:
    def test_exact_wire_body(self, fake_http, questions, wire_payload):
        FakeClient, calls = fake_http
        FakeClient.payload = wire_payload
        backend = KevBackend()
        result = backend.decide("STATE", questions, timeout_s=2.0)
        assert len(calls) == 1
        call = calls[0]
        assert call["path"] == "/v1/systemone"
        assert call["json"] == expected_wire_body("jaredpalmer/kev-4b")
        # No Authorization header when no key is configured.
        assert "Authorization" not in call["headers"]
        assert result.backend == "kev"
        assert result.model == "jaredpalmer/kev-4b"
        assert result.latency_ms >= 0

    def test_api_key_sent_as_bearer(self, fake_http, questions, wire_payload):
        FakeClient, calls = fake_http
        FakeClient.payload = wire_payload
        KevBackend(api_key="fake-key").decide("STATE", questions, timeout_s=2.0)
        assert calls[0]["headers"]["Authorization"] == "Bearer fake-key"

    def test_base_url_used_and_trailing_slash_stripped(
        self, fake_http, questions, wire_payload
    ):
        FakeClient, calls = fake_http
        FakeClient.payload = wire_payload
        KevBackend(base_url="http://127.0.0.1:9000/").decide(
            "STATE", questions, timeout_s=2.0
        )
        assert calls[0]["kwargs"]["base_url"] == "http://127.0.0.1:9000"
        # Loopback traffic must not go through an egress proxy.
        assert calls[0]["kwargs"]["trust_env"] is False

    def test_timeout_configured(self, fake_http, questions, wire_payload):
        FakeClient, calls = fake_http
        FakeClient.payload = wire_payload
        KevBackend().decide("STATE", questions, timeout_s=7.5)
        assert calls[0]["kwargs"]["timeout"] == 7.5

    def test_answers_normalized(self, fake_http, questions, wire_payload):
        FakeClient, _ = fake_http
        FakeClient.payload = wire_payload
        result = KevBackend().decide("STATE", questions, timeout_s=2.0)
        assert set(result.answers) == {"risky", "tier", "action"}
        risky = result.answers["risky"]
        assert risky.probabilities == {"yes": 0.7, "no": 0.3}
        assert risky.top == "yes" and risky.confidence == pytest.approx(0.7)
        tier = result.answers["tier"]
        assert tier.top == "high" and tier.confidence == pytest.approx(0.7)
        action = result.answers["action"]
        assert action.top == "allow"

    def test_noul_label_variants_tolerated(self, fake_http, questions):
        FakeClient, _ = fake_http
        FakeClient.payload = {
            "answers": [
                {"name": "risky", "probs": {"TRUE": 0.8, "False": 0.2}},
                {"name": "tier", "probabilities": {"low": 0.5, "medium": 0.3, "high": 0.2}},
                {"name": "action", "probabilities": {"allow": 1.0, "ask": 0.0, "deny": 0.0}},
            ]
        }
        result = KevBackend().decide("STATE", questions, timeout_s=2.0)
        assert result.answers["risky"].probabilities == {"yes": 0.8, "no": 0.2}

    def test_timeout_fails_closed(self, fake_http, questions):
        FakeClient, _ = fake_http
        FakeClient.behavior = "timeout"
        with pytest.raises(JudgeUnavailable):
            KevBackend().decide("STATE", questions, timeout_s=0.5)

    def test_connect_error_fails_closed(self, fake_http, questions):
        FakeClient, _ = fake_http
        FakeClient.behavior = "conn_error"
        with pytest.raises(JudgeUnavailable):
            KevBackend().decide("STATE", questions, timeout_s=2.0)

    def test_non_2xx_fails_closed(self, fake_http, questions):
        FakeClient, _ = fake_http
        FakeClient.behavior = "http500"
        with pytest.raises(JudgeUnavailable):
            KevBackend().decide("STATE", questions, timeout_s=2.0)

    def test_malformed_json_fails_closed(self, fake_http, questions):
        FakeClient, _ = fake_http
        FakeClient.behavior = "badjson"
        with pytest.raises(JudgeUnavailable):
            KevBackend().decide("STATE", questions, timeout_s=2.0)

    def test_missing_answer_never_fabricated(self, fake_http, questions):
        FakeClient, _ = fake_http
        FakeClient.payload = {"answers": []}
        with pytest.raises(JudgeUnavailable):
            KevBackend().decide("STATE", questions, timeout_s=2.0)

    def test_missing_option_fails_closed(self, fake_http, questions):
        FakeClient, _ = fake_http
        FakeClient.payload = {
            "answers": [
                {"name": "risky", "probabilities": {"yes": 1.0, "no": 0.0}},
                {"name": "tier", "probabilities": {"low": 0.5, "medium": 0.3, "high": 0.2}},
                # "deny" missing from the choice answer.
                {"name": "action", "probabilities": {"allow": 0.6, "ask": 0.4}},
            ]
        }
        with pytest.raises(JudgeUnavailable):
            KevBackend().decide("STATE", questions, timeout_s=2.0)

    def test_openrouter_constructor(self, monkeypatch):
        monkeypatch.setenv("KEV_API_KEY", "fake-or-key")
        b = KevBackend.openrouter()
        assert b.base_url == "https://openrouter.ai/api/v1"
        assert b.api_key == "fake-or-key"
        assert b.model == "jaredpalmer/kev-4b"

    def test_openrouter_constructor_explicit_key(self):
        b = KevBackend.openrouter(api_key="explicit-fake")
        assert b.api_key == "explicit-fake"

    def test_openrouter_no_key_raises(self, monkeypatch):
        monkeypatch.delenv("KEV_API_KEY", raising=False)
        with pytest.raises(ValueError):
            KevBackend.openrouter()


# ---------------------------------------------------------------------------
# JevBackend: same contract, same mapping
# ---------------------------------------------------------------------------


class TestJevBackend:
    def test_exact_wire_body(self, fake_http, questions, wire_payload):
        FakeClient, calls = fake_http
        FakeClient.payload = wire_payload
        backend = JevBackend(base_url="https://api.typesafe.example", api_key="fake-k")
        result = backend.decide("STATE", questions, timeout_s=2.0)
        assert calls[0]["path"] == "/v1/systemone"
        assert calls[0]["json"] == expected_wire_body("jev-latest")
        assert calls[0]["headers"]["Authorization"] == "Bearer fake-k"
        assert result.backend == "jev"
        assert result.model == "jev-latest"

    def test_constructor_requires_key(self):
        with pytest.raises(ValueError):
            JevBackend(base_url="https://x.example", api_key="")

    def test_constructor_requires_base_url(self):
        with pytest.raises(ValueError):
            JevBackend(base_url="", api_key="fake-k")

    def test_timeout_fails_closed(self, fake_http, questions):
        FakeClient, _ = fake_http
        FakeClient.behavior = "timeout"
        backend = JevBackend(base_url="https://x.example", api_key="fake-k")
        with pytest.raises(JudgeUnavailable):
            backend.decide("STATE", questions, timeout_s=1.0)

    def test_non_2xx_fails_closed(self, fake_http, questions):
        FakeClient, _ = fake_http
        FakeClient.behavior = "http500"
        backend = JevBackend(base_url="https://x.example", api_key="fake-k")
        with pytest.raises(JudgeUnavailable):
            backend.decide("STATE", questions, timeout_s=1.0)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def _settings(monkeypatch, **env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    return Settings()


class TestFactory:
    def test_default_is_none(self, monkeypatch):
        monkeypatch.delenv("GATEWAY_JUDGE_BACKEND", raising=False)
        s = Settings()
        assert s.judge_backend == "none"
        assert s.judge_kev_url == "http://127.0.0.1:8009"
        assert s.judge_timeout_s == 2.0
        backend = backend_from_settings(s)
        assert isinstance(backend, DisabledBackend)
        assert backend.name == "none"

    def test_kev_selection(self, monkeypatch):
        s = _settings(
            monkeypatch,
            GATEWAY_JUDGE_BACKEND="kev",
            GATEWAY_JUDGE_KEV_URL="http://127.0.0.1:9001",
        )
        backend = backend_from_settings(s)
        assert isinstance(backend, KevBackend)
        assert backend.base_url == "http://127.0.0.1:9001"

    def test_jev_selection(self, monkeypatch):
        s = _settings(
            monkeypatch,
            GATEWAY_JUDGE_BACKEND="jev",
            GATEWAY_JUDGE_JEV_URL="https://jev.example/v1",
            GATEWAY_JUDGE_JEV_API_KEY="fake-key",
        )
        backend = backend_from_settings(s)
        assert isinstance(backend, JevBackend)
        assert backend.base_url == "https://jev.example/v1"

    def test_jev_missing_url_raises(self, monkeypatch):
        s = _settings(
            monkeypatch,
            GATEWAY_JUDGE_BACKEND="jev",
            GATEWAY_JUDGE_JEV_API_KEY="fake-key",
        )
        monkeypatch.delenv("GATEWAY_JUDGE_JEV_URL", raising=False)
        with pytest.raises(ValueError):
            backend_from_settings(Settings())

    def test_jev_missing_key_raises(self, monkeypatch):
        s = _settings(
            monkeypatch,
            GATEWAY_JUDGE_BACKEND="jev",
            GATEWAY_JUDGE_JEV_URL="https://jev.example/v1",
        )
        monkeypatch.delenv("GATEWAY_JUDGE_JEV_API_KEY", raising=False)
        with pytest.raises(ValueError):
            backend_from_settings(Settings())

    def test_unknown_backend_raises(self, monkeypatch):
        s = _settings(monkeypatch, GATEWAY_JUDGE_BACKEND="grok")
        with pytest.raises(ValueError):
            backend_from_settings(s)

    def test_timeout_env_parsed(self, monkeypatch):
        s = _settings(monkeypatch, GATEWAY_JUDGE_TIMEOUT_S="0.25")
        assert s.judge_timeout_s == 0.25

    def test_kev_model_selection(self, monkeypatch):
        """GH #33: the model id is a config knob, passed to the client."""
        s = _settings(
            monkeypatch,
            GATEWAY_JUDGE_BACKEND="kev",
            GATEWAY_JUDGE_KEV_MODEL="jaredpalmer/kev-0.8b",
        )
        assert s.judge_kev_model == "jaredpalmer/kev-0.8b"
        backend = backend_from_settings(s)
        assert isinstance(backend, KevBackend)
        assert backend.model == "jaredpalmer/kev-0.8b"

    def test_kev_model_default_is_4b(self, monkeypatch):
        """GH #33: default model stays the production recommendation."""
        monkeypatch.delenv("GATEWAY_JUDGE_KEV_MODEL", raising=False)
        s = _settings(monkeypatch, GATEWAY_JUDGE_BACKEND="kev")
        assert s.judge_kev_model == "jaredpalmer/kev-4b"
        backend = backend_from_settings(s)
        assert backend.model == "jaredpalmer/kev-4b"

    def test_validate_flags_bad_backend(self, monkeypatch):
        s = _settings(monkeypatch, GATEWAY_JUDGE_BACKEND="grok")
        assert any("GATEWAY_JUDGE_BACKEND" in p for p in s.validate())

    def test_validate_flags_bad_timeout(self, monkeypatch):
        s = _settings(monkeypatch, GATEWAY_JUDGE_TIMEOUT_S="0")
        assert any("GATEWAY_JUDGE_TIMEOUT_S" in p for p in s.validate())

    def test_validate_clean_defaults(self, monkeypatch):
        monkeypatch.delenv("GATEWAY_JUDGE_BACKEND", raising=False)
        s = Settings()
        problems = [p for p in s.validate() if "JUDGE" in p]
        assert problems == []


# ---------------------------------------------------------------------------
# Backend-swap: identical normalized shapes through both drivers
# ---------------------------------------------------------------------------


class TestBackendSwap:
    def test_same_state_same_questions_identical_shapes(
        self, fake_http, questions, wire_payload
    ):
        FakeClient, _ = fake_http
        FakeClient.payload = wire_payload

        kev = KevBackend(base_url="http://127.0.0.1:8009")
        jev = JevBackend(base_url="https://jev.example", api_key="fake-key")

        r_kev = kev.decide("STATE", questions, timeout_s=2.0)
        r_jev = jev.decide("STATE", questions, timeout_s=2.0)

        # Interchangeable: same normalized answer shapes.
        assert r_kev.answers == r_jev.answers
        assert set(r_kev.answers) == {"risky", "tier", "action"}
        for name in r_kev.answers:
            a, b = r_kev.answers[name], r_jev.answers[name]
            assert a.kind == b.kind == questions[
                [q.name for q in questions].index(name)
            ].kind
            assert a.probabilities == b.probabilities
            assert a.top == b.top
            assert a.confidence == b.confidence
        # The driver identity still differs (provenance, not shape).
        assert (r_kev.backend, r_kev.model) == ("kev", "jaredpalmer/kev-4b")
        assert (r_jev.backend, r_jev.model) == ("jev", "jev-latest")

    def test_swap_with_tolerant_wire_labels(self, fake_http, questions):
        """Even divergent-but-valid wire labels normalize identically."""
        FakeClient, _ = fake_http
        kev_payload = {
            "answers": [
                {"name": "risky", "probabilities": {"yes": 0.7, "no": 0.3}},
                {"name": "tier", "probabilities": {"low": 0.1, "medium": 0.2, "high": 0.7}},
                {"name": "action", "probabilities": {"allow": 0.6, "ask": 0.3, "deny": 0.1}},
            ]
        }
        jev_payload = {
            "results": [  # alternate envelope key
                {"name": "risky", "distribution": {"Y": 0.7, "N": 0.3}},
                {"name": "tier", "probs": {"LOW": 0.1, "Medium": 0.2, "HIGH": 0.7}},
                {"name": "action", "probabilities": {"Allow": 0.6, "ASK": 0.3, "Deny": 0.1}},
            ]
        }

        FakeClient.payload = kev_payload
        r_kev = KevBackend().decide("STATE", questions, timeout_s=2.0)
        FakeClient.payload = jev_payload
        r_jev = JevBackend(base_url="https://x.example", api_key="k").decide(
            "STATE", questions, timeout_s=2.0
        )
        assert r_kev.answers == r_jev.answers
