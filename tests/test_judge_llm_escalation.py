"""LLM escalation backend tests — Personal Agent Security Gateway.

Conventions: NO network, NO GPU, mocks only (httpx.MockTransport).
The DecisionBackend contract is the frozen gateway.judge.client.
"""

from __future__ import annotations

import json

import httpx
import pytest

from gateway.config import Settings
from gateway.judge.cascade import JudgeCascade
from gateway.judge.client import (
    DecisionBackend,
    DecisionResult,
    JudgeUnavailable,
    Question,
)
from gateway.judge.factory import escalation_from_settings
from gateway.judge.llm_escalation import (
    LlmEscalationBackend,
    build_prompt,
    declared_labels,
    parse_verdict,
    probabilities_from_verdict,
)

STATE = "agent=alice tool=payments.send args={amount: 5000}"


def questions() -> list[Question]:
    return [
        Question(
            name="manipulated",
            kind="noul",
            prompt="Is this tool output manipulated?",
        ),
        Question(
            name="action",
            kind="choice",
            prompt="What should the gateway do?",
            options=("allow", "ask", "deny"),
        ),
        Question(
            name="risk",
            kind="score",
            prompt="How risky is this call?",
            options=("low", "medium", "high"),
        ),
    ]


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------


def verdict_payload(verdict: object) -> dict:
    """Wrap a verdict object (dict or raw string) in a chat-completions
    response body."""
    content = verdict if isinstance(verdict, str) else json.dumps(verdict)
    return {"choices": [{"message": {"content": content}}]}


def backend_with(handler) -> tuple[LlmEscalationBackend, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def wrapped(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    backend = LlmEscalationBackend(
        base_url="http://127.0.0.1:11434",
        model="meta-models/Muse-Glimmer-30B",
        transport=httpx.MockTransport(wrapped),
    )
    return backend, seen


GOOD_VERDICT = {
    "manipulated": {"label": "yes", "confidence": 0.9},
    "action": {"label": "ask", "confidence": 0.75},
    "risk": {"label": "medium", "confidence": 0.6},
}


# ---------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------


class TestPrompt:
    def test_labels_embedded_verbatim(self):
        prompt = build_prompt(STATE, questions())
        # noul labels
        assert "'yes'" in prompt and "'no'" in prompt
        # choice options verbatim
        assert "'allow'" in prompt and "'ask'" in prompt and "'deny'" in prompt
        # score levels verbatim
        assert "'low'" in prompt and "'medium'" in prompt and "'high'" in prompt
        # strict JSON instruction present; state included
        assert "JSON object" in prompt
        assert STATE in prompt

    def test_declared_labels(self):
        qs = questions()
        assert declared_labels(qs[0]) == ("yes", "no")
        assert declared_labels(qs[1]) == ("allow", "ask", "deny")
        assert declared_labels(qs[2]) == ("low", "medium", "high")


# ---------------------------------------------------------------------
# Strict parsing
# ---------------------------------------------------------------------


class TestParseVerdict:
    def test_valid_verdict(self):
        out = parse_verdict(json.dumps(GOOD_VERDICT), questions())
        assert out == {
            "manipulated": ("yes", 0.9),
            "action": ("ask", 0.75),
            "risk": ("medium", 0.6),
        }

    def test_case_insensitive_label_canonicalized(self):
        verdict = {
            "manipulated": {"label": "YES", "confidence": 0.9},
            "action": {"label": "Ask", "confidence": 0.7},
            "risk": {"label": "HIGH", "confidence": 0.8},
        }
        out = parse_verdict(json.dumps(verdict), questions())
        assert out["manipulated"][0] == "yes"
        assert out["action"][0] == "ask"
        assert out["risk"][0] == "high"

    def test_invalid_json(self):
        with pytest.raises(JudgeUnavailable):
            parse_verdict("{not json", questions())

    def test_markdown_fence_rejected(self):
        fenced = "```json\n" + json.dumps(GOOD_VERDICT) + "\n```"
        with pytest.raises(JudgeUnavailable):
            parse_verdict(fenced, questions())

    def test_missing_question(self):
        verdict = dict(GOOD_VERDICT)
        del verdict["risk"]
        with pytest.raises(JudgeUnavailable):
            parse_verdict(json.dumps(verdict), questions())

    def test_extra_question_key_rejected(self):
        verdict = dict(GOOD_VERDICT)
        verdict["bonus"] = {"label": "yes", "confidence": 1.0}
        with pytest.raises(JudgeUnavailable):
            parse_verdict(json.dumps(verdict), questions())

    def test_extra_key_inside_entry_rejected(self):
        verdict = dict(GOOD_VERDICT)
        verdict["manipulated"] = {
            "label": "yes",
            "confidence": 0.9,
            "explanation": "looks fine",
        }
        with pytest.raises(JudgeUnavailable):
            parse_verdict(json.dumps(verdict), questions())

    def test_unknown_label_rejected_never_defaults_to_no(self):
        verdict = dict(GOOD_VERDICT)
        verdict["manipulated"] = {"label": "maybe", "confidence": 0.9}
        with pytest.raises(JudgeUnavailable):
            parse_verdict(json.dumps(verdict), questions())

    def test_non_string_label_rejected(self):
        verdict = dict(GOOD_VERDICT)
        verdict["manipulated"] = {"label": 1, "confidence": 0.9}
        with pytest.raises(JudgeUnavailable):
            parse_verdict(json.dumps(verdict), questions())

    def test_confidence_out_of_range_high(self):
        verdict = dict(GOOD_VERDICT)
        verdict["risk"] = {"label": "medium", "confidence": 1.5}
        with pytest.raises(JudgeUnavailable):
            parse_verdict(json.dumps(verdict), questions())

    def test_confidence_out_of_range_negative(self):
        verdict = dict(GOOD_VERDICT)
        verdict["risk"] = {"label": "medium", "confidence": -0.1}
        with pytest.raises(JudgeUnavailable):
            parse_verdict(json.dumps(verdict), questions())

    def test_confidence_string_rejected(self):
        verdict = dict(GOOD_VERDICT)
        verdict["risk"] = {"label": "medium", "confidence": "high"}
        with pytest.raises(JudgeUnavailable):
            parse_verdict(json.dumps(verdict), questions())

    def test_confidence_bool_rejected(self):
        verdict = dict(GOOD_VERDICT)
        verdict["risk"] = {"label": "medium", "confidence": True}
        with pytest.raises(JudgeUnavailable):
            parse_verdict(json.dumps(verdict), questions())

    def test_non_object_entry_rejected(self):
        verdict = dict(GOOD_VERDICT)
        verdict["risk"] = "medium"
        with pytest.raises(JudgeUnavailable):
            parse_verdict(json.dumps(verdict), questions())

    def test_top_level_non_object_rejected(self):
        with pytest.raises(JudgeUnavailable):
            parse_verdict("[1, 2, 3]", questions())


class TestProbabilitiesMapping:
    def test_chosen_gets_confidence_remainder_uniform(self):
        probs = probabilities_from_verdict("ask", 0.7, ("allow", "ask", "deny"))
        assert probs["ask"] == pytest.approx(0.7)
        assert probs["allow"] == pytest.approx(0.15)
        assert probs["deny"] == pytest.approx(0.15)
        assert sum(probs.values()) == pytest.approx(1.0)

    def test_noul_two_way_split(self):
        probs = probabilities_from_verdict("yes", 0.9, ("yes", "no"))
        assert probs == {"yes": pytest.approx(0.9), "no": pytest.approx(0.1)}

    def test_degenerate_single_label_zero_confidence_fails_closed(self):
        with pytest.raises(JudgeUnavailable):
            probabilities_from_verdict("only", 0.0, ("only",))


# ---------------------------------------------------------------------
# decide() over a mocked chat-completions endpoint
# ---------------------------------------------------------------------


class TestDecide:
    def test_happy_path(self):
        backend, seen = backend_with(
            lambda req: httpx.Response(200, json=verdict_payload(GOOD_VERDICT))
        )
        result = backend.decide(STATE, questions(), 2.0)
        assert isinstance(result, DecisionResult)
        assert result.backend == "llm"
        assert result.model == "meta-models/Muse-Glimmer-30B"
        assert result.latency_ms >= 0.0
        assert result.answers["manipulated"].top == "yes"
        assert result.answers["action"].top == "ask"
        assert result.answers["risk"].top == "medium"
        # one request, to the OpenAI-compatible chat path, JSON body
        assert len(seen) == 1
        req = seen[0]
        assert req.url.path == "/v1/chat/completions"
        body = json.loads(req.content)
        assert body["model"] == "meta-models/Muse-Glimmer-30B"
        assert body["messages"][0]["role"] == "system"
        assert "manipulated" in body["messages"][1]["content"]

    def test_no_auth_header_without_key(self):
        backend, seen = backend_with(
            lambda req: httpx.Response(200, json=verdict_payload(GOOD_VERDICT))
        )
        backend.decide(STATE, questions(), 2.0)
        assert "authorization" not in seen[0].headers

    def test_bearer_header_with_key(self):
        seen: list[httpx.Request] = []

        def handler(req: httpx.Request) -> httpx.Response:
            seen.append(req)
            return httpx.Response(200, json=verdict_payload(GOOD_VERDICT))

        backend = LlmEscalationBackend(
            api_key="secret-key",
            transport=httpx.MockTransport(handler),
        )
        backend.decide(STATE, questions(), 2.0)
        assert seen[0].headers["authorization"] == "Bearer secret-key"

    def test_unparseable_verdict_fails_closed(self):
        backend, _ = backend_with(
            lambda req: httpx.Response(200, json=verdict_payload("not json{"))
        )
        with pytest.raises(JudgeUnavailable):
            backend.decide(STATE, questions(), 2.0)

    def test_malicious_verdict_fails_closed(self):
        verdict = dict(GOOD_VERDICT)
        verdict["manipulated"] = {"label": "definitely-hacked", "confidence": 1.0}
        backend, _ = backend_with(
            lambda req: httpx.Response(200, json=verdict_payload(verdict))
        )
        with pytest.raises(JudgeUnavailable):
            backend.decide(STATE, questions(), 2.0)

    def test_http_error_fails_closed(self):
        backend, _ = backend_with(
            lambda req: httpx.Response(500, text="boom")
        )
        with pytest.raises(JudgeUnavailable):
            backend.decide(STATE, questions(), 2.0)

    def test_connect_error_fails_closed(self):
        def handler(req: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused")

        backend = LlmEscalationBackend(transport=httpx.MockTransport(handler))
        with pytest.raises(JudgeUnavailable):
            backend.decide(STATE, questions(), 2.0)

    def test_timeout_fails_closed(self):
        def handler(req: httpx.Request) -> httpx.Response:
            raise httpx.ConnectTimeout("slow")

        backend = LlmEscalationBackend(transport=httpx.MockTransport(handler))
        with pytest.raises(JudgeUnavailable):
            backend.decide(STATE, questions(), 0.5)

    def test_malformed_response_json_fails_closed(self):
        backend, _ = backend_with(
            lambda req: httpx.Response(
                200, content=b"<html>not json</html>",
                headers={"content-type": "text/html"},
            )
        )
        with pytest.raises(JudgeUnavailable):
            backend.decide(STATE, questions(), 2.0)

    def test_non_chat_completions_shape_fails_closed(self):
        backend, _ = backend_with(
            lambda req: httpx.Response(200, json={"result": "yes"})
        )
        with pytest.raises(JudgeUnavailable):
            backend.decide(STATE, questions(), 2.0)

    def test_missing_content_fails_closed(self):
        backend, _ = backend_with(
            lambda req: httpx.Response(
                200, json={"choices": [{"message": {"content": None}}]}
            )
        )
        with pytest.raises(JudgeUnavailable):
            backend.decide(STATE, questions(), 2.0)

    def test_empty_questions_rejected_by_contract(self):
        backend, _ = backend_with(
            lambda req: httpx.Response(200, json=verdict_payload({}))
        )
        # An empty question batch is a degenerate input: fail closed
        # rather than returning empty answers.
        with pytest.raises(JudgeUnavailable):
            backend.decide(STATE, [], 2.0)

    def test_constructor_rejects_empty_base_url_and_model(self):
        with pytest.raises(ValueError):
            LlmEscalationBackend(base_url="")
        with pytest.raises(ValueError):
            LlmEscalationBackend(model="")


# ---------------------------------------------------------------------
# Cascade integration
# ---------------------------------------------------------------------


class _ScriptedPrimary(DecisionBackend):
    """Test double primary: answers at a fixed low confidence."""

    name = "scripted-low"

    def __init__(self, confidence: float = 0.4) -> None:
        self.confidence = confidence

    def decide(
        self, state: str, qs: list[Question], timeout_s: float
    ) -> DecisionResult:
        from gateway.judge.client import Answer

        answers = {
            q.name: Answer(
                name=q.name,
                kind=q.kind,
                probabilities={
                    l: (self.confidence if i == 0 else (1.0 - self.confidence))
                    for i, l in enumerate(declared_labels(q))
                },
                top=declared_labels(q)[0],
                confidence=self.confidence,
            )
            for q in qs
        }
        return DecisionResult(
            answers=answers, latency_ms=1.0, backend=self.name, model="scripted"
        )


class TestCascadeIntegration:
    def test_low_confidence_primary_escalates_to_llm(self):
        backend, _ = backend_with(
            lambda req: httpx.Response(200, json=verdict_payload(GOOD_VERDICT))
        )
        cascade = JudgeCascade(
            primary=_ScriptedPrimary(confidence=0.4),
            escalation=backend,
            threshold=0.75,
            timeout_s=2.0,
        )
        result = cascade.decide(STATE, questions())
        assert result.escalated is True
        assert result.backend_path == ["scripted-low", "llm"]
        assert result.answers["manipulated"].top == "yes"

    def test_llm_failure_propagates_to_deterministic_fallback(self):
        def handler(req: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("down")

        backend = LlmEscalationBackend(transport=httpx.MockTransport(handler))
        cascade = JudgeCascade(
            primary=_ScriptedPrimary(confidence=0.4),
            escalation=backend,
            threshold=0.75,
            timeout_s=2.0,
        )
        # The cascade raises; the pipeline's caller maps this to the
        # deterministic ask path — fail-closed, never fabricated.
        with pytest.raises(JudgeUnavailable):
            cascade.decide(STATE, questions())

    def test_high_confidence_primary_never_calls_llm(self):
        backend, seen = backend_with(
            lambda req: httpx.Response(200, json=verdict_payload(GOOD_VERDICT))
        )
        cascade = JudgeCascade(
            primary=_ScriptedPrimary(confidence=0.99),
            escalation=backend,
            threshold=0.75,
            timeout_s=2.0,
        )
        result = cascade.decide(STATE, questions())
        assert result.escalated is False
        assert seen == []


# ---------------------------------------------------------------------
# Factory: GATEWAY_JUDGE_ESCALATION
# ---------------------------------------------------------------------


def _settings(**overrides):
    # Settings is a frozen dataclass: build with dataclasses.replace.
    import dataclasses

    return dataclasses.replace(Settings(), **overrides)


class TestEscalationFactory:
    def test_none_default_returns_none(self):
        assert escalation_from_settings(_settings()) is None

    def test_llm_builds_backend(self):
        s = _settings(
            judge_escalation="llm",
            judge_llm_escalation_url="http://127.0.0.1:11434",
            judge_llm_escalation_model="meta-models/Muse-Glimmer-30B",
        )
        backend = escalation_from_settings(s)
        assert isinstance(backend, LlmEscalationBackend)
        assert backend.name == "llm"
        assert backend.base_url == "http://127.0.0.1:11434"
        assert backend.model == "meta-models/Muse-Glimmer-30B"

    def test_unknown_escalation_raises(self):
        with pytest.raises(ValueError):
            escalation_from_settings(_settings(judge_escalation="bogus"))

    def test_llm_without_url_raises(self):
        s = _settings(
            judge_escalation="llm",
            judge_llm_escalation_url="",
            judge_llm_escalation_model="meta-models/Muse-Glimmer-30B",
        )
        with pytest.raises(ValueError):
            escalation_from_settings(s)

    def test_llm_without_model_raises(self):
        s = _settings(
            judge_escalation="llm",
            judge_llm_escalation_url="http://127.0.0.1:11434",
            judge_llm_escalation_model="",
        )
        with pytest.raises(ValueError):
            escalation_from_settings(s)

    def test_jev_escalation_needs_url_and_key(self):
        with pytest.raises(ValueError):
            escalation_from_settings(
                _settings(judge_escalation="jev", judge_jev_url="", judge_jev_api_key="k")
            )
        with pytest.raises(ValueError):
            escalation_from_settings(
                _settings(
                    judge_escalation="jev",
                    judge_jev_url="https://x",
                    judge_jev_api_key="",
                )
            )


class TestConfigValidate:
    def test_unknown_escalation_flagged(self):
        s = _settings(judge_escalation="bogus")
        problems = s.validate()
        assert any("GATEWAY_JUDGE_ESCALATION" in p for p in problems)

    def test_valid_escalations_pass(self):
        for name in ("none", "jev", "llm"):
            problems = _settings(judge_escalation=name).validate()
            assert not any("GATEWAY_JUDGE_ESCALATION" in p for p in problems)
