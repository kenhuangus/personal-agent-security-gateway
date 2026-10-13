"""LLM escalation backend for the judge cascade ("bring-your-own model").

TECHNICAL HONESTY — READ THIS BEFORE USING
------------------------------------------
Muse Glimmer 30B is a GENERATIVE agentic chat model, NOT a
``/v1/systemone`` decision model. Kev-4B returns calibrated
probabilities from a purpose-built decision head; Glimmer does not.
This backend is an ADAPTER: it asks a chat model for a typed JSON
verdict and parses it STRICTLY. The "probabilities" in the returned
:class:`Answer` are a normalized self-report (the chosen label gets
its stated confidence, the remainder splits uniformly across the
other labels) — NOT a calibrated distribution like Kev's. Any claim
that these confidences are calibrated would be false.

Escalation-only by design: the cascade's primary stays Kev (fast,
calibrated, local). The LLM fires only when the primary is
low-confidence or unavailable, and its answers win ONLY then
(cascade.escalated=True).

Validated target: ``meta-models/Muse-Glimmer-30B`` (Apache-2.0),
served via Ollama, vLLM, or SGLang — all expose an OpenAI-compatible
``POST /v1/chat/completions`` endpoint, which is all this adapter
needs.

No real keys anywhere: the optional API key comes from the
constructor arg or the environment at runtime only. Mocks only in
tests.

Fail-closed: ANY transport error, timeout, non-2xx status, invalid
JSON, missing question, unknown label, or out-of-range confidence
raises :class:`JudgeUnavailable`. The backend NEVER fabricates an
answer, NEVER invents labels, and NEVER defaults to "no".
"""

from __future__ import annotations

import json
import time
from typing import Optional

import httpx

from .client import (
    Answer,
    DecisionBackend,
    DecisionResult,
    JudgeUnavailable,
    Question,
)

#: Default local-serve endpoint (Ollama default). vLLM and SGLang
#: expose the same OpenAI-compatible path on their own ports — point
#: this at them instead.
DEFAULT_BASE_URL = "http://127.0.0.1:11434"

#: Validated escalation target (deploy target with a GPU). Served
#: locally via Ollama (``ollama pull hf.co/meta-models/Muse-Glimmer-30B``)
#: or vLLM/SGLang with ``--model meta-models/Muse-Glimmer-30B``.
DEFAULT_MODEL = "meta-models/Muse-Glimmer-30B"

#: Env var holding the optional API key (hosted OpenAI-compatible
#: endpoints; Ollama needs none).
API_KEY_ENV = "GATEWAY_LLM_ESCALATION_API_KEY"

#: Labels for ``noul`` questions (case-insensitive match to canonical).
NOUL_LABELS = ("yes", "no")

#: Hard cap on the verdict payload so a runaway model cannot blow the
#: parse budget.
_MAX_VERDICT_CHARS = 16_384

#: Max tokens the adapter asks the model to emit (a typed verdict for
#: a handful of questions is small; this is a hint only — parsing
#: stays strict regardless).
_MAX_TOKENS = 1024


def declared_labels(question: Question) -> tuple[str, ...]:
    """The only labels the model may use for *question*.

    ``noul`` → yes/no; ``choice`` → the declared option names;
    ``score`` → the declared level names. The prompt embeds these
    VERBATIM so the model cannot invent new ones.
    """
    if question.kind == "noul":
        return NOUL_LABELS
    return tuple(question.options)


def _question_block(question: Question) -> str:
    labels = declared_labels(question)
    lines = [
        f"- name: {question.name}",
        f"  kind: {question.kind}",
        f"  question: {question.prompt}",
        "  allowed_labels:",
    ]
    lines.extend(f"  - {label!r}" for label in labels)
    return "\n".join(lines)


def build_prompt(state: str, questions: list[Question]) -> str:
    """STRICT prompt template: a JSON object mapping each question
    name to ``{"label": <one of the allowed labels>, "confidence":
    <0..1>}``. Labels are embedded verbatim; the model MUST NOT
    invent new ones.
    """
    blocks = "\n".join(_question_block(q) for q in questions)
    return (
        "You are a strict verdict function for a security decision system.\n"
        "Read the STATE below, then answer EVERY question with a label from "
        "its allowed_labels and a confidence number between 0 and 1.\n\n"
        "Respond with EXACTLY one JSON object and nothing else. The object "
        "maps each question name to an object with two keys: \"label\" and "
        "\"confidence\". Example:\n"
        "{\"some_question\": {\"label\": \"yes\", \"confidence\": 0.9}}\n\n"
        "Rules:\n"
        "- Use ONLY the allowed labels listed for each question. They are "
        "the complete set. Inventing a new label is a failure.\n"
        "- \"confidence\" must be a number between 0 and 1, not a string.\n"
        "- Answer every question. Do not add extra questions or extra keys.\n\n"
        "STATE:\n"
        f"{state}\n\n"
        "QUESTIONS:\n"
        f"{blocks}\n\n"
        "Respond with the JSON object only."
    )


def _canonicalize_label(raw: object, labels: tuple[str, ...]) -> str:
    """Match *raw* to a canonical label, case-insensitively.

    Anything that is not a string exactly matching one of the
    declared labels (modulo case) → JudgeUnavailable. Never invent.
    """
    if not isinstance(raw, str):
        raise JudgeUnavailable(
            f"verdict label must be a string, got {type(raw).__name__}"
        )
    lowered = raw.strip().lower()
    for canonical in labels:
        if lowered == canonical.lower():
            return canonical
    raise JudgeUnavailable(
        f"verdict label {raw!r} is not one of the declared labels "
        f"{list(labels)!r}"
    )


def _parse_confidence(raw: object, name: str) -> float:
    """Strict [0,1] confidence check. Booleans, NaN/inf, strings,
    out-of-range → JudgeUnavailable."""
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        raise JudgeUnavailable(
            f"verdict confidence for {name!r} must be a number, "
            f"got {type(raw).__name__}"
        )
    value = float(raw)
    if not 0.0 <= value <= 1.0:
        raise JudgeUnavailable(
            f"verdict confidence for {name!r} out of range [0,1]: {raw!r}"
        )
    return value


def parse_verdict(
    payload: str, questions: list[Question]
) -> dict[str, tuple[str, float]]:
    """STRICT verdict parse → {question name: (canonical label, confidence)}.

    Rules (all violations → JudgeUnavailable):
    - the payload must be valid JSON (bare object; a markdown fence is
      NOT valid JSON and is rejected),
    - the top level must be an object with exactly the asked question
      names (no missing, no extras),
    - each entry must be an object with exactly "label" and
      "confidence" (no extras),
    - the label must be one of the question's declared labels
      (case-insensitive match back to canonical),
    - the confidence must be a number in [0,1].
    """
    try:
        parsed = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise JudgeUnavailable(
            f"escalation verdict is not valid JSON: {exc}"
        ) from exc
    if not isinstance(parsed, dict):
        raise JudgeUnavailable(
            "escalation verdict must be a JSON object, "
            f"got {type(parsed).__name__}"
        )
    asked = {q.name for q in questions}
    got = set(parsed.keys())
    if got != asked:
        missing = sorted(asked - got)
        extra = sorted(got - asked)
        raise JudgeUnavailable(
            "escalation verdict question mismatch: "
            + (
                f"missing {missing}; extra {extra}"
                if missing or extra
                else "unexpected shape"
            )
        )
    verdict: dict[str, tuple[str, float]] = {}
    by_name = {q.name: q for q in questions}
    for name, entry in parsed.items():
        question = by_name[name]
        if not isinstance(entry, dict):
            raise JudgeUnavailable(
                f"verdict entry for {name!r} must be an object, "
                f"got {type(entry).__name__}"
            )
        entry_keys = set(entry.keys())
        if entry_keys != {"label", "confidence"}:
            raise JudgeUnavailable(
                f"verdict entry for {name!r} must have exactly "
                f"label/confidence keys, got {sorted(entry_keys)}"
            )
        label = _canonicalize_label(entry["label"], declared_labels(question))
        confidence = _parse_confidence(entry["confidence"], name)
        verdict[name] = (label, confidence)
    return verdict


def probabilities_from_verdict(
    label: str, confidence: float, labels: tuple[str, ...]
) -> dict[str, float]:
    """Build the probabilities map for one verdict.

    The chosen label gets its stated confidence; the remainder splits
    uniformly across the other labels. DOCUMENTED LIMITATION: this is
    a normalized SELF-REPORT — the model's own stated confidence — and
    NOT a calibrated distribution like Kev's pointer-head
    probabilities. Do not compare the two as like-for-like.
    """
    others = [l for l in labels if l != label]
    if not others:
        if confidence <= 0.0:
            raise JudgeUnavailable(
                f"single-label verdict for {label!r} with confidence "
                f"{confidence}: probabilities would sum to zero"
            )
        return {label: confidence}
    share = (1.0 - confidence) / len(others)
    return {l: (confidence if l == label else share) for l in labels}


class LlmEscalationBackend(DecisionBackend):
    """DecisionBackend over any OpenAI-compatible chat-completions
    endpoint (Ollama / vLLM / SGLang / hosted).

    Escalation-only: use it as the cascade's ``escalation`` argument,
    never as the primary (a generative chat model is a strictly worse
    primary than Kev's calibrated decision model).
    """

    name = "llm"

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        model: str = DEFAULT_MODEL,
        api_key: Optional[str] = None,
        *,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> None:
        if not base_url:
            raise ValueError("base_url must be non-empty")
        if not model:
            raise ValueError("model must be non-empty")
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key or None  # normalize "" → None
        # ``transport`` is a TEST SEAM only: tests inject
        # httpx.MockTransport so no real endpoint is ever hit.
        self._transport = transport

    def _post(self, body: dict, timeout_s: float) -> httpx.Response:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        try:
            # Same loopback/proxy lesson as _wire.post and
            # opa_client: trust_env=False, otherwise this runtime's
            # proxy env breaks httpx URL parsing outright.
            with httpx.Client(
                base_url=self.base_url,
                timeout=timeout_s,
                trust_env=False,
                transport=self._transport,
            ) as client:
                return client.post("/v1/chat/completions", json=body, headers=headers)
        except httpx.TimeoutException as exc:
            raise JudgeUnavailable(
                f"llm escalation request timed out: {exc}"
            ) from exc
        except httpx.HTTPError as exc:
            raise JudgeUnavailable(
                f"llm escalation transport error: {exc}"
            ) from exc

    def decide(
        self, state: str, questions: list[Question], timeout_s: float
    ) -> DecisionResult:
        if not questions:
            raise JudgeUnavailable("llm escalation: no questions to decide")
        start = time.perf_counter()
        prompt = build_prompt(state, questions)
        body = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a strict verdict function for a security "
                        "decision system. Output exactly one JSON object "
                        "mapping each question name to an object with keys "
                        "\"label\" and \"confidence\". Use ONLY the "
                        "allowed labels for each question; inventing a label "
                        "is a failure. Confidence is a number between 0 "
                        "and 1."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": 0,
            "max_tokens": _MAX_TOKENS,
            # Hint only (Ollama/vLLM/SGLang/OpenAI all accept it); the
            # strict parser below is the real contract.
            "response_format": {"type": "json_object"},
        }
        resp = self._post(body, timeout_s)
        if not 200 <= resp.status_code < 300:
            raise JudgeUnavailable(
                f"llm escalation HTTP {resp.status_code}: {resp.text[:200]!r}"
            )
        try:
            payload = resp.json()
        except ValueError as exc:
            raise JudgeUnavailable(
                f"llm escalation malformed JSON response: {exc}"
            ) from exc
        if not isinstance(payload, dict):
            raise JudgeUnavailable(
                "llm escalation response is not a JSON object: "
                f"{type(payload).__name__}"
            )
        try:
            text = payload["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise JudgeUnavailable(
                f"llm escalation response is not a chat-completions payload: {exc}"
            ) from exc
        if not isinstance(text, str) or len(text) > _MAX_VERDICT_CHARS:
            raise JudgeUnavailable(
                "llm escalation verdict content is missing or exceeds "
                f"{_MAX_VERDICT_CHARS} chars"
            )
        verdict = parse_verdict(text, questions)
        by_name = {q.name: q for q in questions}
        answers: dict[str, Answer] = {}
        for name, (label, confidence) in verdict.items():
            question = by_name[name]
            answers[name] = Answer(
                name=name,
                kind=question.kind,
                # Note: Answer.__post_init__ re-derives top/confidence
                # from the probabilities and normalizes; the mapping
                # itself (chosen label gets stated confidence, remainder
                # uniform) is this adapter's honest self-report — see
                # probabilities_from_verdict.
                probabilities=probabilities_from_verdict(
                    label, confidence, declared_labels(question)
                ),
                top=label,
                confidence=confidence,
            )
        return DecisionResult(
            answers=answers,
            latency_ms=(time.perf_counter() - start) * 1000.0,
            backend=self.name,
            model=self.model,
        )


__all__ = [
    "API_KEY_ENV",
    "DEFAULT_BASE_URL",
    "DEFAULT_MODEL",
    "LlmEscalationBackend",
    "build_prompt",
    "declared_labels",
    "parse_verdict",
    "probabilities_from_verdict",
]
