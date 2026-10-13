"""Shared /v1/systemone HTTP plumbing for the judge backends.

Wire contract VERIFIED against the real kev.serve implementation
(~/workspace/kev-upstream/kev/api.py, Apache-2.0) — the earlier
list-based shape (from the public TypeSafe docs) is NOT what the
server speaks; the corrected shape below is asserted against a live
server in tests/test_judge_live.py:

  POST {base}/v1/systemone
  {"state": "<text>", "model": "<model id>",
   "questions": {"<name>": {"type": "noul"|"choice"|"score",
                            "instructions": "<prompt>",
                            "criteria": ...}}}
    criteria: noul -> null (options default to "no"/"yes");
              choice -> {"<option>": ""} (empty description renders as
              the bare option name, which is also the wire
              probability key); score -> ["<level 0>", "<level 1>", ...]
              (wire probability keys are the level indices "0".."n-1").

  Response: {"model": str,
             "answers": {"<name>": {...}},   # a DICT, not a list
             "usage": {...}, "latency_ms": float}

Per-question answer shapes (real):
  noul:   {"type": "noul", "noul": p_true}           # scalar, no probability map
  choice: {"type": "choice", "choice": "<name>",
           "confidence": f, "probabilities": {name: p}}
  score:  {"type": "score", "score": <expected level>,
           "legend": {"0": ...}, "probabilities": {"0": p, ...},
           "confidence": f}

We keep a tolerant fallback for the OLD assumed shapes (list
envelopes, name-keyed probability maps, noul yes/no labels) because
Jev's hosted API is unverified and may speak them. Anything we cannot
map to the declared questions is fail-closed (JudgeUnavailable) — the
backend NEVER invents an answer.
"""

from __future__ import annotations

import logging
import time

import httpx

from .client import Answer, DecisionResult, JudgeUnavailable, Question

log = logging.getLogger(__name__)

#: The decision-model endpoint on both backends.
SYSTEMONE_PATH = "/v1/systemone"

#: Alternate envelope keys seen/expected for the answers object.
_ANSWER_LIST_KEYS: tuple[str, ...] = ("answers", "results", "decisions")

#: Alternate per-entry probability keys.
_PROB_KEYS: tuple[str, ...] = ("probabilities", "probs", "distribution")

#: noul label normalization: wire key (lowercased) -> canonical label.
_NOUL_YES = {"yes", "y", "true", "1"}
_NOUL_NO = {"no", "n", "false", "0"}


def encode_request(state: str, questions: list[Question], model: str) -> dict:
    """Map our questions to the /v1/systemone request body.

    Verified against kev.serve (kev/api.py): ``questions`` is a dict
    keyed by question id; each entry carries ``type``, ``instructions``
    (the prompt), and ``criteria``. Duplicate question names are
    refused — in dict form the second would silently overwrite the
    first, which is a fabrication risk.
    """
    if not isinstance(state, str) or not state:
        raise ValueError("state must be a non-empty string")
    if not questions:
        raise ValueError("questions must be non-empty")
    wire_questions: dict[str, dict] = {}
    for q in questions:
        if q.name in wire_questions:
            raise ValueError(f"duplicate question name {q.name!r}")
        if q.kind == "noul":
            criteria = None
        elif q.kind == "choice":
            # Empty description renders as the bare option name, which is
            # also the wire probability key for the choice entry.
            criteria = {option: "" for option in q.options}
        else:  # score
            criteria = list(q.options)
        wire_questions[q.name] = {
            "type": q.kind,
            "instructions": q.prompt,
            "criteria": criteria,
        }
    return {"state": state, "model": model, "questions": wire_questions}


def post(base_url: str, api_key: str | None, body: dict, timeout_s: float) -> dict:
    """POST the body; return the parsed JSON. Fail closed on anything."""
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    try:
        # Local judge traffic is loopback: never route it through an
        # egress proxy (and this runtime's proxy env breaks httpx URL
        # parsing outright) — same lesson as opa_client.
        with httpx.Client(
            base_url=base_url, timeout=timeout_s, trust_env=False
        ) as client:
            resp = client.post(SYSTEMONE_PATH, json=body, headers=headers)
    except httpx.TimeoutException as exc:
        raise JudgeUnavailable(f"judge request timed out: {exc}") from exc
    except httpx.HTTPError as exc:
        raise JudgeUnavailable(f"judge transport error: {exc}") from exc
    if not 200 <= resp.status_code < 300:
        raise JudgeUnavailable(
            f"judge HTTP {resp.status_code}: {resp.text[:200]!r}"
        )
    try:
        payload = resp.json()
    except ValueError as exc:
        raise JudgeUnavailable(f"judge malformed JSON response: {exc}") from exc
    if not isinstance(payload, dict):
        raise JudgeUnavailable(
            f"judge response is not a JSON object: {type(payload).__name__}"
        )
    return payload


def decide_once(
    *,
    backend_name: str,
    model: str,
    base_url: str,
    api_key: str | None,
    state: str,
    questions: list[Question],
    timeout_s: float,
) -> DecisionResult:
    """Full request cycle: encode -> POST -> decode. Raises JudgeUnavailable."""
    body = encode_request(state, questions, model=model)
    t0 = time.perf_counter()
    payload = post(base_url, api_key, body, timeout_s)
    latency_ms = (time.perf_counter() - t0) * 1000.0
    return decode_response(
        payload, questions, backend=backend_name, model=model, latency_ms=latency_ms
    )


def decode_response(
    payload: dict,
    questions: list[Question],
    *,
    backend: str,
    model: str,
    latency_ms: float,
) -> DecisionResult:
    """Normalize the wire response to our DecisionResult shape."""
    entries = _answer_entries(payload)
    by_name: dict[str, dict] = {
        name: entry
        for name, entry in entries.items()
        if isinstance(entry, dict)
    }
    answers: dict[str, Answer] = {}
    for q in questions:
        entry = by_name.get(q.name)
        if entry is None:
            raise JudgeUnavailable(
                f"judge response has no answer for question {q.name!r}: "
                "refusing to fabricate one"
            )
        raw = _probability_map(entry, q)
        probs = _canonicalize(q, raw)
        # top/confidence are derived in Answer.__post_init__.
        answers[q.name] = Answer(
            name=q.name, kind=q.kind, probabilities=probs, top="", confidence=0.0
        )
    return DecisionResult(
        answers=answers, latency_ms=latency_ms, backend=backend, model=model
    )


def _answer_entries(payload: dict) -> dict[str, dict]:
    """Name -> answer entry.

    The real server returns a dict (``{"answers": {qid: {...}}}``).
    The old assumed list form (``[{"name": ..., ...}]``) is kept as a
    tolerant fallback for unverified servers (Jev hosted).
    """
    for key in _ANSWER_LIST_KEYS:
        value = payload.get(key)
        entries: dict[str, dict] = {}
        if isinstance(value, dict):
            for name, entry in value.items():
                if isinstance(name, str) and isinstance(entry, dict):
                    entries[name] = entry
        elif isinstance(value, list):
            for entry in value:
                if isinstance(entry, dict) and isinstance(entry.get("name"), str):
                    entries[entry["name"]] = entry
        if entries:
            return entries
    raise JudgeUnavailable(
        "judge response carries no answer entries "
        f"(looked for {list(_ANSWER_LIST_KEYS)})"
    )


def _probability_map(entry: dict, q: Question) -> dict[str, float]:
    # Real server: noul answers carry the scalar p(true) as "noul" (no
    # probability map). Everything else carries a probability map.
    if q.kind == "noul" and isinstance(entry.get("noul"), (int, float)):
        p_true = float(entry["noul"])
        if not 0.0 <= p_true <= 1.0:
            raise JudgeUnavailable(
                f"judge answer for {q.name!r}: noul {p_true!r} out of [0, 1]"
            )
        # Complement rounded to the wire's 4-decimal precision (the
        # server's round_prob); avoids 1.0 - 0.7 == 0.30000000000000004.
        return {"yes": p_true, "no": round(1.0 - p_true, 4)}
    raw = None
    for key in _PROB_KEYS:
        if isinstance(entry.get(key), dict):
            raw = entry[key]
            break
    if raw is None:
        raise JudgeUnavailable(
            f"judge answer for {q.name!r} carries no probability map "
            f"(looked for {list(_PROB_KEYS)})"
        )
    probs: dict[str, float] = {}
    for label, value in raw.items():
        try:
            probs[str(label)] = float(value)
        except (TypeError, ValueError) as exc:
            raise JudgeUnavailable(
                f"judge answer for {q.name!r} has a non-numeric "
                f"probability for {label!r}"
            ) from exc
    if not probs:
        raise JudgeUnavailable(f"judge answer for {q.name!r} is empty")
    return probs


def _canonicalize(q: Question, raw: dict[str, float]) -> dict[str, float]:
    """Map wire labels onto our canonical label space.

    noul -> {"yes", "no"}; choice -> the declared option names;
    score -> the declared options in order (the real server keys
    score probabilities by level index "0".."n-1"; name-keyed maps
    are a tolerated fallback). Unmappable or missing labels are
    fail-closed.
    """
    if q.kind == "noul":
        out: dict[str, float] = {}
        for label, value in raw.items():
            key = label.strip().lower()
            if key in _NOUL_YES:
                out["yes"] = out.get("yes", 0.0) + value
            elif key in _NOUL_NO:
                out["no"] = out.get("no", 0.0) + value
            else:
                raise JudgeUnavailable(
                    f"judge answer for {q.name!r}: unmappable noul label {label!r}"
                )
        if "yes" not in out or "no" not in out:
            raise JudgeUnavailable(
                f"judge answer for {q.name!r}: noul needs yes+no labels"
            )
        return out
    if q.kind == "score":
        # Real server: probability keys are level indices "0".."n-1".
        if all(str(i) in raw for i in range(len(q.options))):
            return {option: raw[str(i)] for i, option in enumerate(q.options)}
        # Tolerated fallback: keys are the option names themselves.
    # choice, or score-with-name-keys: wire keys must cover every
    # declared option (extra keys ignored).
    lowered = {label.strip().lower(): (label, value) for label, value in raw.items()}
    out = {}
    for option in q.options:
        hit = raw.get(option)
        if hit is None:
            hit = lowered.get(option.strip().lower(), (None, None))[1]
        if hit is None:
            raise JudgeUnavailable(
                f"judge answer for {q.name!r}: missing declared option {option!r}"
            )
        out[option] = hit
    return out
