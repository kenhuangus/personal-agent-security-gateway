"""Cross-context leakage flagging (M5; FR-PAA03-003).

Adapters surface context labels on the facts they return; this module
reads those labels WITHOUT touching adapter code:

- ``email.search`` / ``email.read``: the mock message ``labels`` list
  (``"work"`` / ``"private"`` / ``"family"``);
- ``calendar.list``: event ``visibility`` (``"private"`` → private;
  anything else is UNLABELED — never guessed);
- everything else: unlabeled.

Leak rule: a ``private``- or ``family``-labeled fact inside a response
whose mandate purpose is ``work`` is flagged, and redacted per the
per-tool ``leakage_action`` policy hook ("redact" default, "flag" =
leave in place but flag + log). The event is always audit-logged.

Unlabeled facts pass through with an "unlabeled" marker recorded in
the leakage report — the gateway never guesses a label.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Optional

# Labels that must not appear in a work-purpose response.
_SENSITIVE_LABELS = ("private", "family")

# Per fact kind, the text fields that carry the fact's content (these
# are what "redact" replaces).
_FACT_TEXT_FIELDS: dict[str, tuple[str, ...]] = {
    "message": ("subject", "snippet", "body"),
    "event": ("title", "description"),
}


@dataclass
class LabeledFact:
    kind: str            # "message" | "event"
    label: Optional[str]  # "work" | "private" | "family" | None (unlabeled)
    path: tuple          # path into the result, e.g. ("messages", 2)
    text_fields: tuple[str, ...]


@dataclass
class LeakageReport:
    flagged: list[dict[str, str]] = field(default_factory=list)
    unlabeled_count: int = 0
    action: str = "redact"

    @property
    def hit(self) -> bool:
        return bool(self.flagged)


def _label_from_labels(labels: Any) -> Optional[str]:
    if not isinstance(labels, (list, tuple)):
        return None
    lowered = [str(item).lower() for item in labels]
    for candidate in ("private", "family", "work"):
        if candidate in lowered:
            return candidate
    return None


def extract_labeled_facts(tool: str, result: Any) -> list[LabeledFact]:
    """Pull (fact, label) pairs out of a tool result using each
    connector's label convention. Unknown shapes → unlabeled."""
    facts: list[LabeledFact] = []
    if not isinstance(result, dict):
        return facts
    if tool in ("email.search",):
        for i, msg in enumerate(result.get("messages") or []):
            if not isinstance(msg, dict):
                continue
            facts.append(LabeledFact(
                kind="message",
                label=_label_from_labels(msg.get("labels")),
                path=("messages", i),
                text_fields=_FACT_TEXT_FIELDS["message"],
            ))
    elif tool in ("email.read",):
        facts.append(LabeledFact(
            kind="message",
            label=_label_from_labels(result.get("labels")),
            path=(),
            text_fields=_FACT_TEXT_FIELDS["message"],
        ))
    elif tool in ("calendar.list",):
        for i, event in enumerate(result.get("events") or []):
            if not isinstance(event, dict):
                continue
            visibility = str(event.get("visibility") or "").lower()
            label = "private" if visibility == "private" else None
            facts.append(LabeledFact(
                kind="event",
                label=label,
                path=("events", i),
                text_fields=_FACT_TEXT_FIELDS["event"],
            ))
    return facts


def check_leakage(
    ctx: Any,
    result: Any,
    leakage_action: str = "redact",
) -> tuple[Any, LeakageReport]:
    """Flag (+ optionally redact) cross-context leakage in a result.

    The response purpose comes from the call's mandate
    (``ctx.mandate.purpose_key``); without a mandate purpose there is
    nothing to compare against and the result passes through untouched.

    Returns (possibly-redacted result, report). ``leakage_action`` is
    the per-tool policy hook: "redact" (default) or "flag".
    """
    report = LeakageReport(action=leakage_action)
    mandate = getattr(ctx, "mandate", None)
    purpose = getattr(mandate, "purpose_key", None) if mandate else None
    facts = extract_labeled_facts(ctx.tool, result)
    report.unlabeled_count = sum(1 for f in facts if f.label is None)
    if purpose is None:
        return result, report

    redacted = copy.deepcopy(result)
    for fact in facts:
        if fact.label not in _SENSITIVE_LABELS:
            continue
        if purpose != "work":
            continue  # only private/family-in-work is a leak per FR-PAA03-003
        report.flagged.append({
            "label": fact.label,
            "kind": fact.kind,
            "field": _path_str(fact.path),
            "action": leakage_action,
        })
        if leakage_action == "redact":
            _redact_fact(redacted, fact)
    return redacted, report


def _redact_fact(container: Any, fact: LabeledFact) -> None:
    target = container
    try:
        for el in fact.path:
            target = target[el]
    except (KeyError, IndexError, TypeError):
        return
    if not isinstance(target, dict):
        return
    for text_field in fact.text_fields:
        if isinstance(target.get(text_field), str):
            target[text_field] = "[redacted:context-leak]"


def _path_str(path: tuple) -> str:
    parts: list[str] = []
    for el in path:
        if isinstance(el, int):
            parts.append(f"[{el}]")
        else:
            if parts:
                parts.append(".")
            parts.append(str(el))
    return "".join(parts) or "result"


def log_leakage_event(audit: Any, ctx: Any, report: LeakageReport) -> None:
    """Emit the leakage detection event to the audit log (FR-PAA03-003)."""
    if audit is None or not report.hit:
        return
    audit.append(
        agent_id=ctx.agent_id,
        tool="inspection.context_leakage",
        decision="allowed",
        request_id=ctx.request_id,
        reason=(
            "context_leak_redacted"
            if report.action == "redact" else "context_leak_flagged"
        ),
        redacted_args={
            "fields": sorted({f["field"] for f in report.flagged}),
            "labels": sorted({f["label"] for f in report.flagged}),
            "action": report.action,
        },
    )
