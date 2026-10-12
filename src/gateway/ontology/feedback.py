"""Living ontology: the world feeds back into the ontology (PAA04).

Decision outcomes (allowed / denied / approved), corrections
(counterparty-record corrections, mandate narrow/pause/end, redaction-
catalog edits), and mandate lifecycle events are recorded as immutable
feedback events with provenance + timestamps. Detectors then FLAG
stale or conflicting entries into the review queue — surfaced for the
M6 console, never silently applied.

Hard rule: nothing in this module mutates authority. Preference
groups, dimension groups, principals, and relationships change only
through explicit store writes or candidate confirmation. The review
queue is the only output besides the event log.
"""

from __future__ import annotations

import datetime as dt
from typing import Any, Optional

from ..models import utcnow
from .integration import _tool_selector_matches, applicable_preference_groups
from .store import OntologyStore

#: Mandate lifecycle events that feed back into the ontology.
MANDATE_EVENTS: tuple[str, ...] = (
    "narrow",
    "pause",
    "resume",
    "end",
    "withdraw",
    "expired",
)

#: Events after which purpose-scoped entries are considered suspect.
TERMINAL_MANDATE_EVENTS: tuple[str, ...] = ("end", "withdraw", "expired")

#: Correction kinds the gateway produces.
CORRECTION_KINDS: tuple[str, ...] = (
    "counterparty",
    "mandate",
    "redaction",
    "instruction",
)

#: A tool denied this many times recently triggers a staleness flag.
REPEATED_DENIAL_THRESHOLD = 5


def record_decision_outcome(
    store: OntologyStore,
    *,
    decision: str,
    agent_id: str,
    tool: str,
    dimensions: Optional[dict[str, str]] = None,
    principal_id: Optional[str] = None,
    snapshot_ref: Optional[str] = None,
    reason: Optional[str] = None,
    provenance: str = "inferred:pipeline",
) -> list:
    """Record a decision outcome and flag conflicts.

    Flags (into the review queue, never auto-applied):
    - denied while an applicable preference group documents ``allow``
      for the tool → the group's documentation contradicts reality;
    - the same tool denied >= ``REPEATED_DENIAL_THRESHOLD`` times
      recently → the purpose binding or preference slice may be stale.

    Returns the review items created (possibly empty).
    """
    dimensions = dict(dimensions or {})
    store.record_feedback_event(
        "decision",
        {
            "decision": decision,
            "agent_id": agent_id,
            "tool": tool,
            "dimensions": dimensions,
            "principal_id": principal_id,
            "snapshot_ref": snapshot_ref,
            "reason": reason,
        },
        provenance,
    )
    flagged = []
    if decision == "denied":
        for pref in applicable_preference_groups(store.db, dimensions):
            constraints = pref.constraints or {}
            if any(
                _tool_selector_matches(sel, tool)
                for sel in constraints.get("allow", [])
            ):
                flagged.append(
                    store.flag_for_review(
                        "preference_group",
                        pref.id,
                        f"preference group {pref.name!r} documents allow for "
                        f"{tool!r}, but a call was denied — the group's "
                        "documentation contradicts the enforced decision",
                        provenance,
                        {
                            "tool": tool,
                            "agent_id": agent_id,
                            "dimensions": dimensions,
                            "snapshot_ref": snapshot_ref,
                        },
                    )
                )
        recent_denials = sum(
            1
            for e in store.list_feedback_events(kind="decision", limit=200)
            if (e.summary or {}).get("decision") == "denied"
            and (e.summary or {}).get("tool") == tool
        )
        if recent_denials >= REPEATED_DENIAL_THRESHOLD:
            flagged.append(
                store.flag_for_review(
                    "tool",
                    tool,
                    f"{tool!r} denied {recent_denials} times recently — "
                    "the purpose binding or preference slice covering it "
                    "may be stale",
                    provenance,
                    {"tool": tool, "recent_denials": recent_denials},
                )
            )
    return flagged


def record_correction(
    store: OntologyStore,
    *,
    correction_kind: str,
    target_kind: str,
    target_id: str,
    note: str = "",
    provenance: str = "explicit:console",
):
    """Record a correction and flag the corrected entry for review.

    Corrections (counterparty-record, mandate, redaction-catalog,
    standing-instruction) propagate as review flags on dependent
    entries — the correction itself is recorded, dependents are
    flagged, nothing is rewritten (FR-PAA04-003).
    """
    if correction_kind not in CORRECTION_KINDS:
        raise ValueError(
            f"unknown correction kind {correction_kind!r}; "
            f"want one of {CORRECTION_KINDS}"
        )
    event = store.record_feedback_event(
        "correction",
        {
            "correction_kind": correction_kind,
            "target_kind": target_kind,
            "target_id": target_id,
            "note": note,
        },
        provenance,
    )
    item = store.flag_for_review(
        target_kind,
        target_id,
        f"{correction_kind} correction recorded"
        + (f": {note}" if note else "")
        + " — verify dependent entries still hold",
        provenance,
        {"correction_kind": correction_kind, "note": note},
    )
    return event, item


def record_mandate_event(
    store: OntologyStore,
    *,
    mandate_id: str,
    event: str,
    purpose_key: Optional[str] = None,
    provenance: str = "inferred:mandates",
) -> list:
    """Record a mandate lifecycle event and flag dependents.

    On terminal events (end / withdraw / expired) with a known
    ``purpose_key``, every preference group and dimension group scoped
    to that purpose is flagged — the mandate that justified the slice
    is gone, so the slice needs human eyes (PAA04: mandate withdrawal
    flags dependent preference groups). Nothing is deleted or
    rewritten.
    """
    if event not in MANDATE_EVENTS:
        raise ValueError(
            f"unknown mandate event {event!r}; want one of {MANDATE_EVENTS}"
        )
    store.record_feedback_event(
        "mandate",
        {"mandate_id": mandate_id, "event": event, "purpose_key": purpose_key},
        provenance,
    )
    flagged = []
    if event in TERMINAL_MANDATE_EVENTS:
        if purpose_key:
            for pref in store.list_preference_groups():
                group = store.get_dimension_group(pref.dimension_group_id)
                if group is None:
                    continue
                if (group.dimensions or {}).get("purpose") == purpose_key:
                    flagged.append(
                        store.flag_for_review(
                            "preference_group",
                            pref.id,
                            f"mandate {mandate_id} {event}; preference group "
                            f"{pref.name!r} is scoped to purpose "
                            f"{purpose_key!r} — confirm it still applies",
                            provenance,
                            {
                                "mandate_id": mandate_id,
                                "event": event,
                                "purpose_key": purpose_key,
                            },
                        )
                    )
            for group in store.list_dimension_groups():
                if (group.dimensions or {}).get("purpose") == purpose_key:
                    flagged.append(
                        store.flag_for_review(
                            "dimension_group",
                            group.id,
                            f"mandate {mandate_id} {event}; dimension group "
                            f"{group.name!r} is scoped to purpose "
                            f"{purpose_key!r} — confirm it still applies",
                            provenance,
                            {
                                "mandate_id": mandate_id,
                                "event": event,
                                "purpose_key": purpose_key,
                            },
                        )
                    )
        else:
            flagged.append(
                store.flag_for_review(
                    "mandate",
                    mandate_id,
                    f"mandate {event} with no recorded purpose — review "
                    "ontology entries that may have depended on it",
                    provenance,
                    {"mandate_id": mandate_id, "event": event},
                )
            )
    return flagged


def sweep_stale(
    store: OntologyStore,
    *,
    older_than_days: int = 90,
    now: Optional[dt.datetime] = None,
) -> list:
    """Flag inferred candidates that were never confirmed.

    A pending candidate older than ``older_than_days`` is probably a
    stale inference (the world moved on) or a proposal nobody trusts —
    either way it needs eyes, not silent promotion or silent deletion.
    """
    now = now or utcnow()
    cutoff = now - dt.timedelta(days=older_than_days)
    flagged = []
    for cand in store.list_candidates(status="pending_confirmation"):
        created = cand.created_at
        if created is None:
            continue
        if created.tzinfo is None:
            created = created.replace(tzinfo=dt.timezone.utc)
        if created < cutoff:
            flagged.append(
                store.flag_for_review(
                    "candidate",
                    cand.id,
                    f"stale candidate: {cand.kind} proposed "
                    f"{created.date().isoformat()} from {cand.provenance} "
                    f"(confidence {cand.confidence:.2f}), never confirmed",
                    "inferred:pipeline",
                    {
                        "kind": cand.kind,
                        "provenance": cand.provenance,
                        "confidence": cand.confidence,
                    },
                )
            )
    return flagged


def detect_conflicts(store: OntologyStore) -> list:
    """Detect contradictory entries already in the ontology.

    - A preference group whose dimension combo contradicts a NEWER
      mandate-scoped dimension group with the same name root is out of
      scope for automatic detection (names are free-form), so this
      pass covers what IS machine-checkable:
    - a ``deny`` and an ``allow`` selector for the same tool inside one
      preference group (self-contradictory documentation);
    - a relationship whose target principal no longer exists is
      impossible (the store forbids dangling refs) — instead: duplicate
      dimension groups with the same name are impossible (unique) —
      so the check is: two preference groups on the SAME dimension
      group where one denies and the other allow-documents the same
      tool selector.
    """
    flagged = []
    by_group: dict[str, list] = {}
    for pref in store.list_preference_groups():
        by_group.setdefault(pref.dimension_group_id, []).append(pref)
    for group_id, prefs in by_group.items():
        for i, a in enumerate(prefs):
            for b in prefs[i + 1:]:
                # Either direction: the group that DOCUMENTS allow while
                # the other DENIES is the flagged one (deny is enforced).
                for denier,allower in ((a, b), (b, a)):
                    cd = denier.constraints or {}
                    ca = allower.constraints or {}
                    for sel in cd.get("deny", []):
                        if any(
                            _tool_selector_matches(sel, other)
                            or _tool_selector_matches(other, sel)
                            for other in ca.get("allow", [])
                        ):
                            flagged.append(
                                store.flag_for_review(
                                    "preference_group",
                                    allower.id,
                                    f"conflict: {allower.name!r} documents allow "
                                    f"for {sel!r} on the same dimension slice "
                                    f"where {denier.name!r} denies it",
                                    "inferred:pipeline",
                                    {
                                        "dimension_group_id": group_id,
                                        "selector": sel,
                                    },
                                )
                            )
    return flagged
