"""Ontology discovery: bootstrap from observed reality, not hand-authoring.

Two sources:
(a) connected-account metadata — mailbox / calendar account owners become
    person-principal candidates (plus their data resources);
(b) the AUDIT log — recurring (agent, tool) patterns become candidate
    resources and candidate dimension values. ``purpose`` is inferred
    from mandate purpose text (via a caller-supplied lookup) or from
    tool-class heuristics; time patterns are inferred cautiously (only
    when the dimension already exists, high concentration, low
    confidence, always ``inferred``).

Every proposed entry carries ``provenance="inferred:<source>"``, a
0..1 confidence, and ``status="pending_confirmation"``. Candidates are
NOT authority — they become real entities only through
``OntologyStore.confirm_candidate`` (FR-PAA04-002: no auto-promotion;
FR-PAA04-001: inferred stays distinguished from explicit).

The inspiration repository was never touched; these heuristics are
original (see docs/build-log.md).
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Callable, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import AuditEntry
from .store import OntologyStore

#: Fallback purpose inference when no mandate purpose text is available.
#: Kept deliberately coarse — these are low-confidence hints, and the
#: reviewer confirms or corrects them.
TOOL_CLASS_PURPOSE: dict[str, str] = {
    "email": "communication",
    "calendar": "scheduling",
    "payment": "spending",
    "social": "social",
    "code": "engineering",
    "files": "documents",
    "sms": "communication",
    "phone": "communication",
}

#: Hour buckets for cautious time-pattern inference.
TIME_BUCKETS: tuple[tuple[str, range], ...] = (
    ("morning", range(5, 12)),
    ("afternoon", range(12, 18)),
    ("evening", range(18, 23)),
    ("night", list(range(23, 24)) + list(range(0, 5))),
)

#: Minimum share of a group's calls inside one bucket before a
#: time-pattern candidate is proposed (cautious by design).
TIME_CONCENTRATION = 0.8


def _person_exists(store: OntologyStore, display_name: str) -> bool:
    return any(
        p.display_name == display_name
        for p in store.list_principals(kind="person")
    )


# ---------------------------------------------------------------------
# (a) Connected-account metadata
# ---------------------------------------------------------------------

def discover_from_accounts(
    store: OntologyStore,
    accounts: list[dict[str, Any]],
) -> list:
    """Propose principals (+ their data resources) from connected-account
    metadata.

    ``accounts``: ``[{"source": "gmail", "account_id": "...",
    "display_name": "...", "kind": "mailbox"|"calendar"|...,
    "label_class": "private"|...}]``. The caller assembles these from
    connector metadata — this module never touches credentials.
    """
    proposals: list[dict[str, Any]] = []
    for acct in accounts or []:
        display_name = (acct.get("display_name") or "").strip()
        if not display_name:
            continue
        source = acct.get("source") or "accounts"
        kind = acct.get("kind") or "mailbox"
        label_class = acct.get("label_class") or "private"
        if label_class not in ("work", "private", "family"):
            label_class = "private"
        if not _person_exists(store, display_name):
            proposals.append(
                {
                    "kind": "principal",
                    "payload": {"kind": "person", "display_name": display_name},
                    "provenance": f"inferred:{source}",
                    "confidence": 0.9,
                }
            )
        proposals.append(
            {
                "kind": "resource",
                "payload": {
                    "kind": kind,
                    "display_name": acct.get("account_id") or f"{display_name} {kind}",
                    "label_class": label_class,
                    "owner_display_name": display_name,
                },
                "provenance": f"inferred:{source}",
                "confidence": 0.8,
            }
        )
    return store.propose_candidates(proposals)


# ---------------------------------------------------------------------
# (b) Audit-log tool-call patterns
# ---------------------------------------------------------------------

def _bucket_for_hour(hour: int) -> Optional[str]:
    for name, hours in TIME_BUCKETS:
        if hour in hours:
            return name
    return None


def discover_from_audit(
    store: OntologyStore,
    audit_db: Session,
    *,
    min_occurrences: int = 3,
    mandate_purpose_of: Optional[Callable[[str], Optional[str]]] = None,
    owner_for_agent: Optional[Callable[[str], Optional[str]]] = None,
    limit: int = 5000,
) -> list:
    """Propose candidates from observed tool-call patterns.

    For each recurring ``(agent_id, tool)`` tuple (>= ``min_occurrences``
    rows): a candidate resource (owned by the agent's bound principal
    when known) and candidate ``purpose`` dimension values inferred
    from mandate purpose text (``mandate_purpose_of(mandate_id)``) or,
    failing that, from tool-class heuristics. Time-of-day patterns are
    proposed only when a ``time_of_day`` dimension already exists and
    one bucket dominates (>= ``TIME_CONCENTRATION``) — cautious,
    low-confidence, and always labeled inferred.

    ``owner_for_agent`` optionally maps an agent id to an owner display
    name (e.g. from account metadata); when it names someone other
    than the agent's bound principal, an ``acts_for`` relationship
    candidate is proposed.
    """
    rows = audit_db.execute(
        select(AuditEntry).order_by(AuditEntry.timestamp.desc()).limit(limit)
    ).scalars().all()

    groups: dict[tuple[str, str], list[AuditEntry]] = defaultdict(list)
    for row in rows:
        if row.agent_id and row.tool:
            groups[(row.agent_id, row.tool)].append(row)

    proposals: list[dict[str, Any]] = []
    purpose_values: set[str] = set()

    for (agent_id, tool), entries in sorted(groups.items()):
        if len(entries) < min_occurrences:
            continue
        tool_class = tool.split(".")[0] if "." in tool else tool

        # -- purpose inference: mandate purpose text first, tool class as
        # -- a low-confidence fallback.
        inferred_purpose: Optional[str] = None
        if mandate_purpose_of is not None:
            seen: Counter[str] = Counter()
            for e in entries:
                if e.mandate_id:
                    pk = mandate_purpose_of(e.mandate_id)
                    if pk:
                        seen[pk] += 1
            if seen:
                inferred_purpose, _ = seen.most_common(1)[0]
                purpose_values.add(inferred_purpose)
        if inferred_purpose is None:
            inferred_purpose = TOOL_CLASS_PURPOSE.get(tool_class)
            if inferred_purpose:
                purpose_values.add(inferred_purpose)
        purpose_conf = 0.7 if mandate_purpose_of else 0.5

        # -- candidate resource, owned by the agent's bound principal.
        owner_id = store.principal_for_agent(agent_id)
        owner_name = None
        if owner_id is None and owner_for_agent is not None:
            owner_name = owner_for_agent(agent_id)
        if owner_id is not None or owner_name:
            payload: dict[str, Any] = {
                "kind": tool_class,
                "display_name": tool,
                # Label class is a placeholder until confirmed — the
                # reviewer sets the real one (PAA03 labels are explicit).
                "label_class": "private",
            }
            if owner_id is not None:
                payload["owner_id"] = owner_id
            else:
                payload["owner_display_name"] = owner_name
            proposals.append(
                {
                    "kind": "resource",
                    "payload": payload,
                    "provenance": "inferred:audit-log",
                    "confidence": 0.6,
                }
            )

        # -- acts_for hint: the agent routinely touches an account whose
        # -- owner is someone else.
        if owner_name and owner_id is not None:
            bound = store.get_principal(owner_id)
            if (
                bound is not None
                and bound.display_name != owner_name
                and _person_exists(store, owner_name)
            ):
                proposals.append(
                    {
                        "kind": "relationship",
                        "payload": {
                            "source_id": bound.id,
                            "relation_type": "acts_for",
                            "target_display_name": owner_name,
                        },
                        "provenance": "inferred:audit-log",
                        "confidence": 0.6,
                    }
                )

        # -- cautious time-pattern: only when the dimension already
        # -- exists (never invent time/location dimensions from logs).
        existing_time = store.get_dimension("time_of_day")
        if existing_time is not None and purpose_values:
            buckets = Counter(
                _bucket_for_hour(e.timestamp.hour)
                for e in entries
                if e.timestamp is not None
            )
            buckets.pop(None, None)
            if buckets:
                top_bucket, top_count = buckets.most_common(1)[0]
                if top_count / len(entries) >= TIME_CONCENTRATION:
                    if top_bucket in (existing_time.allowed_values or []):
                        proposals.append(
                            {
                                "kind": "dimension_group",
                                "payload": {
                                    "name": (
                                        f"pattern_{agent_id}_{tool_class}_{top_bucket}"
                                    ),
                                    "dimensions": {
                                        "time_of_day": top_bucket,
                                        **(
                                            {"purpose": inferred_purpose}
                                            if inferred_purpose
                                            else {}
                                        ),
                                    },
                                },
                                "provenance": "inferred:audit-log",
                                "confidence": 0.4,
                            }
                        )

    # -- purpose dimension values (one candidate proposing the union).
    if purpose_values:
        proposals.append(
            {
                "kind": "dimension",
                "payload": {
                    "name": "purpose",
                    "allowed_values": sorted(purpose_values),
                },
                "provenance": "inferred:audit-log",
                "confidence": purpose_conf,
            }
        )

    # Payloads stay minimal and machine-checkable; the audit log rows
    # are the evidence trail the reviewer inspects.
    return store.propose_candidates(proposals)
