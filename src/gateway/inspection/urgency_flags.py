"""False-urgency / deceptive-relationship-claim detection (M5; FR-PAA09-002).

Scans the content that TRIGGERS a call (the agent's arguments) for:

- false-urgency patterns: manufactured time pressure designed to rush
  a decision ("urgent", "act now", "final notice", account-suspension
  threats, same-day deadlines);
- deceptive relationship claims: assertions that a trusted person
  authorized the action ("your boss asked me to", "Ken told me to"),
  which must never be treated as evidence (02 §4.4 counterparty
  evidence rule).

Placement note (why this runs in ``validate_inputs``, step 2, not in
``inspect_output``, step 8): FR-PAA09-002 requires the flags to be
surfaced ON THE APPROVAL CARD, and approval (step 5) runs before
output inspection (step 8). Computing the flags at validation time is
the only placement that satisfies the card requirement.

Approval-record contract (additive hook for M3 — this module does NOT
touch M3's files): the approval service SHOULD call
``urgency_flags_for_approval_record(ctx)`` when creating an approval
request and store the returned list under the ``inspection_flags``
JSON key of the approval record. Each flag is::

    {"type": "false_urgency" | "relationship_claim",
     "pattern": "<pattern name>", "field": "<top-level arg field>"}

No urgency language is ever rendered on the card itself (FR-PAA09-001):
the flags are structured data for the incentives / counterparty-evidence
sections (02 §4.4), not display text.
"""

from __future__ import annotations

import re
from typing import Any

from .validation import walk_strings  # noqa: F401  (shared string walker)

# (pattern name, compiled regex)
_FALSE_URGENCY: list[tuple[str, re.Pattern]] = [
    ("urgent_keyword", re.compile(r"(?i)\burgent\b")),
    ("asap", re.compile(r"(?i)\basap\b|\ba\.s\.a\.p\b")),
    ("act_now", re.compile(r"(?i)\bact\s+(right\s+)?now\b")),
    ("immediately", re.compile(r"(?i)\bimmediately\b")),
    ("final_notice", re.compile(r"(?i)\bfinal\s+notice\b")),
    ("account_suspended", re.compile(
        r"(?i)\baccount\b.{0,30}\b(suspend|close|lock|terminat)")),
    ("same_day_deadline", re.compile(
        r"(?i)\b(by|before)\s+(today|tonight|eod|end of day|5\s?pm)\b")),
    ("expires_soon", re.compile(r"(?i)\bexpir(es|y)\s+(today|tonight|in\s+\d+\s+(minutes?|hours?))\b")),
    ("time_sensitive", re.compile(r"(?i)\btime[\s-]?sensitive\b")),
    ("do_not_delay", re.compile(r"(?i)\bdon'?t\s+(delay|wait|hesitate)\b")),
]

_RELATIONSHIP_CLAIM: list[tuple[str, re.Pattern]] = [
    ("boss_claim", re.compile(
        r"(?i)\b(your|my|our)\s+(boss|manager|supervisor|ceo)\s+"
        r"(asked|told|said|instructed|wants?|requested)\b")),
    ("family_claim", re.compile(
        r"(?i)\b(your|my)\s+(wife|husband|spouse|partner|mother|father)\s+"
        r"(asked|told|said|instructed|wants?|requested)\b")),
    ("ken_told_me", re.compile(
        r"(?i)\bken\s+(told|asked|instructed)\s+me\b")),
    ("on_behalf", re.compile(
        r"(?i)\bon\s+behalf\s+of\s+your\s+(boss|manager|family|wife|husband)\b")),
    ("approved_claim", re.compile(
        r"(?i)\b(they|he|she)\s+said\s+you\s+(already\s+)?approved\b")),
]


def scan_trigger_content(args: Any) -> list[dict[str, str]]:
    """Scan trigger content (call arguments) for urgency/deception flags.

    Returns a list of flag dicts; empty when nothing is found. Field
    names only — matched text is never echoed.
    """
    flags: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for path, text in walk_strings(args):
        field = str(path[0]) if path else "arguments"
        for name, rx in _FALSE_URGENCY:
            if rx.search(text):
                key = ("false_urgency", name, field)
                if key not in seen:
                    seen.add(key)
                    flags.append(
                        {"type": "false_urgency", "pattern": name, "field": field}
                    )
        for name, rx in _RELATIONSHIP_CLAIM:
            if rx.search(text):
                key = ("relationship_claim", name, field)
                if key not in seen:
                    seen.add(key)
                    flags.append(
                        {"type": "relationship_claim", "pattern": name, "field": field}
                    )
    return flags


def urgency_flags_for_approval_record(ctx: Any) -> list[dict[str, str]]:
    """Additive hook for M3's approval service (FR-PAA09-002).

    Returns the urgency flags computed for this call. M3 SHOULD store
    them on the approval record under the ``inspection_flags`` JSON key
    so the approval card can render them in the incentives /
    counterparty-evidence sections. This function reads only; it never
    modifies M3-owned records.
    """
    return list(getattr(ctx, "urgency_flags", None) or [])
