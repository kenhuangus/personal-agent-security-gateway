"""Counterparty records (PAA05 — Counterparty Deception and Agent Mediated Scams).

- Per-payee records are written from audited calls (FR-PAA05-001):
  ``record_from_call`` runs after a call executes (wired into the
  pipeline's audit stage in M3 builds).
- New payee → auto-sensitive for commitment-adjacent actions
  (FR-PAA05-002): ``assess`` feeds the policy stage's sensitivity
  escalator, converting an "allow" into "require_approval".
- Changed details → escalate to approval with the delta displayed
  (FR-PAA05-001/003): the delta is snapshotted into the approval
  record's evidence subset and shown on the card.
- Console review/correction with diff, audit-logged (Approvals page;
  03 AOQ-12).

Commitment-adjacent tools in the MVP inventory: ``email.send`` (a new
recipient is a new counterparty), ``code.pr.open`` (a new repo), plus
the destructive/protected tools where a payee model applies. Tools
without an extractable payee (``calendar.delete``,
``email.settings.write``) return "known" — no payee model in MVP,
documented here rather than invented.

Agent-supplied legitimacy assertions are NEVER evidence (FR-PAA05-004):
``assess`` only compares against the recorded snapshot.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import CounterpartyRecord, as_utc, utcnow

#: Tools whose calls carry a counterparty the gateway tracks
#: (FR-PAA05-002: new payee → auto-sensitive).
COMMITMENT_ADJACENT_TOOLS: frozenset[str] = frozenset({
    "email.send",
    "email.settings.write",
    "calendar.create",
    "calendar.delete",
    "code.pr.open",
    # Pillar 1: payment calls carry a payee_key (account fingerprint).
    "payment.initiate",
    "payment.cancel",
})


def extract_payee_key(tool: str, args: dict[str, Any]) -> Optional[str]:
    """Stable identity key for the call's counterparty, or None when the
    tool has no payee model in MVP."""
    if tool == "email.send":
        recipients = args.get("to") or []
        if recipients:
            return str(recipients[0]).strip().lower()
        return None
    if tool == "code.pr.open":
        repo = args.get("repo")
        return str(repo).strip().lower() if repo else None
    if tool == "payment.initiate":
        # Account fingerprint (e.g. "ach:schwab:xxxx1234"); never the
        # full account number — the allowlist stores last-4 only.
        payee = args.get("payee_key")
        return str(payee).strip().lower() if payee else None
    if tool == "payment.cancel":
        # The canceled payment's payee is resolved from the referenced
        # receipt; pre-execution there is no payee to assess.
        return None
    return None


def snapshot_details(tool: str, args: dict[str, Any]) -> dict[str, Any]:
    """Last-known-good detail snapshot for delta detection."""
    if tool == "email.send":
        return {
            "to": sorted(str(x).strip().lower() for x in (args.get("to") or [])),
            "cc": sorted(str(x).strip().lower() for x in (args.get("cc") or [])),
            "bcc": sorted(str(x).strip().lower() for x in (args.get("bcc") or [])),
        }
    if tool == "code.pr.open":
        return {"repo": args.get("repo"), "base": args.get("base")}
    if tool == "payment.initiate":
        return {"payee_key": args.get("payee_key"), "currency": args.get("currency")}
    return {}


def diff_snapshots(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """Human-readable delta between two snapshots."""
    delta: dict[str, Any] = {}
    for key in sorted(set(old) | set(new)):
        o, n = old.get(key), new.get(key)
        if o == n:
            continue
        if isinstance(o, list) and isinstance(n, list):
            added = sorted(set(n) - set(o))
            removed = sorted(set(o) - set(n))
            if added or removed:
                delta[key] = {"added": added, "removed": removed}
        else:
            delta[key] = {"was": o, "now": n}
    return delta


@dataclass
class CounterpartyAssessment:
    key: Optional[str]
    known: bool          # a record exists (or no payee model → treated known)
    is_new: bool         # no prior audited history → auto-sensitive (FR-PAA05-002)
    delta: dict[str, Any] = field(default_factory=dict)  # changed details vs record
    record: Optional[CounterpartyRecord] = None


class CounterpartyService:
    def __init__(self, db: Session) -> None:
        self.db = db

    # -- reads --------------------------------------------------------

    def get(self, key: str) -> Optional[CounterpartyRecord]:
        return self.db.execute(
            select(CounterpartyRecord).where(CounterpartyRecord.key == key)
        ).scalars().first()

    def list(self, limit: int = 200) -> list[CounterpartyRecord]:
        return list(
            self.db.execute(
                select(CounterpartyRecord)
                .order_by(CounterpartyRecord.last_seen_at.desc())
                .limit(limit)
            ).scalars().all()
        )

    def assess(self, tool: str, args: dict[str, Any]) -> CounterpartyAssessment:
        """Compare the call's counterparty against the recorded snapshot."""
        key = extract_payee_key(tool, args or {})
        if key is None:
            # No payee model for this tool in MVP: never escalates here.
            return CounterpartyAssessment(key=None, known=True, is_new=False)
        record = self.get(key)
        if record is None:
            return CounterpartyAssessment(key=key, known=False, is_new=True)
        delta = diff_snapshots(record.details_snapshot or {}, snapshot_details(tool, args or {}))
        return CounterpartyAssessment(key=key, known=True, is_new=False, delta=delta, record=record)

    # -- writes --------------------------------------------------------

    def record_from_call(self, agent_id: str, tool: str, args: dict[str, Any]) -> Optional[CounterpartyRecord]:
        """Write/update the per-payee record from an executed (audited)
        call (FR-PAA05-001). Called after successful execution only."""
        key = extract_payee_key(tool, args or {})
        if key is None:
            return None
        now = utcnow()
        record = self.get(key)
        if record is None:
            record = CounterpartyRecord(
                key=key, first_seen_at=now, last_seen_at=now, call_count=1,
                details_snapshot=snapshot_details(tool, args or {}),
            )
            self.db.add(record)
        else:
            record.last_seen_at = now
            record.call_count += 1
            record.details_snapshot = snapshot_details(tool, args or {})
        self.db.commit()
        return record

    def correct(
        self,
        key: str,
        *,
        notes: str,
        details: dict[str, Any],
        admin_id: str,
        audit: Any,  # AuditLog; typed loosely to avoid a cycle
    ) -> CounterpartyRecord:
        """Console review/correction (03 AOQ-12): Ken fixes a record;
        the change is diffed and audit-logged.

        GH #12: the audit row carries the before/after snapshots, which
        for email.send are raw recipient addresses. They are redacted
        through the redaction catalog before the audit write
        (NFR-DATA-001: redacted args ONLY). If redaction itself fails,
        only the changed KEY names are logged — never raw values.

        The ``key`` field itself is NOT redacted: it is the record's
        primary identifier (the audit row must identify WHICH record
        was corrected — the same role agent_id plays in call rows).
        Only the before/after PII payload is redacted.
        """
        record = self.get(key)
        if record is None:
            raise ValueError(f"unknown counterparty {key!r}")
        before = {"notes": record.notes, "details_snapshot": record.details_snapshot}
        record.notes = notes
        record.details_snapshot = details
        record.last_seen_at = utcnow()
        self.db.commit()
        audit.append(
            agent_id="admin",
            tool="counterparty.correct",
            decision="allowed",
            action="correct",
            redacted_args={
                "key": key,
                "corrected_by": admin_id,
                "before": self._redacted_for_audit(before),
                "after": self._redacted_for_audit(
                    {"notes": notes, "details_snapshot": details}),
            },
        )
        return record

    def _redacted_for_audit(self, value: dict[str, Any]) -> dict[str, Any]:
        """Redact a correction snapshot for the audit row (GH #12)."""
        # Lazy: keeps the top-level import arrow one-way (counterparty
        # is imported by approvals/pipeline; inspection must not be
        # pulled in at module import time).
        from .inspection.redaction import RedactionCatalog, redact_value

        try:
            catalog = RedactionCatalog(self.db)
            redacted, _events = redact_value(
                value, catalog, tool="counterparty.correct", agent_id="admin")
            return redacted
        except Exception:  # noqa: BLE001 — redaction must not block the correction
            keys = sorted(value.get("details_snapshot", {}).keys()) \
                if isinstance(value, dict) else []
            return {"_redaction_failed": True, "details_keys": keys}


def counterparty_escalator(service: CounterpartyService):
    """Build the policy-stage sensitivity escalator (FR-PAA05-002).

    Returns a callable ``(agent_id, tool, args) -> Optional[str]``:
    "new_payee" / "changed_details" when a commitment-adjacent action
    targets a new or changed counterparty, else None.
    """

    def escalate(agent_id: str, tool: str, args: dict[str, Any]) -> Optional[str]:
        if tool not in COMMITMENT_ADJACENT_TOOLS:
            return None
        assessment = service.assess(tool, args or {})
        if assessment.is_new:
            return "new_payee"
        if assessment.delta:
            return "changed_details"
        return None

    return escalate
