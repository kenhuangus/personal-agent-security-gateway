"""Counterparty allowlist (Pillar 1 §1.6).

Distinct from the auto-built ``counterparty_records`` (written from
audited calls, FR-PAA05-001): the allowlist is operator-curated.
Behavior matrix (enforced in ``MoneyStage``):
- listed + verified + within limits → allow-or-step-up per thresholds
- unlisted → always ``require_approval`` with card flag "new counterparty"
- ``blocked`` → hard deny ``counterparty_blocked``
- ``pending`` → ``require_approval`` (never silent allow)

Full account/routing numbers are never stored: the operator enters
last-4 only (the design's single exception to the no-last-4 rule, for
the operator's own accounts). Edits bump ``record_version`` —
freezing/expiring in-flight quorum requests via the context check
(§2.5) instead of creating policy versions.
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import CounterpartyAllowlist, as_utc, utcnow

#: Verification states.
STATE_VERIFIED = "verified"
STATE_PENDING = "pending"
STATE_BLOCKED = "blocked"

_VALID_STATES = (STATE_VERIFIED, STATE_PENDING, STATE_BLOCKED)


class AllowlistService:
    def __init__(self, db: Session) -> None:
        self.db = db

    # -- reads --------------------------------------------------------

    def lookup(
        self, namespace_id: Optional[str], payee_key: str
    ) -> Optional[CounterpartyAllowlist]:
        return self.db.execute(
            select(CounterpartyAllowlist).where(
                (
                    CounterpartyAllowlist.namespace_id.is_(None)
                    if namespace_id is None
                    else CounterpartyAllowlist.namespace_id == namespace_id
                ),
                CounterpartyAllowlist.payee_key == payee_key,
            )
        ).scalars().first()

    def list(
        self, namespace_id: Optional[str] = None, limit: int = 200
    ) -> list[CounterpartyAllowlist]:
        q = select(CounterpartyAllowlist).order_by(CounterpartyAllowlist.label.asc())
        if namespace_id is not None:
            q = q.where(CounterpartyAllowlist.namespace_id == namespace_id)
        return list(self.db.execute(q.limit(limit)).scalars().all())

    def keys(self, namespace_id: Optional[str] = None) -> set[str]:
        return {r.payee_key for r in self.list(namespace_id)}

    # -- writes (admin-only; console; audit-logged by the caller) -------

    def add(
        self,
        *,
        payee_key: str,
        label: str,
        namespace_id: Optional[str] = None,
        details_snapshot: Optional[dict] = None,
        verification_state: str = STATE_PENDING,
        verified_by: Optional[str] = None,
        notes: str = "",
    ) -> CounterpartyAllowlist:
        if verification_state not in _VALID_STATES:
            raise ValueError(f"unknown verification state {verification_state!r}")
        existing = self.lookup(namespace_id, payee_key)
        if existing is not None:
            raise ValueError(f"payee {payee_key!r} already allowlisted")
        row = CounterpartyAllowlist(
            namespace_id=namespace_id,
            payee_key=payee_key,
            label=label,
            details_snapshot=details_snapshot or {},
            verification_state=verification_state,
            verified_by=verified_by,
            verified_at=(
                utcnow() if verification_state == STATE_VERIFIED else None
            ),
            record_version=1,
            notes=notes,
        )
        self.db.add(row)
        self.db.commit()
        return row

    def set_verification(
        self,
        *,
        namespace_id: Optional[str],
        payee_key: str,
        verification_state: str,
        verified_by: str,
    ) -> CounterpartyAllowlist:
        if verification_state not in _VALID_STATES:
            raise ValueError(f"unknown verification state {verification_state!r}")
        row = self.lookup(namespace_id, payee_key)
        if row is None:
            raise ValueError(f"payee {payee_key!r} not allowlisted")
        row.verification_state = verification_state
        row.verified_by = verified_by
        row.verified_at = utcnow()
        row.record_version += 1
        self.db.commit()
        return row

    def record_version_of(
        self, namespace_id: Optional[str], payee_key: str
    ) -> Optional[int]:
        row = self.lookup(namespace_id, payee_key)
        return row.record_version if row is not None else None

    @staticmethod
    def as_of(row: Optional[CounterpartyAllowlist]) -> dict:
        """Card-safe rendering: state + last-4 details only."""
        if row is None:
            return {"listed": False}
        return {
            "listed": True,
            "label": row.label,
            "verification_state": row.verification_state,
            "verified_by": row.verified_by,
            "verified_at": (
                (as_utc(row.verified_at) or row.verified_at).isoformat()
                if row.verified_at
                else None
            ),
            "details_snapshot": row.details_snapshot or {},
            "record_version": row.record_version,
        }
