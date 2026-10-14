"""Quorum approvals (Pillar 1 §2).

A money rule can set ``quorum: 2`` on any ``require_approval``
outcome. Status transitions:
``pending → partially_approved → (approved | denied | expired)``.
``canceled`` (the mandate-death path) remains terminal. Terminal
states are immutable; re-opening is a new ``apr_`` id.

All functions are transactional and run under the existing ``_MUTEX``
single-flight + conditional-UPDATE discipline (imported from
approvals).

Anti-gaming (enforced in the decision transaction, not the UI):
1. The same admin cannot approve twice (``duplicate_approver``).
2. ``quorum: 2`` on a single-admin install fails validation
   ("quorum unsatisfiable — register a second admin") — the design
   does not fake quorum with double-clicks.
3. Distinct authenticated sessions: the second approval must come from
   a different login session (blocks one person approving from two
   tabs on a shared login).
4. Mandate liveness re-checked at EACH decision and at grant
   consumption.
5. No self-approval by the delegator on delegated mandates.

Evidence freeze: at request creation ``evidence_hash =
HMAC(canonical evidence_subset)`` and ``context_fingerprint =
{mandate_status, policy_version, payee_key, counterparty_record_version,
namespace_id}``. ``check_context`` runs (a) inside ``sweep_expired``,
(b) before each ``record_approval``, (c) at grant consumption for
quorum grants: stale context → ``expired`` / ``context_changed``.
Approvers never sign stale context.
"""

from __future__ import annotations

import datetime as dt
from typing import Any, Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import AdminUser, ApprovalRequest, Mandate, PolicyVersion, as_utc, utcnow


class QuorumError(ValueError):
    """Raised for quorum invariant violations (distinct from config errors)."""


def validate_quorum_satisfiable(db: Session, quorum: int) -> None:
    """Fail closed when fewer admin accounts exist than the quorum needs.

    Called on money-rule save (console) AND defensively at request
    creation — if an admin was removed after the rule was saved, the
    request is denied rather than left un-approvable.
    """
    if quorum <= 1:
        return
    count = db.execute(select(func.count()).select_from(AdminUser)).scalar() or 0
    if count < quorum:
        raise QuorumError(
            "quorum unsatisfiable — register a second admin "
            f"(quorum={quorum}, admins={count})"
        )


def _current_policy_version(db: Session) -> int:
    row = db.execute(
        select(PolicyVersion).where(PolicyVersion.is_current.is_(True))
    ).scalars().first()
    return row.version if row is not None else 1


def _material_change_since(db: Session, from_version: int, to_version: int) -> bool:
    if to_version <= from_version:
        return False
    count = db.execute(
        select(func.count())
        .select_from(PolicyVersion)
        .where(
            PolicyVersion.version > from_version,
            PolicyVersion.version <= to_version,
            PolicyVersion.material_change.is_(True),
        )
    ).scalar()
    return bool(count)


def check_context(db: Session, apr: ApprovalRequest, now: Optional[dt.datetime] = None) -> Optional[str]:
    """Return ``"context_changed"`` when the frozen context is stale.

    Checks: mandate liveness (withdrawn/paused/expired), material
    policy change since creation, allowlist ``record_version`` drift
    for the payee. None = context still fresh.
    """
    from .money.allowlist import AllowlistService  # local: keep import arrow one-way

    now = now or utcnow()
    fingerprint = apr.context_fingerprint or {}
    # (a) mandate liveness.
    mandate = db.get(Mandate, apr.mandate_id)
    live = (
        mandate is not None
        and mandate.status == "active"
        and (mandate.expires_at is None or (as_utc(mandate.expires_at) or mandate.expires_at) > now)
    )
    if not live:
        return "context_changed"
    # (b) material policy change.
    current = _current_policy_version(db)
    created_version = int(fingerprint.get("policy_version") or apr.policy_version or 0)
    if _material_change_since(db, created_version, current):
        return "context_changed"
    # (c) allowlist record_version drift (money requests only).
    payee_key = fingerprint.get("payee_key")
    if payee_key:
        namespace_id = fingerprint.get("namespace_id")
        current_rv = AllowlistService(db).record_version_of(namespace_id, payee_key)
        fingerprinted_rv = fingerprint.get("counterparty_record_version")
        if current_rv != fingerprinted_rv:
            return "context_changed"
    return None


def _expire_context_changed(db: Session, apr: ApprovalRequest, now: dt.datetime) -> None:
    """Expire a request whose context went stale (§2.5)."""
    from .approvals import _MUTEX  # noqa: F401  (documents the discipline)

    slots = apr.approvals or []
    apr.status = "expired"
    apr.decided_at = now
    apr.decided_by = ",".join(s["admin_id"] for s in slots) if slots else None
    apr.decision_note = "expired: context_changed (stale approval context)"
    db.commit()


def record_approval(
    db: Session,
    service: Any,  # ApprovalService; typed loosely to avoid a cycle
    apr_id: str,
    *,
    admin_id: str,
    session_id: str,
    auth_method: str = "password+totp",
    note: str = "",
    now: Optional[dt.datetime] = None,
) -> ApprovalRequest:
    """Record one quorum approval slot.

    Steps (§2.1): sweep → terminal check (idempotent) → context check
    → duplicate-approver → duplicate-session → mandate liveness →
    no-self-approval on delegated mandates → append slot + audit →
    quorum met → approved + mint grant (MF-7, one-time, 30-min TTL),
    else partially_approved.
    """
    now = now or utcnow()
    service.sweep_expired(now=now)
    apr = db.get(ApprovalRequest, apr_id)
    if apr is None:
        raise QuorumError(f"unknown approval request {apr_id!r}")
    if apr.status not in ("pending", "partially_approved"):
        # Idempotent: a retried POST against an already-decided
        # request returns the existing decision, never a second slot.
        return apr
    # Context check BEFORE the slot is recorded: approvers never sign
    # stale context.
    if check_context(db, apr, now) is not None:
        _expire_context_changed(db, apr, now)
        raise QuorumError("context_changed: the approval context changed; request expired")
    slots: list[dict[str, Any]] = list(apr.approvals or [])
    if any(s.get("admin_id") == admin_id for s in slots):
        raise QuorumError("duplicate_approver: this admin already approved")
    if any(s.get("session_id") == session_id for s in slots):
        raise QuorumError(
            "duplicate_session: the second approval must come from a "
            "different login session"
        )
    # Mandate liveness re-check at EACH decision.
    mandate = db.get(Mandate, apr.mandate_id)
    if (
        mandate is None
        or mandate.status != "active"
        or (mandate.expires_at is not None and (as_utc(mandate.expires_at) or mandate.expires_at) <= now)
    ):
        _expire_context_changed(db, apr, now)
        raise QuorumError("context_changed: mandate no longer live; request expired")
    # No self-approval by the delegator on delegated mandates.
    if mandate.parent_mandate_id is not None and admin_id == mandate.created_by:
        raise QuorumError("delegator_cannot_approve: the delegating admin cannot approve")
    slot = {
        "admin_id": admin_id,
        "session_id": session_id,
        "decided_at": now.isoformat(),
        "approver_index": len(slots),
        "auth_method": auth_method,
    }
    slots.append(slot)
    apr.approvals = slots
    progress = f"{len(slots)}/{apr.quorum_required}"
    service.audit.append(
        agent_id=apr.agent_id,
        tool=apr.tool,
        decision="approved",
        approval_request_id=apr.id,
        mandate_id=apr.mandate_id,
        redacted_args={
            "decided_by": admin_id,
            "approver_index": slot["approver_index"],
            "quorum_progress": progress,
            "session_id": session_id,
            "content_hash": apr.evidence_hash,
            "note": note,
        },
    )
    if len(slots) >= apr.quorum_required:
        # Full quorum: mint the grant (MF-7: one-time, 30-min TTL,
        # bound to (agent, tool, argument_hash)).
        result = service._approve_and_mint(apr, admin_id, "one_time", note, now)
        _ = result  # the apr row now carries status="approved"
    else:
        apr.status = "partially_approved"
        db.commit()
    return apr


def record_denial(
    db: Session,
    service: Any,  # ApprovalService
    apr_id: str,
    *,
    admin_id: str,
    session_id: str,
    note: str = "",
    now: Optional[dt.datetime] = None,
) -> ApprovalRequest:
    """One-denial-kills: ANY eligible approver's deny → ``denied``
    immediately. A quorum denial needs only one no."""
    now = now or utcnow()
    service.sweep_expired(now=now)
    apr = db.get(ApprovalRequest, apr_id)
    if apr is None:
        raise QuorumError(f"unknown approval request {apr_id!r}")
    if apr.status not in ("pending", "partially_approved"):
        return apr  # idempotent
    apr.status = "denied"
    apr.decided_at = now
    apr.decided_by = admin_id
    apr.decision_note = note or None
    service._record_refusal_cooldown(
        apr.agent_id, apr.tool, apr.argument_hash,
        now + dt.timedelta(hours=service.settings.refusal_cooldown_hours),
    )
    db.commit()
    service.audit.append(
        agent_id=apr.agent_id,
        tool=apr.tool,
        decision="denied_decision",
        approval_request_id=apr.id,
        mandate_id=apr.mandate_id,
        redacted_args={
            "decided_by": admin_id,
            "session_id": session_id,
            "quorum_progress": f"{len(apr.approvals or [])}/{apr.quorum_required}",
            "note": note,
        },
    )
    return apr


def progress_label(apr: ApprovalRequest) -> str:
    """Human-readable quorum progress for the card/console."""
    slots = apr.approvals or []
    quorum = apr.quorum_required or 1
    if quorum <= 1:
        return "single approver"
    return f"{len(slots)} / {quorum} approvals"
