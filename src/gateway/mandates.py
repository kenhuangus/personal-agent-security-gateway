"""Mandate service (PAA01 — Personal Mandate Drift).

- A default standing mandate is created at registration: scope-limited,
  Ken-visible (00 §4 M1 exit criteria).
- The mandate-validity check runs BEFORE any tool logic on every call
  (FR-PAA01-002). Expired / paused / withdrawn deny with DISTINCT
  reasons (Round-3 MAJOR-1): ``mandate_expired``, ``mandate_paused``,
  ``mandate_withdrawn``.
- Scope check: action classes outside the mandate's allowed classes
  deny with ``mandate_scope_exceeded`` (FR-PAA01-003).
- Delegated sub-mandates (FR-PAA01-005): must reference a parent
  ``mandate_id`` and carry equal-or-narrower scope. Read-only →
  transact transitions need a NEW mandate (FR-PAA01-008).
- Pause / narrow / end are one console action each (FR-PAA01-006).
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Iterable, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from .ids import new_mandate_id
from .models import Agent, Mandate, as_utc


def _class_matches(tool: str, allowed_classes: Iterable[str]) -> bool:
    """True if *tool* (``<connector>.<action>``) is inside the mandate's
    allowed classes. Supports ``email.*`` and ``*`` wildcards."""
    for pattern in allowed_classes:
        if pattern == "*":
            return True
        if pattern.endswith(".*"):
            if tool.split(".")[0] == pattern[:-2]:
                return True
        elif tool == pattern:
            return True
    return False


def _scope_is_narrower_or_equal(child: Iterable[str], parent: Iterable[str]) -> bool:
    child = set(child)
    parent = set(parent)
    if "*" in parent:
        return True
    if "*" in child and "*" not in parent:
        return False
    # Every child class must be covered by a parent class (wildcard-aware).
    for c in child:
        if c in parent:
            continue
        namespace = c.split(".")[0] if "." in c else c
        if f"{namespace}.*" in parent or "*" in parent:
            continue
        return False
    return True


@dataclass(frozen=True)
class MandateCheck:
    mandate: Optional[Mandate]
    ok: bool
    reason: Optional[str]  # one of mandate_expired/paused/withdrawn/scope_exceeded/missing


class MandateService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def create_mandate(
        self,
        agent_id: str,
        purpose: str,
        allowed_classes: list[str],
        expires_at: Optional[dt.datetime] = None,
        parent_mandate_id: Optional[str] = None,
        created_by: str = "admin",
        purpose_key: Optional[str] = None,
    ) -> Mandate:
        """Create a standing mandate. Delegated sub-mandates must carry
        equal-or-narrower scope than their parent (FR-PAA01-005).

        ``purpose_key`` (M2): exact key into the purpose registry for
        FR-PAA03-002 purpose-bound policy rules. None = undeclared;
        purpose-bound rules never match an undeclared mandate.
        """
        if parent_mandate_id is not None:
            parent = self.db.get(Mandate, parent_mandate_id)
            if parent is None:
                raise ValueError(f"parent mandate {parent_mandate_id!r} not found")
            if not _scope_is_narrower_or_equal(allowed_classes, parent.allowed_classes):
                raise ValueError(
                    "delegated sub-mandate must carry equal-or-narrower scope "
                    "than its parent (FR-PAA01-005)"
                )
        mandate = Mandate(
            id=new_mandate_id(),
            agent_id=agent_id,
            purpose=purpose,
            allowed_classes=allowed_classes,
            expires_at=expires_at,
            parent_mandate_id=parent_mandate_id,
            status="active",
            created_by=created_by,
            provenance="explicit",
            purpose_key=purpose_key,
        )
        self.db.add(mandate)
        self.db.commit()
        return mandate

    def create_default_mandate(self, agent: Agent) -> Mandate:
        """Default standing mandate at registration (00 §4 M1 exit).

        Scope-limited and read-only: the agent starts with read access
        only. A read-only mandate NEVER silently authorizes communicate
        or transact actions (FR-PAA01-003); stepping up to transact
        requires a NEW mandate (FR-PAA01-008).

        ``gateway.*`` (the routine ``gateway.approval_status`` meta tool,
        02 §2.5) is included: without it an agent could never poll its
        own approval requests, and the Fix-B loop could not complete.
        """
        return self.create_mandate(
            agent_id=agent.id,
            purpose=f"Default read-only mandate for {agent.display_name} ({agent.household_role})",
            allowed_classes=["email.search", "email.read", "calendar.list", "code.file.read", "gateway.*"],
            expires_at=None,
            created_by="admin",
        )

    def live_mandates(self, agent_id: str) -> list[Mandate]:
        rows = (
            self.db.execute(
                select(Mandate).where(
                    Mandate.agent_id == agent_id, Mandate.status == "active"
                )
            )
            .scalars()
            .all()
        )
        return list(rows)

    def check(self, agent_id: str, tool: str) -> MandateCheck:
        """Mandate-validity check used BEFORE any tool logic (FR-PAA01-002).

        An agent may hold several mandates (standing + delegated). The
        call is allowed when ANY live mandate covers the tool. Otherwise
        the deny reason is distinct per state (Round-3 MAJOR-1):
        withdrawn/ended -> mandate_withdrawn, expired -> mandate_expired,
        paused -> mandate_paused; live mandates with no covering scope ->
        mandate_scope_exceeded. Precedence when several mandates are
        non-live: withdrawn > ended > paused > expired.
        """
        mandates = (
            self.db.execute(select(Mandate).where(Mandate.agent_id == agent_id))
            .scalars()
            .all()
        )
        if not mandates:
            return MandateCheck(mandate=None, ok=False, reason="mandate_withdrawn")
        now = dt.datetime.now(dt.timezone.utc)
        live = [
            m
            for m in mandates
            if m.status == "active"
            and (m.expires_at is None or as_utc(m.expires_at) > now)
        ]
        for m in live:
            if _class_matches(tool, m.allowed_classes):
                return MandateCheck(mandate=m, ok=True, reason=None)
        if live:
            return MandateCheck(mandate=live[0], ok=False, reason="mandate_scope_exceeded")
        for m in mandates:
            if m.status == "withdrawn":
                return MandateCheck(mandate=m, ok=False, reason="mandate_withdrawn")
        for m in mandates:
            if m.status == "ended":
                return MandateCheck(mandate=m, ok=False, reason="mandate_withdrawn")
        for m in mandates:
            if m.status == "paused":
                return MandateCheck(mandate=m, ok=False, reason="mandate_paused")
        for m in mandates:
            if m.expires_at is not None and as_utc(m.expires_at) <= now:
                return MandateCheck(mandate=m, ok=False, reason="mandate_expired")
        return MandateCheck(mandate=None, ok=False, reason="mandate_withdrawn")

    # -- lifecycle actions (FR-PAA01-006: one-action pause / narrow / end)

    def pause(self, mandate_id: str) -> Mandate:
        m = self._get(mandate_id)
        m.status = "paused"
        self.db.commit()
        return m

    def resume(self, mandate_id: str) -> Mandate:
        m = self._get(mandate_id)
        if m.status != "paused":
            raise ValueError(f"mandate {mandate_id!r} is not paused")
        m.status = "active"
        self.db.commit()
        return m

    def narrow(self, mandate_id: str, allowed_classes: list[str]) -> Mandate:
        """Narrow a mandate's scope. Narrowing is one action; widening a
        read-only mandate toward transact requires a NEW mandate
        (FR-PAA01-008) — narrow() therefore only permits equal-or-narrower
        scope."""
        m = self._get(mandate_id)
        if not _scope_is_narrower_or_equal(allowed_classes, m.allowed_classes):
            raise ValueError(
                "narrowing only permits equal-or-narrower scope; "
                "widening requires a new mandate (FR-PAA01-008)"
            )
        m.allowed_classes = allowed_classes
        self.db.commit()
        return m

    def end(self, mandate_id: str) -> Mandate:
        """End a mandate permanently (ended state)."""
        m = self._get(mandate_id)
        m.status = "ended"
        m.ended_at = dt.datetime.now(dt.timezone.utc)
        self.db.commit()
        return m

    def withdraw(self, mandate_id: str) -> Mandate:
        """Withdraw a mandate: immediate effect (FR-PAA01-004)."""
        m = self._get(mandate_id)
        m.status = "withdrawn"
        m.ended_at = dt.datetime.now(dt.timezone.utc)
        self.db.commit()
        return m

    def _get(self, mandate_id: str) -> Mandate:
        m = self.db.get(Mandate, mandate_id)
        if m is None:
            raise ValueError(f"unknown mandate {mandate_id!r}")
        return m
