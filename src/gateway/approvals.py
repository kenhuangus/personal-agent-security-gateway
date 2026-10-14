"""Step-up approval workflow (Fix B; 02 §2.8; 00 §4 M3).

- ``ApprovalService``: the approval-request lifecycle — idempotent
  creation per the 02 §2.8 step-3 lookup order (pending dedupe →
  already-executed → refusal cooldown → denial-streak escalation →
  queue cap → create), console decisions (approve/deny, one-time
  scope, idempotent), expiry sweeps, and the caller-bound
  ``gateway.approval_status`` read path.
- ``GrantService``: one-time grants bound to (agent, tool,
  argument-hash). Grant lookup runs BEFORE rule evaluation via the
  ``PolicyEngine(grant_checker=...)`` seam (MF-7): live-mandate
  re-check at consumption (withdrawn→``mandate_withdrawn``,
  expired→``mandate_expired``, paused→``mandate_paused``, each
  audit-logged; remaining unconsumed grants under a dead mandate are
  invalidated), policy-supersession check (material change →
  ``policy_superseded``), atomic compare-and-consume (first concurrent
  re-invoke wins, the second gets ``already_executed``). 30-minute TTL
  from approval (00 §7 param 21). Agent revocation kills grants
  immediately (via ``kill_agent_grants``).
- ``ApprovalStage``: replaces the pipeline stub — runs the service
  when the policy stage flagged ``ctx.needs_approval``.
- ``make_approval_status_tool``: the ``gateway.approval_status`` meta
  tool descriptor (caller-bound, own rate budget, audit carve-out).
- ``UnknownOutcomeService``: FR-PAA06-003 retry gate — a timed-out /
  ambiguous call blocks automatic retry of the identical call until
  the console resolves it (status check via the connector's
  ``transaction_status`` capability where one exists).

Concurrency note (03 §1.3 logical-in-MVP): the gateway is a single
stateful process in MVP. Grant consumption is guarded BOTH by a
module-level lock (single-flight in-process) AND by a conditional
``UPDATE ... WHERE consumed = false`` (the DB-level backstop, correct
under real concurrency). Physical distribution would need a real
distributed lock; the UPDATE guard already expresses the invariant.
"""

from __future__ import annotations

import copy
import datetime as dt
import threading
from dataclasses import dataclass
from typing import Any, Callable, Optional

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from .approval_card import (
    build_evidence_subset,
    build_replay_args,
    redact_code_like_secrets,
)
from .audit import AuditLog
from .config import Settings
from .counterparty import CounterpartyService
from .errors import GatewayError, ToolHalt, invalid_input, make_error
from .hmac_util import HmacKeyRing
from .ids import is_valid_id, new_approval_id
from .judge.counterparty_hook import judge_signals_for_approval_record
from .judge.risk import judge_risk_for_approval_record
from .mandates import MandateService
from .models import (
    ApprovalRequest,
    Grant,
    Mandate,
    PolicyVersion,
    RefusalCooldown,
    UnknownOutcomeBlock,
    as_utc,
    utcnow,
)

# ---------------------------------------------------------------------
# Destructive-action registry (02 §2.7): 5-minute approval window and
# per-decision re-auth/confirmation token (FR-042).
# ---------------------------------------------------------------------

DESTRUCTIVE_TOOLS: frozenset[str] = frozenset({
    "calendar.delete",
    "email.settings.write",
})

#: MVP grant scope vocabulary (02 §2.6): one-time only. Windowed grants
#: are deferred post-MVP (00 §3).
GRANT_SCOPE_ONE_TIME = "one_time"

# Single-flight for grant consumption + approval creation (see module
# docstring: the conditional UPDATE is the real invariant).
_MUTEX = threading.RLock()


def _iso(value: Optional[dt.datetime]) -> Optional[str]:
    if value is None:
        return None
    return (as_utc(value) or value).isoformat()


# ---------------------------------------------------------------------
# Grant check result (the M3 shape of the PolicyEngine grant_checker
# seam; plain-str returns keep the M2 shape working).
# ---------------------------------------------------------------------

@dataclass
class GrantCheckResult:
    allowed: bool
    approval_request_id: str = ""
    mandate_id: str = ""
    policy_version: int = 0
    # Safe-vocabulary deny reason (mandate_withdrawn / mandate_expired /
    # mandate_paused / policy_superseded) when allowed is False.
    deny_reason: Optional[str] = None
    # Terminal agent-visible code (already_executed) when allowed is False.
    terminal_code: Optional[str] = None


def _current_policy_version(db: Session) -> int:
    row = db.execute(
        select(PolicyVersion).where(PolicyVersion.is_current.is_(True))
    ).scalars().first()
    return row.version if row is not None else 1


def policy_materially_superseded(db: Session, since_version: int) -> bool:
    """True when a MATERIAL policy version newer than ``since_version``
    exists (FR-PAA04-003).

    Shared by the grant path (``GrantService._superseded``) and the
    MF-11 server-side replay (``pipeline.execute_approved_call``, GH #23):
    both consumption paths of an approval use the same semantics, so a
    non-material edit (rename, reorder, note) never blocks execution
    while a material change always does.
    """
    current = _current_policy_version(db)
    if since_version >= current:
        return False
    material = db.execute(
        select(func.count())
        .select_from(PolicyVersion)
        .where(
            PolicyVersion.version > since_version,
            PolicyVersion.version <= current,
            PolicyVersion.material_change.is_(True),
        )
    ).scalar()
    return bool(material)


class GrantService:
    """One-time grant store + the grant_checker seam implementation."""

    def __init__(
        self,
        db: Session,
        audit: AuditLog,
        clock: Callable[[], dt.datetime] | None = None,
    ) -> None:
        self.db = db
        self.audit = audit
        self._clock = clock or utcnow

    # -- the PolicyEngine seam ----------------------------------------

    def check(
        self, agent_id: str, tool: str, argument_hash: str, db: Optional[Session] = None
    ) -> Optional[GrantCheckResult]:
        """Grant lookup BEFORE rule evaluation (Fix B, MF-7).

        Returns None when no grant covers the call (→ normal rule
        evaluation). Otherwise consumes atomically or denies with a
        named reason.
        """
        db = db or self.db
        now = self._clock()
        with _MUTEX:
            grant = db.execute(
                select(Grant).where(
                    Grant.agent_id == agent_id,
                    Grant.tool == tool,
                    Grant.argument_hash == argument_hash,
                    Grant.consumed.is_(False),
                    Grant.invalidated.is_(False),
                )
            ).scalars().first()
            if grant is None:
                return None
            if (as_utc(grant.expires_at) or grant.expires_at) <= now:
                # Expired grant: no match → the call re-enters the
                # standard flow (fresh approval_request, never a silent
                # re-execution).
                return None
            # Live-mandate re-check at consumption (BLOCKER-1,
            # FR-PAA01-004): the grant's mandate, not just the call's.
            mandate = db.get(Mandate, grant.mandate_id)
            dead_reason = _mandate_dead_reason(mandate, now)
            if dead_reason is not None:
                self.invalidate_mandate_grants(grant.mandate_id, db)
                self.audit.append(
                    agent_id=agent_id,
                    tool=tool,
                    decision="denied",
                    reason=dead_reason,
                    approval_request_id=grant.approval_request_id,
                    mandate_id=grant.mandate_id,
                    redacted_args={"grant_invalidated": True},
                )
                db.commit()
                return GrantCheckResult(
                    allowed=False,
                    approval_request_id=grant.approval_request_id,
                    mandate_id=grant.mandate_id,
                    deny_reason=dead_reason,
                )
            # Policy-supersession check (FR-PAA04-003): a MATERIAL
            # change since issuance denies with policy_superseded;
            # non-material changes preserve the grant.
            if self._superseded(grant, db):
                self.audit.append(
                    agent_id=agent_id,
                    tool=tool,
                    decision="denied",
                    reason="policy_superseded",
                    approval_request_id=grant.approval_request_id,
                    mandate_id=grant.mandate_id,
                    redacted_args={"grant_policy_version": grant.policy_version},
                )
                db.commit()
                return GrantCheckResult(
                    allowed=False,
                    approval_request_id=grant.approval_request_id,
                    mandate_id=grant.mandate_id,
                    deny_reason="policy_superseded",
                )
            # Atomic compare-and-consume: the UPDATE only matches an
            # unconsumed, uninvalidated row. Concurrent re-invokes:
            # first wins, second sees rowcount 0 → already_executed.
            res = db.execute(
                update(Grant)
                .where(
                    Grant.id == grant.id,
                    Grant.consumed.is_(False),
                    Grant.invalidated.is_(False),
                )
                .values(consumed=True, consumed_at=now)
            )
            db.commit()
            if res.rowcount != 1:
                return GrantCheckResult(
                    allowed=False,
                    approval_request_id=grant.approval_request_id,
                    mandate_id=grant.mandate_id,
                    terminal_code="already_executed",
                )
            return GrantCheckResult(
                allowed=True,
                approval_request_id=grant.approval_request_id,
                mandate_id=grant.mandate_id,
                policy_version=grant.policy_version,
            )

    # -- invalidation --------------------------------------------------

    def invalidate_mandate_grants(self, mandate_id: str, db: Optional[Session] = None) -> int:
        """Invalidate all remaining unconsumed grants under a mandate
        (FR-PAA01-004: withdrawal/expiry/pause kills approved-but-
        unconsumed grants)."""
        db = db or self.db
        res = db.execute(
            update(Grant)
            .where(
                Grant.mandate_id == mandate_id,
                Grant.consumed.is_(False),
                Grant.invalidated.is_(False),
            )
            .values(invalidated=True)
        )
        db.flush()
        return res.rowcount or 0

    def kill_agent_grants(self, agent_id: str) -> int:
        """Agent revocation kills grants immediately (Fix B)."""
        res = self.db.execute(
            update(Grant)
            .where(
                Grant.agent_id == agent_id,
                Grant.consumed.is_(False),
                Grant.invalidated.is_(False),
            )
            .values(invalidated=True)
        )
        self.db.commit()
        return res.rowcount or 0

    def _superseded(self, grant: Grant, db: Session) -> bool:
        return policy_materially_superseded(db, grant.policy_version)


def _mandate_dead_reason(mandate: Optional[Mandate], now: dt.datetime) -> Optional[str]:
    """Distinct deny reasons per mandate state (Round-3 MAJOR-1)."""
    if mandate is None:
        return "mandate_withdrawn"
    if mandate.status in ("withdrawn", "ended"):
        return "mandate_withdrawn"
    if mandate.status == "paused":
        return "mandate_paused"
    if mandate.expires_at is not None and (as_utc(mandate.expires_at) or mandate.expires_at) <= now:
        return "mandate_expired"
    return None


# ---------------------------------------------------------------------
# Unknown-outcome retry gate (FR-PAA06-003; 02 §2.7).
# ---------------------------------------------------------------------

class UnknownOutcomeService:
    """Blocks automatic retry after a timeout/ambiguous call outcome.

    The block is keyed by (agent, tool, argument-hash) and resolved
    via the console — after a status check through the connector's
    ``transaction_status`` capability where one exists
    (``MockGmail.transaction_status`` in tests), or by Ken's explicit
    confirmation otherwise.
    """

    def __init__(self, db: Session) -> None:
        self.db = db

    def record_block(
        self, agent_id: str, tool: str, argument_hash: str, detail: str
    ) -> UnknownOutcomeBlock:
        existing = self.find_unresolved(agent_id, tool, argument_hash)
        if existing is not None:
            return existing
        block = UnknownOutcomeBlock(
            agent_id=agent_id, tool=tool, argument_hash=argument_hash, detail=detail[:500]
        )
        self.db.add(block)
        self.db.commit()
        return block

    def find_unresolved(
        self, agent_id: str, tool: str, argument_hash: str
    ) -> Optional[UnknownOutcomeBlock]:
        return self.db.execute(
            select(UnknownOutcomeBlock).where(
                UnknownOutcomeBlock.agent_id == agent_id,
                UnknownOutcomeBlock.tool == tool,
                UnknownOutcomeBlock.argument_hash == argument_hash,
                UnknownOutcomeBlock.resolved_at.is_(None),
            )
        ).scalars().first()

    def list_unresolved(self, limit: int = 100) -> list[UnknownOutcomeBlock]:
        return list(
            self.db.execute(
                select(UnknownOutcomeBlock)
                .where(UnknownOutcomeBlock.resolved_at.is_(None))
                .order_by(UnknownOutcomeBlock.created_at.desc())
                .limit(limit)
            ).scalars().all()
        )

    def resolve(self, block_id: int, note: str, audit: AuditLog) -> UnknownOutcomeBlock:
        block = self.db.get(UnknownOutcomeBlock, block_id)
        if block is None:
            raise ValueError(f"unknown outcome block {block_id!r}")
        if block.resolved_at is not None:
            return block
        block.resolved_at = utcnow()
        block.resolve_note = note
        self.db.commit()
        audit.append(
            agent_id="admin",
            tool="unknown_outcome.resolve",
            decision="allowed",
            action="resolve",
            redacted_args={
                "block_id": block_id,
                "agent_id": block.agent_id,
                "tool": block.tool,
                "note": note,
            },
        )
        return block


# ---------------------------------------------------------------------
# M3-minimal full-argument redaction (the evidence-subset record).
#
# 02 §2.8 step 4 stores the full argument set REDACTED. The full
# catalog (email/phone/SSN/account-number patterns, console-editable)
# is M5's (NFR-DATA-001/AC-07); M3 redacts code-like secrets
# (verification codes, OTPs, API-key-shaped strings — FR-PAA02-001)
# and stores everything else structurally. Documented here so the
# seam hardens without a schema change.
# ---------------------------------------------------------------------

def redact_full_args(args: dict[str, Any]) -> dict[str, Any]:
    def walk(value: Any) -> Any:
        if isinstance(value, str):
            return redact_code_like_secrets(value)
        if isinstance(value, list):
            return [walk(v) for v in value]
        if isinstance(value, dict):
            return {k: walk(v) for k, v in value.items()}
        return value

    return walk(copy.deepcopy(args or {}))


# ---------------------------------------------------------------------
# ApprovalService
# ---------------------------------------------------------------------

class ApprovalService:
    """The approval-request lifecycle (02 §2.8)."""

    def __init__(
        self,
        db: Session,
        audit: AuditLog,
        settings: Settings,
        hmac_ring: Optional[HmacKeyRing],
        mandates: MandateService,
        notifier: Any | None = None,  # Notifier; loose to avoid import weight
        counterparty: Optional[CounterpartyService] = None,
        confirmations: Any | None = None,  # ConfirmationTokenIssuer (console.csrf)
        clock: Callable[[], dt.datetime] | None = None,
    ) -> None:
        self.db = db
        self.audit = audit
        self.settings = settings
        self.ring = hmac_ring
        self.mandates = mandates
        self.notifier = notifier
        self.counterparty = counterparty or CounterpartyService(db)
        self.confirmations = confirmations
        self._clock = clock or utcnow
        self.grants = GrantService(db, audit, clock=self._clock)
        self.unknown_outcome = UnknownOutcomeService(db)
        # Execute-on-approval executor: wired by the console/pipeline
        # (needs the connector registry + minter). Signature:
        #   (agent_id, tool, args, approval_request_id, policy_version,
        #    mandate_id) -> {"ok": bool, ...}
        self.executor: Optional[Callable[..., dict[str, Any]]] = None

    # -- step-3 lookup chain + creation (02 §2.8 steps 3–4) --------------

    def request_approval(self, ctx: Any) -> GatewayError:
        """Run the step-3 lookup order EXACTLY, then create-or-return.

        Always halts the pipeline: a sensitive call never proceeds
        without a consumed grant. Validate-first (MF-4) is structural —
        this stage runs after ValidateInputsStage in the fixed order.
        """
        if self.ring is None or ctx.argument_hash is None:
            raise RuntimeError(
                "approval flow requires the HMAC ring (GATEWAY_HMAC_KEY); "
                "refusing to create approval requests without keyed hashing"
            )
        now = self._clock()
        arg_hash = ctx.argument_hash
        with _MUTEX:
            self.sweep_expired(now=now)
            # (a) Pending dedupe → existing apr_ id (before the cap check,
            # so an at-cap agent re-submitting gets the id, not
            # approval_queue_full).
            existing = self._pending_request(ctx.agent_id, ctx.tool, arg_hash)
            if existing is not None:
                ctx.approval_request_id = existing.id
                return self._approval_required(ctx, existing)
            # (b) Consumed grant → already_executed: terminal, no new
            # request, no re-execution, no notification.
            grant = self.db.execute(
                select(Grant).where(
                    Grant.agent_id == ctx.agent_id,
                    Grant.tool == ctx.tool,
                    Grant.argument_hash == arg_hash,
                    Grant.consumed.is_(True),
                )
            ).scalars().first()
            if grant is not None:
                return make_error(
                    "already_executed",
                    f"{ctx.tool}: this exact call already executed; re-invoking "
                    "does not re-execute",
                    ctx.request_id,
                    {"tool": ctx.tool, "reason": "already_executed"},
                )
            # (c) Refusal cooldown (agent, tool, argument-hash).
            cooldown = self.db.execute(
                select(RefusalCooldown).where(
                    RefusalCooldown.agent_id == ctx.agent_id,
                    RefusalCooldown.tool == ctx.tool,
                    RefusalCooldown.argument_hash == arg_hash,
                )
            ).scalars().first()
            if cooldown is not None and (as_utc(cooldown.expires_at) or cooldown.expires_at) > now:
                retry_after = int(((as_utc(cooldown.expires_at) or cooldown.expires_at) - now).total_seconds())
                return make_error(
                    "cooldown_active",
                    f"{ctx.tool}: identical request denied during the refusal cooldown",
                    ctx.request_id,
                    {"tool": ctx.tool, "reason": "cooldown_active",
                     "retry_after": max(retry_after, 0)},
                )
            # (d) Denial-streak escalation: ≥3 denied/expired sensitive
            # for (agent, tool)/24h → pair-level cooldown regardless of
            # arguments (FR-PAA09-003).
            if self._denial_streak_hit(ctx.agent_id, ctx.tool, now):
                return make_error(
                    "cooldown_active",
                    f"{ctx.tool}: denial-streak cooldown active for this agent and tool",
                    ctx.request_id,
                    {"tool": ctx.tool, "reason": "cooldown_active"},
                )
            # Queue cap (after the lookups, per 02 §2.8 step 4).
            if self.pending_count(ctx.agent_id) >= self.settings.approval_queue_cap:
                return make_error(
                    "approval_queue_full",
                    f"{ctx.tool}: per-agent pending-approval cap "
                    f"({self.settings.approval_queue_cap}) reached",
                    ctx.request_id,
                    {"tool": ctx.tool, "reason": "approval_queue_full"},
                )
            return self._create_request(ctx, now, arg_hash)

    def _create_request(self, ctx: Any, now: dt.datetime, arg_hash: str) -> GatewayError:
        assert self.ring is not None
        destructive = ctx.tool in DESTRUCTIVE_TOOLS
        window_minutes = (
            self.settings.destructive_approval_window_minutes
            if destructive
            else self.settings.approval_window_minutes
        )
        evidence = build_evidence_subset(ctx.tool, ctx.args, self.ring)
        # Counterparty snapshot at creation time (FR-PAA05-003): the
        # card shows the delta vs the record AS OF the request.
        assessment = self.counterparty.assess(ctx.tool, ctx.args)
        evidence["counterparty"] = {
            "key": assessment.key,
            "known": assessment.known,
            "is_new": assessment.is_new,
            "delta": assessment.delta,
            "record": (
                {
                    "call_count": assessment.record.call_count,
                    "last_seen_at": _iso(assessment.record.last_seen_at),
                    "notes": assessment.record.notes,
                }
                if assessment.record is not None
                else None
            ),
            # Claim source: the message/document that triggered the call
            # (FR-PAA05-003). Not captured as structured metadata in
            # MVP — stated, never invented (FR-PAA05-005).
            "claim_source": "not provided in MVP",
        }
        # Judge advisory signals (additive; mirrors the
        # urgency_flags_for_approval_record() pattern): the risk
        # assessment and counterparty signals ride on the record so
        # the card can render them. Stored only when the judge scored
        # this call; the deterministic evidence is untouched.
        judge_risk = judge_risk_for_approval_record(ctx)
        if judge_risk is not None:
            evidence["judge_risk"] = judge_risk
        judge_cp_signals = judge_signals_for_approval_record(ctx)
        if judge_cp_signals is not None:
            evidence["counterparty"]["judge_signals"] = judge_cp_signals
        if ctx.mandate is None:
            raise RuntimeError("approval requested without a live mandate (unreachable)")
        apr = ApprovalRequest(
            id=new_approval_id(),
            agent_id=ctx.agent_id,
            mandate_id=ctx.mandate.id,
            tool=ctx.tool,
            policy_version=ctx.policy_version,
            argument_hash=arg_hash,
            evidence_subset=evidence,
            redacted_args=redact_full_args(ctx.args),
            status="pending",
            expires_at=now + dt.timedelta(minutes=window_minutes),
            # M6 checklist (d): ontology decision-snapshot ref + the
            # deciding-entry citation ride on the approval record so the
            # card and audit timeline can cite them (PAA04).
            ontology_snapshot_ref=getattr(ctx, "ontology_snapshot_ref", None),
            ontology_ref=getattr(ctx, "ontology_ref", None),
        )
        self.db.add(apr)
        self.db.commit()
        # Link the paused-call audit row to this request (the pipeline's
        # terminal audit stage reads ctx.approval_request_id).
        ctx.approval_request_id = apr.id
        # Exempt notification path (02 §2.8 step 5) — never the
        # policy-gated email.send connector.
        if self.notifier is not None:
            agent_name = getattr(ctx.agent, "display_name", None) or ctx.agent_id
            self.notifier.notify_new_request(
                agent_id=ctx.agent_id,
                agent_name=agent_name,
                tool_name=ctx.tool,
                approval_id=apr.id,
                created_at=now,
            )
        return self._approval_required(ctx, apr)

    @staticmethod
    def _approval_required(ctx: Any, apr: ApprovalRequest) -> GatewayError:
        details: dict[str, Any] = {
            "approval_request_id": apr.id,
            "expires_at": _iso(apr.expires_at),
            "tool": ctx.tool,
        }
        # M6 checklist (d): the envelope already supports ontology_ref
        # (no errors.py change needed); copy it when present.
        ontology_ref = getattr(ctx, "ontology_ref", None)
        if ontology_ref is not None:
            details["ontology_ref"] = ontology_ref
        return make_error(
            "approval_required",
            f"{ctx.tool} is sensitive. Approval requested ({apr.id}). "
            "Poll gateway.approval_status or wait for the admin.",
            ctx.request_id,
            details,
        )

    # -- lookups ---------------------------------------------------------

    def _pending_request(
        self, agent_id: str, tool: str, argument_hash: str
    ) -> Optional[ApprovalRequest]:
        return self.db.execute(
            select(ApprovalRequest).where(
                ApprovalRequest.agent_id == agent_id,
                ApprovalRequest.tool == tool,
                ApprovalRequest.argument_hash == argument_hash,
                ApprovalRequest.status == "pending",
            )
        ).scalars().first()

    def pending_count(self, agent_id: str) -> int:
        return self.db.execute(
            select(func.count())
            .select_from(ApprovalRequest)
            .where(
                ApprovalRequest.agent_id == agent_id,
                ApprovalRequest.status == "pending",
            )
        ).scalar() or 0

    def pending_for_agent(self, agent_id: str, limit: int = 100) -> list[ApprovalRequest]:
        return list(
            self.db.execute(
                select(ApprovalRequest)
                .where(
                    ApprovalRequest.agent_id == agent_id,
                    ApprovalRequest.status == "pending",
                )
                .order_by(ApprovalRequest.created_at.asc())
                .limit(limit)
            ).scalars().all()
        )

    def history(self, limit: int = 100) -> list[ApprovalRequest]:
        return list(
            self.db.execute(
                select(ApprovalRequest)
                .where(ApprovalRequest.status != "pending")
                .order_by(ApprovalRequest.decided_at.desc())
                .limit(limit)
            ).scalars().all()
        )

    def cancel_mandate_requests(
        self, mandate_id: str, *, reason: str = "mandate_dead", admin_id: str = "admin_ken"
    ) -> list[str]:
        """Cancel every PENDING approval request under a mandate (FR-PAA01-004).

        Used when a mandate is paused/ended/withdrawn: queued approvals
        die with it, each recorded as canceled and audit-logged. Grants
        under the mandate are invalidated separately via
        GrantService.invalidate_mandate_grants. Returns the canceled
        request ids (per-item status for the console, FR-PAA10-003).
        """
        now = self._clock()
        rows = self.db.execute(
            select(ApprovalRequest).where(
                ApprovalRequest.mandate_id == mandate_id,
                ApprovalRequest.status == "pending",
            )
        ).scalars().all()
        canceled: list[str] = []
        for apr in rows:
            apr.status = "canceled"
            apr.decided_at = now
            apr.decided_by = admin_id
            apr.decision_note = f"canceled: {reason}"
            canceled.append(apr.id)
            self.audit.append(
                agent_id=apr.agent_id,
                tool=apr.tool,
                decision="denied_decision",
                reason="mandate_canceled",
                mandate_id=mandate_id,
                request_id=apr.id,
                approval_request_id=apr.id,
                redacted_args={"cancel_reason": reason},
            )
        self.db.commit()
        return canceled

    def _denial_streak_hit(self, agent_id: str, tool: str, now: dt.datetime) -> bool:
        window_start = now - dt.timedelta(hours=self.settings.denial_streak_window_hours)
        count = self.db.execute(
            select(func.count())
            .select_from(ApprovalRequest)
            .where(
                ApprovalRequest.agent_id == agent_id,
                ApprovalRequest.tool == tool,
                ApprovalRequest.status.in_(["denied", "expired"]),
                ApprovalRequest.decided_at >= window_start,
            )
        ).scalar() or 0
        return count >= self.settings.denial_streak_threshold

    # -- expiry sweep (step 10: timeout) ----------------------------------

    def sweep_expired(self, now: Optional[dt.datetime] = None) -> int:
        """Mark lapsed pendings expired. Timeouts record the refusal
        cooldown and increment the denial counter like denies (M3:
        step 10 covers deny AND timeout)."""
        now = now or self._clock()
        rows = self.db.execute(
            select(ApprovalRequest).where(
                ApprovalRequest.status == "pending",
                ApprovalRequest.expires_at <= now,
            )
        ).scalars().all()
        for apr in rows:
            apr.status = "expired"
            apr.decided_at = now
            self._record_refusal_cooldown(
                apr.agent_id, apr.tool, apr.argument_hash,
                (as_utc(apr.expires_at) or apr.expires_at)
                + dt.timedelta(hours=self.settings.refusal_cooldown_hours),
            )
            self.audit.append(
                agent_id=apr.agent_id,
                tool=apr.tool,
                decision="expired",
                reason="approval_expired",
                approval_request_id=apr.id,
                mandate_id=apr.mandate_id,
                redacted_args=apr.redacted_args,
            )
        if rows:
            self.db.commit()
        return len(rows)

    def _record_refusal_cooldown(
        self, agent_id: str, tool: str, argument_hash: str, expires_at: dt.datetime
    ) -> None:
        """(agent, tool, argument-hash) → cooldown until timestamp."""
        existing = self.db.execute(
            select(RefusalCooldown).where(
                RefusalCooldown.agent_id == agent_id,
                RefusalCooldown.tool == tool,
                RefusalCooldown.argument_hash == argument_hash,
            )
        ).scalars().first()
        if existing is not None:
            existing.expires_at = expires_at
        else:
            self.db.add(
                RefusalCooldown(
                    agent_id=agent_id, tool=tool,
                    argument_hash=argument_hash, expires_at=expires_at,
                )
            )
        self.db.flush()

    # -- console decision (02 §2.6; idempotent) ------------------------------

    def decide(
        self,
        apr_id: str,
        *,
        decision: str,
        admin_id: str = "admin",
        scope: str = GRANT_SCOPE_ONE_TIME,
        note: str = "",
        confirmation_token: Optional[str] = None,
        execute_on_approval: bool = False,
    ) -> dict[str, Any]:
        """Approve or deny. Idempotent: a retried POST against an
        already-decided request returns the existing decision, never a
        second grant (02 §2.6)."""
        now = self._clock()
        self.sweep_expired(now=now)
        apr = self.db.get(ApprovalRequest, apr_id)
        if apr is None:
            raise ValueError(f"unknown approval request {apr_id!r}")
        if apr.status != "pending":
            return {
                "approval_request_id": apr.id,
                "status": apr.status,
                "already_decided": True,
                "decided_at": _iso(apr.decided_at),
                "decided_by": apr.decided_by,
            }
        if decision not in ("approve", "deny"):
            raise ValueError("decision must be 'approve' or 'deny'")
        if scope != GRANT_SCOPE_ONE_TIME:
            # MVP grants are one-time only; windowed grants deferred
            # post-MVP (00 §3). Reject anything else loudly.
            raise ValueError(f"unsupported grant scope {scope!r} (MVP: one_time only)")

        if decision == "deny":
            apr.status = "denied"
            apr.decided_at = now
            apr.decided_by = admin_id
            apr.decision_note = note or None
            self._record_refusal_cooldown(
                apr.agent_id, apr.tool, apr.argument_hash,
                now + dt.timedelta(hours=self.settings.refusal_cooldown_hours),
            )
            self.db.commit()
            self.audit.append(
                agent_id=apr.agent_id,
                tool=apr.tool,
                decision="denied_decision",
                approval_request_id=apr.id,
                mandate_id=apr.mandate_id,
                redacted_args={
                    "decided_by": admin_id, "scope": scope, "note": note,
                },
            )
            return {
                "approval_request_id": apr.id, "status": "denied",
                "already_decided": False, "decided_at": _iso(now),
                "decided_by": admin_id,
            }

        # approve -------------------------------------------------------
        if apr.tool in DESTRUCTIVE_TOOLS:
            # Per-decision confirmation token for destructive scopes
            # (FR-042). Full admin re-auth arrives with M6 (FR-036);
            # the single-use token is the M3 bar.
            if self.confirmations is None or not self.confirmations.redeem(
                confirmation_token or "", apr.id
            ):
                raise ValueError(
                    "destructive scope requires a per-decision confirmation "
                    "token (FR-042); mint one from the approval card"
                )
        grant = Grant(
            approval_request_id=apr.id,
            agent_id=apr.agent_id,
            tool=apr.tool,
            argument_hash=apr.argument_hash,
            mandate_id=apr.mandate_id,
            policy_version=_current_policy_version(self.db),
            expires_at=now + dt.timedelta(minutes=self.settings.grant_ttl_minutes),
        )
        if execute_on_approval:
            # MF-11: the approval action itself consumes the grant
            # atomically at approval time — nothing is left for a later
            # re-invoke, so double execution is impossible.
            grant.consumed = True
            grant.consumed_at = now
        self.db.add(grant)
        apr.status = "approved"
        apr.decided_at = now
        apr.decided_by = admin_id
        apr.decision_note = note or None
        self.db.commit()
        self.audit.append(
            agent_id=apr.agent_id,
            tool=apr.tool,
            decision="approved",
            approval_request_id=apr.id,
            mandate_id=apr.mandate_id,
            redacted_args={
                "decided_by": admin_id, "scope": scope, "note": note,
                "grant_ttl_minutes": self.settings.grant_ttl_minutes,
                "execute_on_approval": execute_on_approval,
            },
        )
        executed = False
        if execute_on_approval:
            executed = self._execute_on_approval(apr, admin_id)
        return {
            "approval_request_id": apr.id, "status": "approved",
            "already_decided": False, "decided_at": _iso(now),
            "decided_by": admin_id,
            "grant_expires_at": _iso(grant.expires_at),
            "executed": executed,
            "result_summary": apr.result_summary,
        }

    def _execute_on_approval(self, apr: ApprovalRequest, admin_id: str) -> bool:
        """MF-11 fallback: run the approved call server-side NOW.

        The grant was already consumed at approval time (see decide()).
        The replay rebuilds args from the evidence subset only — what
        Ken saw on the card is exactly what executes (WYSIWYE). The
        result reaches the human through the console record;
        ``result_summary`` (PII-redacted) is its machine-readable mirror
        on gateway.approval_status (02 §2.5/§2.8).
        """
        if self.executor is None:
            raise RuntimeError("execute-on-approval needs an executor (wired by console/pipeline)")
        replay_args = build_replay_args(apr.evidence_subset or {})
        outcome = self.executor(
            agent_id=apr.agent_id,
            tool=apr.tool,
            args=replay_args,
            approval_request_id=apr.id,
            policy_version=apr.policy_version,
            mandate_id=apr.mandate_id,
        )
        if outcome.get("ok"):
            text = str(outcome.get("result"))[:500]
        else:
            text = str(outcome.get("error"))[:500]
        apr.result_summary = {
            "ok": bool(outcome.get("ok")),
            "request_id": outcome.get("request_id"),
            "summary": redact_code_like_secrets(text),
            "executed_by": admin_id,
        }
        self.db.commit()
        return True

    # -- revocation ---------------------------------------------------------

    def kill_agent_grants(self, agent_id: str) -> int:
        """Agent revocation kills grants immediately (Fix B)."""
        return self.grants.kill_agent_grants(agent_id)

    # -- caller-bound status read (02 §2.5) ----------------------------------

    def status_for_agent(
        self, apr_id: str, caller_agent_id: str, audit: AuditLog
    ) -> dict[str, Any]:
        """Status of ONE approval request, bound to the caller's agent
        identity (MF-5). Another agent's id → not-found, never "denied".

        ``result_summary`` is present ONLY in execute-on-approval mode.
        """
        now = self._clock()
        self.sweep_expired(now=now)
        apr = self.db.get(ApprovalRequest, apr_id)
        if apr is None or apr.agent_id != caller_agent_id:
            audit.append(
                agent_id=caller_agent_id,
                tool="gateway.approval_status",
                decision="error",
                reason="approval_not_found",
                redacted_args={"approval_request_id": apr_id},
            )
            return {"approval_request_id": apr_id, "status": "not_found"}
        if apr.status == "denied":
            audit.append(
                agent_id=caller_agent_id,
                tool="gateway.approval_status",
                decision="denied",
                reason="approval_denied",
                approval_request_id=apr.id,
                mandate_id=apr.mandate_id,
            )
        elif apr.status == "expired":
            audit.append(
                agent_id=caller_agent_id,
                tool="gateway.approval_status",
                decision="expired",
                reason="approval_expired",
                approval_request_id=apr.id,
                mandate_id=apr.mandate_id,
            )
        # pending/approved polls are exempt from per-call audit rows
        # (02 §2.5 carve-out).
        result: dict[str, Any] = {
            "approval_request_id": apr.id,
            "status": apr.status,
            "decided_at": _iso(apr.decided_at),
            "expires_at": _iso(apr.expires_at),
        }
        if apr.result_summary is not None:
            result["result_summary"] = apr.result_summary
        return result


# ---------------------------------------------------------------------
# ApprovalStage — replaces the pipeline stub (Fix-B order position 5).
# ---------------------------------------------------------------------

class ApprovalStage:
    """Step 5: step-up approval (Fix B).

    Runs ``ApprovalService.request_approval`` when the policy stage
    flagged ``ctx.needs_approval`` (require_approval, incl. the
    counterparty new-payee/changed-details escalation). Always halts:
    a sensitive call never proceeds without a consumed grant.
    ``service=None`` preserves the M1/M2 no-op for legacy builders.
    """

    name = "approval"

    def __init__(self, service: Optional[ApprovalService] = None) -> None:
        self.service = service

    def run(self, ctx: Any) -> Optional[GatewayError]:
        if self.service is None or not getattr(ctx, "needs_approval", False):
            return None
        return self.service.request_approval(ctx)


# ---------------------------------------------------------------------
# gateway.approval_status meta tool (02 §2.5)
# ---------------------------------------------------------------------

APPROVAL_STATUS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "approval_request_id": {
            "type": "string",
            "description": "From an approval_required error.",
        },
    },
    "required": ["approval_request_id"],
}


def make_approval_status_tool(
    *,
    config_session_factory: Callable[[], Session],
    audit_session_factory: Callable[[], Session],
    settings: Settings,
    hmac_ring: Optional[HmacKeyRing],
) -> Any:  # ToolDescriptor; loose to avoid importing pipeline at top
    """Build the ``gateway.approval_status`` tool descriptor.

    The handler runs INSIDE the pipeline (authenticate → validate →
    mandate → policy → execute), so caller identity comes from the
    Fix-A auth, not from arguments. The own rate budget (02 §2.5,
    ``approval_status_polls_per_minute``) is enforced by the pipeline's
    validate-stage rate limiter — polling never consumes the tool-call
    budget. The handler sets ``ctx.skip_audit`` and writes the
    carve-out rows itself: routine pending/approved polls leave no
    row; denied/expired/not-found polls are audit-logged.
    """
    # Local import: pipeline imports this module lazily; keep the
    # top-level dependency arrow one-way.
    from .pipeline import ToolDescriptor

    def handler(ctx: Any, args: dict[str, Any]) -> dict[str, Any]:
        apr_id = (args or {}).get("approval_request_id", "")
        if not is_valid_id(apr_id, "apr_"):
            raise ToolHalt(
                invalid_input(ctx.request_id, "approval_request_id",
                              tool="gateway.approval_status")
            )
        ctx.skip_audit = True
        with config_session_factory() as config_db, audit_session_factory() as audit_db:
            audit = AuditLog(audit_db)
            service = ApprovalService(
                config_db, audit, settings, hmac_ring,
                MandateService(config_db),
            )
            return service.status_for_agent(apr_id, ctx.agent_id, audit)

    return ToolDescriptor(
        name="gateway.approval_status",
        description=(
            "Check the status of a pending step-up approval request. "
            "Caller-bound: only your own requests resolve."
        ),
        input_schema=APPROVAL_STATUS_SCHEMA,
        sensitivity="routine",
        handler=handler,
    )
