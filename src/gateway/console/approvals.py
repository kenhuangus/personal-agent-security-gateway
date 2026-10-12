"""Approvals console page + API (M3; 02 §4.4; FR-042).

Routes (all state-changing routes require the anti-CSRF token —
``X-CSRF-Token`` header for JSON, hidden form field for forms):

- ``GET /approvals`` — the Approvals page: pending queue, decision
  history, counterparty review/correction, unknown-outcome blocks.
- ``GET /api/csrf-token`` — issue a CSRF token (+ SameSite=Strict cookie).
- ``GET /api/approvals/pending`` — pending queue as JSON.
- ``GET /api/approvals/{apr_id}`` — the approval card (02 §4.4):
  inert-rendered HTML + structured sections; a per-decision
  confirmation token for destructive scopes (FR-042).
- ``POST /api/approvals/{apr_id}/decision`` — approve/deny, one-time
  scope, idempotent. Optional ``execute_on_approval`` (MF-11).
- ``GET /api/counterparties`` / ``POST /api/counterparties/{key}/correct``
- ``GET /api/unknown-outcome`` / ``POST /api/unknown-outcome/{id}/resolve``

Admin authentication (FR-036/039/040) is M6's; the CSRF token +
per-decision confirmation token are the M3 bars. Every decision and
correction is audit-logged (FR-031/FR-041).
"""

from __future__ import annotations

import functools
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..approval_card import build_card, render_inert_html
from ..approvals import (
    DESTRUCTIVE_TOOLS,
    ApprovalService,
    make_approval_status_tool,  # noqa: F401 (re-export for wiring)
)
from ..audit import AuditLog
from ..config import Settings
from ..counterparty import CounterpartyService
from ..hmac_util import HmacKeyRing
from ..mandates import MandateService
from ..models import Agent, ApprovalRequest, DecisionCriteria, Mandate, utcnow
from .csrf import CsrfProtector


@dataclass
class ApprovalConsoleDeps:
    """Everything the approvals routes need beyond DB sessions."""

    settings: Settings
    csrf: CsrfProtector
    # Connector registry + token minter for the execute-on-approval
    # fallback (MF-11) replay.
    registry: Any
    minter: Any
    hmac_ring: Optional[HmacKeyRing] = None
    notifier_transport: Any = None
    # M6: vault store for the Vault & Settings page (None = not
    # configured; the vault section renders a notice) and the
    # connector objects for health checks (Connectors page).
    vault_store: Any = None
    connectors: list[Any] = field(default_factory=list)


def _service(
    config_db: Session,
    audit_db: Session,
    deps: ApprovalConsoleDeps,
    config_session_factory: Callable[[], Session],
    audit_session_factory: Callable[[], Session],
) -> ApprovalService:
    from ..notifier import build_notifier

    audit = AuditLog(audit_db)
    service = ApprovalService(
        config_db,
        audit,
        deps.settings,
        deps.hmac_ring,
        MandateService(config_db),
        notifier=build_notifier(deps.settings, audit, transport=deps.notifier_transport),
        counterparty=CounterpartyService(config_db),
        confirmations=deps.csrf.confirmations,
    )
    # MF-11 executor: runs the approved call server-side with fresh
    # sessions (lazy pipeline import — pipeline imports approvals
    # lazily, so this module must not import pipeline at top level).
    from ..pipeline import execute_approved_call

    service.executor = functools.partial(
        execute_approved_call,
        config_session_factory=config_session_factory,
        audit_session_factory=audit_session_factory,
        settings=deps.settings,
        hmac_ring=deps.hmac_ring,
        registry=deps.registry,
        minter=deps.minter,
    )
    return service


def _card_response(
    service: ApprovalService, config_db: Session, apr: ApprovalRequest, deps: ApprovalConsoleDeps
) -> dict[str, Any]:
    agent = config_db.get(Agent, apr.agent_id)
    mandate = config_db.get(Mandate, apr.mandate_id)
    criteria = config_db.execute(
        select(DecisionCriteria).where(DecisionCriteria.domain == apr.tool)
    ).scalars().first()
    destructive = apr.tool in DESTRUCTIVE_TOOLS
    card = build_card(
        apr,
        agent_display_name=getattr(agent, "display_name", apr.agent_id),
        mandate=mandate,
        cap_used=service.pending_count(apr.agent_id),
        cap_total=deps.settings.approval_queue_cap,
        recorded_criteria=criteria.criteria if criteria is not None else None,
        destructive=destructive,
        now=utcnow(),
    )
    out: dict[str, Any] = {
        "approval_request_id": apr.id,
        "status": apr.status,
        "card": card,
        "card_html": render_inert_html(card),
        "decided_at": apr.decided_at.isoformat() if apr.decided_at else None,
        "decided_by": apr.decided_by,
        "decision_note": apr.decision_note,
        "result_summary": apr.result_summary,
    }
    if destructive and apr.status == "pending":
        # Per-decision confirmation token for destructive scopes
        # (FR-042): single-use, bound to this apr_ id.
        out["confirmation_token"] = deps.csrf.confirmations.mint(apr.id)
    return out


def _csrf_fail() -> JSONResponse:
    return JSONResponse({"error": "csrf_failed",
                         "detail": "missing or invalid anti-CSRF token"}, status_code=403)


def register_approval_routes(
    app: Any,
    config_session_factory: Callable[[], Session],
    audit_session_factory: Callable[[], Session],
    deps: ApprovalConsoleDeps,
    render_page: Callable[..., HTMLResponse],
) -> None:
    """Register the M3 approvals routes on the console app."""

    def need_csrf(request: Request, form_token: Optional[str] = None) -> bool:
        return deps.csrf.check_request(request.cookies, request.headers, form_token)

    # -- CSRF token ----------------------------------------------------

    @app.get("/api/csrf-token")
    def csrf_token() -> JSONResponse:
        token = deps.csrf.issue()
        resp = JSONResponse({"csrf_token": token})
        deps.csrf.set_cookie(resp, token)
        return resp

    # -- Approvals page --------------------------------------------------

    @app.get("/approvals", response_class=HTMLResponse)
    def approvals_page() -> HTMLResponse:
        with config_session_factory() as config_db, audit_session_factory() as audit_db:
            service = _service(config_db, audit_db, deps,
                               config_session_factory, audit_session_factory)
            service.sweep_expired()
            pending = service.db.execute(
                select(ApprovalRequest)
                .where(ApprovalRequest.status == "pending")
                .order_by(ApprovalRequest.created_at.asc())
                .limit(100)
            ).scalars().all()
            queue = [
                {
                    "id": a.id, "agent_id": a.agent_id, "tool": a.tool,
                    "created_at": a.created_at, "expires_at": a.expires_at,
                    "destructive": a.tool in DESTRUCTIVE_TOOLS,
                    "cap_used": service.pending_count(a.agent_id),
                    "cap_total": deps.settings.approval_queue_cap,
                }
                for a in pending
            ]
            history = [
                {
                    "id": a.id, "agent_id": a.agent_id, "tool": a.tool,
                    "status": a.status, "decided_at": a.decided_at,
                    "decided_by": a.decided_by,
                }
                for a in service.history(limit=50)
            ]
            counterparties = [
                {
                    "key": c.key, "call_count": c.call_count,
                    "last_seen_at": c.last_seen_at, "notes": c.notes,
                    "details_snapshot": c.details_snapshot,
                }
                for c in service.counterparty.list(limit=100)
            ]
            blocks = [
                {
                    "id": b.id, "agent_id": b.agent_id, "tool": b.tool,
                    "created_at": b.created_at, "detail": b.detail,
                }
                for b in service.unknown_outcome.list_unresolved()
            ]
        token = deps.csrf.issue()
        resp = render_page(
            "approvals.html", active="approvals", queue=queue, history=history,
            counterparties=counterparties, blocks=blocks, csrf_token=token,
        )
        deps.csrf.set_cookie(resp, token)
        return resp

    # -- queue + card APIs -------------------------------------------------

    @app.get("/api/approvals/pending")
    def api_pending() -> JSONResponse:
        with config_session_factory() as config_db, audit_session_factory() as audit_db:
            service = _service(config_db, audit_db, deps,
                               config_session_factory, audit_session_factory)
            service.sweep_expired()
            rows = service.db.execute(
                select(ApprovalRequest)
                .where(ApprovalRequest.status == "pending")
                .order_by(ApprovalRequest.created_at.asc())
            ).scalars().all()
            return JSONResponse([
                {"approval_request_id": a.id, "agent_id": a.agent_id,
                 "tool": a.tool,
                 "created_at": a.created_at.isoformat(),
                 "expires_at": a.expires_at.isoformat(),
                 "destructive": a.tool in DESTRUCTIVE_TOOLS}
                for a in rows
            ])

    @app.get("/api/approvals/{apr_id}")
    def api_card(apr_id: str) -> JSONResponse:
        with config_session_factory() as config_db, audit_session_factory() as audit_db:
            service = _service(config_db, audit_db, deps,
                               config_session_factory, audit_session_factory)
            apr = config_db.get(ApprovalRequest, apr_id)
            if apr is None:
                return JSONResponse({"error": "unknown approval request"}, status_code=404)
            return JSONResponse(_card_response(service, config_db, apr, deps))

    @app.post("/api/approvals/{apr_id}/decision")
    async def api_decision(apr_id: str, request: Request) -> JSONResponse:
        if not need_csrf(request):
            return _csrf_fail()
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            return JSONResponse({"error": "invalid JSON body"}, status_code=400)
        decision = body.get("decision")
        scope = body.get("scope", "one_time")
        note = body.get("note", "") or ""
        confirmation_token = body.get("confirmation_token")
        execute_on_approval = bool(body.get("execute_on_approval"))
        with config_session_factory() as config_db, audit_session_factory() as audit_db:
            service = _service(config_db, audit_db, deps,
                               config_session_factory, audit_session_factory)
            try:
                result = service.decide(
                    apr_id, decision=decision, scope=scope, note=note,
                    confirmation_token=confirmation_token,
                    execute_on_approval=execute_on_approval,
                )
            except ValueError as exc:
                return JSONResponse({"error": str(exc)}, status_code=400)
            except RuntimeError as exc:
                return JSONResponse({"error": str(exc)}, status_code=500)
        return JSONResponse(result)

    # -- counterparty review -----------------------------------------------

    @app.get("/api/counterparties")
    def api_counterparties() -> JSONResponse:
        with config_session_factory() as config_db:
            rows = CounterpartyService(config_db).list()
            return JSONResponse([
                {"key": c.key, "call_count": c.call_count,
                 "first_seen_at": c.first_seen_at.isoformat(),
                 "last_seen_at": c.last_seen_at.isoformat(),
                 "notes": c.notes, "details_snapshot": c.details_snapshot}
                for c in rows
            ])

    @app.post("/api/counterparties/{key}/correct")
    async def api_counterparty_correct(key: str, request: Request) -> JSONResponse:
        if not need_csrf(request):
            return _csrf_fail()
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            return JSONResponse({"error": "invalid JSON body"}, status_code=400)
        notes = body.get("notes", "") or ""
        details = body.get("details") or {}
        if not isinstance(details, dict):
            return JSONResponse({"error": "details must be an object"}, status_code=400)
        with config_session_factory() as config_db, audit_session_factory() as audit_db:
            try:
                record = CounterpartyService(config_db).correct(
                    key, notes=notes, details=details,
                    admin_id="admin", audit=AuditLog(audit_db),
                )
            except ValueError as exc:
                return JSONResponse({"error": str(exc)}, status_code=404)
        return JSONResponse({"key": record.key, "notes": record.notes,
                             "details_snapshot": record.details_snapshot})

    # -- unknown-outcome blocks -----------------------------------------------

    @app.get("/api/unknown-outcome")
    def api_unknown_outcome() -> JSONResponse:
        with config_session_factory() as config_db, audit_session_factory() as audit_db:
            service = _service(config_db, audit_db, deps,
                               config_session_factory, audit_session_factory)
            return JSONResponse([
                {"id": b.id, "agent_id": b.agent_id, "tool": b.tool,
                 "argument_hash": b.argument_hash,
                 "created_at": b.created_at.isoformat(), "detail": b.detail}
                for b in service.unknown_outcome.list_unresolved()
            ])

    @app.post("/api/unknown-outcome/{block_id}/resolve")
    async def api_unknown_outcome_resolve(block_id: int, request: Request) -> JSONResponse:
        if not need_csrf(request):
            return _csrf_fail()
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = {}
        note = (body.get("note") if isinstance(body, dict) else "") or ""
        with config_session_factory() as config_db, audit_session_factory() as audit_db:
            service = _service(config_db, audit_db, deps,
                               config_session_factory, audit_session_factory)
            try:
                block = service.unknown_outcome.resolve(
                    block_id, note, AuditLog(audit_db))
            except ValueError as exc:
                return JSONResponse({"error": str(exc)}, status_code=404)
        return JSONResponse({"id": block.id, "resolved_at": block.resolved_at.isoformat()})
