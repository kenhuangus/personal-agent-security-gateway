"""Policies → Money console page (Pillar 1 §5).

GET /policies/money: the money-rule builder + the current money rules,
the counterparty allowlist, and the agent budget panel (remaining
budgets from the state builder — never the reason string).

POST /policies/money/save: validate the money block
(``validate_money_block``) and the quorum
(``validate_quorum_satisfiable``) BEFORE the OPA gate; save as a new
policy version. Money-rule saves are always classified MATERIAL.

POST /policies/money/allowlist/add: add a counterparty (last-4 only).
POST /policies/money/allowlist/verify: set the verification state.

Everything is behind GATEWAY_MONEY_ENABLED=1 (404 otherwise).
"""

from __future__ import annotations

import json
from typing import Any, Callable, Optional

from fastapi import Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select

from ..config import Settings
from ..money.allowlist import (
    STATE_BLOCKED,
    STATE_PENDING,
    STATE_VERIFIED,
    AllowlistService,
)
from ..money.limits import validate_money_block
from ..money.state import MoneyStateBuilder
from ..models import Agent, CounterpartyAllowlist, MoneyLedger, utcnow
from ..policy import PolicyEngine
from ..quorum import validate_quorum_satisfiable
from .csrf import CsrfProtector


def register_money(
    app: Any,
    config_session_factory: Callable[[], Any],
    audit_session_factory: Callable[[], Any],
    settings: Settings,
    csrf: CsrfProtector,
) -> None:
    from .pages import _RENDER, _admin_audit

    def csrf_fail() -> HTMLResponse:
        return HTMLResponse("missing or invalid anti-CSRF token", status_code=403)

    def money_off() -> HTMLResponse:
        return HTMLResponse(
            "the money pack is disabled (GATEWAY_MONEY_ENABLED=1 to enable)",
            status_code=404,
        )

    def _money_rules(db: Any) -> list[dict[str, Any]]:
        engine = PolicyEngine(db)
        rules = engine.version_rules_as_dicts()
        out = []
        for r in rules:
            conditions = (r or {}).get("conditions") or {}
            if conditions.get("money"):
                out.append(r)
        return out

    def _budgets(db: Any, agent_id: str) -> Optional[dict[str, Any]]:
        agent = db.get(Agent, agent_id)
        if agent is None:
            return None
        state = MoneyStateBuilder(db).build(
            agent_id, None, "", utcnow(), allowlisted_keys=set()
        )
        return {
            "agent_id": agent_id,
            "spent_today_cents": state.spent_today_cents,
            "spent_month_cents": state.spent_month_cents,
            "payments_last_hour": state.payments_last_hour,
            "payments_today": state.payments_today,
            "new_counterparties_today": state.new_counterparties_today,
        }

    @app.get("/policies/money", response_class=HTMLResponse)
    def money_page(
        request: Request, agent_id: str = "", message: str = ""
    ) -> HTMLResponse:
        if not settings.money_enabled:
            return money_off()
        with config_session_factory() as db:
            token = csrf.issue()
            rules = _money_rules(db)
            counterparties = [
                {
                    "payee_key": c.payee_key,
                    "label": c.label,
                    "account_last4": (c.details_snapshot or {}).get("account_last4"),
                    "verification_state": c.verification_state,
                    "record_version": c.record_version,
                    "notes": c.notes,
                }
                for c in db.execute(
                    select(CounterpartyAllowlist).order_by(
                        CounterpartyAllowlist.payee_key)
                ).scalars().all()
            ]
            agents = [a.id for a in db.query(Agent).order_by(Agent.id).all()]
            budgets = _budgets(db, agent_id) if agent_id else None
            recent = (
                db.execute(
                    select(MoneyLedger)
                    .order_by(MoneyLedger.occurred_at.desc())
                    .limit(25)
                )
                .scalars()
                .all()
            )
            ledger = [
                {
                    "occurred_at": r.occurred_at.isoformat() if r.occurred_at else None,
                    "agent_id": r.agent_id, "tool": r.tool,
                    "amount_cents": r.amount_cents,
                    "payee_key": r.counterparty_key,
                    "request_id": r.request_id,
                    "dry_run": r.dry_run,
                }
                for r in recent
            ]
            resp = _RENDER(
                "money.html", active="money", csrf_token=token,
                money_rules=rules, counterparties=counterparties,
                agents=agents, selected_agent=agent_id, budgets=budgets,
                ledger=ledger, message=message,
                verification_states=[STATE_VERIFIED, STATE_PENDING, STATE_BLOCKED],
            )
            csrf.set_cookie(resp, token)
            return resp

    @app.post("/policies/money/save")
    def money_save(
        request: Request,
        name: str = Form(...),
        agent_id: str = Form(""),
        money_json: str = Form(...),
        change_note: str = Form(""),
        csrf_token: str = Form(""),
    ) -> HTMLResponse:
        """Save a money rule (always MATERIAL) after structural +
        quorum validation, before the OPA gate."""
        if not csrf.check_request(request.cookies, request.headers, csrf_token):
            return csrf_fail()
        if not settings.money_enabled:
            return money_off()
        try:
            money_block = json.loads(money_json)
        except json.JSONDecodeError as exc:
            return HTMLResponse(f"invalid money JSON: {exc}", status_code=400)
        try:
            validate_money_block(money_block)
        except ValueError as exc:
            return HTMLResponse(f"money block rejected: {exc}", status_code=400)
        # Quorum validation on save: an unsatisfiable quorum would
        # wedge every future approval — fail closed here, at
        # authoring time (arch §1.4).
        quorum = int(money_block.get("quorum") or 1)
        with config_session_factory() as db:
            # Quorum satisfiability is checked against the admin
            # roster (accounts that can actually approve).
            try:
                validate_quorum_satisfiable(db, quorum)
            except Exception as exc:  # noqa: BLE001 — fail closed
                return HTMLResponse(f"quorum rejected: {exc}", status_code=400)
            engine = PolicyEngine(db)
            rules = engine.version_rules_as_dicts()
            new_rule: dict[str, Any] = {
                "name": name.strip(), "rule_type": "standard",
                "effect": "allow",  # nominal: money rules are evaluated by
                                    # the money ladder, never OPA
                "tool": "payment.*",
                "conditions": {"money": money_block},
                "description": change_note.strip(),
            }
            if agent_id.strip():
                new_rule["agent_id"] = agent_id.strip()
            rules.append(new_rule)
            try:
                version = engine.save_version(
                    rules,
                    change_note=change_note or f"add money rule: {name.strip()}",
                    created_by="admin_ken",
                    material_change=True,  # money rules are always material
                )
            except (ValueError, Exception) as exc:  # noqa: BLE001
                return HTMLResponse(f"policy save rejected: {exc}", status_code=400)
        _admin_audit(
            audit_session_factory, "policy.money_save",
            {"version": version, "rule": name.strip(),
             "quorum": quorum, "classification": "material",
             "note": change_note},
        )
        return RedirectResponse(
            url="/policies/money?message=" + _q(f"saved as v{version} (material)"),
            status_code=302,
        )

    @app.post("/policies/money/allowlist/add")
    def allowlist_add(
        request: Request,
        payee_key: str = Form(...),
        account_last4: str = Form(...),
        note: str = Form(""),
        csrf_token: str = Form(""),
    ) -> HTMLResponse:
        if not csrf.check_request(request.cookies, request.headers, csrf_token):
            return csrf_fail()
        if not settings.money_enabled:
            return money_off()
        import re as _re

        if not _re.fullmatch(r"[0-9]{4}", account_last4.strip()):
            # Server-side: the last-4 is exactly four digits (the form
            # also constrains it client-side; never trust the client).
            return HTMLResponse(
                "allowlist add rejected: account_last4 must be 4 digits",
                status_code=400,
            )
        with config_session_factory() as db:
            svc = AllowlistService(db)
            try:
                row = svc.add(
                    payee_key=payee_key.strip(), label=note.strip() or payee_key.strip(),
                    details_snapshot={"account_last4": account_last4.strip()},
                    notes=note.strip(),
                )
            except ValueError as exc:
                return HTMLResponse(f"allowlist add rejected: {exc}", status_code=400)
        _admin_audit(
            audit_session_factory, "money.allowlist_add",
            {"payee_key": payee_key.strip(), "account_last4": account_last4.strip(),
             "record_version": row.record_version},
        )
        return RedirectResponse(
            url="/policies/money?message=" + _q("counterparty added (pending verification)"),
            status_code=302,
        )

    @app.post("/policies/money/allowlist/verify")
    def allowlist_verify(
        request: Request,
        payee_key: str = Form(...),
        state: str = Form(...),
        csrf_token: str = Form(""),
    ) -> HTMLResponse:
        if not csrf.check_request(request.cookies, request.headers, csrf_token):
            return csrf_fail()
        if not settings.money_enabled:
            return money_off()
        if state not in (STATE_VERIFIED, STATE_PENDING, STATE_BLOCKED):
            return HTMLResponse("unknown verification state", status_code=400)
        with config_session_factory() as db:
            svc = AllowlistService(db)
            try:
                row = svc.set_verification(
                    namespace_id=None, payee_key=payee_key.strip(),
                    verification_state=state, verified_by="admin_ken",
                )
            except ValueError as exc:
                return HTMLResponse(f"allowlist verify rejected: {exc}", status_code=400)
        _admin_audit(
            audit_session_factory, "money.allowlist_verify",
            {"payee_key": payee_key.strip(), "state": state,
             "record_version": row.record_version},
        )
        return RedirectResponse(
            url="/policies/money?message=" + _q(f"counterparty {state}"),
            status_code=302,
        )


def _q(message: str) -> str:
    from urllib.parse import quote_plus

    return quote_plus(message)
