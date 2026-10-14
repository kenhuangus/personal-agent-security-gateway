"""M6 console pages (02 §3.2): Dashboard, Connectors, Policies, Vault &
Settings, Mandates, Context boundaries, plus the ontology review queue.

All routes sit behind the admin-auth middleware in app.py; every
state-changing route additionally requires the anti-CSRF token
(FR-042, extending the M3 csrf.py pattern). Admin actions that mutate
security state are audit-logged (FR-041).
"""

from __future__ import annotations

import datetime as dt
import json
from importlib.metadata import version as _pkg_version
from typing import Any, Callable, Optional

from fastapi import Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from sqlalchemy import select

from ..approvals import ApprovalService
from ..audit import AuditLog
from ..config import Settings
from ..identity import IdentityService
from ..inspection.redaction import RedactionCatalog
from ..latency import AC11_BUDGET_MS, recorder
from ..mandates import MandateService
from ..models import (
    AdminUser,
    Agent,
    ApprovalRequest,
    ConfigSetting,
    DecisionCriteria,
    Mandate,
    utcnow,
)
from ..ontology.integration import validate_ontology_conditions
from ..ontology.store import OntologyStore
from ..policy import PolicyEngine, diff_versions, dry_run
from .csrf import CsrfProtector
from .settings_store import EDITABLE_SETTINGS, SettingsStore, effective_settings

_RENDER: Callable[..., HTMLResponse]


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _admin_audit(
    audit_session_factory: Callable[[], Any],
    tool: str,
    redacted_args: Optional[dict[str, Any]] = None,
    decision: str = "allowed",
    reason: Optional[str] = None,
) -> None:
    """Audit-log one admin action (FR-041)."""
    with audit_session_factory() as audit_db:
        AuditLog(audit_db).append(
            agent_id="admin",
            tool=tool,
            decision=decision,
            reason=reason,
            redacted_args=redacted_args or {},
        )


def _sdk_version() -> str:
    try:
        return _pkg_version("mcp")
    except Exception:  # noqa: BLE001
        return "unknown"


# ---------------------------------------------------------------------
# Dashboard (02 §4.1): posture + global stop (FR-PAA10-001/003/004)
# ---------------------------------------------------------------------


def register_dashboard(
    app: Any,
    config_session_factory: Callable[[], Any],
    audit_session_factory: Callable[[], Any],
    settings: Settings,
    csrf: CsrfProtector,
) -> None:
    def csrf_fail() -> HTMLResponse:
        return HTMLResponse("missing or invalid anti-CSRF token", status_code=403)

    def _dashboard_data() -> dict[str, Any]:
        with config_session_factory() as db:
            agents = db.query(Agent).order_by(Agent.id).all()
            agent_rows = [
                {
                    "id": a.id, "display_name": a.display_name,
                    "platform": a.platform, "status": a.status,
                    "last_seen_at": a.last_seen_at,
                }
                for a in agents
            ]
            pending = (
                db.execute(
                    select(ApprovalRequest).where(ApprovalRequest.status == "pending")
                ).scalars().all()
            )
            pending_rows = [
                {"id": p.id, "agent_id": p.agent_id, "tool": p.tool,
                 "created_at": p.created_at, "expires_at": p.expires_at}
                for p in pending
            ]
            with audit_session_factory() as audit_db:
                log = AuditLog(audit_db)
                day_start = _utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
                calls_today = log.search(since=day_start, limit=100000)
                denied_today = log.search(since=day_start, decision="denied", limit=100000)
                tail = log.search(limit=10)
            active_agents = sum(1 for a in agents if a.status == "active")
        return {
            "agent_rows": agent_rows,
            "active_agents": active_agents,
            "calls_today": len(calls_today),
            "denied_today": len(denied_today),
            "pending_rows": pending_rows,
            "pending_count": len(pending_rows),
            "tail": [
                {"timestamp": e.timestamp, "agent_id": e.agent_id, "tool": e.tool,
                 "decision": e.decision, "reason": e.reason, "request_id": e.request_id}
                for e in tail
            ],
        }

    @app.get("/dashboard", response_class=HTMLResponse)
    def dashboard_page() -> HTMLResponse:
        data = _dashboard_data()
        token = csrf.issue()
        resp = _RENDER("dashboard.html", active="dashboard", csrf_token=token, **data)
        csrf.set_cookie(resp, token)
        return resp

    @app.post("/admin/stop-all", response_class=HTMLResponse)
    def stop_all(request: Request, csrf_token: str = Form("")) -> HTMLResponse:
        """GLOBAL STOP (FR-PAA10-001): pause every agent, cancel every
        pending approval. The acknowledgment distinguishes "received"
        from "enforced" and names per-item status (FR-PAA10-003/004)."""
        if not csrf.check_request(request.cookies, request.headers, csrf_token):
            return csrf_fail()
        received_at = _utcnow()
        items: list[dict[str, Any]] = []
        with config_session_factory() as db:
            identity = IdentityService(db)
            agents = db.query(Agent).order_by(Agent.id).all()
            for a in agents:
                before = a.status
                if before in ("active", "paused"):
                    identity.set_status(a.id, "paused", actor="admin")
                    after = "paused"
                    note = "paused by global stop" if before == "active" else "already paused"
                else:
                    after = before
                    note = f"skipped (state: {before})"
                items.append(
                    {"kind": "agent", "id": a.id, "before": before,
                     "after": after, "ok": True, "note": note}
                )
            pending = (
                db.execute(
                    select(ApprovalRequest).where(ApprovalRequest.status == "pending")
                ).scalars().all()
            )
            for apr in pending:
                apr.status = "canceled"
                apr.decided_at = received_at
                apr.decided_by = "admin_ken"
                apr.decision_note = "canceled by global stop"
                items.append(
                    {"kind": "approval", "id": apr.id, "before": "pending",
                     "after": "canceled", "ok": True,
                     "note": f"{apr.agent_id} {apr.tool}"}
                )
            db.commit()
        enforced_at = _utcnow()
        agents_paused = sum(1 for i in items if i["kind"] == "agent" and i["after"] == "paused")
        approvals_canceled = sum(1 for i in items if i["kind"] == "approval")
        _admin_audit(
            audit_session_factory, "admin.global_stop",
            {"agents_paused": agents_paused, "approvals_canceled": approvals_canceled,
             "received_at": received_at.isoformat(), "enforced_at": enforced_at.isoformat()},
        )
        data = _dashboard_data()
        ack = {
            "received_at": received_at,
            "enforced_at": enforced_at,
            "agents_paused": agents_paused,
            "approvals_canceled": approvals_canceled,
            "items": items,
        }
        token = csrf.issue()
        resp = _RENDER(
            "dashboard.html", active="dashboard", csrf_token=token,
            stop_ack=ack, **data,
        )
        csrf.set_cookie(resp, token)
        return resp


# ---------------------------------------------------------------------
# Latency (AC-11): live per-stage p50/p95/max + judge backend (hackathon demo)
# ---------------------------------------------------------------------

_STAGE_ORDER = ("policy", "inspection", "judge")
_STAGE_DESCRIPTIONS = {
    "policy": "OPA decide call (policy evaluation, ms)",
    "inspection": "output-inspection stage (ms)",
    "judge": "advisory judge cascade (ms; label = backend path)",
}


def _judge_backend_summary(settings: Settings) -> dict[str, Any]:
    """What judge backend the gateway is configured to use.

    Reads straight from settings — the backend line is config truth,
    never a placeholder. ``escalation`` is ``"none"`` unless an
    escalation backend is configured (see ``judge_escalation`` in
    config.py).
    """
    return {
        "backend": (getattr(settings, "judge_backend", "none") or "none").strip().lower(),
        "enabled": bool(getattr(settings, "judge_enabled", False)),
        "always_on": bool(getattr(settings, "judge_always_on", False)),
        "escalation": getattr(settings, "judge_escalation", "none") or "none",
        "timeout_s": getattr(settings, "judge_timeout_s", 2.0),
    }


def register_latency(app: Any, settings: Settings, csrf: CsrfProtector) -> None:
    @app.get("/latency", response_class=HTMLResponse)
    def latency_page() -> HTMLResponse:
        # Every number below is computed from the in-memory ring
        # buffer at read time (gateway.latency). Empty stages render
        # an honest "no samples yet" state — never placeholders.
        stages = [
            {
                "name": name,
                "desc": _STAGE_DESCRIPTIONS[name],
                "stats": recorder.stats(name),
                "labels": recorder.labels(name),
            }
            for name in _STAGE_ORDER
        ]
        data = {
            "stages": stages,
            "has_data": any(s["stats"] is not None for s in stages),
            "budget_ms": AC11_BUDGET_MS,
            "judge": _judge_backend_summary(settings),
        }
        token = csrf.issue()
        resp = _RENDER("latency.html", active="latency", csrf_token=token, **data)
        csrf.set_cookie(resp, token)
        return resp


# ---------------------------------------------------------------------
# Connectors (02 §3.2): registry, tools, health checks (FR-007–FR-010)
# ---------------------------------------------------------------------


def register_connectors(
    app: Any,
    csrf: CsrfProtector,
    health: Any,
) -> None:
    def csrf_fail() -> HTMLResponse:
        return HTMLResponse("missing or invalid anti-CSRF token", status_code=403)

    @app.get("/connectors", response_class=HTMLResponse)
    def connectors_page() -> HTMLResponse:
        def _as_list(value: Any) -> list:
            return value() if callable(value) else (value or [])

        snapshot = health.snapshot()
        rows = []
        for connector in health._connectors:  # in-process registry
            name = getattr(connector, "name", None) or type(connector).__name__
            tools = [t.name for t in _as_list(getattr(connector, "tools", None))]
            st = snapshot.get(name, {})
            rows.append(
                {
                    "name": name,
                    "tools": tools,
                    "scopes": _as_list(getattr(connector, "upstream_scopes", None)),
                    "healthy": st.get("healthy"),
                    "credential_valid": st.get("credential_valid"),
                    "api_reachable": st.get("api_reachable"),
                    "detail": st.get("detail", "not checked yet"),
                    "checked_at": st.get("checked_at"),
                    "ssrf": connector.ssrf_checklist() if hasattr(connector, "ssrf_checklist") else {},
                }
            )
        token = csrf.issue()
        resp = _RENDER("connectors.html", active="connectors", connectors=rows, csrf_token=token)
        csrf.set_cookie(resp, token)
        return resp

    @app.post("/connectors/check")
    def connectors_check(request: Request, csrf_token: str = Form("")) -> RedirectResponse:
        # FR-042: anti-CSRF on all state-changing console routes.
        if not csrf.check_request(request.cookies, request.headers, csrf_token):
            return csrf_fail()  # type: ignore[return-value]
        health.run_all()
        return RedirectResponse(url="/connectors", status_code=302)


# ---------------------------------------------------------------------
# Policies (02 §4.3, §5): list + builder + raw + history + dry-run
# ---------------------------------------------------------------------


def _engine(config_session_factory: Callable[[], Any]) -> tuple[PolicyEngine, Any]:
    db = config_session_factory()
    return PolicyEngine(db), db


def register_policies(
    app: Any,
    config_session_factory: Callable[[], Any],
    audit_session_factory: Callable[[], Any],
    settings: Settings,
    csrf: CsrfProtector,
) -> None:
    def csrf_fail() -> HTMLResponse:
        return HTMLResponse("missing or invalid anti-CSRF token", status_code=403)

    def _versions(db: Any) -> list[dict[str, Any]]:
        from ..models import PolicyVersion

        rows = (
            db.query(PolicyVersion).order_by(PolicyVersion.version.desc()).all()
        )
        return [
            {
                "version": r.version, "is_current": r.is_current,
                "material_change": r.material_change,
                "change_note": r.change_note, "created_by": r.created_by,
                "created_at": r.created_at,
            }
            for r in rows
        ]

    @app.get("/policies", response_class=HTMLResponse)
    def policies_page(request: Request, diff_a: str = "", diff_b: str = "") -> HTMLResponse:
        engine, db = _engine(config_session_factory)
        try:
            from ..models import PolicyVersion

            current = (
                db.execute(
                    select(PolicyVersion).where(PolicyVersion.is_current.is_(True))
                ).scalar_one_or_none()
            )
            current_version = current.version if current else None
            rules = engine.list_rules_with_default_deny()
            raw_rules = json.dumps(engine.version_rules_as_dicts(), indent=2)
            versions = _versions(db)
            diff = None
            if diff_a and diff_b:
                try:
                    a = int(diff_a)
                    b = int(diff_b)
                    diff = {
                        "a": a, "b": b,
                        **diff_versions(
                            engine.version_rules_as_dicts(a),
                            engine.version_rules_as_dicts(b),
                        ),
                    }
                except (ValueError, Exception):  # noqa: BLE001 — bad version input
                    diff = {"error": "unknown version(s)"}
        finally:
            db.close()
        token = csrf.issue()
        resp = _RENDER(
            "policies.html", active="policies", rules=rules,
            raw_rules=raw_rules, versions=versions,
            current_version=current_version, diff=diff,
            csrf_token=token,
        )
        csrf.set_cookie(resp, token)
        return resp

    @app.post("/policies/save")
    def policies_save(
        request: Request,
        raw_rules: str = Form(""),
        change_note: str = Form(""),
        material: str = Form("auto"),
        csrf_token: str = Form(""),
    ) -> HTMLResponse:
        # FR-042: anti-CSRF on all state-changing console routes.
        if not csrf.check_request(request.cookies, request.headers, csrf_token):
            return csrf_fail()
        try:
            rules = json.loads(raw_rules)
            if not isinstance(rules, list):
                raise ValueError("raw rules must be a JSON/YAML list of rule objects")
        except json.JSONDecodeError:
            try:
                import yaml as _yaml

                rules = _yaml.safe_load(raw_rules)
            except Exception as exc:
                return HTMLResponse(f"invalid rules JSON/YAML: {exc}", status_code=400)
            if not isinstance(rules, list):
                return HTMLResponse(
                    "invalid rules: top level must be a list", status_code=400
                )
        except ValueError as exc:
            return HTMLResponse(f"invalid rules JSON: {exc}", status_code=400)
        engine, db = _engine(config_session_factory)
        try:
            # M6 ontology seam: store-aware validation of ontology
            # clauses BEFORE save_version (M6 checklist (e)).
            for rule in rules:
                conditions = (rule or {}).get("conditions") or {}
                if conditions.get("ontology"):
                    validate_ontology_conditions(db, conditions)
            material_change = (
                None if material == "auto" else material.lower() == "true"
            )
            version = engine.save_version(
                rules, change_note=change_note, created_by="admin_ken",
                material_change=material_change,
            )
        except (ValueError, Exception) as exc:  # noqa: BLE001 — OPA gate / ontology
            db.close()
            return HTMLResponse(f"policy save rejected: {exc}", status_code=400)
        db.close()
        _admin_audit(
            audit_session_factory, "policy.save",
            {"version": version, "rule_count": len(rules), "note": change_note},
        )
        return RedirectResponse(url="/policies", status_code=302)

    @app.post("/policies/add-rule")
    def policies_add_rule(
        request: Request,
        name: str = Form(...),
        agent_id: str = Form(""),
        tool: str = Form(""),
        effect: str = Form(...),
        conditions: str = Form(""),
        change_note: str = Form(""),
        csrf_token: str = Form(""),
    ) -> HTMLResponse:
        """The no-DSL rule builder (02 §5): append one rule to the
        current version and save as a new version."""
        if not csrf.check_request(request.cookies, request.headers, csrf_token):
            return csrf_fail()
        engine, db = _engine(config_session_factory)
        try:
            rules = engine.version_rules_as_dicts()
            cond: dict[str, Any] = {}
            if conditions.strip():
                try:
                    cond = json.loads(conditions)
                except json.JSONDecodeError as exc:
                    return HTMLResponse(f"invalid conditions JSON: {exc}", status_code=400)
            if effect not in ("allow", "deny", "require_approval"):
                return HTMLResponse("unknown effect", status_code=400)
            new_rule: dict[str, Any] = {
                "name": name.strip(), "rule_type": "standard", "effect": effect,
                "description": change_note.strip(),
            }
            if agent_id.strip():
                new_rule["agent_id"] = agent_id.strip()
            if tool.strip():
                new_rule["tool"] = tool.strip()
            if cond:
                new_rule["conditions"] = cond
            rules.append(new_rule)
            if cond.get("ontology"):
                validate_ontology_conditions(db, cond)
            version = engine.save_version(
                rules,
                change_note=change_note or f"add rule: {name.strip()}",
                created_by="admin_ken",
            )
        except (ValueError, Exception) as exc:  # noqa: BLE001 — OPA gate / ontology
            db.close()
            return HTMLResponse(f"policy save rejected: {exc}", status_code=400)
        db.close()
        _admin_audit(
            audit_session_factory, "policy.save",
            {"version": version, "added_rule": name.strip(), "note": change_note},
        )
        return RedirectResponse(url="/policies", status_code=302)

    @app.post("/policies/rollback")
    def policies_rollback(
        request: Request,
        version: int = Form(...),
        csrf_token: str = Form(""),
    ) -> HTMLResponse:
        """Rollback = a NEW version copying the old content; history is
        never rewritten (02 §5; FR-032 philosophy)."""
        if not csrf.check_request(request.cookies, request.headers, csrf_token):
            return csrf_fail()
        engine, db = _engine(config_session_factory)
        try:
            rules = engine.version_rules_as_dicts(version)
            if not rules:
                return HTMLResponse("unknown version", status_code=404)
            new_version = engine.save_version(
                rules,
                change_note=f"rollback to v{version}",
                created_by="admin_ken",
                material_change=True,  # content reverts: grants re-evaluate (FR-PAA04-003)
            )
        except (ValueError, Exception) as exc:  # noqa: BLE001
            db.close()
            return HTMLResponse(f"rollback rejected: {exc}", status_code=400)
        db.close()
        _admin_audit(
            audit_session_factory, "policy.rollback",
            {"from_version": version, "new_version": new_version},
        )
        return RedirectResponse(url="/policies", status_code=302)

    @app.post("/api/policy/dry-run")
    async def api_policy_dry_run(request: Request) -> JSONResponse:
        """AC-12 / 02 §2.6: replay a policy version against history.

        Body: {policy_version, window_days}. Returns
        {counts: {would_allow, would_deny, would_require_approval},
        changed_calls: [...], corpus: "history"|"synthetic"}.
        Admin-only; CSRF-protected; enforcement is never changed.
        """
        if not csrf.check_request(request.cookies, request.headers):
            return JSONResponse({"error": "csrf_failed"}, status_code=403)
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            return JSONResponse({"error": "invalid_json"}, status_code=400)
        policy_version = body.get("policy_version")
        window_days = body.get("window_days", 7)
        if not isinstance(policy_version, int):
            return JSONResponse({"error": "policy_version must be an integer"}, status_code=400)
        try:
            window_days = int(window_days)
        except (TypeError, ValueError):
            return JSONResponse({"error": "window_days must be an integer"}, status_code=400)
        with config_session_factory() as config_db, audit_session_factory() as audit_db:
            result = dry_run(
                config_db, audit_db, policy_version, window_days=window_days
            )
        return JSONResponse(result)

    @app.post("/api/policy/evaluate")
    async def api_policy_evaluate(request: Request) -> JSONResponse:
        """02 §2.6: dry-run ONE hypothetical call against a policy version.

        Body: {agent_id, tool, arguments, policy_version?, ontology_ctx?}.
        Returns {decision, matched_rule_id, requires_approval}. Admin-only.
        (An agent-callable policy.evaluate would let agents probe policy
        boundaries; rejected by design.)
        """
        if not csrf.check_request(request.cookies, request.headers):
            return JSONResponse({"error": "csrf_failed"}, status_code=403)
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            return JSONResponse({"error": "invalid_json"}, status_code=400)
        agent_id = body.get("agent_id")
        tool = body.get("tool")
        arguments = body.get("arguments") or {}
        if not agent_id or not tool:
            return JSONResponse({"error": "agent_id and tool are required"}, status_code=400)
        engine, db = _engine(config_session_factory)
        try:
            agent = db.get(Agent, agent_id)
            if agent is None:
                return JSONResponse({"error": "unknown_agent"}, status_code=404)
            ontology_ctx = body.get("ontology_ctx")
            if ontology_ctx:
                try:
                    validate_ontology_conditions(db, {"ontology": ontology_ctx})
                except Exception as exc:  # noqa: BLE001 — fail closed
                    return JSONResponse(
                        {"error": "invalid_ontology_ctx", "detail": str(exc)}, status_code=400
                    )
            result = engine.evaluate_call(
                agent, tool, arguments,
                policy_version=body.get("policy_version"),
                ontology_ctx=ontology_ctx,
            )
        finally:
            db.close()
        return JSONResponse(
            {
                "decision": result.decision,
                "matched_rule_id": result.matched_rule_id,
                "requires_approval": result.requires_approval,
                "data_snapshot_id": result.data_snapshot_id,
                "ontology_ref": result.ontology_ref,
            }
        )


# ---------------------------------------------------------------------
# Vault & Settings (02 §3.2): credential entries, rotation, global
# settings, redaction-catalog editor, recorded decision criteria
# (FR-PAA09-004).
# ---------------------------------------------------------------------


def register_vault_settings(
    app: Any,
    config_session_factory: Callable[[], Any],
    audit_session_factory: Callable[[], Any],
    settings: Settings,
    csrf: CsrfProtector,
    vault_store: Any,
) -> None:
    def csrf_fail() -> HTMLResponse:
        return HTMLResponse("missing or invalid anti-CSRF token", status_code=403)

    @app.get("/settings", response_class=HTMLResponse)
    def settings_page() -> HTMLResponse:
        with config_session_factory() as db:
            eff = effective_settings(settings, db)
            store = SettingsStore(db)
            overrides = store.get_overrides()
            editable = [
                {"key": key, "label": label, "kind": kind,
                 "env_value": getattr(settings, field),
                 "effective": getattr(eff, field),
                 "override": overrides.get(key)}
                for key, (field, label, kind) in EDITABLE_SETTINGS.items()
            ]
            catalog = RedactionCatalog(db)
            patterns = catalog.list_patterns()
            criteria = [
                {"domain": c.domain, "criteria": c.criteria, "updated_at": c.updated_at}
                for c in db.query(DecisionCriteria).order_by(DecisionCriteria.domain).all()
            ]
        entries = vault_store.list_entries() if vault_store is not None else None
        token = csrf.issue()
        resp = _RENDER(
            "settings.html", active="settings", entries=entries,
            editable=editable, sdk_version=_sdk_version(),
            hmac_key_id=settings.hmac_key_id,
            notifier_configured=bool(settings.notifier_secret),
            patterns=patterns, criteria=criteria, csrf_token=token,
        )
        csrf.set_cookie(resp, token)
        return resp

    @app.post("/settings/update")
    def settings_update(
        request: Request, key: str = Form(...), value: str = Form(...),
        csrf_token: str = Form(""),
    ) -> RedirectResponse:
        if not csrf.check_request(request.cookies, request.headers, csrf_token):
            return csrf_fail()  # type: ignore[return-value]
        with config_session_factory() as db:
            store = SettingsStore(db, audit_session_factory)
            try:
                store.set(key, value, admin_id="admin_ken")
            except (KeyError, ValueError) as exc:
                return HTMLResponse(f"bad setting: {exc}", status_code=400)  # type: ignore[return-value]
        return RedirectResponse(url="/settings", status_code=302)

    @app.post("/settings/reset")
    def settings_reset(
        request: Request, key: str = Form(...), csrf_token: str = Form("")
    ) -> RedirectResponse:
        if not csrf.check_request(request.cookies, request.headers, csrf_token):
            return csrf_fail()  # type: ignore[return-value]
        with config_session_factory() as db:
            SettingsStore(db, audit_session_factory).reset(key)
        _admin_audit(audit_session_factory, "settings.update", {"key": key, "reset": True})
        return RedirectResponse(url="/settings", status_code=302)

    @app.post("/settings/vault/rotate")
    def vault_rotate(
        request: Request, connector: str = Form(...), new_cred: str = Form(...),
        csrf_token: str = Form(""),
    ) -> HTMLResponse:
        # FR-042 anti-CSRF; the secret itself is never logged (FR-022).
        if not csrf.check_request(request.cookies, request.headers, csrf_token):
            return csrf_fail()
        if vault_store is None:
            return HTMLResponse("vault not configured", status_code=400)
        try:
            vault_store.rotate(connector.strip(), new_cred, admin_id="admin_ken")
        except Exception as exc:  # noqa: BLE001 — rotation is fail-visible
            return HTMLResponse(f"rotation failed: {exc}", status_code=400)
        return RedirectResponse(url="/settings", status_code=302)

    # -- redaction catalog editor (M5 catalog; console-editable from day one) --

    @app.post("/settings/redaction/add")
    def redaction_add(
        request: Request, name: str = Form(...), regex: str = Form(...),
        pattern_mask: str = Form(""), category: str = Form("pii"),
        description: str = Form(""), csrf_token: str = Form(""),
    ) -> HTMLResponse:
        if not csrf.check_request(request.cookies, request.headers, csrf_token):
            return csrf_fail()
        with config_session_factory() as db:
            catalog = RedactionCatalog(db)
            try:
                catalog.add_pattern(
                    name.strip(), regex, pattern_mask.strip() or f"[redacted:{name.strip()}]",
                    category=category, description=description,
                )
            except ValueError as exc:
                return HTMLResponse(f"bad pattern: {exc}", status_code=400)
        _admin_audit(
            audit_session_factory, "redaction.catalog_update",
            {"action": "add", "name": name.strip()},
        )
        return RedirectResponse(url="/settings", status_code=302)

    @app.post("/settings/redaction/toggle")
    def redaction_toggle(
        request: Request, name: str = Form(...), enabled: str = Form("true"),
        csrf_token: str = Form(""),
    ) -> Response:
        if not csrf.check_request(request.cookies, request.headers, csrf_token):
            return csrf_fail()  # type: ignore[return-value]
        with config_session_factory() as db:
            try:
                # set_enabled -> _require raises ValueError on unknown
                # names (GH #28: the unguarded call could 500).
                RedactionCatalog(db).set_enabled(name, enabled.lower() == "true")
            except ValueError as exc:
                _admin_audit(
                    audit_session_factory, "redaction.catalog_update",
                    {"action": "toggle", "name": name, "error": str(exc)},
                    decision="denied", reason="unknown_pattern",
                )
                return HTMLResponse(f"unknown pattern: {exc}", status_code=404)
        _admin_audit(
            audit_session_factory, "redaction.catalog_update",
            {"action": "toggle", "name": name, "enabled": enabled},
        )
        return RedirectResponse(url="/settings", status_code=302)

    @app.post("/settings/redaction/delete")
    def redaction_delete(
        request: Request, name: str = Form(...), csrf_token: str = Form("")
    ) -> Response:
        if not csrf.check_request(request.cookies, request.headers, csrf_token):
            return csrf_fail()  # type: ignore[return-value]
        with config_session_factory() as db:
            try:
                # delete_pattern -> _require raises ValueError on unknown
                # names (GH #28: the old `except KeyError` was dead code).
                RedactionCatalog(db).delete_pattern(name)
            except ValueError as exc:
                _admin_audit(
                    audit_session_factory, "redaction.catalog_update",
                    {"action": "delete", "name": name, "error": str(exc)},
                    decision="denied", reason="unknown_pattern",
                )
                return HTMLResponse(f"unknown pattern: {exc}", status_code=404)
        _admin_audit(
            audit_session_factory, "redaction.catalog_update",
            {"action": "delete", "name": name},
        )
        return RedirectResponse(url="/settings", status_code=302)

    # -- recorded decision criteria (FR-PAA09-004) --

    @app.post("/settings/criteria/upsert")
    def criteria_upsert(
        request: Request, domain: str = Form(...), criteria_json: str = Form(...),
        csrf_token: str = Form(""),
    ) -> HTMLResponse:
        if not csrf.check_request(request.cookies, request.headers, csrf_token):
            return csrf_fail()
        try:
            criteria = json.loads(criteria_json)
        except json.JSONDecodeError as exc:
            return HTMLResponse(f"invalid criteria JSON: {exc}", status_code=400)
        with config_session_factory() as db:
            existing = (
                db.query(DecisionCriteria)
                .filter(DecisionCriteria.domain == domain.strip()).first()
            )
            if existing is None:
                db.add(DecisionCriteria(domain=domain.strip(), criteria=criteria))
            else:
                existing.criteria = criteria
                existing.updated_at = _utcnow()
            db.commit()
        _admin_audit(
            audit_session_factory, "criteria.update", {"domain": domain.strip()}
        )
        return RedirectResponse(url="/settings", status_code=302)

    @app.post("/settings/criteria/delete")
    def criteria_delete(
        request: Request, domain: str = Form(...), csrf_token: str = Form("")
    ) -> RedirectResponse:
        if not csrf.check_request(request.cookies, request.headers, csrf_token):
            return csrf_fail()  # type: ignore[return-value]
        with config_session_factory() as db:
            row = (
                db.query(DecisionCriteria)
                .filter(DecisionCriteria.domain == domain.strip()).first()
            )
            if row is not None:
                db.delete(row)
                db.commit()
        _admin_audit(
            audit_session_factory, "criteria.update",
            {"domain": domain.strip(), "deleted": True},
        )
        return RedirectResponse(url="/settings", status_code=302)


# ---------------------------------------------------------------------
# Mandates (02 §3.2): standing instructions — list, pause, narrow, end
# (FR-PAA01-001…008). Pausing/ending/withdrawing a mandate cancels its
# pending approvals and invalidates its grants (FR-PAA01-004).
# ---------------------------------------------------------------------


def register_mandates(
    app: Any,
    config_session_factory: Callable[[], Any],
    audit_session_factory: Callable[[], Any],
    settings: Settings,
    csrf: CsrfProtector,
    hmac_ring: Any,
) -> None:
    def csrf_fail() -> HTMLResponse:
        return HTMLResponse("missing or invalid anti-CSRF token", status_code=403)

    def _mandate_service(db: Any, audit_db: Any) -> ApprovalService:
        return ApprovalService(
            db, AuditLog(audit_db), settings, hmac_ring, MandateService(db)
        )

    @app.get("/mandates", response_class=HTMLResponse)
    def mandates_page() -> HTMLResponse:
        with config_session_factory() as db:
            agents = db.query(Agent).order_by(Agent.id).all()
            rows = []
            for a in agents:
                mandates = (
                    db.query(Mandate)
                    .filter(Mandate.agent_id == a.id)
                    .order_by(Mandate.created_at.desc())
                    .all()
                )
                rows.append(
                    {
                        "agent_id": a.id, "display_name": a.display_name,
                        "mandates": [
                            {
                                "id": m.id, "purpose": m.purpose,
                                "purpose_key": m.purpose_key,
                                "allowed_classes": m.allowed_classes,
                                "status": m.status,
                                "expires_at": m.expires_at,
                                "parent_mandate_id": m.parent_mandate_id,
                                "created_at": m.created_at,
                            }
                            for m in mandates
                        ],
                    }
                )
        token = csrf.issue()
        resp = _RENDER("mandates.html", active="mandates", agents=rows, csrf_token=token)
        csrf.set_cookie(resp, token)
        return resp

    @app.post("/mandates/{mandate_id}/action")
    def mandate_action(
        request: Request, mandate_id: str, action: str = Form(...),
        allowed_classes: str = Form(""), csrf_token: str = Form(""),
    ) -> HTMLResponse:
        # FR-042: anti-CSRF on all state-changing console routes.
        if not csrf.check_request(request.cookies, request.headers, csrf_token):
            return csrf_fail()
        if action not in ("pause", "resume", "narrow", "end", "withdraw"):
            return HTMLResponse("unknown action", status_code=400)
        with config_session_factory() as config_db, audit_session_factory() as audit_db:
            service = MandateService(config_db)
            approval = _mandate_service(config_db, audit_db)
            detail: dict[str, Any] = {"mandate_id": mandate_id, "action": action}
            if action == "pause":
                m = service.pause(mandate_id)
                detail["canceled_approvals"] = approval.cancel_mandate_requests(
                    mandate_id, reason="mandate_paused"
                )
                detail["grants_invalidated"] = approval.grants.invalidate_mandate_grants(
                    mandate_id
                )
            elif action == "resume":
                m = service.resume(mandate_id)
            elif action == "narrow":
                classes = [c.strip() for c in allowed_classes.split(",") if c.strip()]
                if not classes:
                    return HTMLResponse("allowed_classes required", status_code=400)
                try:
                    m = service.narrow(mandate_id, classes)
                except ValueError as exc:
                    return HTMLResponse(str(exc), status_code=400)
            elif action == "end":
                m = service.end(mandate_id)
                detail["canceled_approvals"] = approval.cancel_mandate_requests(
                    mandate_id, reason="mandate_ended"
                )
                detail["grants_invalidated"] = approval.grants.invalidate_mandate_grants(
                    mandate_id
                )
            else:  # withdraw
                m = service.withdraw(mandate_id)
                detail["canceled_approvals"] = approval.cancel_mandate_requests(
                    mandate_id, reason="mandate_withdrawn"
                )
                detail["grants_invalidated"] = approval.grants.invalidate_mandate_grants(
                    mandate_id
                )
            detail["agent_id"] = m.agent_id
            detail["status"] = m.status
        _admin_audit(audit_session_factory, f"mandate.{action}", detail)
        return RedirectResponse(url="/mandates", status_code=302)


# ---------------------------------------------------------------------
# Context boundaries (02 §3.2): purpose registry, data-label classes,
# cross-context leakage events (FR-PAA03-001…004).
# ---------------------------------------------------------------------


def register_context(
    app: Any,
    config_session_factory: Callable[[], Any],
    audit_session_factory: Callable[[], Any],
    csrf: CsrfProtector,
) -> None:
    @app.get("/context", response_class=HTMLResponse)
    def context_page() -> HTMLResponse:
        with config_session_factory() as db:
            purpose_keys = sorted(
                {m.purpose_key for m in db.query(Mandate).all() if m.purpose_key}
            )
            store = OntologyStore(db)
            dims = {d.name: d for d in store.list_dimensions()}
            purpose_values = []
            if "purpose" in dims:
                purpose_values = sorted(dims["purpose"].allowed_values or [])
            resources = store.list_resources()
            labels: dict[str, int] = {}
            for r in resources:
                labels[r.label_class] = labels.get(r.label_class, 0) + 1
        with audit_session_factory() as audit_db:
            leakage = AuditLog(audit_db).search(tool="inspection.context_leakage", limit=50)
            leakage_rows = [
                {"timestamp": e.timestamp, "agent_id": e.agent_id,
                 "reason": e.reason, "request_id": e.request_id,
                 "redacted_args": e.redacted_args}
                for e in leakage
            ]
        return _RENDER(
            "context.html", active="context",
            mandate_purposes=purpose_keys,
            purpose_values=purpose_values,
            label_counts=labels,
            label_classes=["work", "private", "family"],
            leakage_rows=leakage_rows,
        )


# ---------------------------------------------------------------------
# Ontology review queue (M6, small): flagged stale/conflicting entries
# and discovery candidates (confirm/reject). No heavy CRUD — the
# store's validate path runs before any save.
# ---------------------------------------------------------------------


def register_ontology(
    app: Any,
    config_session_factory: Callable[[], Any],
    audit_session_factory: Callable[[], Any],
    csrf: CsrfProtector,
) -> None:
    def csrf_fail() -> HTMLResponse:
        return HTMLResponse("missing or invalid anti-CSRF token", status_code=403)

    @app.get("/ontology", response_class=HTMLResponse)
    def ontology_page() -> HTMLResponse:
        with config_session_factory() as db, audit_session_factory() as audit_db:
            store = OntologyStore(db, AuditLog(audit_db), admin_id="admin_ken")
            review_items = [
                {
                    "id": i.id, "entry_kind": i.entry_kind,
                    "entry_id": i.entry_id, "reason": i.reason,
                    "provenance": i.provenance, "context": i.context,
                    "status": i.status, "detected_at": i.detected_at,
                }
                for i in store.list_review_items()
            ]
            candidates = [
                {
                    "id": c.id, "kind": c.kind, "payload": c.payload,
                    "provenance": c.provenance, "confidence": c.confidence,
                    "status": c.status, "created_at": c.created_at,
                }
                for c in store.list_candidates(status="pending_confirmation")
            ]
            principals = [
                {"id": p.id, "kind": p.kind, "display_name": p.display_name}
                for p in store.list_principals()
            ]
        token = csrf.issue()
        resp = _RENDER(
            "ontology.html", active="ontology",
            review_items=review_items, candidates=candidates,
            principals=principals, csrf_token=token,
        )
        csrf.set_cookie(resp, token)
        return resp

    @app.post("/ontology/review/{item_id}/resolve")
    def review_resolve(
        request: Request, item_id: str, note: str = Form(""),
        csrf_token: str = Form(""),
    ) -> RedirectResponse:
        if not csrf.check_request(request.cookies, request.headers, csrf_token):
            return csrf_fail()  # type: ignore[return-value]
        with config_session_factory() as db, audit_session_factory() as audit_db:
            OntologyStore(db, AuditLog(audit_db), admin_id="admin_ken").resolve_review_item(
                item_id, resolution=note or ""
            )
        return RedirectResponse(url="/ontology", status_code=302)

    @app.post("/ontology/review/{item_id}/dismiss")
    def review_dismiss(
        request: Request, item_id: str, csrf_token: str = Form("")
    ) -> RedirectResponse:
        if not csrf.check_request(request.cookies, request.headers, csrf_token):
            return csrf_fail()  # type: ignore[return-value]
        with config_session_factory() as db, audit_session_factory() as audit_db:
            OntologyStore(db, AuditLog(audit_db), admin_id="admin_ken").dismiss_review_item(
                item_id
            )
        return RedirectResponse(url="/ontology", status_code=302)

    @app.post("/ontology/candidates/{candidate_id}/confirm")
    def candidate_confirm(
        request: Request, candidate_id: str, corrections: str = Form(""),
        csrf_token: str = Form(""),
    ) -> HTMLResponse:
        if not csrf.check_request(request.cookies, request.headers, csrf_token):
            return csrf_fail()
        corr: dict[str, Any] = {}
        if corrections.strip():
            try:
                corr = json.loads(corrections)
            except json.JSONDecodeError as exc:
                return HTMLResponse(f"invalid corrections JSON: {exc}", status_code=400)
        with config_session_factory() as db, audit_session_factory() as audit_db:
            try:
                OntologyStore(db, AuditLog(audit_db), admin_id="admin_ken").confirm_candidate(
                    candidate_id, corrections=corr or None
                )
            except Exception as exc:  # noqa: BLE001 — validation failure
                return HTMLResponse(f"confirm rejected: {exc}", status_code=400)
        return RedirectResponse(url="/ontology", status_code=302)

    @app.post("/ontology/candidates/{candidate_id}/reject")
    def candidate_reject(
        request: Request, candidate_id: str, csrf_token: str = Form("")
    ) -> RedirectResponse:
        if not csrf.check_request(request.cookies, request.headers, csrf_token):
            return csrf_fail()  # type: ignore[return-value]
        with config_session_factory() as db, audit_session_factory() as audit_db:
            OntologyStore(db, AuditLog(audit_db), admin_id="admin_ken").reject_candidate(
                candidate_id
            )
        return RedirectResponse(url="/ontology", status_code=302)


# ---------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------


def register_m6_pages(
    app: Any,
    config_session_factory: Callable[[], Any],
    audit_session_factory: Callable[[], Any],
    settings: Settings,
    csrf: CsrfProtector,
    health: Any,
    vault_store: Any,
    hmac_ring: Any,
    render_page: Callable[..., HTMLResponse],
) -> None:
    global _RENDER
    _RENDER = render_page
    register_dashboard(app, config_session_factory, audit_session_factory, settings, csrf)
    register_latency(app, settings, csrf)
    register_connectors(app, csrf, health)
    register_policies(app, config_session_factory, audit_session_factory, settings, csrf)
    register_vault_settings(
        app, config_session_factory, audit_session_factory, settings, csrf, vault_store
    )
    register_mandates(
        app, config_session_factory, audit_session_factory, settings, csrf, hmac_ring
    )
    register_context(app, config_session_factory, audit_session_factory, csrf)
    register_ontology(app, config_session_factory, audit_session_factory, csrf)
