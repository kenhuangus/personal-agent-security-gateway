"""Admin console (M6: all nine pages + admin auth + hardening).

FastAPI app factory + Jinja2 templates.

Pages (02 §3.2): Dashboard, Agents, Connectors, Policies, Approvals,
Audit Log, Vault & Settings, Mandates, Context boundaries, plus the
ontology review queue (M6, small).

Admin auth (FR-036/039/040; 02 §2.6): password + TOTP, first-run
/setup with QR provisioning, login rate-limit + lockout/backoff, and
EVERY auth attempt audit-logged. All console routes except /login,
/setup, and /logout require a valid admin session (middleware gate).
Anti-CSRF tokens on ALL state-changing console routes (FR-042):
SameSite=Strict cookie + X-CSRF-Token custom header (JSON APIs) or
hidden form field (server-rendered forms). Destructive-scope
decisions additionally require a per-decision confirmation token.

Connector health (00 §7 param 16): credential-valid + API-reachable
per connector, every 5 minutes via a daemon background thread; a
banner renders on any failure.

The console never touches vault secrets (FR-022) and never edits
audit rows (FR-032). Agent credentials are shown ONCE at issuance,
then never again.

``dev_no_auth`` is a TEST-ONLY escape hatch (never enable in
production): it disables the admin-auth middleware so pre-M6 tests
keep exercising the pages unchanged.
"""

from __future__ import annotations

import datetime as dt
import logging
import secrets
from pathlib import Path
from typing import Any, Callable, Optional

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import select

from ..audit import AuditLog
from ..config import Settings
from ..hmac_util import HmacKeyRing
from ..identity import IdentityService
from ..mandates import MandateService
from ..models import Agent, ApprovalRequest
from ..pipeline import ConnectorRegistry, StubTokenMinter
from .admin_auth import (
    ADMIN_ID,
    SESSION_COOKIE,
    AdminAuth,
    new_totp_secret,
    totp_qr_data_uri,
    verify_totp,
)
from .approvals import ApprovalConsoleDeps, register_approval_routes
from .csrf import CsrfProtector
from .health import HealthMonitor
from .pages import _admin_audit, register_m6_pages
from .settings_store import effective_settings

_TEMPLATES_DIR = Path(__file__).parent / "templates"

_jinja = Environment(
    loader=FileSystemLoader(str(_TEMPLATES_DIR)),
    autoescape=select_autoescape(["html", "xml"]),
)


def _make_localtime(display_tz: str):  # type: ignore[no-untyped-def]
    """Jinja filter: UTC storage -> Ken's local timezone in display.

    00 §7 param 15. Naive datetimes are treated as UTC (SQLite
    returns naive datetimes for DateTime(timezone=True); models.py
    documents the as_utc convention).
    """
    from zoneinfo import ZoneInfo

    try:
        tz = ZoneInfo(display_tz)
    except Exception:  # noqa: BLE001 — unknown tz falls back to UTC
        tz = dt.timezone.utc

    def _localtime(value):  # type: ignore[no-untyped-def]
        if value is None or value == "":
            return "—"
        if isinstance(value, dt.datetime):
            v = value if value.tzinfo is not None else value.replace(
                tzinfo=dt.timezone.utc
            )
            return v.astimezone(tz).strftime("%Y-%m-%d %H:%M %Z")
        return str(value)

    return _localtime


def _render(name: str, **ctx: Any) -> HTMLResponse:
    return HTMLResponse(_jinja.get_template(name).render(**ctx))


def create_console_app(
    config_session_factory: Callable[[], Any],
    audit_session_factory: Callable[[], Any],
    settings: Optional[Settings] = None,
    *,
    approval_deps: Optional[ApprovalConsoleDeps] = None,
    connectors: Optional[list] = None,
    vault_store: Optional[Any] = None,
    dev_no_auth: bool = False,
) -> FastAPI:
    """Build the console FastAPI app.

    Session factories keep request handling independent of the MCP
    pipeline's sessions (single process in MVP, NFR-REL-001).

    ``approval_deps`` wires the M3 approvals routes (registry + minter
    for the execute-on-approval replay, HMAC ring, notifier transport,
    CSRF protector). When None, safe defaults are built: an ephemeral
    CSRF protector, an empty connector registry, and the stub minter
    (execute-on-approval then fails closed at validation).

    ``connectors`` are the connector objects for health checks
    (Connectors page + banner). ``vault_store`` backs the Vault &
    Settings page (None = vault section renders a notice).

    ``dev_no_auth`` disables the admin-auth middleware. TEST ONLY.
    """
    settings = settings or Settings()
    app = FastAPI(title="Agent Security Gateway — console (M6)")

    # 00 §7 param 15: UTC in storage, Ken's local timezone in display.
    _jinja.filters["localtime"] = _make_localtime(settings.display_tz)

    # Console-editable settings overrides apply at boot (M6, Vault &
    # Settings page). The env/config-file values remain the base.
    with config_session_factory() as _db:
        settings = effective_settings(settings, _db)

    if approval_deps is None:
        hmac_ring = None
        if settings.hmac_key:
            hmac_ring = HmacKeyRing.from_env_string(settings.hmac_key_id, settings.hmac_key)
        approval_deps = ApprovalConsoleDeps(
            settings=settings,
            csrf=CsrfProtector(),
            registry=ConnectorRegistry(),
            minter=StubTokenMinter(),
            hmac_ring=hmac_ring,
        )
    csrf = approval_deps.csrf
    hmac_ring = approval_deps.hmac_ring
    if connectors:
        approval_deps.connectors = list(connectors)
    if vault_store is not None:
        approval_deps.vault_store = vault_store

    admin_auth = AdminAuth(settings, audit_session_factory)

    # GH #20: first-run /setup guard. When no admin exists yet, /setup is
    # in _OPEN_PATHS (no auth) — anyone who can reach the console could
    # claim the admin account. From non-loopback addresses /setup now
    # requires a single-use token printed LOUDLY at startup; loopback
    # keeps working token-free. The token dies with the process (and is
    # cleared the moment setup completes).
    with config_session_factory() as _db:
        _no_admin = not admin_auth.admin_exists(_db)
    if _no_admin and not dev_no_auth:
        app.state.setup_token = secrets.token_urlsafe(32)
        logging.getLogger(__name__).critical(
            "NO ADMIN PROVISIONED: the console has no admin account. "
            "First-run /setup is reachable WITHOUT auth — from loopback "
            "it works directly; from any other address it requires the "
            "one-time setup token: %s (pass as ?token=...; single use, "
            "valid for this process only). Complete /setup immediately.",
            app.state.setup_token,
        )
    else:
        app.state.setup_token = None
    health = HealthMonitor()
    for connector in approval_deps.connectors:
        health.register(connector)
    if approval_deps.connectors and not dev_no_auth:
        # One synchronous baseline check at boot so the banner is
        # accurate from the first page load; the daemon refreshes.
        health.run_all()
    health.start_background()

    # -- per-render nav context ----------------------------------------
    def render_page(name: str, **ctx: Any) -> HTMLResponse:
        if "pending_count" not in ctx:
            with config_session_factory() as db:
                ctx["pending_count"] = (
                    db.execute(
                        select(ApprovalRequest).where(
                            ApprovalRequest.status == "pending"
                        )
                    ).scalars().all()
                ).__len__()
        ctx.setdefault("health_unhealthy", health.any_unhealthy())
        ctx.setdefault("admin_id", ADMIN_ID if not dev_no_auth else "dev")
        return _render(name, **ctx)

    # -- admin-auth middleware (FR-036) ---------------------------------
    # "/" is open because the home route does its own smart redirect
    # (setup when no admin exists, login when unauthenticated, agents
    # when authenticated).
    _OPEN_PATHS = {"/", "/login", "/setup", "/logout"}

    @app.middleware("http")
    async def admin_gate(request: Request, call_next):  # type: ignore[no-untyped-def]
        if dev_no_auth:
            return await call_next(request)
        path = request.url.path
        if path in _OPEN_PATHS:
            return await call_next(request)
        admin_id = admin_auth.verify_session(request.cookies.get(SESSION_COOKIE))
        if admin_id is None:
            if path.startswith("/api/"):
                return JSONResponse({"error": "admin_auth_required"}, status_code=401)
            return RedirectResponse(url="/login", status_code=302)
        request.state.admin_id = admin_id
        return await call_next(request)

    def csrf_fail() -> HTMLResponse:
        return HTMLResponse("missing or invalid anti-CSRF token", status_code=403)

    def issue_token(response: HTMLResponse) -> str:
        token = csrf.issue()
        csrf.set_cookie(response, token)
        return token

    # ------------------------------------------------------------------
    # Admin auth routes (FR-036/039/040; 02 §2.6)
    # ------------------------------------------------------------------
    def _is_loopback(request: Request) -> bool:
        client = request.client
        return client is not None and client.host in ("127.0.0.1", "::1")

    def _setup_gate(request: Request, token: str | None) -> HTMLResponse | None:
        """GH #20: guard the unauthenticated first-run /setup.

        Returns None when the request may proceed, otherwise the
        response to send (redirect or 403). Loopback is always allowed;
        non-loopback requires the single-use startup token.
        ``dev_no_auth`` (TEST ONLY) bypasses the gate.
        """
        if dev_no_auth:
            return None
        if _is_loopback(request):
            return None
        expected = app.state.setup_token
        if expected and token and secrets.compare_digest(token, expected):
            return None
        return HTMLResponse(
            "first-run setup requires a loopback connection or the "
            "one-time setup token printed in the console startup log",
            status_code=403,
        )

    @app.get("/setup", include_in_schema=False)
    def setup_page(request: Request) -> HTMLResponse:
        with config_session_factory() as db:
            if admin_auth.admin_exists(db):
                return RedirectResponse(url="/login", status_code=302)
        gate = _setup_gate(request, request.query_params.get("token"))
        if gate is not None:
            return gate
        secret = new_totp_secret()
        token = csrf.issue()
        resp = _render(
            "setup.html", csrf_token=token, totp_secret=secret,
            qr_data_uri=totp_qr_data_uri(secret),
            setup_token=request.query_params.get("token", ""),
        )
        csrf.set_cookie(resp, token)
        return resp

    @app.post("/setup", include_in_schema=False)
    def setup_create(
        request: Request,
        password: str = Form(...),
        totp_code: str = Form(...),
        totp_seed: str = Form(...),
        csrf_token: str = Form(""),
        setup_token: str = Form(""),
    ) -> HTMLResponse:
        if not csrf.check_request(request.cookies, request.headers, csrf_token):
            return csrf_fail()
        gate = _setup_gate(request, setup_token or None)
        if gate is not None:
            return gate
        with config_session_factory() as db:
            if admin_auth.admin_exists(db):
                return RedirectResponse(url="/login", status_code=302)
            if not verify_totp(totp_seed, totp_code.strip()):
                token = csrf.issue()
                resp = _render(
                    "setup.html", csrf_token=token, totp_seed=totp_seed,
                    qr_data_uri=totp_qr_data_uri(totp_seed),
                    error="That authenticator code did not verify — check the app and try again.",
                    setup_token=setup_token,
                )
                csrf.set_cookie(resp, token)
                return resp
            try:
                admin_auth.setup_admin(db, password, totp_seed)
            except ValueError as exc:
                token = csrf.issue()
                resp = _render(
                    "setup.html", csrf_token=token, totp_seed=totp_seed,
                    qr_data_uri=totp_qr_data_uri(totp_seed), error=str(exc),
                    setup_token=setup_token,
                )
                csrf.set_cookie(resp, token)
                return resp
            # GH #20: single-use — the token dies with the first completed
            # setup (an admin now exists, so /setup redirects anyway).
            request.app.state.setup_token = None
        session_token, _exp = admin_auth.issue_session()
        resp = RedirectResponse(url="/dashboard", status_code=302)
        admin_auth.set_session_cookie(resp, session_token)
        return resp

    @app.get("/login", include_in_schema=False)
    def login_page(request: Request) -> HTMLResponse:
        if admin_auth.verify_session(request.cookies.get(SESSION_COOKIE)):
            return RedirectResponse(url="/dashboard", status_code=302)
        with config_session_factory() as db:
            if not admin_auth.admin_exists(db):
                return RedirectResponse(url="/setup", status_code=302)
        token = csrf.issue()
        resp = _render("login.html", csrf_token=token)
        csrf.set_cookie(resp, token)
        return resp

    @app.post("/login", include_in_schema=False)
    def login_attempt(
        request: Request,
        password: str = Form(...),
        totp_code: str = Form(...),
        csrf_token: str = Form(""),
    ) -> HTMLResponse:
        if not csrf.check_request(request.cookies, request.headers, csrf_token):
            return csrf_fail()
        client_ip = request.client.host if request.client else "unknown"
        with config_session_factory() as db:
            if not admin_auth.admin_exists(db):
                return RedirectResponse(url="/setup", status_code=302)
            ok, reason = admin_auth.login(db, password, totp_code, client_ip)
        if not ok:
            messages = {
                "locked_out": "Too many failed attempts — try again later.",
                "invalid_password": "Wrong password.",
                "invalid_totp": "Wrong authenticator code.",
                "no_such_admin": "No admin is provisioned.",
            }
            token = csrf.issue()
            resp = _render(
                "login.html", csrf_token=token,
                error=messages.get(reason, "Sign-in failed."),
            )
            csrf.set_cookie(resp, token)
            return resp
        session_token, _exp = admin_auth.issue_session()
        resp = RedirectResponse(url="/dashboard", status_code=302)
        admin_auth.set_session_cookie(resp, session_token)
        return resp

    @app.post("/logout", include_in_schema=False)
    def logout() -> RedirectResponse:
        resp = RedirectResponse(url="/login", status_code=302)
        admin_auth.clear_session_cookie(resp)
        return resp

    @app.post("/admin/totp-reset", response_class=HTMLResponse)
    def totp_reset(request: Request, csrf_token: str = Form("")) -> HTMLResponse:
        # Re-issue the TOTP secret; the new QR is shown once (FR-036).
        if not csrf.check_request(request.cookies, request.headers, csrf_token):
            return csrf_fail()
        with config_session_factory() as db:
            secret, qr = admin_auth.reset_totp(db)
        return _render(
            "setup.html", csrf_token=csrf.issue(), totp_secret=secret,
            qr_data_uri=qr, error=None,
        )

    # ------------------------------------------------------------------
    # Home
    # ------------------------------------------------------------------
    @app.get("/", include_in_schema=False)
    def home(request: Request) -> RedirectResponse:
        if dev_no_auth or admin_auth.verify_session(request.cookies.get(SESSION_COOKIE)):
            return RedirectResponse(url="/agents", status_code=302)
        with config_session_factory() as db:
            target = "/login" if admin_auth.admin_exists(db) else "/setup"
        return RedirectResponse(url=target, status_code=302)

    # ------------------------------------------------------------------
    # Agents page (M2)
    # ------------------------------------------------------------------
    @app.get("/agents", response_class=HTMLResponse)
    def agents_page() -> HTMLResponse:
        with config_session_factory() as db:
            agents = db.query(Agent).order_by(Agent.id).all()
            rows = [
                {
                    "id": a.id,
                    "platform": a.platform,
                    "display_name": a.display_name,
                    "household_role": a.household_role,
                    "status": a.status,
                    "auth_method": a.auth_method,
                    "last_seen_at": a.last_seen_at,
                }
                for a in agents
            ]
        token = csrf.issue()
        resp = render_page("agents.html", agents=rows, active="agents", csrf_token=token)
        csrf.set_cookie(resp, token)
        return resp

    @app.post("/agents", response_class=HTMLResponse)
    def agents_register(
        request: Request,
        agent_id: str = Form(...),
        platform: str = Form(...),
        display_name: str = Form(...),
        household_role: str = Form(...),
        csrf_token: str = Form(""),
    ) -> HTMLResponse:
        # FR-042: anti-CSRF on all state-changing console routes.
        if not csrf.check_request(request.cookies, request.headers, csrf_token):
            return csrf_fail()
        with config_session_factory() as db:
            identity = IdentityService(db)
            agent, client_id, client_secret = identity.register_agent(
                agent_id.strip(), platform.strip(), display_name.strip(),
                household_role.strip(),
            )
            mandate = MandateService(db).create_default_mandate(agent)
        return render_page(
            "agent_created.html",
            active="agents",
            agent_id=agent.id,
            client_id=client_id,
            client_secret=client_secret,
            mandate_id=mandate.id,
        )

    @app.get("/agents/{agent_id}", response_class=HTMLResponse)
    def agent_detail(agent_id: str) -> HTMLResponse:
        with config_session_factory() as config_db:
            agent = config_db.get(Agent, agent_id)
            if agent is None:
                return HTMLResponse("unknown agent", status_code=404)
            mandates = MandateService(config_db).live_mandates(agent_id)
            info = {
                "id": agent.id,
                "platform": agent.platform,
                "display_name": agent.display_name,
                "household_role": agent.household_role,
                "status": agent.status,
                "auth_method": agent.auth_method,
                "verified_test_date": agent.verified_test_date,
                "created_at": agent.created_at,
                "last_seen_at": agent.last_seen_at,
            }
            mandate_rows = [
                {
                    "id": m.id, "purpose": m.purpose,
                    "purpose_key": m.purpose_key,
                    "status": m.status, "expires_at": m.expires_at,
                }
                for m in mandates
            ]
        with audit_session_factory() as audit_db:
            recent = AuditLog(audit_db).search(agent_id=agent_id, limit=20)
            calls = [
                {
                    "timestamp": e.timestamp, "tool": e.tool,
                    "decision": e.decision, "reason": e.reason,
                    "request_id": e.request_id,
                }
                for e in recent
            ]
        token = csrf.issue()
        resp = render_page(
            "agent_detail.html", active="agents", agent=info,
            mandates=mandate_rows, calls=calls, csrf_token=token,
        )
        csrf.set_cookie(resp, token)
        return resp

    @app.post("/agents/{agent_id}/status")
    def agent_status(
        request: Request,
        agent_id: str,
        action: str = Form(...),
        csrf_token: str = Form(""),
    ) -> RedirectResponse:
        # FR-042: anti-CSRF on all state-changing console routes.
        # Actions: pause | resume | revoke (FR-PAA10-002; revoke is
        # immediate per FR-015).
        if not csrf.check_request(request.cookies, request.headers, csrf_token):
            return csrf_fail()  # type: ignore[return-value]
        with config_session_factory() as db:
            identity = IdentityService(db)
            if action == "pause":
                identity.set_status(agent_id, "paused")
            elif action == "resume":
                identity.set_status(agent_id, "active")
            elif action == "revoke":
                identity.revoke(agent_id)
                # Fix B: revocation kills grants immediately.
                from ..approvals import ApprovalService

                with audit_session_factory() as audit_db:
                    ApprovalService(
                        db, AuditLog(audit_db), settings, None,
                        MandateService(db),
                    ).kill_agent_grants(agent_id)
            else:
                return HTMLResponse("unknown action", status_code=400)  # type: ignore[return-value]
            # FR-041: agent lifecycle admin actions are audit-logged.
            _admin_audit(
                audit_session_factory, f"agent.{action}", {"agent_id": agent_id}
            )
        return RedirectResponse(url=f"/agents/{agent_id}", status_code=302)

    # ------------------------------------------------------------------
    # Audit Log page (M2)
    # ------------------------------------------------------------------
    @app.get("/audit", response_class=HTMLResponse)
    def audit_page(
        request: Request,
        agent_id: str = "",
        tool: str = "",
        decision: str = "",
    ) -> HTMLResponse:
        with audit_session_factory() as audit_db:
            rows = AuditLog(audit_db).search(
                agent_id=agent_id or None,
                tool=tool or None,
                decision=decision or None,
                limit=200,
            )
            entries = [
                {
                    "timestamp": e.timestamp,
                    "agent_id": e.agent_id,
                    "tool": e.tool,
                    "decision": e.decision,
                    "reason": e.reason,
                    "mandate_id": e.mandate_id,
                    "scope_rule": e.scope_rule,
                    "request_id": e.request_id,
                    "redacted_args": e.redacted_args,
                }
                for e in rows
            ]
        return render_page(
            "audit.html", active="audit", entries=entries,
            agent_id=agent_id, tool=tool, decision=decision,
        )

    @app.get("/audit/export")
    def audit_export(
        request: Request,
        format: str = "json",
        agent_id: str = "",
        tool: str = "",
        decision: str = "",
    ) -> Response:
        # The export itself is audit-logged (FR-033). MVP staging is a
        # direct download (00 §7 param 19).
        if format not in ("json", "csv"):
            return HTMLResponse("unknown format", status_code=400)
        import csv as _csv
        import io as _io
        import json as _json

        with audit_session_factory() as audit_db:
            log = AuditLog(audit_db)
            rows = log.search(
                agent_id=agent_id or None,
                tool=tool or None,
                decision=decision or None,
                limit=100000,
            )
            if format == "json":
                payload = _json.dumps(
                    [log._row(e) for e in rows], indent=2, ensure_ascii=True
                )
                media = "application/json"
            else:
                buf = _io.StringIO()
                fieldnames = [
                    "request_id", "agent_id", "tool", "timestamp", "decision",
                    "reason", "mandate_id", "scope_rule", "redacted_args",
                ]
                writer = _csv.DictWriter(buf, fieldnames=fieldnames)
                writer.writeheader()
                for e in rows:
                    writer.writerow(
                        {
                            "request_id": e.request_id,
                            "agent_id": e.agent_id,
                            "tool": e.tool,
                            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                            "decision": e.decision,
                            "reason": e.reason,
                            "mandate_id": e.mandate_id,
                            "scope_rule": e.scope_rule,
                            "redacted_args": _json.dumps(e.redacted_args or {}, ensure_ascii=True),
                        }
                    )
                payload = buf.getvalue()
                media = "text/csv"
            log.append(
                agent_id="console",
                tool="audit.export",
                decision="allowed",
                redacted_args={
                    "format": format, "agent_id": agent_id or None,
                    "tool": tool or None, "decision": decision or None,
                    "row_count": len(rows),
                },
            )
        return Response(
            content=payload,
            media_type=media,
            headers={"Content-Disposition": f"attachment; filename=audit-export.{format}"},
        )

    # ------------------------------------------------------------------
    # Approvals page + API (M3)
    # ------------------------------------------------------------------
    register_approval_routes(
        app, config_session_factory, audit_session_factory, approval_deps, render_page
    )

    # ------------------------------------------------------------------
    # M6 pages: Dashboard, Connectors, Policies, Vault & Settings,
    # Mandates, Context boundaries, Ontology review queue
    # ------------------------------------------------------------------
    register_m6_pages(
        app, config_session_factory, audit_session_factory, settings, csrf,
        health, approval_deps.vault_store, hmac_ring, render_page,
    )

    return app
