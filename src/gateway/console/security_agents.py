"""Security Agents console page (Pillar 2 §7).

GET /security-agents: the fleet view — one row per security agent
(the redteam row first): status, schedule (enabled / cron or
interval / next run), last run, heartbeat health (green/amber/red per
the missed-heartbeat rule), recent findings, and recent issues filed.

State-changing routes (CSRF-protected):
- POST /security-agents/run-now — insert a manual agent_runs row
  (trigger='manual', status='requested'); the scheduler picks it up
  on the next tick (~15s).
- POST /security-agents/schedule — enable/disable the schedule and
  set the cron expression.
- POST /security-agents/restart — the only way back after a pause or
  global stop: re-validates the mandate, sets the agent active, and
  re-enables the schedule. There is deliberately no "restart all".
- POST /security-agents/global-stop/clear — clear the persisted
  global-stop flag after the operator has restarted agents
  individually (never auto-cleared).

Everything is behind GATEWAY_AGENTS_ENABLED=1 (404 otherwise).
Stealth wording: "candidate OWASP project" only.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from fastapi import Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select

from ..config import Settings
from ..ids import new_run_id
from ..models import (
    Agent,
    AgentHeartbeat,
    AgentRun,
    AgentSchedule,
    ConfigSetting,
    utcnow,
)
from .csrf import CsrfProtector

#: The four security agents (Pillar 2 §1.2), redteam first.
FLEET_ORDER = [
    "agent_redteam",
    "agent_sentinel",
    "agent_policy_assistant",
    "agent_incident",
]

DISPLAY_NAMES = {
    "agent_redteam": "redteam",
    "agent_sentinel": "sentinel",
    "agent_policy_assistant": "policy-assistant",
    "agent_incident": "incident",
}

ROLE_DESCRIPTIONS = {
    "agent_redteam": (
        "Scheduled attack-scenario prober (RT-01…RT-07). Observes, "
        "drafts, and escalates; never pauses agents or changes policy."
    ),
    "agent_sentinel": (
        "Continuous audit-pattern watcher (extension). Observes and "
        "escalates only."
    ),
    "agent_policy_assistant": (
        "On-demand policy drafter (extension). Proposes; never applies."
    ),
    "agent_incident": (
        "On-demand incident timeline builder (extension). Documents "
        "only."
    ),
}


def register_security_agents(
    app: Any,
    config_session_factory: Callable[[], Any],
    audit_session_factory: Callable[[], Any],
    settings: Settings,
    csrf: CsrfProtector,
) -> None:
    from .pages import _RENDER, _admin_audit

    def csrf_fail() -> HTMLResponse:
        return HTMLResponse("missing or invalid anti-CSRF token", status_code=403)

    def agents_off() -> HTMLResponse:
        return HTMLResponse(
            "security agents are disabled (GATEWAY_AGENTS_ENABLED=1 to enable)",
            status_code=404,
        )

    def _global_stop(db: Any) -> Optional[dict[str, Any]]:
        row = db.get(ConfigSetting, "global_stop")
        if row is None:
            return None
        value = row.value or {}
        return value if value.get("engaged") else None

    def _fleet(db: Any) -> list[dict[str, Any]]:
        from agents.scheduler import heartbeat_health  # local: runner-side import

        rows: list[dict[str, Any]] = []
        for agent_id in FLEET_ORDER:
            agent = db.get(Agent, agent_id)
            schedule = db.get(AgentSchedule, agent_id)
            heartbeat = db.get(AgentHeartbeat, agent_id)
            last_run = (
                db.execute(
                    select(AgentRun)
                    .where(AgentRun.agent_id == agent_id)
                    .order_by(AgentRun.created_at.desc())
                    .limit(1)
                )
                .scalars()
                .first()
            )
            recent_runs = (
                db.execute(
                    select(AgentRun)
                    .where(AgentRun.agent_id == agent_id)
                    .order_by(AgentRun.created_at.desc())
                    .limit(10)
                )
                .scalars()
                .all()
            )
            rows.append(
                {
                    "agent_id": agent_id,
                    "display_name": DISPLAY_NAMES.get(agent_id, agent_id),
                    "description": ROLE_DESCRIPTIONS.get(agent_id, ""),
                    "exists": agent is not None,
                    "status": agent.status if agent else "not seeded",
                    "schedule": (
                        {
                            "enabled": schedule.enabled,
                            "cron_expr": schedule.cron_expr,
                            "timezone": schedule.timezone,
                            "interval_seconds": schedule.interval_seconds,
                            "next_run_at": schedule.next_run_at,
                        }
                        if schedule
                        else None
                    ),
                    "heartbeat": (
                        {
                            "status": heartbeat.status,
                            "run_id": heartbeat.run_id,
                            "ts": heartbeat.ts,
                            "note": heartbeat.note,
                            "health": heartbeat_health(db, agent_id, settings),
                        }
                        if heartbeat
                        else None
                    ),
                    "last_run": (
                        {
                            "id": last_run.id, "trigger": last_run.trigger,
                            "status": last_run.status,
                            "started_at": last_run.started_at,
                            "finished_at": last_run.finished_at,
                            "run_log": last_run.run_log,
                        }
                        if last_run
                        else None
                    ),
                    "recent_runs": [
                        {
                            "id": r.id, "trigger": r.trigger, "status": r.status,
                            "started_at": r.started_at, "finished_at": r.finished_at,
                        }
                        for r in recent_runs
                    ],
                }
            )
        return rows

    @app.get("/security-agents", response_class=HTMLResponse)
    def security_agents_page(
        request: Request, message: str = ""
    ) -> HTMLResponse:
        if not settings.agents_enabled:
            return agents_off()
        with config_session_factory() as db:
            token = csrf.issue()
            fleet = _fleet(db)
            stop = _global_stop(db)
            resp = _RENDER(
                "security_agents.html", active="security_agents",
                csrf_token=token, fleet=fleet, global_stop=stop,
                message=message,
            )
            csrf.set_cookie(resp, token)
            return resp

    @app.post("/security-agents/run-now")
    def run_now(
        request: Request, agent_id: str = Form(...),
        csrf_token: str = Form(""),
    ) -> HTMLResponse:
        if not csrf.check_request(request.cookies, request.headers, csrf_token):
            return csrf_fail()
        if not settings.agents_enabled:
            return agents_off()
        if agent_id not in FLEET_ORDER:
            return HTMLResponse("unknown agent", status_code=400)
        with config_session_factory() as db:
            schedule = db.get(AgentSchedule, agent_id)
            if schedule is not None and not schedule.enabled:
                return HTMLResponse(
                    "schedule is disabled — enable it before a manual run",
                    status_code=400,
                )
            db.add(
                AgentRun(
                    id=new_run_id(), agent_id=agent_id,
                    trigger="manual", status="requested",
                )
            )
            db.commit()
        _admin_audit(
            audit_session_factory, "agents.run_now", {"agent_id": agent_id}
        )
        return RedirectResponse(
            url="/security-agents", status_code=302,
        )

    @app.post("/security-agents/schedule")
    def schedule_update(
        request: Request,
        agent_id: str = Form(...),
        enabled: str = Form("false"),
        cron_expr: str = Form(""),
        csrf_token: str = Form(""),
    ) -> HTMLResponse:
        if not csrf.check_request(request.cookies, request.headers, csrf_token):
            return csrf_fail()
        if not settings.agents_enabled:
            return agents_off()
        if agent_id not in FLEET_ORDER:
            return HTMLResponse("unknown agent", status_code=400)
        cron_expr = cron_expr.strip()
        if cron_expr:
            # Validate the cron expression (fail closed on bad cron —
            # the runner skips schedules it cannot parse).
            from croniter import croniter

            if not croniter.is_valid(cron_expr):
                return HTMLResponse(
                    f"invalid cron expression: {cron_expr}", status_code=400
                )
        with config_session_factory() as db:
            schedule = db.get(AgentSchedule, agent_id)
            if schedule is None:
                return HTMLResponse("no schedule for agent", status_code=404)
            schedule.enabled = enabled.lower() == "true"
            if cron_expr:
                schedule.cron_expr = cron_expr
                schedule.next_run_at = None  # recomputed on next tick
            db.commit()
        _admin_audit(
            audit_session_factory, "agents.schedule",
            {"agent_id": agent_id, "enabled": enabled, "cron_expr": cron_expr},
        )
        return RedirectResponse(url="/security-agents", status_code=302)

    @app.post("/security-agents/restart")
    def restart(
        request: Request, agent_id: str = Form(...),
        csrf_token: str = Form(""),
    ) -> HTMLResponse:
        """The only way back after pause/global stop: re-validate the
        mandate, set the agent active, re-enable the schedule. Per
        agent only — there is deliberately no 'restart all'."""
        if not csrf.check_request(request.cookies, request.headers, csrf_token):
            return csrf_fail()
        if not settings.agents_enabled:
            return agents_off()
        if agent_id not in FLEET_ORDER:
            return HTMLResponse("unknown agent", status_code=400)
        from agents.scheduler import pre_run_gate, AGENT_KEYS

        with config_session_factory() as db:
            agent = db.get(Agent, agent_id)
            if agent is None:
                return HTMLResponse("agent not seeded — run python -m agents.seed",
                                    status_code=400)
            # Re-validate the mandate BEFORE re-enabling (fail closed).
            gate = pre_run_gate(db, agent_id, AGENT_KEYS.get(agent_id, ""))
            if gate.status in ("mandate_missing", "mandate_forbidden"):
                return HTMLResponse(
                    f"restart refused: {gate.note}", status_code=400
                )
            # The global-stop flag may still be engaged: restarting one
            # agent does not clear it (per-agent semantics). The
            # scheduler skips dispatch while the flag is engaged, so
            # the operator must also clear the flag explicitly — the
            # page surfaces both steps.
            from ..identity import IdentityService

            IdentityService(db).set_status(agent_id, "active", actor="admin")
            schedule = db.get(AgentSchedule, agent_id)
            if schedule is not None:
                schedule.enabled = True
                schedule.next_run_at = None
            db.commit()
        _admin_audit(
            audit_session_factory, "agents.restart", {"agent_id": agent_id}
        )
        return RedirectResponse(url="/security-agents", status_code=302)

    @app.post("/security-agents/global-stop/clear")
    def global_stop_clear(
        request: Request, csrf_token: str = Form(""),
    ) -> HTMLResponse:
        if not csrf.check_request(request.cookies, request.headers, csrf_token):
            return csrf_fail()
        if not settings.agents_enabled:
            return agents_off()
        with config_session_factory() as db:
            flag = db.get(ConfigSetting, "global_stop")
            if flag is not None:
                flag.value = {"engaged": False,
                              "cleared_at": utcnow().isoformat(),
                              "by": "admin_ken"}
                flag.updated_at = utcnow()
                flag.updated_by = "admin_ken"
                db.commit()
        _admin_audit(audit_session_factory, "agents.global_stop_clear", {})
        return RedirectResponse(url="/security-agents", status_code=302)
