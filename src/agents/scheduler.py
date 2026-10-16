"""Agent scheduler (Pillar 2 §1.3).

Tick loop: every ``GATEWAY_AGENTS_RUNNER_POLL_S`` (default 15s) the
runner loads ``agent_schedules`` rows, computes due runs with
croniter (``cron_expr``, ``timezone``), and dispatches. On-demand runs:
the console "Run now" button inserts an ``agent_runs`` row with
``trigger='manual', status='requested'``; the scheduler picks it up on
the next tick (no signal mechanism needed; 15s latency is acceptable).

Concurrency: one ``asyncio.Semaphore(GATEWAY_REDATEAM_MAX_CONCURRENCY)``
(default 2) per agent for scenario fan-out; runs for different agents
are independent tasks.

Pre-run gate (every run, every agent): (1) global-stop flag clear;
(2) agent status ``active``; (3) a live mandate covering the agent's
tools; (4) ``validate_security_mandate()`` on the resolved allowlist.
"""

from __future__ import annotations

import asyncio
import datetime as dt
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional
from zoneinfo import ZoneInfo

from croniter import croniter
from sqlalchemy import select
from sqlalchemy.orm import Session

from gateway.models import Agent, AgentHeartbeat, AgentRun, AgentSchedule, Mandate, as_utc, utcnow

from .mandates import ForbiddenMandateError, validate_security_mandate

#: agent_id → agent key (for credential env vars + dispatch).
AGENT_KEYS: dict[str, str] = {
    "agent_redteam": "redteam",
    "agent_sentinel": "sentinel",
    "agent_policy_assistant": "policy_assistant",
    "agent_incident": "incident",
}


def global_stop_engaged(db: Session) -> bool:
    """True when the dashboard's global stop flag is engaged."""
    from gateway.models import ConfigSetting

    row = db.get(ConfigSetting, "global_stop")
    if row is None:
        return False
    value = row.value or {}
    return bool(value.get("engaged"))


def compute_next_run(
    cron_expr: str, timezone: str, now: dt.datetime
) -> Optional[dt.datetime]:
    """Next run time after *now* per the cron expression (schedule tz)."""
    try:
        tz = ZoneInfo(timezone or "UTC")
    except Exception:  # noqa: BLE001 — fail closed: no schedule on bad tz
        return None
    local_now = (as_utc(now) or now).astimezone(tz)
    try:
        cron = croniter(cron_expr, local_now)
        nxt = cron.get_next(dt.datetime)
    except Exception:  # noqa: BLE001 — bad cron: no schedule
        return None
    if nxt.tzinfo is None:
        nxt = nxt.replace(tzinfo=tz)
    return nxt.astimezone(dt.timezone.utc)


@dataclass
class PreRunGate:
    """Result of the pre-run gate (§1.3)."""

    ok: bool
    status: str = "ok"   # heartbeat status when not ok
    note: str = ""


def pre_run_gate(
    db: Session, agent_id: str, agent_key: str, now: Optional[dt.datetime] = None
) -> PreRunGate:
    """Run the four pre-run checks (§1.3)."""
    now = now or utcnow()
    if global_stop_engaged(db):
        return PreRunGate(False, "stopped", "global stop engaged")
    agent = db.get(Agent, agent_id)
    if agent is None:
        return PreRunGate(False, "error", f"unknown agent {agent_id}")
    if agent.status != "active":
        return PreRunGate(False, "paused", f"agent status is {agent.status}")
    # Live mandate covering the agent's tools: the union of live
    # mandates' allowlists must be non-empty, and the resolved
    # allowlist must pass validate_security_mandate (defense in depth
    # against hand-edited mandates).
    mandates = (
        db.execute(
            select(Mandate).where(
                Mandate.agent_id == agent_id, Mandate.status == "active"
            )
        )
        .scalars()
        .all()
    )
    live = [
        m for m in mandates
        if m.expires_at is None or (as_utc(m.expires_at) or m.expires_at) > now
    ]
    if not live:
        return PreRunGate(False, "mandate_missing", "no live mandate for the agent")
    resolved: list[str] = []
    for m in live:
        for cls in (m.allowed_classes or []):
            if cls not in resolved:
                resolved.append(cls)
    try:
        validate_security_mandate(resolved)
    except ForbiddenMandateError as exc:
        return PreRunGate(False, "mandate_forbidden", str(exc))
    return PreRunGate(True)


def write_heartbeat(
    db: Session,
    agent_id: str,
    status: str,
    run_id: Optional[str] = None,
    note: str = "",
) -> None:
    row = db.get(AgentHeartbeat, agent_id)
    if row is None:
        row = AgentHeartbeat(agent_id=agent_id)
        db.add(row)
    row.run_id = run_id
    row.status = status
    row.note = note[:500]
    row.ts = utcnow()
    db.commit()


@dataclass
class Scheduler:
    """The tick-loop scheduler. Owns scheduling, per-agent rate
    limiting, heartbeats, and kill-switch polling."""

    session_factory: Callable[[], Session]
    settings: Any
    # agent_key → async runner fn(ctx-like, run) ; None = not implemented.
    runners: dict[str, Optional[Callable[..., Awaitable[dict[str, Any]]]]] = field(
        default_factory=dict
    )
    clock: Callable[[], dt.datetime] = utcnow
    # In-flight stop events per run id (the kill-switch signal).
    stop_events: dict[str, asyncio.Event] = field(default_factory=dict)
    # Optional audit session factory for the global-stop audit trail.
    audit_session_factory: Optional[Callable[[], Session]] = None

    async def tick(self) -> list[str]:
        """One scheduler tick: kill-switch poll, due computation,
        manual-run pickup, dispatch. Returns dispatched run ids."""
        now = self.clock()
        dispatched: list[str] = []
        with self.session_factory() as db:
            if global_stop_engaged(db):
                await self._on_global_stop(db, now)
                return []
            # Cooperative stop: an agent paused mid-run halts after
            # the current scenario (the engine checks the stop event
            # between scenarios).
            for run_id, event in list(self.stop_events.items()):
                run = db.get(AgentRun, run_id)
                if run is None:
                    continue
                agent = db.get(Agent, run.agent_id)
                if agent is None or agent.status != "active":
                    event.set()
            due = self._due_schedules(db, now)
            for schedule in due:
                run = self._insert_run(
                    db, schedule.agent_id, trigger="scheduled", now=now
                )
                schedule.next_run_at = compute_next_run(
                    schedule.cron_expr, schedule.timezone, now
                )
                db.commit()
                dispatched.append(run.id)
            # Manual "Run now" pickup.
            manual = (
                db.execute(
                    select(AgentRun).where(AgentRun.status == "requested")
                )
                .scalars()
                .all()
            )
            for run in manual:
                dispatched.append(run.id)
        for run_id in dispatched:
            await self.dispatch(run_id)
        return dispatched

    async def _on_global_stop(self, db: Session, now: dt.datetime) -> None:
        """Global stop: halt dispatch, cooperatively stop in-flight
        runs, persist schedules disabled (no auto-resume), audit-log
        each step as system actions (fail-visible)."""
        for event in self.stop_events.values():
            event.set()
        schedules = db.execute(select(AgentSchedule)).scalars().all()
        disabled = 0
        for schedule in schedules:
            if schedule.enabled:
                schedule.enabled = False
                disabled += 1
        db.commit()
        if self.audit_session_factory is not None:
            from gateway.audit import AuditLog

            with self.audit_session_factory() as audit_db:
                AuditLog(audit_db).append(
                    agent_id="system",
                    tool="agents.global_stop",
                    decision="allowed",
                    action="engage",
                    redacted_args={
                        "schedules_disabled": disabled,
                        "in_flight_stopped": len(self.stop_events),
                        "engaged_at": now.isoformat(),
                    },
                )

    def _due_schedules(
        self, db: Session, now: dt.datetime
    ) -> list[AgentSchedule]:
        out: list[AgentSchedule] = []
        schedules = db.execute(select(AgentSchedule)).scalars().all()
        for schedule in schedules:
            if not schedule.enabled:
                continue
            next_at = schedule.next_run_at
            if next_at is None:
                next_at = compute_next_run(schedule.cron_expr, schedule.timezone, now)
                schedule.next_run_at = next_at
                db.commit()
                continue
            if (as_utc(next_at) or next_at) <= now:
                out.append(schedule)
        return out

    def _insert_run(
        self, db: Session, agent_id: str, *, trigger: str, now: dt.datetime
    ) -> AgentRun:
        from gateway.ids import new_run_id

        run = AgentRun(
            id=new_run_id(), agent_id=agent_id, trigger=trigger,
            status="requested",
        )
        db.add(run)
        db.commit()
        return run

    async def dispatch(self, run_id: str) -> dict[str, Any]:
        """Dispatch one run: pre-run gate → runner → heartbeat."""
        from .mcp_client import CredentialMissing, load_agent_credentials

        now = self.clock()
        with self.session_factory() as db:
            run = db.get(AgentRun, run_id)
            if run is None or run.status != "requested":
                return {"run_id": run_id, "dispatched": False}
            agent_key = AGENT_KEYS.get(run.agent_id, "")
            gate = pre_run_gate(db, run.agent_id, agent_key, now)
            if not gate.ok:
                run.status = "error"
                db.commit()
                write_heartbeat(db, run.agent_id, gate.status, run.id, gate.note)
                return {"run_id": run_id, "dispatched": False, "gate": gate.status}
            try:
                creds = load_agent_credentials(agent_key)
            except CredentialMissing as exc:
                run.status = "error"
                db.commit()
                write_heartbeat(db, run.agent_id, "credential_missing", run.id, str(exc))
                return {"run_id": run_id, "dispatched": False, "gate": "credential_missing"}
            runner_fn = self.runners.get(agent_key)
            if runner_fn is None:
                run.status = "error"
                db.commit()
                write_heartbeat(
                    db, run.agent_id, "error", run.id,
                    f"no runner implemented for {agent_key} (extension)",
                )
                return {"run_id": run_id, "dispatched": False, "gate": "not_implemented"}
            stop_event = asyncio.Event()
            self.stop_events[run.id] = stop_event
            run.status = "running"
            run.started_at = now
            db.commit()
            agent_id, trigger, run_input = run.agent_id, run.trigger, dict(run.input or {})
            credential_id = creds.credential_id
        # The runner fn runs outside the DB session (it opens its own).
        try:
            outcome = await runner_fn(
                agent_id=agent_id, agent_key=agent_key, run_id=run_id,
                trigger=trigger, run_input=run_input,
                credential_id=credential_id,
                stop_event=stop_event,
                settings=self.settings,
                session_factory=self.session_factory,
            )
            final_status = str(outcome.get("status", "ok"))
        except Exception as exc:  # noqa: BLE001 — fail-visible, never fail-silent
            final_status = "error"
            outcome = {"status": "error", "error": str(exc)[:500]}
        finally:
            self.stop_events.pop(run_id, None)
        with self.session_factory() as db:
            run = db.get(AgentRun, run_id)
            if run is not None:
                run.status = final_status if final_status in (
                    "ok", "findings", "error", "stopped", "rate_limited") else "error"
                run.finished_at = self.clock()
                run.run_log = outcome.get("log", {})
                db.commit()
            write_heartbeat(db, agent_id, run.status if run else final_status,
                            run_id, str(outcome.get("note", ""))[:500])
        return {"run_id": run_id, "dispatched": True, "status": final_status}


def heartbeat_health(
    db: Session, agent_id: str, settings: Any, now: Optional[dt.datetime] = None
) -> str:
    """Fleet health rule (§1.4): expected interval from the schedule
    row; >2× amber, >5× red (+ console banner)."""
    now = now or utcnow()
    row = db.get(AgentHeartbeat, agent_id)
    schedule = db.get(AgentSchedule, agent_id)
    if row is None or schedule is None:
        return "unknown"
    interval_s = schedule.interval_seconds or 3600
    amber_mult = int(getattr(settings, "agents_heartbeat_missed_amber", 2) or 2)
    red_mult = int(getattr(settings, "agents_heartbeat_missed_red", 5) or 5)
    missed = ((as_utc(now) or now) - (as_utc(row.ts) or row.ts)).total_seconds() / max(interval_s, 1)
    if missed > red_mult:
        return "red"
    if missed > amber_mult:
        return "amber"
    return "green"
