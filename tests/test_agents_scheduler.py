"""Pillar 2 §1.3/§1.4/§8: the scheduler.

Covers: cron due-computation (incl. timezones); manual-run pickup;
the pre-run gate (global stop, paused agent, missing/forbidden
mandate); no auto-resume (global stop persists schedules disabled);
heartbeat staleness (green/amber/red); cooperative stop of in-flight
runs when the agent is paused.
"""

from __future__ import annotations

import asyncio
import datetime as dt

import pytest

from agents.scheduler import (
    Scheduler,
    compute_next_run,
    heartbeat_health,
    pre_run_gate,
    write_heartbeat,
)
from gateway.config import Settings
from gateway.db import Databases
from gateway.identity import IdentityService
from gateway.mandates import MandateService
from gateway.models import (
    Agent, AgentHeartbeat, AgentRun, AgentSchedule, ConfigSetting, utcnow,
)


@pytest.fixture()
def settings(tmp_path):
    return Settings(
        config_db_path=str(tmp_path / "config.db"),
        audit_db_path=str(tmp_path / "audit.db"),
        hmac_key="test-hmac-key-material-32bytes!",
        agents_enabled=True,
    )


@pytest.fixture()
def dbs(settings):
    d = Databases(settings.config_db_path, settings.audit_db_path)
    d.create_all()
    return d


@pytest.fixture()
def seeded(dbs):
    with dbs.config.session() as db:
        ident = IdentityService(db)
        ag, _cid, _secret = ident.register_agent(
            "agent_redteam", "internal", "agent/redteam", "security")
        MandateService(db).create_mandate(
            ag.id, "redteam mandate",
            ["audit.search", "sandbox.echo", "gateway.approval_status"],
            purpose_key="security")
        db.add(AgentSchedule(
            agent_id=ag.id, enabled=True,
            cron_expr="0 2 * * *", timezone="America/New_York",
            next_run_at=None))
        db.commit()
    return ag.id


def test_compute_next_run_timezone():
    # 2am America/New_York daily: from 2026-10-13 12:00 UTC the next
    # run is 2026-10-14 06:00 UTC (EDT = UTC-4).
    now = dt.datetime(2026, 10, 13, 12, 0, tzinfo=dt.timezone.utc)
    nxt = compute_next_run("0 2 * * *", "America/New_York", now)
    assert nxt is not None
    assert nxt.tzinfo is not None
    assert (nxt.year, nxt.month, nxt.day, nxt.hour) == (2026, 10, 14, 6)


def test_compute_next_run_bad_cron_none():
    now = dt.datetime(2026, 10, 13, 12, 0, tzinfo=dt.timezone.utc)
    assert compute_next_run("not a cron", "UTC", now) is None


def test_pre_run_gate_ok(dbs, seeded):
    with dbs.config.session() as db:
        gate = pre_run_gate(db, seeded, "redteam")
    assert gate.ok is True


def test_pre_run_gate_global_stop(dbs, seeded):
    with dbs.config.session() as db:
        db.add(ConfigSetting(key="global_stop",
                             value={"engaged": True, "at": "t", "by": "admin"}))
        db.commit()
        gate = pre_run_gate(db, seeded, "redteam")
    assert gate.ok is False
    assert gate.status == "stopped"


def test_pre_run_gate_paused_agent(dbs, seeded):
    with dbs.config.session() as db:
        agent = db.get(Agent, seeded)
        agent.status = "paused"
        db.commit()
        gate = pre_run_gate(db, seeded, "redteam")
    assert gate.ok is False
    assert gate.status == "paused"


def test_pre_run_gate_missing_mandate(dbs, seeded):
    from gateway.models import Mandate
    from sqlalchemy import select

    with dbs.config.session() as db:
        for m in db.execute(select(Mandate)).scalars().all():
            m.status = "withdrawn"
        db.commit()
        gate = pre_run_gate(db, seeded, "redteam")
    assert gate.ok is False
    assert gate.status == "mandate_missing"


def test_pre_run_gate_forbidden_mandate(dbs, seeded):
    from gateway.models import Mandate
    from sqlalchemy import select

    with dbs.config.session() as db:
        for m in db.execute(select(Mandate)).scalars().all():
            m.allowed_classes = ["vault.read", "audit.search"]
        db.commit()
        gate = pre_run_gate(db, seeded, "redteam")
    assert gate.ok is False
    assert gate.status == "mandate_forbidden"


def _scheduler(dbs, settings, runners=None):
    return Scheduler(
        session_factory=dbs.config.session,
        settings=settings,
        runners=runners or {},
    )


def test_manual_run_pickup(dbs, settings, seeded):
    from gateway.ids import new_run_id

    async def _runner(**kw):
        return {"status": "ok", "note": "ran"}

    sched = _scheduler(dbs, settings, {"redteam": _runner})
    with dbs.config.session() as db:
        db.add(AgentRun(id=new_run_id(), agent_id=seeded,
                        trigger="manual", status="requested"))
        db.commit()
    # Credentials are required at dispatch; without the env var the
    # run fails closed with credential_missing (not dispatched).
    out = asyncio.run(sched.tick())
    assert out != []  # the manual run was picked up
    with dbs.config.session() as db:
        run = db.execute(
            __import__("sqlalchemy").select(AgentRun)
        ).scalars().first()
        assert run.status == "error"
        hb = db.get(AgentHeartbeat, seeded)
        assert hb is not None
        assert hb.status == "credential_missing"


def test_global_stop_disables_schedules_no_autoresume(dbs, settings, seeded):
    sched = _scheduler(dbs, settings, {})
    with dbs.config.session() as db:
        db.add(ConfigSetting(key="global_stop",
                             value={"engaged": True, "at": "t", "by": "admin"}))
        db.commit()
    out = asyncio.run(sched.tick())
    assert out == []  # nothing dispatched
    with dbs.config.session() as db:
        schedule = db.get(AgentSchedule, seeded)
        assert schedule.enabled is False  # persisted, no auto-resume


def test_heartbeat_health(dbs, settings, seeded):
    with dbs.config.session() as db:
        db.add(AgentHeartbeat(agent_id=seeded, status="ok", ts=utcnow()))
        db.commit()
        assert heartbeat_health(db, seeded, settings) == "green"
        hb = db.get(AgentHeartbeat, seeded)
        hb.ts = utcnow() - dt.timedelta(hours=3)  # >2x the 1h interval
        db.commit()
        assert heartbeat_health(db, seeded, settings) == "amber"
        hb.ts = utcnow() - dt.timedelta(hours=6)  # >5x
        db.commit()
        assert heartbeat_health(db, seeded, settings) == "red"


def test_pause_mid_run_sets_stop_event(dbs, settings, seeded):
    """An agent paused mid-run: the next tick sets the in-flight stop
    event (cooperative halt after the current scenario)."""
    sched = _scheduler(dbs, settings, {})
    event = asyncio.Event()
    sched.stop_events["run_123"] = event
    with dbs.config.session() as db:
        from gateway.ids import new_run_id

        db.add(AgentRun(id="run_123", agent_id=seeded,
                        trigger="manual", status="running"))
        agent = db.get(Agent, seeded)
        agent.status = "paused"
        db.commit()
    asyncio.run(sched.tick())
    assert event.is_set()
