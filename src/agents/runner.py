"""agents-runner: the dedicated security-agent process (Pillar 2 §1.1).

Entry point: ``python -m agents.runner``. One long-running process
owning scheduling (croniter), per-agent rate limiting (in-memory token
buckets + ``asyncio.Semaphore``), heartbeats, and kill-switch polling.
It never holds a privileged DB bypass: all *tool* access goes over
MCP as an authenticated client. Its direct DB access is limited to its
own state tables (schedules, runs, heartbeats, findings) — never the
audit log (append-only; the runner reads audit only through the
``audit.search`` tool as the sentinel/redteam agent, never via SQL).

Startup is fail-closed: the runner refuses to start when
``GATEWAY_AGENTS_ENABLED != 1``, when the gateway ``/healthz`` is
unreachable, or when any configured agent has no live mandate (it
logs and idles; it does not invent mandates).

Kill switches are runner-enforced with no auto-resume (§8): the
runner polls the persisted global-stop flag and per-agent
pause/mandate state every tick; on global stop it halts in-flight
runs cooperatively, persists ``schedule.enabled=False``, and never
resumes until the operator restarts each agent explicitly.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys

log = logging.getLogger("agents.runner")


def _fail_closed(reason: str) -> "int":
    log.error("agents-runner refusing to start: %s", reason)
    print(f"agents-runner: refusing to start: {reason}", file=sys.stderr)
    return 2


async def _healthz_ok(settings: object) -> bool:
    import httpx

    url = f"http://{settings.host}:{settings.port}/healthz"
    try:
        async with httpx.AsyncClient(trust_env=False, timeout=5.0) as client:
            resp = await client.get(url)
        return resp.status_code < 500
    except Exception:  # noqa: BLE001 — unreachable gateway: fail closed
        return False


def main() -> int:
    # The agents package lives in src/; the gateway package too. Both
    # must be importable (PYTHONPATH=src or an installed package).
    from gateway.config import load_settings
    from gateway.db import Databases

    settings = load_settings()
    if not settings.agents_enabled:
        return _fail_closed("GATEWAY_AGENTS_ENABLED != 1 (default-off)")
    problems = settings.validate()
    if problems:
        return _fail_closed("config problems: " + "; ".join(problems))

    if not asyncio.run(_healthz_ok(settings)):
        return _fail_closed(
            f"gateway /healthz unreachable at {settings.host}:{settings.port}"
        )

    from .redteam.flow import run_redteam_agent
    from .scheduler import Scheduler, pre_run_gate, AGENT_KEYS

    databases = Databases(settings.config_db_path, settings.audit_db_path)
    databases.create_all()

    # Fail-closed: every configured agent must have a live mandate, or
    # the runner logs and idles (it does not invent mandates).
    with databases.config.session() as db:
        missing = []
        for agent_id in AGENT_KEYS:
            gate = pre_run_gate(db, agent_id, AGENT_KEYS[agent_id])
            # credential_missing is fine at startup (the agent's run is
            # skipped per-run); mandate problems idle the runner.
            if gate.status in ("mandate_missing", "mandate_forbidden"):
                missing.append(f"{agent_id}: {gate.note}")
        if missing:
            for line in missing:
                log.error("no live mandate: %s", line)
            print(
                "agents-runner: idling — no live mandate for: "
                + ", ".join(missing),
                file=sys.stderr,
            )
            # Idle: keep the process up so supervision sees it, but do
            # not dispatch. (A fresh seed + mandate creation un-idles
            # on the next tick check.)
            idle = True
        else:
            idle = False

    from gateway.connectors.issue_store import opener_from_settings

    issue_opener = opener_from_settings(settings)

    scheduler = Scheduler(
        session_factory=databases.config.session,
        audit_session_factory=databases.audit.session,
        settings=settings,
        runners={
            "redteam": _redteam_runner(issue_opener),
            # Extensions (sentinel, policy_assistant, incident) land
            # their runner here; until then the scheduler records
            # "not implemented" heartbeats for enabled schedules.
            "sentinel": None,
            "policy_assistant": None,
            "incident": None,
        },
    )
    poll_s = max(int(settings.agents_runner_poll_s), 1)
    log.info(
        "agents-runner started (poll %ss, idle=%s)", poll_s, idle
    )
    print(f"agents-runner: started (poll {poll_s}s, idle={idle})", flush=True)

    async def _loop() -> None:
        while True:
            try:
                if not idle:
                    await scheduler.tick()
            except Exception:  # noqa: BLE001 — the loop never dies silently
                log.exception("agents-runner tick failed")
            await asyncio.sleep(poll_s)

    try:
        asyncio.run(_loop())
    except KeyboardInterrupt:
        print("agents-runner: stopped", flush=True)
    return 0


def _redteam_runner(issue_opener: object):  # noqa: ANN001, ANN202
    async def _run(**kwargs):  # noqa: ANN003, ANN202
        return await run_redteam_agent(issue_opener=issue_opener, **kwargs)

    return _run


if __name__ == "__main__":
    sys.exit(main())
