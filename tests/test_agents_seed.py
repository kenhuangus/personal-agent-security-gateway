"""Pillar 2 §1.2/§4: ``python -m agents.seed`` — the four security agents.

The seed registers agent_redteam, agent_sentinel, agent_policy_assistant,
and agent_incident (MCP-authenticated, credentials from env only — the
seed prints each secret once and never stores it), creates their
security mandates (validated by ``validate_security_mandate``), writes
disabled schedules, and merges the least-privilege policy rules.
"""

from __future__ import annotations

import os

import pytest
from sqlalchemy import select

from gateway.db import Databases
from gateway.models import Agent, AgentCredential, AgentSchedule, Mandate


@pytest.fixture()
def seed_env(tmp_path, monkeypatch):
    config_db = str(tmp_path / "config.db")
    audit_db = str(tmp_path / "audit.db")
    monkeypatch.setenv("GATEWAY_CONFIG_DB", config_db)
    monkeypatch.setenv("GATEWAY_AUDIT_DB", audit_db)
    return tmp_path


def _run_seed(seed_env):
    from agents.seed import main

    rc = main()
    assert rc == 0
    return Databases(
        os.environ["GATEWAY_CONFIG_DB"], os.environ["GATEWAY_AUDIT_DB"]
    )


def test_seed_registers_four_agents(seed_env, capsys):
    dbs = _run_seed(seed_env)
    with dbs.config.session() as db:
        agents = db.execute(select(Agent)).scalars().all()
    ids = {a.id for a in agents}
    assert ids == {
        "agent_redteam",
        "agent_sentinel",
        "agent_policy_assistant",
        "agent_incident",
    }
    # The seed prints the one-time credentials to stdout; it must never
    # store the raw secret — AgentCredential keeps a bcrypt hash only.
    out = capsys.readouterr().out
    assert "AGENT CREDENTIALS" in out
    from gateway.models import AgentCredential

    with dbs.config.session() as db:
        creds = db.execute(select(AgentCredential)).scalars().all()
    assert len(creds) == 4
    for cred in creds:
        # bcrypt hash only — the raw secret the seed printed to stdout
        # must never land in the DB.
        assert cred.secret_hash.startswith("$2b$")


def test_seed_creates_mandates(seed_env, capsys):
    capsys.readouterr()  # discard prints
    dbs = _run_seed(seed_env)
    with dbs.config.session() as db:
        for agent_id in (
            "agent_redteam",
            "agent_sentinel",
            "agent_policy_assistant",
            "agent_incident",
        ):
            mandates = (
                db.execute(
                    select(Mandate).where(
                        Mandate.agent_id == agent_id,
                        Mandate.status == "active",
                    )
                )
                .scalars()
                .all()
            )
            assert len(mandates) == 1, agent_id


def test_seed_schedules_disabled(seed_env, capsys):
    capsys.readouterr()
    dbs = _run_seed(seed_env)
    with dbs.config.session() as db:
        schedules = db.execute(select(AgentSchedule)).scalars().all()
    assert {s.agent_id for s in schedules} == {
        "agent_redteam",
        "agent_sentinel",
        "agent_policy_assistant",
        "agent_incident",
    }
    # Default-off: every schedule lands disabled; the operator enables
    # each explicitly. No schedule may fire on its own.
    assert all(s.enabled is False for s in schedules)


def test_seed_merges_policy_rules(seed_env, capsys):
    capsys.readouterr()
    dbs = _run_seed(seed_env)
    from gateway.policy import PolicyEngine

    with dbs.config.session() as db:
        engine = PolicyEngine(db)
        rules = engine.version_rules_as_dicts()
    assert len(rules) >= 10  # 4 agents × allow/ask rules
    redteam_tools = {r["tool"] for r in rules if r["agent_id"] == "agent_redteam"}
    assert "audit.search" in redteam_tools
    assert "codehost.issue_open" in redteam_tools


def test_seed_is_idempotent(seed_env, capsys):
    from agents.seed import main

    assert main() == 0
    capsys.readouterr()  # first run: registrations
    assert main() == 0  # second run: everything skipped, still 0
    out = capsys.readouterr().out
    assert "exists — skipping" in out
    dbs = Databases(
        os.environ["GATEWAY_CONFIG_DB"], os.environ["GATEWAY_AUDIT_DB"]
    )
    with dbs.config.session() as db:
        agents = db.execute(select(Agent)).scalars().all()
        mandates = (
            db.execute(
                select(Mandate).where(Mandate.status == "active")
            )
            .scalars()
            .all()
        )
    assert len(agents) == 4
    assert len(mandates) == 4
