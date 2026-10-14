"""Pillar 2 §2.1: the gateway-side agent tools.

audit.search: redacted rows only; non-security callers are
constrained to their own agent_id (defense in depth). policy.inspect:
returns the version + rules, read-only (no state change across
calls). Both are registered on the MCP surface only when
GATEWAY_AGENTS_ENABLED=1 (asserted at the app level in
test_agents_integration).
"""

from __future__ import annotations

import pytest

from gateway.agent_tools import make_agent_tools
from gateway.audit import AuditLog
from gateway.config import Settings
from gateway.db import Databases
from gateway.identity import IdentityService
from gateway.policy import PolicyEngine


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
def tools(dbs):
    return make_agent_tools(dbs.config.session, dbs.audit.session)


class _Ctx:
    def __init__(self, agent_id, role):
        self.agent_id = agent_id
        self.agent = type("A", (), {"household_role": role})()


def _audit_search(tools):
    return next(t for t in tools if t.name == "audit.search")


def _policy_inspect(tools):
    return next(t for t in tools if t.name == "policy.inspect")


def test_audit_search_returns_redacted_rows(dbs, tools):
    with dbs.config.session() as cdb:
        ident = IdentityService(cdb)
        ag, _cid, _s = ident.register_agent(
            "agent_redteam", "internal", "agent/redteam", "security")
    with dbs.audit.session() as adb:
        AuditLog(adb).append(
            agent_id="agent_redteam", tool="sandbox.echo",
            decision="allowed", redacted_args={"payload_id": "x"})
    ctx = _Ctx("agent_redteam", "security")
    out = _audit_search(tools).handler(ctx, {"limit": 10})
    assert out["count"] == 1
    row = out["rows"][0]
    assert row["agent_id"] == "agent_redteam"
    assert row["redacted_args"] == {"payload_id": "x"}


def test_audit_search_constrains_non_security_caller(dbs, tools):
    with dbs.config.session() as cdb:
        ident = IdentityService(cdb)
        ident.register_agent("agent_redteam", "internal", "agent/redteam",
                             "security")
        ident.register_agent("ag_other", "test", "Other", "family")
    with dbs.audit.session() as adb:
        log = AuditLog(adb)
        log.append(agent_id="agent_redteam", tool="sandbox.echo",
                   decision="allowed", redacted_args={})
        log.append(agent_id="ag_other", tool="email.send",
                   decision="allowed", redacted_args={})
    # A non-security caller asking for another agent's rows gets only
    # their own (the handler overrides agent_id).
    ctx = _Ctx("ag_other", "family")
    out = _audit_search(tools).handler(
        ctx, {"agent_id": "agent_redteam", "limit": 10})
    assert out["count"] == 1
    assert out["rows"][0]["agent_id"] == "ag_other"


def test_audit_search_limit_capped(dbs, tools):
    ctx = _Ctx("agent_redteam", "security")
    out = _audit_search(tools).handler(ctx, {"limit": 500})
    assert out["count"] == 0  # capped to 200, no rows seeded


def test_policy_inspect_read_only(dbs, tools):
    with dbs.config.session() as cdb:
        before = PolicyEngine(cdb).current_version_number()
    ctx = _Ctx("agent_redteam", "security")
    out1 = _policy_inspect(tools).handler(ctx, {})
    out2 = _policy_inspect(tools).handler(ctx, {})
    assert out1["policy_version"] == before
    assert out1 == out2  # no state change across calls
    assert isinstance(out1["rules"], list)
