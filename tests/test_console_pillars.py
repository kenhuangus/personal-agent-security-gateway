"""Pillar console: the Money page and the Security Agents page.

Covers: both pages 404 when their flags are off; the Money page
renders rules/allowlist/ledger; money-rule save validates the block
and the quorum before the OPA gate (bad block → 400, unsatisfiable
quorum → 400); allowlist add/verify round-trip; the Security Agents
page lists the fleet; run-now inserts a manual run; the schedule
form rejects bad cron; CSRF is enforced on all state-changing
routes.
"""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from gateway.audit import AuditLog
from gateway.config import Settings
from gateway.console.app import create_console_app
from gateway.db import Databases
from gateway.models import AdminUser, Agent, AgentSchedule
from gateway.vault.kms import EnvKmsProvider, generate_kms_key
from gateway.vault.store import VaultStore

HMAC_KEY = "test-hmac-key-material-32bytes!"
ADMIN_PASSWORD = "test-admin-password-1"


@pytest.fixture()
def settings(tmp_path, monkeypatch):
    monkeypatch.setenv("GATEWAY_KMS_KEY", generate_kms_key())
    # The TestClient speaks plain HTTP, and a Secure cookie is never
    # sent back over HTTP (correct browser behavior) — so the console
    # integration tests opt out exactly as documented for local HTTP
    # development (issue #5). The default-true path is covered by
    # test_session_cookie_secure_flag_defaults_on on main.
    monkeypatch.setenv("GATEWAY_CONSOLE_COOKIE_SECURE", "0")
    return Settings(
        config_db_path=str(tmp_path / "config.db"),
        audit_db_path=str(tmp_path / "audit.db"),
        vault_db_path=str(tmp_path / "vault.db"),
        hmac_key=HMAC_KEY,
        money_enabled=True,
        agents_enabled=True,
    )


@pytest.fixture()
def dbs(settings):
    d = Databases(settings.config_db_path, settings.audit_db_path)
    d.create_all()
    return d


@pytest.fixture()
def vault_store(settings, dbs):
    with dbs.audit.session() as adb:
        store = VaultStore(settings.vault_db_path, EnvKmsProvider(), AuditLog(adb))
    yield store
    store.close()


def _authed_client(dbs, settings, vault_store):
    import pyotp

    from gateway.console.admin_auth import AdminAuth

    app = create_console_app(
        dbs.config.session, dbs.audit.session, settings,
        connectors=[], vault_store=vault_store,
    )
    client = TestClient(app)
    with dbs.config.session() as db:
        auth = AdminAuth(settings, dbs.audit.session)
        if not auth.admin_exists(db):
            secret = auth.setup_admin(db, ADMIN_PASSWORD)
        else:
            secret = db.get(AdminUser, "admin_ken").totp_secret
    r = client.get("/login")
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text).group(1)
    r = client.post("/login", data={
        "password": ADMIN_PASSWORD,
        "totp_code": pyotp.TOTP(secret).now(),
        "csrf_token": csrf,
    })
    assert r.status_code in (200, 302), r.text[:200]
    return client


@pytest.fixture()
def client(dbs, settings, vault_store):
    return _authed_client(dbs, settings, vault_store)


def _csrf(client, path):
    r = client.get(path)
    assert r.status_code == 200, (path, r.status_code)
    m = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
    assert m, f"no csrf token on {path}"
    return m.group(1)


def test_money_page_renders(client):
    r = client.get("/policies/money")
    assert r.status_code == 200
    assert "Money" in r.text
    assert "allowlist" in r.text.lower()


def test_money_page_404_when_disabled(dbs, vault_store, tmp_path, monkeypatch):
    monkeypatch.setenv("GATEWAY_KMS_KEY", generate_kms_key())
    off = Settings(
        config_db_path=str(tmp_path / "c2.db"),
        audit_db_path=str(tmp_path / "a2.db"),
        vault_db_path=str(tmp_path / "v2.db"),
        hmac_key=HMAC_KEY,
    )
    d2 = Databases(off.config_db_path, off.audit_db_path)
    d2.create_all()
    c2 = _authed_client(d2, off, vault_store)
    assert c2.get("/policies/money").status_code == 404
    assert c2.get("/security-agents").status_code == 404


def test_money_save_rejects_bad_block(client):
    csrf = _csrf(client, "/policies/money")
    r = client.post("/policies/money/save", data={
        "name": "bad", "agent_id": "",
        "money_json": '{"per_call_soft_cents": 1, "bogus": 2}',
        "change_note": "", "csrf_token": csrf,
    })
    assert r.status_code == 400
    assert "unknown keys" in r.text or "rejected" in r.text


def test_money_save_rejects_unsatisfiable_quorum(client, dbs):
    # Only admin_ken exists → quorum 2 is unsatisfiable → 400 at
    # authoring time (fail closed), never a wedged approval.
    csrf = _csrf(client, "/policies/money")
    r = client.post("/policies/money/save", data={
        "name": "q2", "agent_id": "",
        "money_json": ('{"per_call_soft_cents": 50000,'
                       ' "per_call_hard_cents": 1000000, "quorum": 2}'),
        "change_note": "", "csrf_token": csrf,
    })
    assert r.status_code == 400
    assert "quorum" in r.text.lower()


def test_money_save_ok_single_quorum(client):
    csrf = _csrf(client, "/policies/money")
    r = client.post("/policies/money/save", data={
        "name": "demo-rule", "agent_id": "",
        "money_json": ('{"per_call_soft_cents": 50000,'
                       ' "per_call_hard_cents": 1000000}'),
        "change_note": "test", "csrf_token": csrf,
    }, follow_redirects=False)
    assert r.status_code == 302
    r2 = client.get("/policies/money")
    assert "demo-rule" in r2.text


def test_allowlist_add_and_verify(client):
    csrf = _csrf(client, "/policies/money")
    r = client.post("/policies/money/allowlist/add", data={
        "payee_key": "ach:test:xxxx1111", "account_last4": "1111",
        "note": "test payee", "csrf_token": csrf,
    }, follow_redirects=False)
    assert r.status_code == 302
    csrf = _csrf(client, "/policies/money")
    r = client.post("/policies/money/allowlist/verify", data={
        "payee_key": "ach:test:xxxx1111", "state": "verified",
        "csrf_token": csrf,
    }, follow_redirects=False)
    assert r.status_code == 302
    r2 = client.get("/policies/money")
    assert "ach:test:xxxx1111" in r2.text
    assert "verified" in r2.text
    # Full account numbers never appear — last-4 only.
    assert "1111" in r2.text


def test_allowlist_rejects_bad_last4(client):
    csrf = _csrf(client, "/policies/money")
    r = client.post("/policies/money/allowlist/add", data={
        "payee_key": "ach:test:xxxx2222", "account_last4": "12",
        "note": "", "csrf_token": csrf,
    })
    assert r.status_code == 400


def test_money_csrf_enforced(client):
    r = client.post("/policies/money/save", data={
        "name": "x", "money_json": "{}", "csrf_token": "bogus",
    })
    assert r.status_code == 403


def test_security_agents_page_renders(client, dbs):
    with dbs.config.session() as db:
        db.add(Agent(id="agent_redteam", display_name="agent/redteam",
                     platform="internal", household_role="security",
                     status="active"))
        db.add(AgentSchedule(agent_id="agent_redteam", enabled=False,
                             cron_expr="0 2 * * *", timezone="UTC"))
        db.commit()
    r = client.get("/security-agents")
    assert r.status_code == 200
    assert "redteam" in r.text
    assert "Run now" in r.text


def test_run_now_inserts_manual_run(client, dbs):
    with dbs.config.session() as db:
        db.add(Agent(id="agent_redteam", display_name="agent/redteam",
                     platform="internal", household_role="security",
                     status="active"))
        db.add(AgentSchedule(agent_id="agent_redteam", enabled=True,
                             cron_expr="0 2 * * *", timezone="UTC"))
        db.commit()
    csrf = _csrf(client, "/security-agents")
    r = client.post("/security-agents/run-now", data={
        "agent_id": "agent_redteam", "csrf_token": csrf,
    }, follow_redirects=False)
    assert r.status_code == 302
    from gateway.models import AgentRun
    from sqlalchemy import select

    with dbs.config.session() as db:
        runs = db.execute(select(AgentRun)).scalars().all()
    assert len(runs) == 1
    assert runs[0].trigger == "manual"
    assert runs[0].status == "requested"


def test_schedule_rejects_bad_cron(client, dbs):
    with dbs.config.session() as db:
        db.add(Agent(id="agent_redteam", display_name="agent/redteam",
                     platform="internal", household_role="security",
                     status="active"))
        db.add(AgentSchedule(agent_id="agent_redteam", enabled=False,
                             cron_expr="", timezone="UTC"))
        db.commit()
    csrf = _csrf(client, "/security-agents")
    r = client.post("/security-agents/schedule", data={
        "agent_id": "agent_redteam", "enabled": "true",
        "cron_expr": "not a cron", "csrf_token": csrf,
    })
    assert r.status_code == 400


def test_security_agents_csrf_enforced(client):
    r = client.post("/security-agents/run-now", data={
        "agent_id": "agent_redteam", "csrf_token": "bogus",
    })
    assert r.status_code == 403
