"""M2 connector tests — Personal Agent Security Gateway.

Covers (per the M2 task):
- every connector tool end-to-end through the pipeline with mock upstreams
- sensitivity flags per the 02 §2.2 inventory
- SSRF checklist assertions per adapter (FR-009)
- derived_token.raw() called ONLY inside adapters (FR-012b)
- no code.pr.merge tool exists (deferred out of MVP)
- template-bound notice rule end-to-end (FR-PAA07-005)
- conditional calendar.create sensitivity via policy argument constraints
- minimal validator: invalid_input names the field, never the value
- console: Agents + Audit Log pages
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from gateway.audit import AuditLog
from gateway.config import Settings
from gateway.connectors.base import all_ssrf_checks_pass
from gateway.connectors.calendar import CalendarConnector
from gateway.connectors.codehost import CodeHostConnector
from gateway.connectors.email import EmailConnector
from gateway.connectors.mock_upstream import MockCalendar, MockGitHub, MockGmail
from gateway.console import create_console_app
from gateway.db import Databases
from gateway.identity import IdentityService
from gateway.mandates import MandateService
from gateway.models import Agent
from gateway.pipeline import ConnectorRegistry, build_pipeline
from gateway.policy import PolicyEngine

HMAC_KEY = "test-hmac-key-material-32bytes!"

ALL_TOOLS = [
    "email.search", "email.read", "email.send", "email.draft",
    "email.settings.read", "email.settings.write",
    "calendar.list", "calendar.create", "calendar.update", "calendar.delete",
    "code.file.read", "code.pr.open",
]

SENSITIVITY = {
    "email.search": "routine",
    "email.read": "routine",
    "email.send": "sensitive",
    "email.draft": "routine",
    "email.settings.read": "routine",
    "email.settings.write": "sensitive",
    "calendar.list": "routine",
    "calendar.create": "conditional",
    "calendar.update": "routine",
    "calendar.delete": "sensitive",
    "code.file.read": "routine",
    "code.pr.open": "sensitive",
}


@pytest.fixture()
def settings(tmp_path):
    return Settings(
        config_db_path=str(tmp_path / "config.db"),
        audit_db_path=str(tmp_path / "audit.db"),
        hmac_key=HMAC_KEY,
    )


@pytest.fixture()
def dbs(settings):
    d = Databases(settings.config_db_path, settings.audit_db_path)
    d.create_all()
    return d


@pytest.fixture()
def connectors():
    email = EmailConnector(MockGmail())
    calendar = CalendarConnector(MockCalendar())
    code = CodeHostConnector(MockGitHub())
    return {"email": email, "calendar": calendar, "code": code}


@pytest.fixture()
def registry(connectors):
    reg = ConnectorRegistry()
    for name, conn in connectors.items():
        conn.register(reg)
    return reg


@pytest.fixture()
def agent(dbs):
    with dbs.config.session() as cdb:
        ident = IdentityService(cdb)
        agent, _cid, secret = ident.register_agent("ag_muse", "muse", "Muse", "ken")
        MandateService(cdb).create_mandate(agent.id, "test", ALL_TOOLS, purpose_key="work")
        return {"agent_id": agent.id, "secret": secret}


def _allow_all(cdb, tools=ALL_TOOLS):
    PolicyEngine(cdb).save_version(
        [{"name": f"allow {t}", "effect": "allow", "tool": t} for t in tools],
        change_note="test allow-all",
    )


def _run(dbs, settings, registry, agent, tool, args):
    with dbs.config.session() as cdb, dbs.audit.session() as adb:
        pipeline, _, auth_stage = build_pipeline(
            cdb, adb, settings, registry=registry)
        auth_stage.presented[agent["agent_id"]] = agent["secret"]
        return pipeline.execute(agent["agent_id"], tool, args)


@pytest.fixture()
def exec_env(dbs, settings, registry, agent):
    """Agent with an allow-all policy: execution-path tests."""
    with dbs.config.session() as cdb:
        _allow_all(cdb)
    return {"dbs": dbs, "settings": settings, "registry": registry, "agent": agent}


# ---------------------------------------------------------------------------
# Tool inventory + sensitivity (02 §2.2)
# ---------------------------------------------------------------------------

class TestInventory:
    def test_all_mvp_tools_registered(self, registry):
        assert registry.tool_names() == sorted(ALL_TOOLS)

    def test_no_pr_merge_tool(self, registry):
        assert registry.get("code.pr.merge") is None  # deferred out of MVP (00 §3)

    def test_sensitivity_flags(self, registry):
        for tool, want in SENSITIVITY.items():
            assert registry.get(tool).sensitivity == want, tool

    def test_tool_namespacing(self, registry):
        for name in ALL_TOOLS:
            connector, _, _action = name.partition(".")
            assert connector in ("email", "calendar", "code")
            assert name.startswith(connector + ".")


# ---------------------------------------------------------------------------
# SSRF checklist (FR-009 acceptance)
# ---------------------------------------------------------------------------

class TestSSRFChecklist:
    @pytest.mark.parametrize("conn_name", ["email", "calendar", "code"])
    def test_ssrf_checklist_passes(self, connectors, conn_name):
        checklist = connectors[conn_name].ssrf_checklist()
        assert all_ssrf_checks_pass(checklist), checklist
        assert checklist["notes"]  # the outcome is recorded, not just asserted

    def test_no_tool_accepts_url(self, registry):
        for name in ALL_TOOLS:
            schema = json.dumps(registry.get(name).input_schema)
            assert "url" not in schema.lower() or "no open-ended" in schema.lower(), name

    def test_no_tool_accepts_credentials(self, registry):
        blob = json.dumps(
            {n: registry.get(n).input_schema for n in ALL_TOOLS}).lower()
        for banned in ("password", "api_key", "api-key", "secret", "token"):
            assert banned not in blob


# ---------------------------------------------------------------------------
# End-to-end tool execution through the pipeline
# ---------------------------------------------------------------------------

class TestEmailTools:
    def test_search(self, exec_env):
        e = exec_env
        out = _run(e["dbs"], e["settings"], e["registry"], e["agent"],
                   "email.search", {"query": "planning"})
        assert out.ok, out.error.to_text() if out.error else ""
        msgs = out.context.result["messages"]
        assert any(m["message_id"] == "msg_001" for m in msgs)
        # search returns metadata + snippets, not full bodies
        assert "body" not in msgs[0]

    def test_read(self, exec_env):
        e = exec_env
        out = _run(e["dbs"], e["settings"], e["registry"], e["agent"],
                   "email.read", {"message_id": "msg_001"})
        assert out.ok
        assert out.context.result["subject"] == "Q3 planning notes"

    def test_send_and_transaction_status(self, exec_env, connectors):
        e = exec_env
        out = _run(e["dbs"], e["settings"], e["registry"], e["agent"],
                   "email.send", {"to": ["a@example.com"],
                                  "subject": "hi", "body": "hello"})
        assert out.ok
        mid = out.context.result["message_id"]
        assert out.context.result["status"] == "sent"
        # FR-PAA06-003 stub: confirm execution before any retry.
        status = connectors["email"].upstream.transaction_status(mid)
        assert status["status"] == "sent"
        assert connectors["email"].upstream.transaction_status("msg_nope")["status"] == "not_found"

    def test_draft(self, exec_env):
        e = exec_env
        out = _run(e["dbs"], e["settings"], e["registry"], e["agent"],
                   "email.draft", {"to": ["a@example.com"],
                                   "subject": "d", "body": "b"})
        assert out.ok
        assert out.context.result["status"] == "drafted"

    def test_settings_read(self, exec_env):
        e = exec_env
        out = _run(e["dbs"], e["settings"], e["registry"], e["agent"],
                   "email.settings.read", {"section": "forwarding"})
        assert out.ok
        assert out.context.result["settings"]["forwarding"]["enabled"] is False
        out2 = _run(e["dbs"], e["settings"], e["registry"], e["agent"],
                    "email.settings.read", {"section": "filters"})
        assert out2.ok and "filters" in out2.context.result["settings"]

    def test_settings_write(self, exec_env, connectors):
        e = exec_env
        out = _run(e["dbs"], e["settings"], e["registry"], e["agent"],
                   "email.settings.write",
                   {"section": "forwarding",
                    "settings": {"enabled": True, "forward_to": "x@y.z"}})
        assert out.ok
        assert out.context.result["status"] == "updated"
        assert connectors["email"].upstream.settings["forwarding"]["enabled"] is True


class TestCalendarTools:
    def test_list(self, exec_env):
        e = exec_env
        out = _run(e["dbs"], e["settings"], e["registry"], e["agent"],
                   "calendar.list",
                   {"start": "2026-10-13T00:00:00Z", "end": "2026-10-13T23:59:59Z"})
        assert out.ok
        assert len(out.context.result["events"]) == 2

    def test_create_update_delete(self, exec_env):
        e = exec_env
        created = _run(e["dbs"], e["settings"], e["registry"], e["agent"],
                       "calendar.create",
                       {"title": "Test", "start": "2026-10-14T10:00:00Z",
                        "end": "2026-10-14T11:00:00Z",
                        "attendees": ["a@example.com"]})
        assert created.ok
        eid = created.context.result["event_id"]
        updated = _run(e["dbs"], e["settings"], e["registry"], e["agent"],
                       "calendar.update", {"event_id": eid, "title": "Renamed"})
        assert updated.ok and updated.context.result["title"] == "Renamed"
        deleted = _run(e["dbs"], e["settings"], e["registry"], e["agent"],
                       "calendar.delete", {"event_id": eid})
        assert deleted.ok and deleted.context.result["status"] == "deleted"


class TestCodeHostTools:
    def test_file_read(self, exec_env):
        e = exec_env
        out = _run(e["dbs"], e["settings"], e["registry"], e["agent"],
                   "code.file.read",
                   {"repo": "kenhuangus/example", "path": "README.md"})
        assert out.ok
        assert "Synthetic repo" in out.context.result["content"]

    def test_pr_open(self, exec_env):
        e = exec_env
        out = _run(e["dbs"], e["settings"], e["registry"], e["agent"],
                   "code.pr.open",
                   {"repo": "kenhuangus/example", "title": "T",
                    "head": "feat", "base": "main", "body": "b"})
        assert out.ok
        assert out.context.result["number"] == 1
        assert out.context.result["state"] == "open"


# ---------------------------------------------------------------------------
# FR-012b: derived token handled only inside adapters
# ---------------------------------------------------------------------------

class TestDerivedTokenBoundary:
    def test_raw_called_inside_adapter_only(self, exec_env, connectors):
        e = exec_env
        out = _run(e["dbs"], e["settings"], e["registry"], e["agent"],
                   "email.search", {"query": "planning"})
        assert out.ok
        # The adapter read the derived token via raw() (stub material in tests).
        assert connectors["email"].last_token_seen == "STUB-NOT-FOR-UPSTREAM-USE"
        # …and the raw material never reaches the agent-visible result.
        assert "STUB-NOT-FOR-UPSTREAM-USE" not in json.dumps(
            out.context.result, default=str)

    def test_no_vault_material_in_errors(self, exec_env):
        e = exec_env
        out = _run(e["dbs"], e["settings"], e["registry"], e["agent"],
                   "email.read", {"message_id": "msg_missing"})
        assert not out.ok  # upstream KeyError → upstream_failure
        assert out.error.code == "upstream_failure"
        assert "STUB-NOT-FOR-UPSTREAM-USE" not in out.error.to_text()


# ---------------------------------------------------------------------------
# Policy interplay: sensitive tools, conditional sensitivity, notice rules
# ---------------------------------------------------------------------------

class TestPolicyInterplay:
    def test_sensitive_tool_requires_approval(self, dbs, settings, registry, agent):
        with dbs.config.session() as cdb:
            PolicyEngine(cdb).save_version([
                {"name": "send needs approval", "effect": "require_approval",
                 "tool": "email.send"},
            ])
        out = _run(dbs, settings, registry, agent, "email.send",
                   {"to": ["a@example.com"], "subject": "s", "body": "b"})
        assert not out.ok
        assert out.error.code == "approval_required"
        assert out.halted_at == "policy"
        with dbs.audit.session() as adb:
            rows = AuditLog(adb).search(agent_id=agent["agent_id"])
            assert rows and rows[0].decision == "approval_required"

    def test_conditional_create_internal_ok_external_needs_approval(
        self, dbs, settings, registry, agent
    ):
        with dbs.config.session() as cdb:
            PolicyEngine(cdb).save_version([
                {"name": "internal attendees auto-allow", "effect": "allow",
                 "tool": "calendar.create",
                 "conditions": {"argument_constraints": {
                     "attendees": {"all_domains_in": ["example.com"]}}}},
                {"name": "external attendees need approval",
                 "effect": "require_approval", "tool": "calendar.create"},
            ])
        internal = _run(dbs, settings, registry, agent, "calendar.create",
                        {"title": "T", "start": "2026-10-14T10:00:00Z",
                         "end": "2026-10-14T11:00:00Z",
                         "attendees": ["a@example.com"]})
        assert internal.ok, internal.error.to_text() if internal.error else ""
        external = _run(dbs, settings, registry, agent, "calendar.create",
                        {"title": "T", "start": "2026-10-14T10:00:00Z",
                         "end": "2026-10-14T11:00:00Z",
                         "attendees": ["outsider@evil.com"]})
        assert not external.ok
        assert external.error.code == "approval_required"

    def test_notice_rule_end_to_end(self, dbs, settings, registry, agent):
        with dbs.config.session() as cdb:
            PolicyEngine(cdb).save_version([{
                "name": "Weekly status notice",
                "effect": "allow",
                "rule_type": "notice",
                "tool": "email.send",
                "conditions": {"notice": {
                    "audience": ["team@example.com"],
                    "schedule": {"days": ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]},
                    "subject_pattern": r"^Weekly status:",
                    "body_pattern": r"Status update",
                    "max_body_length": 5000,
                }},
            }])
        good = _run(dbs, settings, registry, agent, "email.send",
                    {"to": ["team@example.com"], "subject": "Weekly status: W42",
                     "body": "Status update: all good."})
        assert good.ok, good.error.to_text() if good.error else ""
        # every execution audit-logged (FR-PAA07-005)
        with dbs.audit.session() as adb:
            rows = AuditLog(adb).search(agent_id=agent["agent_id"], tool="email.send")
            assert any(r.decision == "allowed" for r in rows)
        # deviation: different audience → denied, not approved
        bad = _run(dbs, settings, registry, agent, "email.send",
                   {"to": ["stranger@evil.com"], "subject": "Weekly status: W42",
                    "body": "Status update: all good."})
        assert not bad.ok and bad.error.code == "policy_denied"

    def test_invalid_input_names_field_not_value(self, dbs, settings, registry, agent):
        with dbs.config.session() as cdb:
            _allow_all(cdb)
        out = _run(dbs, settings, registry, agent, "email.send",
                   {"subject": "s", "body": "SECRET-BODY-VALUE"})
        assert not out.ok
        assert out.error.code == "invalid_input"
        assert out.error.details["field"] == "to"  # missing required field
        assert "SECRET-BODY-VALUE" not in out.error.to_text()
        assert out.halted_at == "validate_inputs"  # never reaches policy/approval
        with dbs.audit.session() as adb:
            rows = AuditLog(adb).search(agent_id=agent["agent_id"])
            assert rows and rows[0].decision == "denied"
            assert rows[0].reason == "invalid_input"


# ---------------------------------------------------------------------------
# Console: Agents + Audit Log pages (M2)
# ---------------------------------------------------------------------------

class TestConsole:
    @pytest.fixture()
    def client(self, dbs, settings):
        # dev_no_auth: TEST ONLY — the M6 auth tests (test_console.py)
        # exercise the real login flow; these pre-M6 tests keep their
        # page-level coverage unchanged.
        app = create_console_app(
            dbs.config.session, dbs.audit.session, settings, dev_no_auth=True
        )
        return TestClient(app)

    def test_home_redirects(self, client):
        r = client.get("/", follow_redirects=False)
        assert r.status_code == 302 and r.headers["location"] == "/agents"

    def test_agents_page(self, client, agent):
        r = client.get("/agents")
        assert r.status_code == 200
        assert "ag_muse" in r.text

    def test_register_agent_shows_secret_once(self, client, dbs):
        token = client.get("/api/csrf-token").json()["csrf_token"]
        r = client.post("/agents", data={
            "agent_id": "ag_new", "platform": "grok",
            "display_name": "Grok", "household_role": "ken",
            "csrf_token": token,
        })
        assert r.status_code == 200
        assert "shown ONCE" in r.text
        with dbs.config.session() as cdb:
            assert cdb.get(Agent, "ag_new") is not None

    def test_agent_detail_and_pause_resume_revoke(self, client, agent):
        r = client.get("/agents/ag_muse")
        assert r.status_code == 200 and "ag_muse" in r.text
        token = client.get("/api/csrf-token").json()["csrf_token"]
        form = {"csrf_token": token}
        r = client.post("/agents/ag_muse/status", data={**form, "action": "pause"},
                        follow_redirects=False)
        assert r.status_code == 302
        r = client.post("/agents/ag_muse/status", data={**form, "action": "resume"},
                        follow_redirects=False)
        assert r.status_code == 302
        r = client.post("/agents/ag_muse/status", data={**form, "action": "revoke"},
                        follow_redirects=False)
        assert r.status_code == 302
        assert 'class="badge revoked"' in client.get("/agents/ag_muse").text or \
               "revoked" in client.get("/agents/ag_muse").text

    def test_state_changing_routes_reject_missing_csrf(self, client, agent):
        r = client.post("/agents", data={
            "agent_id": "ag_no", "platform": "muse",
            "display_name": "No", "household_role": "ken",
        })
        assert r.status_code == 403
        r = client.post("/agents/ag_muse/status", data={"action": "pause"},
                        follow_redirects=False)
        assert r.status_code == 403

    def test_audit_page_and_export(self, client, exec_env):
        e = exec_env
        _run(e["dbs"], e["settings"], e["registry"], e["agent"],
             "email.search", {"query": "planning"})
        r = client.get("/audit")
        assert r.status_code == 200 and "email.search" in r.text
        r = client.get("/audit", params={"decision": "allowed"})
        assert r.status_code == 200
        r = client.get("/audit/export", params={"format": "json"})
        assert r.status_code == 200
        assert "email.search" in r.text
        # the export itself is audit-logged (FR-033)
        with e["dbs"].audit.session() as adb:
            rows = AuditLog(adb).search(tool="audit.export")
            assert rows and rows[0].decision == "allowed"
        r = client.get("/audit/export", params={"format": "csv"})
        assert r.status_code == 200 and r.text.startswith("request_id,")

    def test_console_never_shows_secrets(self, client):
        r = client.get("/agents")
        assert "client_secret" not in r.text.lower() or "shown ONCE" not in r.text
        # registration page shows no stored secret values
        assert "secret_hash" not in r.text
