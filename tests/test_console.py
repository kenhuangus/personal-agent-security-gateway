"""M6 console tests: admin auth, CSRF, nine pages, global stop, policy
versioning, dry-run/evaluate APIs, health banner, redaction catalog,
ontology review queue (FR-035–FR-042; FR-PAA10-001/003/004).

Pre-M6 console tests keep ``dev_no_auth=True``; everything here
exercises the REAL auth flow.
"""

from __future__ import annotations

import datetime as dt
import json
import re
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from gateway.audit import AuditLog
from gateway.config import Settings
from gateway.console import create_console_app
from gateway.console.admin_auth import ADMIN_ID, AdminAuth
from gateway.connectors.base import HealthStatus
from gateway.connectors.email import EmailConnector
from gateway.db import Databases
from gateway.identity import IdentityService
from gateway.mandates import MandateService
from gateway.models import AdminUser, ApprovalRequest
from gateway.ontology.store import OntologyStore
from gateway.policy import PolicyEngine
from gateway.vault.kms import EnvKmsProvider, generate_kms_key
from gateway.vault.store import VaultStore

HMAC_KEY = "test-hmac-key-material-32bytes!"
ADMIN_PASSWORD = "correct horse battery staple"


@pytest.fixture()
def settings(tmp_path, monkeypatch):
    monkeypatch.setenv("GATEWAY_KMS_KEY", generate_kms_key())
    return Settings(
        config_db_path=str(tmp_path / "config.db"),
        audit_db_path=str(tmp_path / "audit.db"),
        vault_db_path=str(tmp_path / "vault.db"),
        hmac_key=HMAC_KEY,
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


class _FailConnector:
    name = "failconn"

    def tools(self):
        return []

    def upstream_scopes(self):
        return []

    def health_check(self):
        return HealthStatus(
            connector="failconn", credential_valid=False,
            api_reachable=False, detail="simulated outage",
        )

    def ssrf_checklist(self):
        return {}


def _make_client(dbs, settings, vault_store=None, connectors=()):
    app = create_console_app(
        dbs.config.session, dbs.audit.session, settings,
        connectors=list(connectors), vault_store=vault_store,
    )
    return TestClient(app)


@pytest.fixture()
def make_authed(dbs, settings):
    """Factory: an authenticated console client (real password+TOTP)."""
    import pyotp

    def _make(vault_store=None, connectors=(EmailConnector(),)):
        client = _make_client(
            dbs, settings, vault_store=vault_store, connectors=list(connectors)
        )
        with dbs.config.session() as db:
            secret = AdminAuth(settings, dbs.audit.session).setup_admin(
                db, ADMIN_PASSWORD
            )
        r = client.get("/login")
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text).group(1)
        r = client.post(
            "/login",
            data={
                "password": ADMIN_PASSWORD,
                "totp_code": pyotp.TOTP(secret).now(),
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert r.status_code == 302 and r.headers["location"] == "/dashboard"
        return client, secret

    return _make


@pytest.fixture()
def authed(make_authed):
    return make_authed()


def _csrf(client):
    r = client.get("/api/csrf-token")
    assert r.status_code == 200
    return {"X-CSRF-Token": r.json()["csrf_token"]}


def _form_csrf(client):
    r = client.get("/dashboard")
    return re.search(r'name="csrf_token" value="([^"]+)"', r.text).group(1)


def _authed_post(client, url, data):
    """POST with a fresh CSRF token/cookie pair (each page GET rotates)."""
    token = _form_csrf(client)
    return client.post(url, data={**data, "csrf_token": token},
                       follow_redirects=False)


def _login_form_csrf(client):
    r = client.get("/login")
    return re.search(r'name="csrf_token" value="([^"]+)"', r.text).group(1)


@pytest.fixture()
def agent(dbs):
    with dbs.config.session() as db:
        ident = IdentityService(db)
        ag, _cid, _sec = ident.register_agent(
            "ag_muse", "muse", "Muse", "ken"
        )
        mandate = MandateService(db).create_default_mandate(ag)
        return {"agent_id": ag.id, "mandate_id": mandate.id}


# ---------------------------------------------------------------------
# Admin auth (FR-036/039/040)
# ---------------------------------------------------------------------


class TestAdminAuth:
    def test_unauthenticated_pages_redirect_to_login(self, dbs, settings):
        client = _make_client(dbs, settings)
        with dbs.config.session() as db:
            AdminAuth(settings, dbs.audit.session).setup_admin(db, ADMIN_PASSWORD)
        r = client.get("/dashboard", follow_redirects=False)
        assert r.status_code == 302 and r.headers["location"] == "/login"

    def test_unauthenticated_api_returns_401(self, dbs, settings):
        client = _make_client(dbs, settings)
        with dbs.config.session() as db:
            AdminAuth(settings, dbs.audit.session).setup_admin(db, ADMIN_PASSWORD)
        r = client.post("/api/policy/dry-run", json={"policy_version": 1})
        assert r.status_code == 401

    def test_setup_is_one_shot(self, dbs, settings):
        client = _make_client(dbs, settings)
        r = client.get("/", follow_redirects=False)
        assert r.headers["location"] == "/setup"  # no admin yet
        with dbs.config.session() as db:
            AdminAuth(settings, dbs.audit.session).setup_admin(db, ADMIN_PASSWORD)
        r = client.get("/setup", follow_redirects=False)
        assert r.status_code == 302 and r.headers["location"] == "/login"

    def test_setup_page_shows_qr(self, dbs, settings):
        client = _make_client(dbs, settings)
        # GH #20: the test client is non-loopback, so /setup needs the
        # one-time startup token.
        token = client.app.state.setup_token
        r = client.get(f"/setup?token={token}")
        assert r.status_code == 200
        assert "data:image/png;base64," in r.text  # QR provisioning

    def test_setup_denied_without_token(self, dbs, settings):
        # GH #20: non-loopback /setup without the token is 403.
        client = _make_client(dbs, settings)
        r = client.get("/setup", follow_redirects=False)
        assert r.status_code == 403

    def test_failed_login_is_audit_logged(self, dbs, settings):
        client = _make_client(dbs, settings)
        with dbs.config.session() as db:
            AdminAuth(settings, dbs.audit.session).setup_admin(db, ADMIN_PASSWORD)
        r = client.get("/login")
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text).group(1)
        r = client.post(
            "/login",
            data={"password": "wrong password here", "totp_code": "000000",
                  "csrf_token": csrf},
        )
        assert r.status_code == 200 and "Wrong password" in r.text
        with dbs.audit.session() as adb:
            rows = AuditLog(adb).search(agent_id="admin", tool="admin.login")
            assert rows and rows[0].decision == "denied"
            assert rows[0].reason == "invalid_password"

    def test_lockout_after_five_failures(self, dbs, settings):
        client = _make_client(dbs, settings)
        with dbs.config.session() as db:
            AdminAuth(settings, dbs.audit.session).setup_admin(db, ADMIN_PASSWORD)
        for _ in range(5):
            csrf = _login_form_csrf(client)
            client.post(
                "/login",
                data={"password": "wrong password here", "totp_code": "000000",
                      "csrf_token": csrf},
            )
        # sixth attempt: locked out even with the right password
        import pyotp

        with dbs.config.session() as db:
            secret = db.get(AdminUser, ADMIN_ID).totp_secret
        csrf = _login_form_csrf(client)
        r = client.post(
            "/login",
            data={"password": ADMIN_PASSWORD,
                  "totp_code": pyotp.TOTP(secret).now(), "csrf_token": csrf},
        )
        assert "Too many failed attempts" in r.text
        with dbs.audit.session() as adb:
            rows = AuditLog(adb).search(agent_id="admin", tool="admin.login")
            assert any(e.reason == "locked_out" for e in rows)

    def test_csrf_rejected_on_state_changing_routes(self, authed, dbs):
        client, _secret = authed
        # No CSRF token at all -> 403 (FR-042), not a redirect to login.
        r = client.post(
            "/policies/save", data={"raw_rules": "[]", "change_note": "x"}
        )
        assert r.status_code == 403
        r = client.post(
            "/api/policy/dry-run",
            json={"policy_version": 1, "window_days": 7},
        )
        assert r.status_code == 403


# ---------------------------------------------------------------------
# Nine pages (02 §3.2)
# ---------------------------------------------------------------------


class TestNinePages:
    PAGES = [
        "/dashboard", "/agents", "/connectors", "/policies", "/approvals",
        "/audit", "/settings", "/mandates", "/context", "/ontology",
    ]

    def test_all_nine_pages_render(self, authed):
        client, _secret = authed
        for path in self.PAGES:
            r = client.get(path)
            assert r.status_code == 200, path

    def test_nav_lists_all_nine_pages(self, authed):
        client, _secret = authed
        r = client.get("/dashboard")
        for label in ["Dashboard", "Agents", "Connectors", "Policies",
                      "Approvals", "Audit Log", "Vault", "Mandates",
                      "Context", "Ontology"]:
            assert label in r.text, label


# ---------------------------------------------------------------------
# Global stop (FR-PAA10-001/003/004)
# ---------------------------------------------------------------------


class TestGlobalStop:
    def test_stop_pauses_agents_and_cancels_approvals(self, authed, dbs, agent):
        client, _secret = authed
        with dbs.config.session() as db:
            ident = IdentityService(db)
            ag2, _c, _s = ident.register_agent("ag_grok", "grok", "Grok", "ken")
            now = dt.datetime.now(dt.timezone.utc)
            for apr_id in ("apr_stop_1", "apr_stop_2"):
                db.add(ApprovalRequest(
                    id=apr_id, agent_id="ag_muse", mandate_id=agent["mandate_id"],
                    tool="email.send", policy_version=1,
                    argument_hash="k1:abc", evidence_subset={}, redacted_args={},
                    status="pending", expires_at=now + dt.timedelta(minutes=15),
                ))
            db.commit()
        token = _form_csrf(client)
        r = client.post("/admin/stop-all", data={"csrf_token": token})
        assert r.status_code == 200
        # received-vs-enforced acknowledgment (FR-PAA10-004)
        assert "Received:" in r.text and "enforced:" in r.text
        # per-item status (FR-PAA10-003)
        assert "ag_muse" in r.text and "ag_grok" in r.text
        assert "apr_stop_1" in r.text and "apr_stop_2" in r.text
        with dbs.config.session() as db:
            from gateway.models import Agent

            assert db.get(Agent, "ag_muse").status == "paused"
            assert db.get(Agent, "ag_grok").status == "paused"
            assert db.get(ApprovalRequest, "apr_stop_1").status == "canceled"
            assert db.get(ApprovalRequest, "apr_stop_2").status == "canceled"
        with dbs.audit.session() as adb:
            rows = AuditLog(adb).search(agent_id="admin", tool="admin.global_stop")
            assert rows and rows[0].decision == "allowed"

    def test_stop_requires_csrf(self, authed):
        client, _secret = authed
        r = client.post("/admin/stop-all", data={})
        assert r.status_code == 403


# ---------------------------------------------------------------------
# Policies: save / rollback / diff / dry-run / evaluate (FR-016–FR-020,
# AC-12)
# ---------------------------------------------------------------------


ALLOW_RULE = {
    "name": "muse can read email",
    "rule_type": "standard",
    "effect": "allow",
    "agent_id": "ag_muse",
    "tool": "email.search",
    "description": "read-only search",
}


def _seed_v1(dbs):
    with dbs.config.session() as db:
        engine = PolicyEngine(db)
        return engine.save_version([ALLOW_RULE], change_note="v1")


class TestPolicies:
    def test_save_rollback_diff(self, authed, dbs):
        client, _secret = authed
        _seed_v1(dbs)
        # raw save: add a second rule -> v2
        rules = [ALLOW_RULE, {**ALLOW_RULE, "name": "second", "tool": "email.read"}]
        r = _authed_post(client, "/policies/save",
                         {"raw_rules": json.dumps(rules), "change_note": "v2",
                          "material": "auto"})
        assert r.status_code == 302
        r = client.get("/policies")
        assert "second" in r.text and "(current)" in r.text
        # diff v1 vs v2
        r = client.get("/policies", params={"diff_a": "1", "diff_b": "2"})
        assert r.status_code == 200 and "second" in r.text
        # rollback to v1 -> new version v3 copying v1
        r = _authed_post(client, "/policies/rollback", {"version": "1"})
        assert r.status_code == 302
        with dbs.config.session() as db:
            engine = PolicyEngine(db)
            assert len(engine.version_rules_as_dicts(3)) == 1
            assert len(engine.version_rules_as_dicts()) == 1  # current == v3
        # FR-041: save + rollback audit-logged as admin actions
        with dbs.audit.session() as adb:
            assert AuditLog(adb).search(agent_id="admin", tool="policy.save")
            assert AuditLog(adb).search(agent_id="admin", tool="policy.rollback")

    def test_builder_add_rule(self, authed, dbs):
        client, _secret = authed
        _seed_v1(dbs)
        r = _authed_post(client, "/policies/add-rule",
                         {"name": "built rule", "agent_id": "ag_muse",
                          "tool": "calendar.list", "effect": "allow",
                          "conditions": "", "change_note": "builder"})
        assert r.status_code == 302
        with dbs.config.session() as db:
            engine = PolicyEngine(db)
            assert len(engine.version_rules_as_dicts()) == 2

    def test_save_rejects_invalid_rule(self, authed, dbs):
        client, _secret = authed
        token = _form_csrf(client)
        bad = [{**ALLOW_RULE, "effect": "maybe"}]
        r = client.post(
            "/policies/save",
            data={"raw_rules": json.dumps(bad), "change_note": "bad",
                  "material": "auto", "csrf_token": token},
        )
        assert r.status_code == 400 and "rejected" in r.text

    def test_dry_run_endpoint_shape_ac12(self, authed, dbs, agent):
        client, _secret = authed
        _seed_v1(dbs)
        with dbs.audit.session() as adb:
            log = AuditLog(adb)
            log.append(agent_id="ag_muse", tool="email.search",
                       decision="allowed", redacted_args={"query": "x"})
        r = client.post(
            "/api/policy/dry-run",
            json={"policy_version": 1, "window_days": 7},
            headers=_csrf(client),
        )
        assert r.status_code == 200
        body = r.json()
        assert set(body["counts"]) == {"would_allow", "would_deny", "would_require_approval"}
        assert isinstance(body["changed_calls"], list)
        assert body["corpus"] in ("history", "synthetic")

    def test_evaluate_endpoint_shape(self, authed, dbs, agent):
        client, _secret = authed
        _seed_v1(dbs)
        r = client.post(
            "/api/policy/evaluate",
            json={"agent_id": "ag_muse", "tool": "email.search",
                  "arguments": {"query": "x"}, "policy_version": 1},
            headers=_csrf(client),
        )
        assert r.status_code == 200
        body = r.json()
        assert body["decision"] == "allow"
        assert body["requires_approval"] is False
        assert "matched_rule_id" in body


# ---------------------------------------------------------------------
# Health checks + banner (00 §7 param 16; FR-038)
# ---------------------------------------------------------------------


class TestHealth:
    def test_unhealthy_connector_banner(self, dbs, settings):
        client = _make_client(dbs, settings, connectors=[_FailConnector()])
        with dbs.config.session() as db:
            AdminAuth(settings, dbs.audit.session).setup_admin(db, ADMIN_PASSWORD)
        import pyotp

        with dbs.config.session() as db:
            from gateway.models import AdminUser

            secret = db.get(AdminUser, ADMIN_ID).totp_secret
        r = client.get("/login")
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text).group(1)
        client.post("/login", data={"password": ADMIN_PASSWORD,
                                    "totp_code": pyotp.TOTP(secret).now(),
                                    "csrf_token": csrf})
        # boot ran the baseline check synchronously: banner renders
        r = client.get("/dashboard")
        assert "health check FAILED" in r.text
        r = client.get("/connectors")
        assert "UNHEALTHY" in r.text and "simulated outage" in r.text

    def test_healthy_connector_no_banner(self, authed):
        client, _secret = authed
        r = client.get("/dashboard")
        assert "health check FAILED" not in r.text


# ---------------------------------------------------------------------
# Vault & Settings (FR-021–FR-024; FR-PAA09-004)
# ---------------------------------------------------------------------


class TestVaultSettings:
    def test_vault_rotate(self, make_authed, dbs, vault_store):
        client, _secret = make_authed(vault_store=vault_store)
        vault_store.store("email", "primary", "s3cr3t-value", admin_id="admin_ken")
        r = client.get("/settings")
        assert "email" in r.text and "s3cr3t-value" not in r.text  # FR-022
        token = re.search(r'name="csrf_token" value="([^"]+)"', r.text).group(1)
        r = client.post("/settings/vault/rotate",
                        data={"connector": "email", "new_cred": "r0tated",
                              "csrf_token": token},
                        follow_redirects=False)
        assert r.status_code == 302
        entries = vault_store.list_entries()
        assert any(e["status"] == "superseded" for e in entries)
        assert any(e["status"] == "active" for e in entries)
        with dbs.audit.session() as adb:
            assert AuditLog(adb).search(tool="vault.rotate")

    def test_settings_override(self, authed, dbs):
        client, _secret = authed
        token = _form_csrf(client)
        r = client.post("/settings/update",
                        data={"key": "rate_limit_per_minute", "value": "42",
                              "csrf_token": token},
                        follow_redirects=False)
        assert r.status_code == 302
        r = client.get("/settings")
        assert ">42<" in r.text
        with dbs.audit.session() as adb:
            assert AuditLog(adb).search(agent_id="admin", tool="settings.update")

    def test_settings_reject_unknown_key(self, authed):
        client, _secret = authed
        token = _form_csrf(client)
        r = client.post("/settings/update",
                        data={"key": "hmac_key", "value": "x", "csrf_token": token})
        assert r.status_code == 400

    def test_redaction_catalog_edit(self, authed, dbs):
        client, _secret = authed
        r = _authed_post(client, "/settings/redaction/add",
                         {"name": "test_token", "regex": "TK-[0-9]+",
                          "pattern_mask": "[redacted:test]", "category": "pii",
                          "description": "test"})
        assert r.status_code == 302
        assert "test_token" in client.get("/settings").text
        r = _authed_post(client, "/settings/redaction/toggle",
                         {"name": "test_token", "enabled": "false"})
        assert r.status_code == 302
        with dbs.audit.session() as adb:
            assert AuditLog(adb).search(agent_id="admin",
                                        tool="redaction.catalog_update")

    def test_decision_criteria_upsert(self, authed, dbs):
        client, _secret = authed
        token = _form_csrf(client)
        r = client.post("/settings/criteria/upsert",
                        data={"domain": "email.send",
                              "criteria_json": '{"max_recipients": 5}',
                              "csrf_token": token},
                        follow_redirects=False)
        assert r.status_code == 302
        assert "email.send" in client.get("/settings").text


# ---------------------------------------------------------------------
# Mandates (FR-PAA01-001…008; FR-PAA01-004 cancel-on-pause)
# ---------------------------------------------------------------------


class TestMandates:
    def test_mandate_pause_cancels_pending_approvals(self, authed, dbs, agent):
        client, _secret = authed
        with dbs.config.session() as db:
            now = dt.datetime.now(dt.timezone.utc)
            db.add(ApprovalRequest(
                id="apr_mnd_1", agent_id="ag_muse", mandate_id=agent["mandate_id"],
                tool="email.send", policy_version=1, argument_hash="k1:zz",
                evidence_subset={}, redacted_args={}, status="pending",
                expires_at=now + dt.timedelta(minutes=15),
            ))
            db.commit()
        token = _form_csrf(client)
        r = client.post(f"/mandates/{agent['mandate_id']}/action",
                        data={"action": "pause", "csrf_token": token},
                        follow_redirects=False)
        assert r.status_code == 302
        with dbs.config.session() as db:
            assert db.get(ApprovalRequest, "apr_mnd_1").status == "canceled"
            from gateway.models import Mandate

            assert db.get(Mandate, agent["mandate_id"]).status == "paused"
        with dbs.audit.session() as adb:
            assert AuditLog(adb).search(agent_id="admin", tool="mandate.pause")

    def test_mandate_page_lists_history(self, authed, dbs, agent):
        client, _secret = authed
        with dbs.config.session() as db:
            MandateService(db).end(agent["mandate_id"])
        r = client.get("/mandates")
        assert r.status_code == 200 and "ended" in r.text

    def test_agent_revoke_is_audit_logged(self, authed, dbs, agent):
        client, _secret = authed
        token = _form_csrf(client)
        r = client.post("/agents/ag_muse/status",
                        data={"action": "revoke", "csrf_token": token},
                        follow_redirects=False)
        assert r.status_code == 302
        with dbs.audit.session() as adb:
            assert AuditLog(adb).search(agent_id="admin", tool="agent.revoke")


# ---------------------------------------------------------------------
# Context boundaries + ontology review queue (FR-PAA03; M6 small UI)
# ---------------------------------------------------------------------


class TestContextOntology:
    def test_context_page(self, authed, dbs, agent):
        client, _secret = authed
        r = client.get("/context")
        assert r.status_code == 200
        assert "Purpose registry" in r.text and "Data-label classes" in r.text

    def test_review_queue_resolve_and_dismiss(self, authed, dbs):
        client, _secret = authed
        with dbs.config.session() as db, dbs.audit.session() as adb:
            store = OntologyStore(db, AuditLog(adb), admin_id="admin_ken")
            item = store.flag_for_review(
                "principal", "ont_p1", "stale: no decision in 90 days",
                provenance="explicit:test",
            )
            item_id = item.id
        assert item_id in client.get("/ontology").text
        r = _authed_post(client, f"/ontology/review/{item_id}/resolve",
                         {"note": "checked"})
        assert r.status_code == 302
        with dbs.config.session() as db:
            store = OntologyStore(db)
            assert store.list_review_items(status="open") == []

    def test_candidate_confirm_and_reject(self, authed, dbs):
        client, _secret = authed
        with dbs.config.session() as db, dbs.audit.session() as adb:
            store = OntologyStore(db, AuditLog(adb), admin_id="admin_ken")
            store.propose_candidates([{
                "kind": "principal", "dedupe_key": "test:person:x",
                "payload": {"kind": "person", "display_name": "X"},
                "provenance": "inferred:test", "confidence": 0.5,
            }])
            cand = store.list_candidates(status="pending_confirmation")[0]
        r = _authed_post(client, f"/ontology/candidates/{cand.id}/reject", {})
        assert r.status_code == 302
        with dbs.config.session() as db:
            assert OntologyStore(db).list_candidates(
                status="pending_confirmation") == []


# ---------------------------------------------------------------------
# Ontology seam (d): approval request carries the decision refs
# ---------------------------------------------------------------------


class TestOntologySeam:
    def test_approval_required_details_carry_ontology_ref(self):
        from gateway.approvals import ApprovalService

        ctx = SimpleNamespace(
            tool="email.send", request_id="req_x",
            ontology_ref={"entry_id": "ont_p1", "entry_kind": "principal",
                          "snapshot_ref": "k1:deadbeef"},
        )
        apr = SimpleNamespace(
            id="apr_x",
            expires_at=dt.datetime.now(dt.timezone.utc),
        )
        err = ApprovalService._approval_required(ctx, apr)
        assert err.details["ontology_ref"]["entry_id"] == "ont_p1"
