"""Batch 2 PR-B tests: config/semantics/traceability mediums.

GH #19, #20, #21, #22, #23, #24, #25, #26, #27 (filed low), #30, #31.
"""

from __future__ import annotations

import datetime as dt
import logging
import re
import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from gateway.approvals import policy_materially_superseded
from gateway.audit import AuditLog
from gateway.config import (
    Settings,
    check_tls_posture,
    is_loopback_host,
)
from gateway.console import create_console_app
from gateway.db import Databases
from gateway.errors import ERROR_CODES
from gateway.hmac_util import HmacKeyRing
from gateway.identity import IdentityService
from gateway.judge.cascade import JudgeCascade
from gateway.judge.client import DecisionBackend, DecisionResult, JudgeUnavailable, Question
from gateway.judge import health as judge_health
from gateway.models import AgentCredential
from gateway.opa_client import OPA_VERSION
from gateway.pipeline import AuthenticateStage, CallContext, execute_approved_call
from gateway.policy import PolicyEngine, validate_rule_dict

HMAC_KEY = "test-hmac-key-material-32bytes!"


@pytest.fixture()
def settings(tmp_path):
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
def config_db(dbs):
    with dbs.config.session() as s:
        yield s


@pytest.fixture()
def audit_db(dbs):
    with dbs.audit.session() as s:
        yield s


@pytest.fixture()
def ring():
    return HmacKeyRing.from_env_string("k1", HMAC_KEY)


def _agent(agent_id="ag_test_01"):
    return SimpleNamespace(id=agent_id, household_role="ken")


# ---------------------------------------------------------------------------
# GH #19: TLS posture check
# ---------------------------------------------------------------------------


class TestTlsPosture:
    def test_loopback_hosts(self):
        assert is_loopback_host("127.0.0.1")
        assert is_loopback_host("::1")
        assert is_loopback_host("localhost")
        assert not is_loopback_host("0.0.0.0")
        assert not is_loopback_host("192.168.1.10")

    def test_loopback_bind_needs_no_tls(self, settings):
        check_tls_posture("127.0.0.1", settings)  # no raise

    def test_nonloopback_without_tls_refuses(self, settings, monkeypatch):
        monkeypatch.delenv("GATEWAY_TLS_TERMINATED", raising=False)
        monkeypatch.delenv("GATEWAY_ALLOW_PLAINTEXT_NONLOOPBACK", raising=False)
        s = Settings(
            config_db_path=settings.config_db_path,
            audit_db_path=settings.audit_db_path,
            tls_terminated=False,
            allow_plaintext_nonloopback=False,
        )
        with pytest.raises(RuntimeError, match="refusing to bind"):
            check_tls_posture("0.0.0.0", s)

    def test_nonloopback_with_tls_terminated_ok(self, settings):
        s = Settings(
            config_db_path=settings.config_db_path,
            audit_db_path=settings.audit_db_path,
            tls_terminated=True,
        )
        check_tls_posture("0.0.0.0", s)  # no raise

    def test_escape_hatch_warns_loudly(self, settings, caplog):
        s = Settings(
            config_db_path=settings.config_db_path,
            audit_db_path=settings.audit_db_path,
            allow_plaintext_nonloopback=True,
        )
        with caplog.at_level(logging.WARNING, logger="gateway.config"):
            check_tls_posture("0.0.0.0", s)  # no raise
        assert any("TLS POSTURE" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# GH #20: first-run /setup gating
# ---------------------------------------------------------------------------


def _console_client(dbs, settings, monkeypatch):
    from gateway.vault.kms import generate_kms_key

    monkeypatch.setenv("GATEWAY_KMS_KEY", generate_kms_key())
    app = create_console_app(dbs.config.session, dbs.audit.session, settings)
    return app, TestClient(app)


class TestSetupGate:
    def test_setup_denied_without_token(self, dbs, settings, monkeypatch):
        app, client = _console_client(dbs, settings, monkeypatch)
        assert app.state.setup_token  # a token was minted at startup
        r = client.get("/setup", follow_redirects=False)
        assert r.status_code == 403

    def test_setup_allowed_with_token(self, dbs, settings, monkeypatch):
        app, client = _console_client(dbs, settings, monkeypatch)
        token = app.state.setup_token
        r = client.get(f"/setup?token={token}")
        assert r.status_code == 200
        assert 'name="setup_token"' in r.text

    def test_setup_wrong_token_denied(self, dbs, settings, monkeypatch):
        _app, client = _console_client(dbs, settings, monkeypatch)
        r = client.get("/setup?token=wrong", follow_redirects=False)
        assert r.status_code == 403

    def test_full_setup_flow_with_token(self, dbs, settings, monkeypatch):
        import pyotp

        app, client = _console_client(dbs, settings, monkeypatch)
        token = app.state.setup_token
        r = client.get(f"/setup?token={token}")
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text).group(1)
        seed = re.search(r'name="totp_seed" value="([^"]+)"', r.text).group(1)
        r = client.post(
            "/setup",
            data={
                "password": "supersecretpassword",
                "totp_code": pyotp.TOTP(seed).now(),
                "totp_seed": seed,
                "csrf_token": csrf,
                "setup_token": token,
            },
            follow_redirects=False,
        )
        assert r.status_code == 302
        assert r.headers["location"] == "/dashboard"
        # Single-use: the token is cleared after setup completes.
        assert app.state.setup_token is None
        # /setup now redirects to /login (admin exists).
        r = client.get(f"/setup?token={token}", follow_redirects=False)
        assert r.status_code == 302
        assert r.headers["location"] == "/login"

    def test_setup_post_without_token_denied(self, dbs, settings, monkeypatch):
        import pyotp

        app, client = _console_client(dbs, settings, monkeypatch)
        token = app.state.setup_token
        r = client.get(f"/setup?token={token}")
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text).group(1)
        seed = re.search(r'name="totp_seed" value="([^"]+)"', r.text).group(1)
        r = client.post(
            "/setup",
            data={
                "password": "supersecretpassword",
                "totp_code": pyotp.TOTP(seed).now(),
                "totp_seed": seed,
                "csrf_token": csrf,
                # no setup_token
            },
            follow_redirects=False,
        )
        assert r.status_code == 403


# ---------------------------------------------------------------------------
# GH #21: fallback-Bearer <redacted> max age enforcement
# ---------------------------------------------------------------------------


def _fallback_agent(config_db, days_old=0):
    """Registered agent with a fallback bearer aged *days_old* days."""
    from sqlalchemy import update

    ident = IdentityService(config_db)
    agent, _cid, _secret = ident.register_agent(
        "ag_fb_01", "muse", "Fallback Agent", "ken"
    )
    _key_id, bearer = ident.issue_fallback_bearer(agent.id, "2026-10-12")
    if days_old:
        old = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days_old)
        config_db.execute(
            update(AgentCredential)
            .where(
                AgentCredential.agent_id == agent.id,
                AgentCredential.kind == "fallback_bearer",
            )
            .values(last_rotated_at=old)
        )
        config_db.commit()
    return agent.id, bearer


class TestFallbackBearerMaxAge:
    def test_error_code_registered(self):
        assert "fallback_bearer_expired" in ERROR_CODES

    def test_expired_bearer_denied_with_distinct_code(self, config_db):
        agent_id, bearer = _fallback_agent(config_db, days_old=91)
        ident = IdentityService(config_db, fallback_bearer_max_days=90)
        with pytest.raises(ValueError, match="fallback_bearer_expired"):
            ident.authenticate(agent_id, bearer)

    def test_fresh_bearer_allowed(self, config_db):
        agent_id, bearer = _fallback_agent(config_db, days_old=89)
        ident = IdentityService(config_db, fallback_bearer_max_days=90)
        result = ident.authenticate(agent_id, bearer)
        assert result.credential_kind == "fallback_bearer"

    def test_oauth_credential_unaffected(self, config_db):
        ident = IdentityService(config_db)
        agent, _cid, secret = ident.register_agent(
            "ag_oa_01", "muse", "OAuth Agent", "ken"
        )
        # OAuth credentials have no bearer max-age enforcement.
        result = ident.authenticate(agent.id, secret)
        assert result.credential_kind == "oauth"

    def test_custom_max_days(self, config_db):
        agent_id, bearer = _fallback_agent(config_db, days_old=10)
        ident = IdentityService(config_db, fallback_bearer_max_days=7)
        with pytest.raises(ValueError, match="fallback_bearer_expired"):
            ident.authenticate(agent_id, bearer)

    def test_null_rotated_at_falls_back_to_issued_at(self, config_db):
        from sqlalchemy import update

        # last_rotated_at is nullable; when unset the age counts from
        # issued_at (which is NOT NULL — the fail-closed null branch in
        # authenticate() is defensive only).
        agent_id, bearer = _fallback_agent(config_db)
        old = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=91)
        config_db.execute(
            update(AgentCredential)
            .where(AgentCredential.agent_id == agent_id)
            .values(last_rotated_at=None, issued_at=old)
        )
        config_db.commit()
        ident = IdentityService(config_db)
        with pytest.raises(ValueError, match="fallback_bearer_expired"):
            ident.authenticate(agent_id, bearer)

    def test_authenticate_stage_maps_distinct_code(self, config_db):
        agent_id, bearer = _fallback_agent(config_db, days_old=91)
        stage = AuthenticateStage(
            IdentityService(config_db, fallback_bearer_max_days=90)
        )
        stage.presented[agent_id] = bearer
        ctx = CallContext(agent_id=agent_id, tool="test.echo", args={})
        error = stage.run(ctx)
        assert error is not None
        assert error.code == "fallback_bearer_expired"
        assert "rotate" in error.message


# ---------------------------------------------------------------------------
# GH #22: derived-token validation semantics (ledger is the authority)
# ---------------------------------------------------------------------------


class _NoIntrospectionIssuer:
    """Production-like issuer: opaque tokens, no introspection endpoint."""

    supports_introspection = False

    def __init__(self):
        self._tokens = {}

    def issue(self, agent_id, scopes, ttl_seconds):
        import secrets as _secrets

        value = "opaque-" + _secrets.token_hex(16)
        self._tokens[value] = True
        return value, time.time() + ttl_seconds

    def validate(self, token_value):
        raise AssertionError("must not be consulted for opaque tokens")

    def expire(self, token_value):
        self._tokens.pop(token_value, None)


def _vault_minter(dbs, settings, monkeypatch, issuer=None):
    from gateway.vault.kms import EnvKmsProvider, generate_kms_key
    from gateway.vault.mock_oauth_issuer import MockOAuthIssuer
    from gateway.vault.minter import VaultTokenMinter
    from gateway.vault.store import VaultStore

    monkeypatch.setenv("GATEWAY_KMS_KEY", generate_kms_key())
    store = VaultStore(
        settings.vault_db_path, EnvKmsProvider(), AuditLog(dbs.audit.session())
    )
    store.store("email", "Test email credential", "mock-refresh-token")
    minter = VaultTokenMinter(
        store, issuer or MockOAuthIssuer(), settings, audit=None
    )
    return minter, store


def _mint_ctx():
    return CallContext(agent_id="ag_vault_01", tool="email.send", args={})


class TestDerivedTokenSemantics:
    def test_ledger_expiry_is_authority(self, dbs, settings, monkeypatch):
        from gateway.vault.minter import _ledger_key

        minter, _store = _vault_minter(dbs, settings, monkeypatch)
        tok = minter.mint(_mint_ctx())
        assert minter.validate_token(tok)
        # Expire the LEDGER record (not the issuer, not the token object).
        minter._ledger[_ledger_key(tok.raw())].expires_at_epoch = time.time() - 1
        assert not minter.validate_token(tok)

    def test_token_self_asserted_expiry_ignored(self, dbs, settings, monkeypatch):
        from gateway.pipeline import DerivedToken
        from gateway.vault.minter import _ledger_key

        minter, _store = _vault_minter(dbs, settings, monkeypatch)
        tok = minter.mint(_mint_ctx())

        def _forged(expiry):
            # Same token material, forged self-asserted expiry.
            return DerivedToken(
                agent_id=tok.agent_id, tool=tok.tool, action=tok.action,
                expires_at_epoch=expiry, _material=tok.raw(),
            )

        # Forging the self-asserted expiry into the past: the ledger
        # still governs, so validation passes.
        assert minter.validate_token(_forged(time.time() - 3600))
        # And forging it into the future cannot extend the lifetime.
        minter._ledger[_ledger_key(tok.raw())].expires_at_epoch = time.time() - 1
        assert not minter.validate_token(_forged(time.time() + 3600))

    def test_ledger_miss_denied(self, dbs, settings, monkeypatch):
        from gateway.pipeline import DerivedToken

        minter, _store = _vault_minter(dbs, settings, monkeypatch)
        forged = DerivedToken(
            agent_id="ag_vault_01", tool="email.send", action="send",
            expires_at_epoch=time.time() + 300, _material="never-minted",
        )
        assert not minter.validate_token(forged)

    def test_mock_introspection_still_consulted(self, dbs, settings, monkeypatch):
        # The mock models an introspectable provider: issuer-side expiry
        # propagates through the introspection check.
        from gateway.vault.mock_oauth_issuer import MockOAuthIssuer

        mock = MockOAuthIssuer()
        assert mock.supports_introspection is True
        minter, _store = _vault_minter(dbs, settings, monkeypatch, issuer=mock)
        tok = minter.mint(_mint_ctx())
        assert minter.validate_token(tok)
        mock.expire(tok.raw())
        assert not minter.validate_token(tok)

    def test_opaque_issuer_never_consulted(self, dbs, settings, monkeypatch):
        issuer = _NoIntrospectionIssuer()
        minter, _store = _vault_minter(dbs, settings, monkeypatch, issuer=issuer)
        tok = minter.mint(_mint_ctx())
        assert minter.validate_token(tok)
        # Upstream "revocation" is invisible without introspection: the
        # ledger alone governs (validate() would raise if consulted).
        issuer.expire(tok.raw())
        assert minter.validate_token(tok)


# ---------------------------------------------------------------------------
# GH #23: policy-supersession re-check in execute_approved_call
# ---------------------------------------------------------------------------


def _replay_kwargs(dbs, settings, ring, policy_version):
    from gateway.pipeline import ConnectorRegistry, StubTokenMinter

    return dict(
        config_session_factory=dbs.config.session,
        audit_session_factory=dbs.audit.session,
        settings=settings,
        hmac_ring=ring,
        registry=ConnectorRegistry(),
        minter=StubTokenMinter(),
        agent_id="ag_test_01",
        tool="email.send",
        args={"to": ["a@b.com"]},
        approval_request_id="apr_test_01",
        policy_version=policy_version,
        mandate_id="mandate_test_01",
    )


class TestReplaySupersession:
    def test_material_change_blocks_replay(self, dbs, settings, ring, config_db):
        v1 = PolicyEngine(config_db).save_version(
            [{"name": "allow email", "effect": "allow", "tool": "email.send"}],
            change_note="v1",
        )
        # A MATERIAL policy change lands after the approval.
        PolicyEngine(config_db).save_version(
            [{"name": "deny email", "effect": "deny", "tool": "email.send"}],
            change_note="v2 material",
        )
        assert policy_materially_superseded(config_db, v1) is True
        out = execute_approved_call(**_replay_kwargs(dbs, settings, ring, v1))
        assert out["ok"] is False
        assert out["error"]["error"]["code"] == "policy_denied"
        assert out["error"]["error"]["details"]["reason"] == "policy_superseded"

    def test_nonmaterial_change_does_not_block(self, dbs, settings, ring, config_db):
        v1 = PolicyEngine(config_db).save_version(
            [{"name": "allow email", "effect": "allow", "tool": "email.send"}],
            change_note="v1",
        )
        # Non-material edit (display name only): the replay is not blocked
        # by the supersession gate (same semantics as the grant path).
        PolicyEngine(config_db).save_version(
            [{"name": "allow email (renamed)", "effect": "allow", "tool": "email.send"}],
            change_note="v2 cosmetic",
            material_change=False,
        )
        assert policy_materially_superseded(config_db, v1) is False

    def test_current_version_not_superseded(self, dbs, settings, ring, config_db):
        v1 = PolicyEngine(config_db).save_version(
            [{"name": "allow email", "effect": "allow", "tool": "email.send"}],
            change_note="v1",
        )
        assert policy_materially_superseded(config_db, v1) is False


# ---------------------------------------------------------------------------
# GH #24: traceability fields through _maybe_escalate
# ---------------------------------------------------------------------------


class TestEscalationTraceability:
    def test_escalated_result_keeps_traceability(
        self, config_db, ring
    ):
        from gateway.ontology.store import OntologyStore

        store = OntologyStore(config_db, AuditLog(config_db))
        store.upsert_dimension("purpose", ["work", "personal"])
        household = store.seed_household("Ken", [])
        owner = household["owner"]
        store.bind_agent("ag_ken", owner.id)

        engine = PolicyEngine(
            config_db,
            hmac_ring=ring,
            sensitivity_escalator=lambda agent_id, tool, args: "new_payee",
        )
        engine.save_version(
            [
                {
                    "name": "allow email",
                    "effect": "allow",
                    "tool": "email.send",
                    "conditions": {
                        "ontology": {"dimension": {"purpose": "work"}}
                    },
                }
            ]
        )
        result = engine.evaluate_call(
            _agent("ag_ken"), "email.send", {"to": ["new@example.com"]},
            ontology_ctx={"dimensions": {"purpose": "work"}},
        )
        assert result.decision == "require_approval"
        assert result.escalation_reason == "new_payee"
        # The carried-over traceability fields (GH #24).
        assert result.matched_rule_id is not None
        assert result.scope_rule is not None
        assert result.data_snapshot_id is not None
        # The allow was ontology-shaped: the entry citation survives the
        # escalation into the approval record.
        assert result.ontology_snapshot_ref is not None
        assert result.ontology_ref is not None
        assert result.ontology_ref["snapshot_ref"] == result.ontology_snapshot_ref


# ---------------------------------------------------------------------------
# GH #25: PAA04 snapshot on ontology-clause denies
# ---------------------------------------------------------------------------


class TestDenyOntologySnapshot:
    def test_deny_with_ontology_clause_captures_snapshot(
        self, config_db, ring
    ):
        from gateway.ontology.store import OntologyStore

        store = OntologyStore(config_db, AuditLog(config_db))
        store.upsert_dimension("purpose", ["work", "personal"])
        household = store.seed_household("Ken", [])
        owner = household["owner"]
        store.bind_agent("ag_ken", owner.id)

        engine = PolicyEngine(config_db, hmac_ring=ring)
        engine.save_version(
            [
                {
                    "name": "deny personal email",
                    "effect": "deny",
                    "tool": "email.send",
                    "conditions": {
                        "ontology": {"dimension": {"purpose": "personal"}}
                    },
                }
            ]
        )
        result = engine.evaluate_call(
            _agent("ag_ken"), "email.send", {},
            ontology_ctx={"dimensions": {"purpose": "personal"}},
        )
        assert result.decision == "deny"
        # GH #25: ontology-driven denies get the snapshot + entry citation.
        assert result.ontology_snapshot_ref is not None
        assert result.ontology_ref is not None


# ---------------------------------------------------------------------------
# GH #26: rule time-window + tool selector validation at save time
# ---------------------------------------------------------------------------


class TestRuleShapeValidation:
    def _rule(self, **overrides):
        rule = {
            "name": "test rule",
            "effect": "allow",
            "tool": "email.send",
            "conditions": {},
        }
        rule.update(overrides)
        return rule

    def test_bad_start_rejected(self):
        with pytest.raises(ValueError, match="HH:MM"):
            validate_rule_dict(
                self._rule(conditions={"time_window": {"start": "9"}})
            )

    def test_bad_end_rejected(self):
        with pytest.raises(ValueError, match="HH:MM"):
            validate_rule_dict(
                self._rule(conditions={"time_window": {"end": "25:00"}})
            )

    def test_bad_day_rejected(self):
        with pytest.raises(ValueError, match="weekday"):
            validate_rule_dict(
                self._rule(conditions={"time_window": {"days": ["funday"]}})
            )

    def test_days_not_a_list_rejected(self):
        with pytest.raises(ValueError, match="days must be a list"):
            validate_rule_dict(
                self._rule(conditions={"time_window": {"days": "mon"}})
            )

    def test_bare_star_selector_rejected(self):
        with pytest.raises(ValueError, match="never matches"):
            validate_rule_dict(self._rule(tool="*"))

    def test_misplaced_wildcard_rejected(self):
        with pytest.raises(ValueError, match="never matches"):
            validate_rule_dict(self._rule(tool="email*"))

    def test_good_shapes_accepted(self):
        r = validate_rule_dict(
            self._rule(
                tool="email.*",
                conditions={
                    "time_window": {
                        "days": ["Mon", "tue"],
                        "start": "09:00",
                        "end": "18:00",
                        "tz": "UTC",
                    }
                },
            )
        )
        # Days are normalized to the vocabulary the Rego matches.
        assert r["conditions"]["time_window"]["days"] == ["mon", "tue"]

    def test_overnight_window_accepted(self):
        r = validate_rule_dict(
            self._rule(
                conditions={"time_window": {"start": "22:00", "end": "06:00"}}
            )
        )
        assert r["conditions"]["time_window"]["start"] == "22:00"

    def test_rejected_at_save_time(self, config_db):
        # The OPA save gate (rule_problems) rejects them too.
        with pytest.raises(ValueError, match="time_window|never matches"):
            PolicyEngine(config_db).save_version(
                [self._rule(conditions={"time_window": {"start": "9"}})],
                change_note="bad window",
            )
        with pytest.raises(ValueError, match="time_window|never matches"):
            PolicyEngine(config_db).save_version(
                [self._rule(tool="*")],
                change_note="bad selector",
            )

    def test_empty_days_still_saves(self, config_db):
        # Empty days = deterministic never-match (documented); not an error.
        v = PolicyEngine(config_db).save_version(
            [self._rule(conditions={"time_window": {"days": []}})],
            change_note="empty days",
        )
        assert v >= 1


# ---------------------------------------------------------------------------
# GH #27: HmacKeyRing.matches is total (False on unknown key id)
# ---------------------------------------------------------------------------


class TestHmacMatchesTotal:
    def test_unknown_key_id_returns_false(self, ring):
        assert ring.matches({"a": 1}, "nope:deadbeef") is False

    def test_malformed_tag_returns_false(self, ring):
        assert ring.matches({"a": 1}, "not-a-tag") is False

    def test_known_key_still_verifies(self, ring):
        tag = ring.digest({"a": 1})
        assert ring.matches({"a": 1}, tag) is True
        assert ring.matches({"a": 2}, tag) is False

    def test_verify_snapshot_false_on_unknown_key(self, ring, config_db):
        from gateway.ontology.models import OntologySnapshot
        from gateway.ontology.snapshots import verify_snapshot

        # A stored snapshot whose key id is not in the ring (retired key
        # removed, or a forged ref): verification returns False instead
        # of raising (GH #27).
        config_db.add(
            OntologySnapshot(id="k_unknown:deadbeef", payload={"x": 1})
        )
        config_db.commit()
        assert (
            verify_snapshot(config_db, ring, "k_unknown:deadbeef") is False
        )


# ---------------------------------------------------------------------------
# GH #30: single OPA_VERSION source of truth
# ---------------------------------------------------------------------------


class TestOpaVersionPin:
    def test_version_file_matches_client(self):
        from pathlib import Path

        version_file = (
            Path(__file__).resolve().parent.parent
            / "third_party"
            / "opa"
            / "OPA_VERSION"
        )
        assert version_file.exists()
        assert version_file.read_text().strip() == OPA_VERSION

    def test_verify_script_pins_official_release(self):
        from pathlib import Path

        script = (
            Path(__file__).resolve().parent.parent
            / "scripts"
            / "verify_opa.sh"
        ).read_text()
        assert "openpolicyagent.org/downloads/v${VERSION}/opa_linux_amd64" in script
        assert "sha256sum -c SHA256SUMS" in script

    def test_compose_uses_version_var(self):
        from pathlib import Path

        compose = (
            Path(__file__).resolve().parent.parent / "docker-compose.yml"
        ).read_text()
        assert "openpolicyagent/opa:${OPA_VERSION:-1.8.0}" in compose


# ---------------------------------------------------------------------------
# GH #31: judge-backend supervision
# ---------------------------------------------------------------------------


class _FailingBackend(DecisionBackend):
    name = "kev"

    def decide(self, state, questions, timeout_s):
        raise JudgeUnavailable("connection refused")


class _OkBackend(DecisionBackend):
    name = "kev"

    def decide(self, state, questions, timeout_s):
        return DecisionResult(
            answers={}, latency_ms=1.0, backend="kev", model="kev-0.8b",
        )


class TestJudgeHealth:
    def setup_method(self):
        judge_health.reset()

    def test_failure_recorded(self):
        cascade = JudgeCascade(primary=_FailingBackend())
        with pytest.raises(JudgeUnavailable):
            cascade.decide("s", [Question(name="q", kind="noul", prompt="p")])
        snap = judge_health.health_snapshot()
        assert snap["kev"]["consecutive_failures"] == 1
        assert snap["kev"]["alerted"] is False

    def test_alert_fires_after_threshold(self, caplog):
        cascade = JudgeCascade(primary=_FailingBackend(), alert_after_minutes=0)
        with caplog.at_level(logging.CRITICAL, logger="gateway.judge.health"):
            with pytest.raises(JudgeUnavailable):
                cascade.decide("s", [Question(name="q", kind="noul", prompt="p")])
        assert any(
            "unreachable" in r.message for r in caplog.records
        )
        assert judge_health.health_snapshot()["kev"]["alerted"] is True

    def test_alert_fires_once_per_outage(self, caplog):
        cascade = JudgeCascade(primary=_FailingBackend(), alert_after_minutes=0)
        with caplog.at_level(logging.CRITICAL, logger="gateway.judge.health"):
            for _ in range(3):
                with pytest.raises(JudgeUnavailable):
                    cascade.decide(
                        "s", [Question(name="q", kind="noul", prompt="p")]
                    )
        criticals = [
            r for r in caplog.records if r.levelno == logging.CRITICAL
        ]
        assert len(criticals) == 1

    def test_success_resets_streak(self, caplog):
        fail = JudgeCascade(primary=_FailingBackend(), alert_after_minutes=0)
        with pytest.raises(JudgeUnavailable):
            fail.decide("s", [Question(name="q", kind="noul", prompt="p")])
        ok = JudgeCascade(primary=_OkBackend(), alert_after_minutes=0)
        with caplog.at_level(logging.INFO, logger="gateway.judge.health"):
            ok.decide("s", [Question(name="q", kind="noul", prompt="p")])
        snap = judge_health.health_snapshot()
        assert snap["kev"]["consecutive_failures"] == 0
        assert snap["kev"]["alerted"] is False
        assert any("recovered" in r.message for r in caplog.records)

    def test_disabled_backend_not_recorded(self):
        from gateway.judge.client import DisabledBackend

        cascade = JudgeCascade(primary=DisabledBackend())
        with pytest.raises(JudgeUnavailable):
            cascade.decide("s", [Question(name="q", kind="noul", prompt="p")])
        assert judge_health.health_snapshot() == {}
