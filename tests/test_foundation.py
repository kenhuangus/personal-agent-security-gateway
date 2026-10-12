"""M1 foundation tests — Personal Agent Security Gateway.

Covers (per the M1 task):
- credential auth (valid / invalid / revoked -> auth_failed / agent_revoked)
- the single-credential invariant (Fix A)
- mandate lifecycle (expiry / pause / withdraw deny with DISTINCT reasons;
  no-mandate denies; scope checks; delegation narrowing)
- audit append-only (no update/delete API exists), search/filter/export
- error envelope shape for every code in 02 §2.7
- id prefix/format checks (req_/apr_/mnd_, 128-bit CSPRNG)
- pipeline stage ORDER (validate-before-policy) with stub stages
- MCP wire: auth middleware rejects unauthenticated initialize/tools/list/
  tools/call; default-deny over the wire (AC-03)
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import os
import threading
import time

import httpx
import pytest
import uvicorn

from gateway.audit import AuditLog
from gateway.config import Settings
from gateway.db import Databases, journal_mode
from gateway.errors import (
    ERROR_CODES,
    SAFE_REASONS,
    GatewayError,
    invalid_input,
    make_error,
    policy_denied,
)
from gateway.hmac_util import HmacKeyRing, canonical_json
from gateway.ids import (
    is_valid_id,
    new_approval_id,
    new_id,
    new_mandate_id,
    new_request_id,
)
from gateway.identity import IdentityService
from gateway.mandates import MandateService
from gateway.mock_oauth import MockOAuthProvider
from gateway.pipeline import (
    AuditStage,
    AuthenticateStage,
    ExecuteStage,
    MandateStage,
    Pipeline,
    PolicyStage,
    StubTokenMinter,
    TokenMintStage,
    ToolDescriptor,
    ValidateInputsStage,
    ApprovalStage,
    InspectOutputStage,
    build_m1_pipeline,
    timing_span,
)
from gateway.models import Agent, AgentCredential


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

HMAC_KEY = "test-hmac-key-material-32bytes!"


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
def config_db(dbs):
    with dbs.config.session() as s:
        yield s


@pytest.fixture()
def audit_db(dbs):
    with dbs.audit.session() as s:
        yield s


@pytest.fixture()
def agent_bundle(config_db):
    """A registered agent with its ONE OAuth credential and a default mandate."""
    ident = IdentityService(config_db)
    agent, client_id, client_secret = ident.register_agent(
        "ag_test_01", "muse", "Test Agent", "ken"
    )
    mandate = MandateService(config_db).create_default_mandate(agent)
    return {
        "agent": agent,
        "agent_id": "ag_test_01",
        "client_id": client_id,
        "client_secret": client_secret,
        "mandate": mandate,
    }


@pytest.fixture()
def pipeline_bundle(config_db, audit_db, settings, agent_bundle):
    """M1 pipeline + registry + auth stage, with the agent's secret presented."""
    ring = HmacKeyRing.from_env_string("k1", HMAC_KEY)
    pipeline, registry, auth_stage = build_m1_pipeline(config_db, audit_db, settings, ring)
    auth_stage.presented[agent_bundle["agent_id"]] = agent_bundle["client_secret"]
    return {
        "pipeline": pipeline,
        "registry": registry,
        "auth_stage": auth_stage,
        "ring": ring,
        "agent": agent_bundle,
    }


# ---------------------------------------------------------------------------
# ids
# ---------------------------------------------------------------------------

class TestIds:
    def test_prefixes(self):
        assert new_request_id().startswith("req_")
        assert new_approval_id().startswith("apr_")
        assert new_mandate_id().startswith("mnd_")

    def test_128_bit_csprng(self):
        # 32 hex chars == 128 bits of entropy.
        for new in (new_request_id, new_approval_id, new_mandate_id):
            value = new()
            hexpart = value.split("_", 1)[1]
            assert len(hexpart) == 32
            int(hexpart, 16)

    def test_uniqueness(self):
        assert len({new_request_id() for _ in range(1000)}) == 1000

    def test_is_valid_id(self):
        assert is_valid_id(new_request_id(), "req_")
        assert not is_valid_id(new_request_id(), "apr_")
        assert not is_valid_id("req_short", "req_")
        assert not is_valid_id("req_ZZZZ00000000000000000000000000", "req_")
        assert not is_valid_id("", "req_")

    def test_unknown_prefix_rejected(self):
        with pytest.raises(ValueError):
            new_id("grt_")


# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------

class TestErrors:
    def test_envelope_shape_for_every_code(self):
        for code in ERROR_CODES:
            if code == "budget_exceeded":
                continue  # reserved; never emitted in MVP
            err = make_error(code, f"message for {code}", "req_abc")
            env = err.to_envelope()
            assert set(env) == {"error"}
            payload = env["error"]
            assert set(payload) == {"code", "message", "request_id", "retryable", "details"}
            assert payload["code"] == code
            assert payload["request_id"] == "req_abc"
            # The wire payload is valid JSON in content[0].text.
            json.loads(err.to_text())

    def test_budget_exceeded_never_emitted(self):
        # FR-029 is post-MVP: the code is reserved, never emitted.
        with pytest.raises(ValueError):
            make_error("budget_exceeded", "x", "req_abc")

    def test_unknown_code_rejected(self):
        with pytest.raises(ValueError):
            make_error("nope_not_a_code", "x", "req_abc")

    def test_policy_denied_safe_vocabulary_enforced(self):
        for reason in SAFE_REASONS:
            policy_denied("req_1", reason, "denied", tool="email.send")
        # Rule text / ids must never leak through the reason field.
        with pytest.raises(ValueError):
            policy_denied("req_1", "rule_42_matched", "denied")
        with pytest.raises(ValueError):
            policy_denied("req_1", "no allow rule for agent", "denied")

    def test_invalid_input_names_field_never_value(self):
        err = invalid_input("req_1", "to", tool="email.send")
        env = err.to_envelope()["error"]
        assert env["code"] == "invalid_input"
        assert env["details"]["field"] == "to"
        assert "victim@example.com" not in err.to_text()

    def test_request_id_present_everywhere(self):
        err = make_error("auth_failed", "nope", "req_xyz")
        assert '"request_id": "req_xyz"' in err.to_text() or '"request_id":"req_xyz"' in err.to_text().replace(" ", "")


# ---------------------------------------------------------------------------
# hmac_util
# ---------------------------------------------------------------------------

class TestHmac:
    def test_digest_tagged_with_key_id(self):
        ring = HmacKeyRing.from_env_string("k1", HMAC_KEY)
        d = ring.digest({"b": 2, "a": 1})
        assert d.startswith("k1:")
        assert ring.matches({"a": 1, "b": 2}, d)  # key order irrelevant

    def test_canonical_json_ignores_key_order_and_whitespace(self):
        assert canonical_json({"b": 2, "a": 1}) == canonical_json({"a": 1, "b": 2})

    def test_tamper_detected(self):
        ring = HmacKeyRing.from_env_string("k1", HMAC_KEY)
        d = ring.digest({"to": ["a@example.com"]})
        assert not ring.matches({"to": ["b@example.com"]}, d)

    def test_rotation_keeps_old_hashes_verifiable(self):
        ring = HmacKeyRing.from_env_string("k1", HMAC_KEY)
        old = ring.digest({"x": 1})
        ring.add_key("k2", "second-key-material-32bytes!!")
        ring.active_key_id = "k2"
        new = ring.digest({"x": 1})
        assert new.startswith("k2:")
        assert ring.matches({"x": 1}, old)  # retired key still verifies in-flight
        assert ring.matches({"x": 1}, new)

    def test_short_key_rejected(self):
        ring = HmacKeyRing()
        with pytest.raises(ValueError):
            ring.add_key("k1", "too-short")

    def test_no_plain_sha256_path(self):
        # The ring API only exposes HMAC digests (Round-3 MINOR-8).
        ring = HmacKeyRing.from_env_string("k1", HMAC_KEY)
        assert not hasattr(ring, "sha256")
        assert ":" in ring.digest({})


# ---------------------------------------------------------------------------
# identity (Fix A)
# ---------------------------------------------------------------------------

class TestIdentity:
    def test_register_issues_exactly_one_credential(self, config_db, agent_bundle):
        ident = IdentityService(config_db)
        assert ident.active_credential_count(agent_bundle["agent_id"]) == 1
        assert agent_bundle["agent"].auth_method == "oauth"

    def test_authenticate_valid(self, config_db, agent_bundle):
        ident = IdentityService(config_db)
        result = ident.authenticate(agent_bundle["agent_id"], agent_bundle["client_secret"])
        assert result.agent.id == agent_bundle["agent_id"]
        assert result.credential_kind == "oauth"

    def test_authenticate_wrong_secret(self, config_db, agent_bundle):
        ident = IdentityService(config_db)
        with pytest.raises(ValueError, match="bad credential"):
            ident.authenticate(agent_bundle["agent_id"], "wrong-secret")

    def test_authenticate_unknown_agent(self, config_db):
        ident = IdentityService(config_db)
        with pytest.raises(ValueError):
            ident.authenticate("ag_nope", "whatever")

    def test_secret_stored_as_hash_only(self, config_db, agent_bundle):
        cred = (
            config_db.query(AgentCredential)
            .filter_by(agent_id=agent_bundle["agent_id"], active=True)
            .one()
        )
        assert agent_bundle["client_secret"] not in cred.secret_hash
        assert cred.secret_hash.startswith("$2b$")  # bcrypt

    def test_fallback_requires_test_date(self, config_db, agent_bundle):
        ident = IdentityService(config_db)
        with pytest.raises(ValueError, match="test-failure date"):
            ident.issue_fallback_bearer(agent_bundle["agent_id"], "")

    def test_fallback_issues_single_credential_and_deactivates_oauth(
        self, config_db, agent_bundle
    ):
        ident = IdentityService(config_db)
        key_id, bearer = ident.issue_fallback_bearer(agent_bundle["agent_id"], "2026-10-12")
        # Still exactly one active credential (never alongside OAuth).
        assert ident.active_credential_count(agent_bundle["agent_id"]) == 1
        agent = config_db.get(Agent, agent_bundle["agent_id"])
        assert agent.auth_method == "fallback_bearer"
        assert agent.verified_test_date == "2026-10-12"
        # The new bearer authenticates; the old OAuth secret no longer does.
        result = ident.authenticate(agent_bundle["agent_id"], bearer)
        assert result.credential_kind == "fallback_bearer"
        with pytest.raises(ValueError):
            ident.authenticate(agent_bundle["agent_id"], agent_bundle["client_secret"])
        assert key_id.startswith("fb_")

    def test_fallback_bearer_age_visible(self, config_db, agent_bundle):
        ident = IdentityService(config_db)
        ident.issue_fallback_bearer(agent_bundle["agent_id"], "2026-10-12")
        age = ident.bearer_age_days(agent_bundle["agent_id"])
        assert age is not None and age < 1.0

    def test_revoke_kills_credential_and_denies(self, config_db, agent_bundle):
        ident = IdentityService(config_db)
        ident.revoke(agent_bundle["agent_id"])
        assert ident.active_credential_count(agent_bundle["agent_id"]) == 0
        with pytest.raises(ValueError, match="agent_revoked"):
            ident.authenticate(agent_bundle["agent_id"], agent_bundle["client_secret"])

    def test_paused_agent_denied_distinctly(self, config_db, agent_bundle):
        ident = IdentityService(config_db)
        ident.set_status(agent_bundle["agent_id"], "paused")
        with pytest.raises(ValueError, match="agent_paused"):
            ident.authenticate(agent_bundle["agent_id"], agent_bundle["client_secret"])

    def test_canceled_agent_denied_distinctly(self, config_db, agent_bundle):
        ident = IdentityService(config_db)
        ident.set_status(agent_bundle["agent_id"], "canceled")
        with pytest.raises(ValueError, match="agent_canceled"):
            ident.authenticate(agent_bundle["agent_id"], agent_bundle["client_secret"])

    def test_two_agents_have_distinct_credentials(self, config_db):
        ident = IdentityService(config_db)
        _, _, s1 = ident.register_agent("ag_a", "muse", "A", "ken")
        _, _, s2 = ident.register_agent("ag_b", "grok", "B", "ken")
        assert s1 != s2
        with pytest.raises(ValueError):
            ident.authenticate("ag_a", s2)  # cross-agent secret rejected


# ---------------------------------------------------------------------------
# mandates (PAA01)
# ---------------------------------------------------------------------------

class TestMandates:
    def test_default_mandate_is_read_only(self, agent_bundle):
        m = agent_bundle["mandate"]
        assert m.id.startswith("mnd_")
        assert "email.send" not in m.allowed_classes
        assert "email.read" in m.allowed_classes

    def test_expired_mandate_denies_distinctly(self, config_db, agent_bundle):
        svc = MandateService(config_db)
        m = agent_bundle["mandate"]
        m.expires_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1)
        config_db.commit()
        check = svc.check(agent_bundle["agent_id"], "email.read")
        assert not check.ok and check.reason == "mandate_expired"

    def test_paused_mandate_denies_distinctly(self, config_db, agent_bundle):
        svc = MandateService(config_db)
        svc.pause(agent_bundle["mandate"].id)
        check = svc.check(agent_bundle["agent_id"], "email.read")
        assert not check.ok and check.reason == "mandate_paused"

    def test_withdrawn_mandate_denies_distinctly(self, config_db, agent_bundle):
        svc = MandateService(config_db)
        svc.withdraw(agent_bundle["mandate"].id)
        check = svc.check(agent_bundle["agent_id"], "email.read")
        assert not check.ok and check.reason == "mandate_withdrawn"

    def test_ended_mandate_denies(self, config_db, agent_bundle):
        svc = MandateService(config_db)
        svc.end(agent_bundle["mandate"].id)
        check = svc.check(agent_bundle["agent_id"], "email.read")
        assert not check.ok

    def test_no_mandate_denies(self, config_db):
        svc = MandateService(config_db)
        check = svc.check("ag_ghost", "email.read")
        assert not check.ok

    def test_scope_exceeded(self, config_db, agent_bundle):
        svc = MandateService(config_db)
        check = svc.check(agent_bundle["agent_id"], "email.send")
        assert not check.ok and check.reason == "mandate_scope_exceeded"

    def test_wildcard_scope(self, config_db):
        svc = MandateService(config_db)
        ident = IdentityService(config_db)
        ident.register_agent("ag_wild", "muse", "Wild", "ken")
        svc.create_mandate("ag_wild", "broad", ["calendar.*"])
        assert svc.check("ag_wild", "calendar.list").ok
        assert svc.check("ag_wild", "calendar.create").ok
        check = svc.check("ag_wild", "email.send")
        assert not check.ok and check.reason == "mandate_scope_exceeded"

    def test_delegated_submandate_must_narrow(self, config_db, agent_bundle):
        svc = MandateService(config_db)
        parent = agent_bundle["mandate"]
        with pytest.raises(ValueError, match="equal-or-narrower"):
            svc.create_mandate(
                agent_bundle["agent_id"], "too broad", ["email.*"],
                parent_mandate_id=parent.id,
            )
        child = svc.create_mandate(
            agent_bundle["agent_id"], "narrower", ["email.read"],
            parent_mandate_id=parent.id,
        )
        assert child.parent_mandate_id == parent.id

    def test_narrow_rejects_widening(self, config_db, agent_bundle):
        svc = MandateService(config_db)
        with pytest.raises(ValueError, match="new mandate"):
            svc.narrow(agent_bundle["mandate"].id, ["email.*"])
        narrowed = svc.narrow(agent_bundle["mandate"].id, ["email.read"])
        assert narrowed.allowed_classes == ["email.read"]

    def test_pause_resume_cycle(self, config_db, agent_bundle):
        svc = MandateService(config_db)
        mid = agent_bundle["mandate"].id
        svc.pause(mid)
        assert not svc.check(agent_bundle["agent_id"], "email.read").ok
        svc.resume(mid)
        assert svc.check(agent_bundle["agent_id"], "email.read").ok


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------

class TestAudit:
    def test_append_only_no_update_delete_api(self):
        for forbidden in ("update", "delete", "clear", "remove", "purge"):
            assert not hasattr(AuditLog, forbidden), f"AuditLog.{forbidden} must not exist"

    def test_append_and_search(self, audit_db):
        log = AuditLog(audit_db)
        log.append(agent_id="ag_a", tool="email.send", decision="denied", reason="no_allow_rule")
        log.append(agent_id="ag_a", tool="email.read", decision="allowed")
        log.append(agent_id="ag_b", tool="email.send", decision="denied", reason="no_allow_rule")
        assert len(log.search(agent_id="ag_a")) == 2
        assert len(log.search(tool="email.send")) == 2
        assert len(log.search(decision="allowed")) == 1

    def test_search_time_range(self, audit_db):
        log = AuditLog(audit_db)
        old = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=2)
        log.append(agent_id="ag_a", tool="t", decision="allowed", timestamp=old)
        log.append(agent_id="ag_a", tool="t", decision="allowed")
        since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)
        assert len(log.search(since=since)) == 1

    def test_search_by_approval_request(self, audit_db):
        log = AuditLog(audit_db)
        log.append(agent_id="ag_a", tool="email.send", decision="approval_required",
                   approval_request_id="apr_abc")
        rows = log.search(approval_request_id="apr_abc")
        assert len(rows) == 1 and rows[0].decision == "approval_required"

    def test_export_json_csv(self, audit_db):
        log = AuditLog(audit_db)
        log.append(agent_id="ag_a", tool="email.send", decision="denied",
                   reason="no_allow_rule", mandate_id="mnd_x",
                   redacted_args={"to": ["[redacted:email]"]}, irreversible=True,
                   irreversible_note="sent email, no recall available")
        data = json.loads(log.export_json())
        assert len(data) == 1
        row = data[0]
        assert row["agent_id"] == "ag_a" and row["reason"] == "no_allow_rule"
        assert row["irreversible"] is True
        assert row["redacted_args"] == {"to": ["[redacted:email]"]}
        csv_text = log.export_csv()
        assert "request_id" in csv_text.splitlines()[0]
        assert "ag_a" in csv_text

    def test_export_is_itself_audit_logged(self, audit_db, tmp_path):
        log = AuditLog(audit_db)
        path = str(tmp_path / "export.json")
        log.export_to_file(path, fmt="json", exporting_agent_id="console")
        rows = log.search(tool="audit.export")
        assert len(rows) == 1 and rows[0].decision == "allowed"

    def test_audit_row_carries_request_id_mandate_and_reason(self, audit_db):
        log = AuditLog(audit_db)
        entry = log.append(
            agent_id="ag_a", tool="email.send", decision="denied",
            request_id="req_test123", mandate_id="mnd_1", reason="mandate_expired",
        )
        assert entry.request_id == "req_test123"
        assert entry.mandate_id == "mnd_1"
        assert entry.reason == "mandate_expired"


# ---------------------------------------------------------------------------
# pipeline
# ---------------------------------------------------------------------------

class _Recorder:
    """Test stage double: records execution order, optionally halts."""

    def __init__(self, name, record, delegate=None, halt_error=None):
        self.name = name
        self._record = record
        self._delegate = delegate
        self._halt_error = halt_error

    def run(self, ctx):
        self._record.append(self.name)
        if self._halt_error is not None:
            return self._halt_error
        if self._delegate is not None:
            return self._delegate.run(ctx)
        return None


class _AllowAllPolicy:
    name = "policy"

    def run(self, ctx):
        with timing_span(ctx, "policy"):
            ctx.policy_version = 1
        return None


def _echo_tools(registry):
    def echo(ctx, args):
        return {"echo": args}

    registry.register("test", [
        ToolDescriptor(
            name="test.echo", description="echo", input_schema={"type": "object"},
            sensitivity="routine", handler=echo,
        )
    ])


def _register_mvp_tools(registry):
    """Register email.read (routine) + email.send (sensitive) so the
    M1 validation stub lets calls through to the mandate/policy stages."""

    def noop(ctx, args):
        return {"ok": True}

    registry.register("email", [
        ToolDescriptor(
            name="email.read", description="read", input_schema={"type": "object"},
            sensitivity="routine", handler=noop,
        ),
        ToolDescriptor(
            name="email.send", description="send", input_schema={"type": "object"},
            sensitivity="sensitive", handler=noop,
        ),
    ])


def _pipeline_with_test_tool(pipeline_bundle, allow=False):
    """Swap the default-deny policy for an allow-all double and register
    a test tool with a mandate covering it."""
    b = pipeline_bundle
    _echo_tools(b["registry"])
    config_db = b["auth_stage"].identity.db
    MandateService(config_db).create_mandate(
        b["agent"]["agent_id"], "test scope", ["test.echo"]
    )
    if allow:
        for i, s in enumerate(b["pipeline"].stages):
            if s.name == "policy":
                b["pipeline"].stages[i] = _AllowAllPolicy()
    return b


class TestPipeline:
    def test_stage_order_validate_before_policy(self, pipeline_bundle):
        b = _pipeline_with_test_tool(pipeline_bundle, allow=True)
        record: list[str] = []
        pipeline = b["pipeline"]
        # Wrap every stage (and the terminal audit) with order recording.
        pipeline.stages = [
            _Recorder(s.name, record, delegate=s) for s in pipeline.stages
        ]
        real_audit = pipeline.audit_stage
        pipeline.audit_stage = _Recorder("audit", record, delegate=real_audit)

        outcome = pipeline.execute(b["agent"]["agent_id"], "test.echo", {"q": "hi"})
        assert outcome.ok, outcome.error.to_text() if outcome.error else ""
        assert record == [
            "authenticate", "validate_inputs", "mandate", "policy", "approval",
            "mint_token", "execute", "inspect_output", "audit",
        ], record
        # Fix-B order: validate runs before policy.
        assert record.index("validate_inputs") < record.index("policy")

    def test_validation_failure_halts_before_policy(self, pipeline_bundle):
        b = _pipeline_with_test_tool(pipeline_bundle, allow=True)
        record: list[str] = []
        pipeline = b["pipeline"]
        for i, s in enumerate(pipeline.stages):
            if s.name == "validate_inputs":
                pipeline.stages[i] = _Recorder(
                    "validate_inputs", record,
                    halt_error=invalid_input("req_x", "to", tool="test.echo"),
                )
            else:
                pipeline.stages[i] = _Recorder(s.name, record, delegate=s)
        outcome = pipeline.execute(b["agent"]["agent_id"], "test.echo", {"q": "hi"})
        assert not outcome.ok
        assert outcome.error.code == "invalid_input"
        assert outcome.halted_at == "validate_inputs"
        assert "policy" not in record  # never reached

    def test_auth_failure_returns_auth_failed(self, pipeline_bundle, audit_db):
        b = pipeline_bundle
        b["auth_stage"].presented[b["agent"]["agent_id"]] = "wrong-secret"
        outcome = b["pipeline"].execute(b["agent"]["agent_id"], "email.read", {})
        assert not outcome.ok
        assert outcome.error.code == "auth_failed"
        assert outcome.halted_at == "authenticate"
        rows = AuditLog(audit_db).search(agent_id=b["agent"]["agent_id"])
        assert len(rows) == 1 and rows[0].decision == "denied"

    def test_revoked_agent_returns_agent_revoked(self, pipeline_bundle):
        b = pipeline_bundle
        IdentityService(b["auth_stage"].identity.db).revoke(b["agent"]["agent_id"])
        outcome = b["pipeline"].execute(b["agent"]["agent_id"], "email.read", {})
        assert outcome.error.code == "agent_revoked"

    def test_paused_agent_returns_agent_paused(self, pipeline_bundle):
        b = pipeline_bundle
        IdentityService(b["auth_stage"].identity.db).set_status(
            b["agent"]["agent_id"], "paused"
        )
        outcome = b["pipeline"].execute(b["agent"]["agent_id"], "email.read", {})
        assert outcome.error.code == "agent_paused"

    def test_mandate_denied_before_policy_with_distinct_reason(self, pipeline_bundle, audit_db):
        b = pipeline_bundle
        _register_mvp_tools(b["registry"])
        MandateService(b["auth_stage"].identity.db).withdraw(b["agent"]["mandate"].id)
        outcome = b["pipeline"].execute(b["agent"]["agent_id"], "email.read", {})
        assert outcome.error.code == "policy_denied"
        assert outcome.error.details["reason"] == "mandate_withdrawn"
        assert outcome.halted_at == "mandate"
        rows = AuditLog(audit_db).search(agent_id=b["agent"]["agent_id"])
        assert rows[0].reason == "mandate_withdrawn"

    def test_mandate_scope_exceeded(self, pipeline_bundle):
        b = pipeline_bundle
        _register_mvp_tools(b["registry"])
        outcome = b["pipeline"].execute(b["agent"]["agent_id"], "email.send", {})
        assert outcome.error.code == "policy_denied"
        assert outcome.error.details["reason"] == "mandate_scope_exceeded"

    def test_default_deny_ac03(self, pipeline_bundle, audit_db):
        """AC-03: an agent with no allow rule for a tool is denied (default-deny)."""
        b = pipeline_bundle
        _register_mvp_tools(b["registry"])
        outcome = b["pipeline"].execute(b["agent"]["agent_id"], "email.read", {})
        assert not outcome.ok
        assert outcome.error.code == "policy_denied"
        assert outcome.error.details["reason"] == "no_allow_rule"
        rows = AuditLog(audit_db).search(agent_id=b["agent"]["agent_id"])
        assert len(rows) == 1
        assert rows[0].decision == "denied"
        assert rows[0].reason == "no_allow_rule"

    def test_unknown_tool_denied(self, pipeline_bundle):
        b = pipeline_bundle
        outcome = b["pipeline"].execute(b["agent"]["agent_id"], "nope.missing", {})
        assert outcome.error.code == "policy_denied"

    def test_success_path_allowed_and_audited(self, pipeline_bundle, audit_db):
        b = _pipeline_with_test_tool(pipeline_bundle, allow=True)
        outcome = b["pipeline"].execute(b["agent"]["agent_id"], "test.echo", {"q": "hi"})
        assert outcome.ok
        assert outcome.context.result == {"echo": {"q": "hi"}}
        assert outcome.context.decision == "allowed"
        rows = AuditLog(audit_db).search(agent_id=b["agent"]["agent_id"])
        assert len(rows) == 1
        assert rows[0].decision == "allowed"
        assert rows[0].mandate_id is not None
        assert rows[0].request_id == outcome.context.request_id

    def test_timing_spans_recorded_ac11(self, pipeline_bundle):
        b = _pipeline_with_test_tool(pipeline_bundle, allow=True)
        outcome = b["pipeline"].execute(b["agent"]["agent_id"], "test.echo", {})
        assert outcome.ok
        spans = outcome.context.spans
        for name in ("authenticate", "mandate", "policy", "execute"):
            assert f"stage:{name}" in spans
            assert spans[f"stage:{name}"] >= 0

    def test_error_envelope_matches_audit_request_id(self, pipeline_bundle):
        b = pipeline_bundle
        outcome = b["pipeline"].execute(b["agent"]["agent_id"], "email.read", {})
        assert outcome.error.to_envelope()["error"]["request_id"] == outcome.context.request_id

    def test_wal_mode_on_both_dbs(self, dbs):
        assert journal_mode(dbs.config.engine) == "WAL"
        assert journal_mode(dbs.audit.engine) == "WAL"


# ---------------------------------------------------------------------------
# mock_oauth
# ---------------------------------------------------------------------------

class TestMockOAuth:
    def test_issue_and_validate(self):
        p = MockOAuthProvider()
        tok = p.issue_token("ag_x", scopes=["read"])
        rec = p.validate(tok.token)
        assert rec is not None and rec.agent_id == "ag_x"

    def test_expiry(self):
        p = MockOAuthProvider(token_ttl_minutes=60)
        tok = p.issue_token("ag_x")
        p.expire(tok.token)
        assert p.validate(tok.token) is None

    def test_unknown_token(self):
        assert MockOAuthProvider().validate("nope") is None

    def test_discovery_document_shape(self):
        doc = MockOAuthProvider().discovery_document()
        for key in ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"):
            assert key in doc


# ---------------------------------------------------------------------------
# MCP wire: auth middleware + default-deny over Streamable HTTP
# ---------------------------------------------------------------------------

def _parse_sse(text):
    for line in text.splitlines():
        if line.startswith("data: "):
            return json.loads(line[len("data: "):])
    raise AssertionError(f"no SSE data in: {text[:300]}")


@pytest.fixture(scope="module")
def gateway_server(tmp_path_factory):
    """A live uvicorn server with one agent and one test tool."""
    tmp = tmp_path_factory.mktemp("gw")
    os_env = {
        "GATEWAY_CONFIG_DB": str(tmp / "config.db"),
        "GATEWAY_AUDIT_DB": str(tmp / "audit.db"),
        "GATEWAY_HMAC_KEY": HMAC_KEY,
    }

    old = {k: os.environ.get(k) for k in os_env}
    os.environ.update(os_env)
    try:
        from gateway.mcp_server import GatewayApp
        from gateway.identity import IdentityService as _IS
        from gateway.mandates import MandateService as _MS

        gw = GatewayApp()
        with gw.new_config_session() as db:
            ident = _IS(db)
            agent, client_id, client_secret = ident.register_agent(
                "ag_wire_01", "muse", "Wire Agent", "ken"
            )
            _MS(db).create_default_mandate(agent)
            # A mandate covering the test tool, so the AC-03 wire test
            # exercises default-deny (no allow rule) rather than mandate scope.
            _MS(db).create_mandate("ag_wire_01", "test scope", ["test.echo"])
            # A second agent used for the revocation test.
            agent2, cid2, sec2 = ident.register_agent(
                "ag_wire_02", "grok", "Wire Agent 2", "ken"
            )
            _MS(db).create_default_mandate(agent2)

        def echo(ctx, args):
            return {"echo": args}

        gw.register_connector_tools("test", [ToolDescriptor(
            name="test.echo", description="echo",
            input_schema={"type": "object"}, sensitivity="routine", handler=echo,
        )])

        import socket

        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()

        server = uvicorn.Server(
            uvicorn.Config(gw.http_app(), host="127.0.0.1", port=port, log_level="warning")
        )
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{port}"
        for _ in range(100):
            try:
                httpx.get(f"{base}/healthz", timeout=1)
                break
            except Exception:
                time.sleep(0.1)
        yield {
            "base": base,
            "gw": gw,
            "agent_id": "ag_wire_01",
            "basic": "Basic " + base64.b64encode(
                f"{client_id}:{client_secret}".encode()
            ).decode(),
            "agent2_id": "ag_wire_02",
            "basic2": "Basic " + base64.b64encode(f"{cid2}:{sec2}".encode()).decode(),
        }
        server.should_exit = True
        thread.join(timeout=15)
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _rpc(base, method, params, auth=None, sid=None, req_id=1):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if auth:
        headers["Authorization"] = auth
    if sid:
        headers["Mcp-Session-Id"] = sid
    return httpx.post(
        f"{base}/mcp",
        json={"jsonrpc": "2.0", "id": req_id, "method": method, "params": params},
        headers=headers,
        timeout=15,
    )


_INIT = {
    "protocolVersion": "2025-06-18",
    "capabilities": {},
    "clientInfo": {"name": "pytest", "version": "1"},
}


def _session(base, auth):
    r = _rpc(base, "initialize", _INIT, auth=auth)
    assert r.status_code == 200, r.text[:300]
    sid = r.headers.get("mcp-session-id")
    assert sid, "no session id returned"
    # initialized notification (auth header still required per request)
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Authorization": auth,
        "Mcp-Session-Id": sid,
    }
    httpx.post(
        f"{base}/mcp",
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        headers=headers,
        timeout=15,
    )
    return sid


class TestMcpWire:
    def test_initialize_rejects_unauthenticated(self, gateway_server):
        r = _rpc(gateway_server["base"], "initialize", _INIT)
        body = _parse_sse(r.text)
        assert "error" in body
        assert "auth_failed" in body["error"]["message"]

    def test_initialize_rejects_bad_credential(self, gateway_server):
        bad = "Basic " + base64.b64encode(b"nope:wrong").decode()
        r = _rpc(gateway_server["base"], "initialize", _INIT, auth=bad)
        body = _parse_sse(r.text)
        assert "auth_failed" in body["error"]["message"]

    def test_initialize_accepts_valid_credential(self, gateway_server):
        sid = _session(gateway_server["base"], gateway_server["basic"])
        assert sid

    def test_tools_list_rejects_unauthenticated(self, gateway_server):
        sid = _session(gateway_server["base"], gateway_server["basic"])
        r = _rpc(gateway_server["base"], "tools/list", {}, sid=sid)
        body = _parse_sse(r.text)
        assert "auth_failed" in body["error"]["message"]

    def test_tools_list_shows_dotted_tool_names(self, gateway_server):
        sid = _session(gateway_server["base"], gateway_server["basic"])
        r = _rpc(gateway_server["base"], "tools/list", {},
                 auth=gateway_server["basic"], sid=sid)
        body = _parse_sse(r.text)
        names = [t["name"] for t in body["result"]["tools"]]
        assert "test.echo" in names

    def test_tools_call_rejects_unauthenticated(self, gateway_server):
        sid = _session(gateway_server["base"], gateway_server["basic"])
        r = _rpc(gateway_server["base"], "tools/call",
                 {"name": "test.echo", "arguments": {}}, sid=sid)
        body = _parse_sse(r.text)
        result = body["result"]
        assert result["isError"] is True
        envelope = json.loads(result["content"][0]["text"])
        assert envelope["error"]["code"] == "auth_failed"

    def test_tools_call_default_deny_ac03(self, gateway_server):
        """AC-03 over the wire: no allow rule -> policy_denied/no_allow_rule."""
        sid = _session(gateway_server["base"], gateway_server["basic"])
        r = _rpc(gateway_server["base"], "tools/call",
                 {"name": "test.echo", "arguments": {"q": "hi"}},
                 auth=gateway_server["basic"], sid=sid)
        body = _parse_sse(r.text)
        result = body["result"]
        assert result["isError"] is True
        envelope = json.loads(result["content"][0]["text"])
        assert envelope["error"]["code"] == "policy_denied"
        assert envelope["error"]["details"]["reason"] == "no_allow_rule"
        assert set(envelope["error"]) == {"code", "message", "request_id", "retryable", "details"}

    def test_revoked_agent_denied_on_wire(self, gateway_server):
        gw = gateway_server["gw"]
        with gw.new_config_session() as db:
            from gateway.identity import IdentityService as _IS

            _IS(db).revoke(gateway_server["agent2_id"])
        # initialize itself now fails with agent_revoked
        r = _rpc(gateway_server["base"], "initialize", _INIT,
                 auth=gateway_server["basic2"])
        body = _parse_sse(r.text)
        assert "agent_revoked" in body["error"]["message"]

    def test_healthz(self, gateway_server):
        r = httpx.get(f"{gateway_server['base']}/healthz", timeout=5)
        assert r.json()["status"] == "ok"
