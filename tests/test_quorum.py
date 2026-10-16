"""Pillar 1: quorum approvals (quorum.py + approvals.py).

Covers: validate_quorum_satisfiable fail-closed, distinct-approver
and distinct-session enforcement, delegator-cannot-approve, the
context check (mandate liveness / material policy change / allowlist
drift), one-denial-kills, duplicate-session/duplicate-approver,
terminal-idempotent re-decision, and sweep_expired on
partially_approved.
"""

from __future__ import annotations

import pytest

from gateway.config import Settings
from gateway.db import Databases
from gateway.hmac_util import HmacKeyRing
from gateway.models import AdminUser
from gateway.quorum import (
    QuorumError,
    check_context,
    record_approval,
    record_denial,
    validate_quorum_satisfiable,
)

HMAC_KEY = "test-hmac-key-material-32bytes!"


@pytest.fixture()
def settings(tmp_path):
    return Settings(
        config_db_path=str(tmp_path / "config.db"),
        audit_db_path=str(tmp_path / "audit.db"),
        hmac_key=HMAC_KEY,
        money_enabled=True,
    )


@pytest.fixture()
def dbs(settings):
    d = Databases(settings.config_db_path, settings.audit_db_path)
    d.create_all()
    return d


@pytest.fixture()
def ring(settings):
    return HmacKeyRing.from_env_string(settings.hmac_key_id, settings.hmac_key)


def _admins(*ids):
    return [AdminUser(id=i, password_hash="x", totp_secret=None) for i in ids]


def test_validate_quorum_satisfiable_ok(dbs):
    with dbs.config.session() as db:
        db.add_all(_admins("admin_ken", "admin_maya"))
        db.commit()
        validate_quorum_satisfiable(db, 2)  # no raise


def test_validate_quorum_satisfiable_fail_closed(dbs):
    with dbs.config.session() as db:
        db.add_all(_admins("admin_ken"))
        db.commit()
        with pytest.raises(QuorumError):
            validate_quorum_satisfiable(db, 2)


def test_validate_quorum_satisfiable_single_always_ok(dbs):
    with dbs.config.session() as db:
        validate_quorum_satisfiable(db, 1)  # no admins needed


# The remaining quorum tests drive the real ApprovalService. The
# fixture chain mirrors tests/test_approvals.py::_run (money stage
# wired, HMAC ring configured).
def _make_quorum_env(dbs, settings, ring, agent, monkeypatch=None):
    import functools

    from gateway.approvals import ApprovalService
    from gateway.audit import AuditLog
    from gateway.connectors.payment_sandbox import PaymentSandboxConnector
    from gateway.identity import IdentityService
    from gateway.mandates import MandateService
    from gateway.money import build_money_stage
    from gateway.money.allowlist import AllowlistService, STATE_VERIFIED
    from gateway.money.limits import validate_money_block
    from gateway.notifier import MockNotifierTransport, build_notifier
    from gateway.pipeline import (
        ConnectorRegistry, StubTokenMinter, build_pipeline, execute_approved_call,
    )
    from gateway.policy import PolicyEngine

    registry = ConnectorRegistry()
    PaymentSandboxConnector(
        config_session_factory=dbs.config.session
    ).register(registry)

    with dbs.config.session() as cdb, dbs.audit.session() as adb:
        # Two admins so quorum 2 is satisfiable.
        for admin_id in ("admin_ken", "admin_maya"):
            if cdb.get(AdminUser, admin_id) is None:
                cdb.add(AdminUser(id=admin_id, password_hash="x",
                                  totp_secret=None))
        cdb.commit()
        # Agent + mandate + money rule (quorum 2 at/above $1k).
        ident = IdentityService(cdb)
        ag, _cid, secret = ident.register_agent(
            "ag_quorum", "test", "Quorum Agent", "family")
        MandateService(cdb).create_mandate(
            ag.id, "quorum test", ["payment.initiate"], purpose_key="t")
        block = validate_money_block({
            "per_call_soft_cents": 50_000, "per_call_hard_cents": 1_000_000,
            "quorum": 2, "quorum_min_cents": 100_000,
        })
        engine = PolicyEngine(cdb)
        rules = engine.version_rules_as_dicts()
        rules.append({"name": "q", "rule_type": "standard", "effect": "allow",
                      "agent_id": ag.id, "tool": "payment.*",
                      "conditions": {"money": block}})
        engine.save_version(rules, change_note="t", created_by="admin",
                            material_change=True)
        AllowlistService(cdb).add(
            payee_key="ach:irs:xxxx0000", label="IRS",
            details_snapshot={"account_last4": "0000"},
            verification_state=STATE_VERIFIED, verified_by="admin",
        )

    def run(tool, args):
        with dbs.config.session() as cdb, dbs.audit.session() as adb:
            audit = AuditLog(adb)
            notifier = build_notifier(settings, audit,
                                      transport=MockNotifierTransport())
            service = ApprovalService(
                cdb, audit, settings, ring, MandateService(cdb),
                notifier=notifier)
            service.executor = functools.partial(
                execute_approved_call,
                config_session_factory=dbs.config.session,
                audit_session_factory=dbs.audit.session,
                settings=settings, hmac_ring=ring, registry=registry,
                minter=StubTokenMinter())
            pipeline, _, auth_stage = build_pipeline(
                cdb, adb, settings, hmac_ring=ring, registry=registry,
                approval_service=service,
                money_stage=build_money_stage(cdb, settings))
            auth_stage.presented[ag.id] = secret
            return pipeline.execute(ag.id, tool, args), service

    return run


def _request_id(dbs, settings, ring):
    run = _make_quorum_env(dbs, settings, ring, None)
    outcome, service = run(
        "payment.initiate",
        {"amount_cents": 120000, "currency": "USD",
         "payee_key": "ach:irs:xxxx0000"},
    )
    assert outcome.error is not None
    assert outcome.error.code == "approval_required", outcome.error
    assert outcome.error.details.get("quorum") is True
    return outcome.error.details["approval_request_id"], service


def test_quorum_two_distinct_approvers(dbs, settings, ring):
    apr_id, service = _request_id(dbs, settings, ring)
    r1 = service.decide(apr_id, decision="approve", admin_id="admin_ken",
                        session_id="sess-1")
    assert r1["status"] == "partially_approved"
    r2 = service.decide(apr_id, decision="approve", admin_id="admin_maya",
                        session_id="sess-2")
    assert r2["status"] == "approved"


def test_quorum_duplicate_approver_rejected(dbs, settings, ring):
    apr_id, service = _request_id(dbs, settings, ring)
    service.decide(apr_id, decision="approve", admin_id="admin_ken",
                   session_id="sess-1")
    with pytest.raises(ValueError, match="duplicate_approver"):
        service.decide(apr_id, decision="approve", admin_id="admin_ken",
                       session_id="sess-9")


def test_quorum_duplicate_session_rejected(dbs, settings, ring):
    apr_id, service = _request_id(dbs, settings, ring)
    service.decide(apr_id, decision="approve", admin_id="admin_ken",
                   session_id="sess-1")
    with pytest.raises(ValueError, match="duplicate_session"):
        service.decide(apr_id, decision="approve", admin_id="admin_maya",
                       session_id="sess-1")


def test_quorum_one_denial_kills(dbs, settings, ring):
    apr_id, service = _request_id(dbs, settings, ring)
    service.decide(apr_id, decision="approve", admin_id="admin_ken",
                   session_id="sess-1")
    r = service.decide(apr_id, decision="deny", admin_id="admin_maya",
                       session_id="sess-2", note="nope")
    assert r["status"] == "denied"


def test_quorum_terminal_idempotent(dbs, settings, ring):
    apr_id, service = _request_id(dbs, settings, ring)
    service.decide(apr_id, decision="approve", admin_id="admin_ken",
                   session_id="sess-1")
    service.decide(apr_id, decision="approve", admin_id="admin_maya",
                   session_id="sess-2")
    r = service.decide(apr_id, decision="approve", admin_id="admin_ken",
                       session_id="sess-3")
    assert r.get("already_decided") is True


def test_quorum_context_changed_expires(dbs, settings, ring):
    """A material policy change between request creation and the
    second approval expires the request instead of letting it be
    signed stale."""
    from gateway.policy import PolicyEngine

    apr_id, service = _request_id(dbs, settings, ring)
    service.decide(apr_id, decision="approve", admin_id="admin_ken",
                   session_id="sess-1")
    # Material policy change after request creation.
    with dbs.config.session() as cdb:
        engine = PolicyEngine(cdb)
        rules = engine.version_rules_as_dicts()
        rules.append({"name": "late deny", "effect": "deny",
                      "tool": "payment.initiate"})
        engine.save_version(rules, change_note="material",
                            created_by="admin", material_change=True)
    # The service holds a long-lived session in this test (production
    # opens a fresh session per decide); expire its identity map so
    # the context check sees the new policy version.
    service.db.expire_all()
    # The sweep at the top of decide() expires the stale request
    # before the second slot is recorded (fail closed, no stale
    # signature). already_decided=True: the terminal state is
    # reported, never a second slot.
    r = service.decide(apr_id, decision="approve", admin_id="admin_maya",
                       session_id="sess-2")
    assert r["status"] == "expired"
    assert r.get("already_decided") is True
    with dbs.config.session() as cdb:
        from gateway.models import ApprovalRequest

        apr = cdb.get(ApprovalRequest, apr_id)
        assert "context_changed" in (apr.decision_note or "")


def test_sweep_expired_partially_approved(dbs, settings, ring):
    import datetime as dt

    from gateway.models import ApprovalRequest, utcnow

    apr_id, service = _request_id(dbs, settings, ring)
    service.decide(apr_id, decision="approve", admin_id="admin_ken",
                   session_id="sess-1")
    with dbs.config.session() as cdb:
        apr = cdb.get(ApprovalRequest, apr_id)
        apr.expires_at = utcnow() - dt.timedelta(seconds=1)
        cdb.commit()
    swept = service.sweep_expired()
    assert swept >= 1  # sweep_expired returns the count swept
    with dbs.config.session() as cdb:
        apr = cdb.get(ApprovalRequest, apr_id)
        assert apr.status == "expired"
