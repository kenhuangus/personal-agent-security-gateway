"""Pillar 1 §1.2: the grant's argument HMAC binds amount + payee.

Approve a payment → the agent re-invokes with identical args (grant
matches → executes) vs tampered args (different amount/payee →
grant_argument_mismatch, terminal, no new approval, no execution).
"""

from __future__ import annotations

import functools

import pytest

from gateway.approvals import ApprovalService
from gateway.audit import AuditLog
from gateway.config import Settings
from gateway.connectors.payment_sandbox import PaymentSandboxConnector
from gateway.db import Databases
from gateway.hmac_util import HmacKeyRing
from gateway.identity import IdentityService
from gateway.mandates import MandateService
from gateway.models import AdminUser
from gateway.money import build_money_stage
from gateway.money.allowlist import AllowlistService, STATE_VERIFIED
from gateway.money.limits import validate_money_block
from gateway.notifier import MockNotifierTransport, build_notifier
from gateway.pipeline import (
    ConnectorRegistry, StubTokenMinter, build_pipeline, execute_approved_call,
)
from gateway.policy import PolicyEngine

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


@pytest.fixture()
def env(dbs, settings, ring):
    registry = ConnectorRegistry()
    PaymentSandboxConnector(
        config_session_factory=dbs.config.session).register(registry)
    with dbs.config.session() as cdb:
        cdb.add(AdminUser(id="admin_ken", password_hash="x", totp_secret=None))
        cdb.commit()
        ident = IdentityService(cdb)
        ag, _cid, secret = ident.register_agent(
            "ag_grant", "test", "Grant Agent", "family")
        MandateService(cdb).create_mandate(
            ag.id, "grant test", ["payment.initiate"], purpose_key="t")
        block = validate_money_block({
            "per_call_soft_cents": 50_000, "per_call_hard_cents": 1_000_000,
        })
        engine = PolicyEngine(cdb)
        rules = engine.version_rules_as_dicts()
        rules.append({"name": "g", "rule_type": "standard", "effect": "allow",
                      "agent_id": ag.id, "tool": "payment.*",
                      "conditions": {"money": block}})
        engine.save_version(rules, change_note="t", created_by="admin",
                            material_change=True)
        AllowlistService(cdb).add(
            payee_key="ach:irs:xxxx0000", label="IRS",
            details_snapshot={"account_last4": "0000"},
            verification_state=STATE_VERIFIED, verified_by="admin")

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


ARGS = {"amount_cents": 60000, "currency": "USD",
        "payee_key": "ach:irs:xxxx0000", "memo": "t"}


def test_grant_match_executes(env):
    outcome, service = env("payment.initiate", dict(ARGS))
    apr_id = outcome.error.details["approval_request_id"]
    service.decide(apr_id, decision="approve", admin_id="admin_ken")
    # Re-invoke with IDENTICAL args: the grant's argument HMAC matches.
    outcome2, _ = env("payment.initiate", dict(ARGS))
    assert outcome2.error is None, outcome2.error
    assert outcome2.context.decision == "allowed_via_approval"


def test_grant_mismatch_amount_denies(env):
    outcome, service = env("payment.initiate", dict(ARGS))
    apr_id = outcome.error.details["approval_request_id"]
    service.decide(apr_id, decision="approve", admin_id="admin_ken")
    # Tampered amount: terminal grant_argument_mismatch, no new
    # approval request, no execution.
    tampered = dict(ARGS, amount_cents=60001)
    outcome2, _ = env("payment.initiate", tampered)
    assert outcome2.error is not None
    assert outcome2.error.code == "grant_argument_mismatch"
    assert outcome2.context.approval_request_id is None


def test_grant_mismatch_payee_denies(env):
    outcome, service = env("payment.initiate", dict(ARGS))
    apr_id = outcome.error.details["approval_request_id"]
    service.decide(apr_id, decision="approve", admin_id="admin_ken")
    tampered = dict(ARGS, payee_key="ach:evil:xxxx9999")
    outcome2, _ = env("payment.initiate", tampered)
    assert outcome2.error is not None
    assert outcome2.error.code == "grant_argument_mismatch"
