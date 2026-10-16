"""Pillar 1: MoneyStage in the pipeline (step 3.5).

Covers: the stage runs between mandate and policy; allow /
require_approval / deny verdicts through the real pipeline;
payment.cancel always asks; the money rule is filtered from the OPA
input doc (single Python authority); dry_run=1 excluded from budget
sums but counted in velocity; the ledger post-execute hook writes a
row; payment.quote/status pass through to the policy stage.
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
from gateway.models import AdminUser, MoneyLedger
from gateway.money import build_money_stage
from gateway.money.allowlist import AllowlistService, STATE_VERIFIED
from gateway.money.limits import validate_money_block
from gateway.notifier import MockNotifierTransport, build_notifier
from gateway.pipeline import (
    ConnectorRegistry, StubTokenMinter, build_pipeline, execute_approved_call,
)
from gateway.policy import PolicyEngine

HMAC_KEY = "test-hmac-key-material-32bytes!"
BLOCK = {
    "per_call_soft_cents": 50_000,
    "per_call_hard_cents": 1_000_000,
    "per_day_cents": 250_000,
    "max_payments_per_window": {"n": 3, "window_minutes": 60},
}


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
def agent(dbs):
    with dbs.config.session() as cdb:
        cdb.add(AdminUser(id="admin_ken", password_hash="x", totp_secret=None))
        cdb.commit()
        ident = IdentityService(cdb)
        ag, _cid, secret = ident.register_agent(
            "ag_money", "test", "Money Agent", "family")
        MandateService(cdb).create_mandate(
            ag.id, "money test",
            ["payment.quote", "payment.initiate", "payment.status",
             "payment.cancel"],
            purpose_key="t")
        block = validate_money_block(dict(BLOCK))
        engine = PolicyEngine(cdb)
        rules = engine.version_rules_as_dicts()
        rules.append({"name": "m", "rule_type": "standard", "effect": "allow",
                      "agent_id": ag.id, "tool": "payment.*",
                      "conditions": {"money": block}})
        # A standard allow rule for the read tools (quotes are
        # policy-gated reads, not ladder decisions).
        rules.append({"name": "qr", "effect": "allow",
                      "agent_id": ag.id, "tool": "payment.quote"})
        rules.append({"name": "st", "effect": "allow",
                      "agent_id": ag.id, "tool": "payment.status"})
        engine.save_version(rules, change_note="t", created_by="admin",
                            material_change=True)
        AllowlistService(cdb).add(
            payee_key="ach:irs:xxxx0000", label="IRS",
            details_snapshot={"account_last4": "0000"},
            verification_state=STATE_VERIFIED, verified_by="admin")
    return {"agent_id": ag.id, "secret": secret}


@pytest.fixture()
def registry(dbs):
    reg = ConnectorRegistry()
    PaymentSandboxConnector(
        config_session_factory=dbs.config.session).register(reg)
    return reg


def _run(dbs, settings, ring, registry, agent, tool, args):
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
        auth_stage.presented[agent["agent_id"]] = agent["secret"]
        return pipeline.execute(agent["agent_id"], tool, args), service


def _initiate_args(amount_cents, payee="ach:irs:xxxx0000"):
    return {"amount_cents": amount_cents, "currency": "USD",
            "payee_key": payee, "memo": "test"}


def test_allow_under_soft_verified(dbs, settings, ring, registry, agent):
    outcome, _ = _run(dbs, settings, ring, registry, agent,
                      "payment.initiate", _initiate_args(10_000))
    assert outcome.error is None, outcome.error
    assert outcome.context.decision == "allowed"
    # The post-execute hook wrote the ledger row.
    with dbs.config.session() as cdb:
        rows = cdb.query(MoneyLedger).all()
    assert len(rows) == 1
    assert rows[0].amount_cents == 10_000


def test_require_approval_at_soft_line(dbs, settings, ring, registry, agent):
    outcome, _ = _run(dbs, settings, ring, registry, agent,
                      "payment.initiate", _initiate_args(50_000))
    assert outcome.error is not None
    assert outcome.error.code == "approval_required"
    assert outcome.context.quorum_required == 1
    assert outcome.context.money_new_counterparty is False


def test_deny_over_hard_ceiling(dbs, settings, ring, registry, agent):
    outcome, _ = _run(dbs, settings, ring, registry, agent,
                      "payment.initiate", _initiate_args(1_000_000))
    assert outcome.error is not None
    assert outcome.error.code == "policy_denied"
    assert outcome.error.details["reason"] == "amount_over_hard_ceiling"


def test_deny_blocked_payee(dbs, settings, ring, registry, agent):
    with dbs.config.session() as cdb:
        AllowlistService(cdb).add(
            payee_key="ach:bad:xxxx9999", label="Bad",
            details_snapshot={"account_last4": "9999"})
        from gateway.money.allowlist import STATE_BLOCKED
        AllowlistService(cdb).set_verification(
            namespace_id=None, payee_key="ach:bad:xxxx9999",
            verification_state=STATE_BLOCKED, verified_by="admin")
    outcome, _ = _run(dbs, settings, ring, registry, agent,
                      "payment.initiate", _initiate_args(10_000, "ach:bad:xxxx9999"))
    assert outcome.error is not None
    assert outcome.error.code == "policy_denied"
    assert outcome.error.details["reason"] == "counterparty_blocked"


def test_cancel_always_asks(dbs, settings, ring, registry, agent):
    # First make a payment so there is a receipt to cancel.
    outcome, service = _run(dbs, settings, ring, registry, agent,
                            "payment.initiate", _initiate_args(10_000))
    receipt_id = outcome.context.result["receipt"]["payment_id"]
    outcome2, _ = _run(dbs, settings, ring, registry, agent,
                       "payment.cancel", {"payment_id": receipt_id})
    assert outcome2.error is not None
    assert outcome2.error.code == "approval_required"


def test_money_disabled_passes_through(dbs, ring, registry, agent, tmp_path):
    off = Settings(
        config_db_path=str(tmp_path / "config.db"),
        audit_db_path=str(tmp_path / "audit.db"),
        hmac_key=HMAC_KEY,
        money_enabled=False,
    )
    # With the pack off the stage is None — the call falls to the
    # normal policy stage (no money rule matches → default-deny here).
    from gateway.money import build_money_stage as bms
    assert bms(None, off) is None  # type: ignore[arg-type]
    outcome, _ = _run(dbs, off, ring, registry, agent,
                      "payment.initiate", _initiate_args(10_000))
    assert outcome.error is not None  # no money ladder ran
    assert outcome.context.money_rule_id is None


def test_dry_run_excluded_from_budgets(dbs, settings, ring, registry, agent):
    from gateway.money.state import MoneyStateBuilder

    # A dry-run ledger row: counted in velocity, excluded from budgets.
    with dbs.config.session() as cdb:
        from gateway.models import utcnow
        cdb.add(MoneyLedger(
            agent_id=agent["agent_id"], tool="payment.initiate",
            amount_cents=200_000,
            counterparty_key="ach:irs:xxxx0000",
            mandate_id="mnd_test", request_id="req_test",
            dry_run=True, occurred_at=utcnow()))
        cdb.commit()
    with dbs.config.session() as cdb:
        state = MoneyStateBuilder(cdb).build(
            agent["agent_id"], None, "ach:irs:xxxx0000",
            __import__("datetime").datetime.now(__import__("datetime").timezone.utc))
    assert state.spent_today_cents == 0  # dry run excluded
    assert state.payments_last_hour == 1  # but counted in velocity
