"""Pillar 1 fix-back: HOLD regression tests (PR #39 security review).

Covers the five HOLD fixes + three required fixes:
1. payee_key canonicalization (blocked-payee bypass via case variation)
2. spend-cap re-verification at grant consumption (+ committed budget)
3. post-approval allowlist change at grant consumption
4. GATEWAY_MONEY_DRY_RUN wiring
5. issue-store path traversal
6. grant-mismatch ordering (false mismatch on concurrent approvals)
7. payment.cancel grant consumption (infinite approval loop)
8. AgentCredentials raw_secret repr exclusion
"""

from __future__ import annotations

import datetime as dt
import functools

import pytest
from sqlalchemy import select

from gateway.approvals import ApprovalService, GrantService
from gateway.audit import AuditLog
from gateway.config import Settings
from gateway.connectors.payment_sandbox import PaymentSandboxConnector
from gateway.db import Databases
from gateway.hmac_util import HmacKeyRing
from gateway.identity import IdentityService
from gateway.mandates import MandateService
from gateway.models import (
    AdminUser,
    ApprovalRequest,
    Grant,
    PolicyRule,
    as_utc,
    utcnow,
)
from gateway.money import build_money_stage
from gateway.money.allowlist import (
    STATE_BLOCKED,
    STATE_VERIFIED,
    AllowlistService,
    canonicalize_payee_key,
)
from gateway.money.limits import (
    evaluate,
    reverify_money_grant,
    validate_money_block,
)
from gateway.money.state import MoneyStateBuilder
from gateway.notifier import MockNotifierTransport, build_notifier
from gateway.pipeline import (
    ConnectorRegistry,
    StubTokenMinter,
    build_pipeline,
    execute_approved_call,
)
from gateway.policy import PolicyEngine

HMAC_KEY = "test-hmac-key-material-32bytes!"
BLOCK = {
    "per_call_soft_cents": 50_000,
    "per_call_hard_cents": 10_000_000,
    "per_day_cents": 10_000_000,  # $100k/day — the fix-2 scenario
    "per_month_cents": 50_000_000,
    "max_payments_per_window": {"n": 10, "window_minutes": 60},
}


class _FakeAgent:
    id = "ag_hold"
    household_role = "family"


class _FakeRule:
    id = 1


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
        cdb.add(AdminUser(id="admin_ken", password_hash="x", totp_secret="y"))
        cdb.commit()
        ident = IdentityService(cdb)
        ag, _cid, secret = ident.register_agent(
            "ag_hold", "test", "Hold Agent", "family")
        MandateService(cdb).create_mandate(
            ag.id, "hold test",
            ["payment.initiate", "payment.cancel"],
            purpose_key="t")
        block = validate_money_block(dict(BLOCK))
        engine = PolicyEngine(cdb)
        rules = engine.version_rules_as_dicts()
        rules.append({"name": "m", "rule_type": "standard", "effect": "allow",
                      "agent_id": ag.id, "tool": "payment.*",
                      "conditions": {"money": block}})
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


def _args(amount_cents, payee="ach:irs:xxxx0000"):
    return {"amount_cents": amount_cents, "currency": "USD",
            "payee_key": payee, "memo": "t"}


# ---------------------------------------------------------------------
# Fix 1: payee_key canonicalization
# ---------------------------------------------------------------------

def test_canonicalize_payee_key_unit():
    assert canonicalize_payee_key("  ACH:IRS:xxxx1234 ") == "ach:irs:xxxx1234"
    assert canonicalize_payee_key("ach:irs:xxxx1234") == "ach:irs:xxxx1234"
    assert canonicalize_payee_key("") == ""


def test_allowlist_write_canonicalizes(dbs):
    with dbs.config.session() as db:
        svc = AllowlistService(db)
        svc.add(payee_key="  ACH:EVIL:xxxx9999 ", label="Evil",
                verification_state=STATE_BLOCKED, verified_by="admin")
        # Read with a different spelling hits the same row.
        row = svc.lookup(None, "ach:evil:xxxx9999")
        assert row is not None
        assert row.verification_state == STATE_BLOCKED
        # Duplicate add in another spelling is rejected.
        with pytest.raises(ValueError):
            svc.add(payee_key="ACH:EVIL:XXXX9999", label="Dup")


def test_blocked_payee_case_variation_denied(dbs, settings, ring, registry, agent):
    """HOLD 1: a blocked payee cannot be evaded by case variation."""
    with dbs.config.session() as db:
        AllowlistService(db).add(
            payee_key="ach:evil:xxxx9999", label="Evil",
            verification_state=STATE_BLOCKED, verified_by="admin")
    outcome, _ = _run(dbs, settings, ring, registry, agent,
                      "payment.initiate", _args(1_000, "ACH:EVIL:XXXX9999"))
    assert outcome.error is not None
    assert outcome.error.code == "policy_denied"
    assert "counterparty_blocked" in str(outcome.error.details)


def test_ladder_blocked_case_variation_direct(dbs):
    """Same hole, one level down: evaluate() with a canonicalized key."""
    with dbs.config.session() as db:
        AllowlistService(db).add(
            payee_key="ach:evil:xxxx9999", label="Evil",
            verification_state=STATE_BLOCKED, verified_by="admin")
        d = evaluate(
            db=db, agent=_FakeAgent(), tool="payment.initiate",
            args={"amount_cents": 1_000, "payee_key": "ACH:EVIL:XXXX9999"},
            amount_cents=1_000,
            payee_key=canonicalize_payee_key("ACH:EVIL:XXXX9999"),
            rule=_FakeRule(), block=dict(BLOCK),
        )
    assert d.decision == "deny"
    assert d.reason == "counterparty_blocked"

# ---------------------------------------------------------------------
# Fix 2 + 3: consumption-time re-verification
# ---------------------------------------------------------------------

def _money_rule_id(db):
    rule = db.execute(
        select(PolicyRule).where(PolicyRule.tool == "payment.*")
    ).scalars().first()
    assert rule is not None
    return rule.id


def _mint_money_grant(db, agent_id, mandate_id, amount_cents, payee_key,
                      rule_id, record_version=None, suffix="a"):
    """Directly mint a money grant + approval request (simulates the
    post-approval state without running the approval flow)."""
    from gateway.ids import new_approval_id
    from gateway.policy import PolicyEngine

    apr_id = new_approval_id()
    now = utcnow()
    policy_version = PolicyEngine(db).current_version_number() or 1
    apr = ApprovalRequest(
        id=apr_id,
        agent_id=agent_id,
        mandate_id=mandate_id,
        tool="payment.initiate",
        policy_version=policy_version,
        argument_hash=f"hash-{suffix}-{amount_cents}",
        evidence_subset={"money_rule_id": rule_id,
                         "terms": {"amount": str(amount_cents)}},
        redacted_args={"amount_cents": amount_cents, "currency": "USD",
                       "payee_key": payee_key, "memo": "t"},
        status="approved",
        expires_at=now + dt.timedelta(minutes=30),
        quorum_required=1,
        approvals=[],
        context_fingerprint={
            "mandate_status": "active",
            "policy_version": policy_version,
            "payee_key": payee_key,
            "counterparty_record_version": record_version,
            "namespace_id": None,
        },
    )
    db.add(apr)
    grant = Grant(
        approval_request_id=apr_id,
        agent_id=agent_id,
        tool="payment.initiate",
        argument_hash=f"hash-{suffix}-{amount_cents}",
        mandate_id=mandate_id,
        policy_version=policy_version,
        expires_at=now + dt.timedelta(minutes=30),
    )
    db.add(grant)
    db.commit()
    return grant


def _mandate_id(db, agent_id):
    from gateway.models import Mandate
    m = db.execute(
        select(Mandate).where(Mandate.agent_id == agent_id)
    ).scalars().first()
    assert m is not None and m.status == "active"
    return m.id


def test_reverify_allows_under_cap(dbs, agent):
    """Single $60k grant against a $100k/day cap: consumption allowed."""
    with dbs.config.session() as db:
        rule_id = _money_rule_id(db)
        mid = _mandate_id(db, agent["agent_id"])
        grant = _mint_money_grant(db, agent["agent_id"], mid, 6_000_000,
                                  "ach:irs:xxxx0000", rule_id,
                                  record_version=1, suffix="ok")
        assert reverify_money_grant(db, grant) is None


def test_reverify_denies_when_caps_exceeded(dbs, agent):
    """HOLD 2: two $60k grants against a $100k/day cap — the second
    consumption is denied even though both were approved."""
    with dbs.config.session() as db:
        rule_id = _money_rule_id(db)
        mid = _mandate_id(db, agent["agent_id"])
        g1 = _mint_money_grant(db, agent["agent_id"], mid, 6_000_000,
                               "ach:irs:xxxx0000", rule_id,
                               record_version=1, suffix="cap1")
        _mint_money_grant(db, agent["agent_id"], mid, 6_000_000,
                          "ach:irs:xxxx0000", rule_id,
                          record_version=1, suffix="cap2")
        # Either grant's consumption now sees 60k committed + 60k
        # current > 100k cap → deny.
        assert reverify_money_grant(db, g1) == "spend_cap_exceeded"


def test_reverify_denies_after_first_executes(dbs, agent):
    """HOLD 2 variant: first grant executes ($60k in ledger), the second
    consumption is denied against the fresh ledger."""
    from gateway.money.state import record_movement
    with dbs.config.session() as db:
        rule_id = _money_rule_id(db)
        mid = _mandate_id(db, agent["agent_id"])
        _mint_money_grant(db, agent["agent_id"], mid, 6_000_000,
                          "ach:irs:xxxx0000", rule_id,
                          record_version=1, suffix="ex1")
        g2 = _mint_money_grant(db, agent["agent_id"], mid, 6_000_000,
                               "ach:irs:xxxx0000", rule_id,
                               record_version=1, suffix="ex2")
        # Simulate grant 1's execution landing in the ledger.
        record_movement(db, agent_id=agent["agent_id"], namespace_id=None,
                        mandate_id=mid, counterparty_key="ach:irs:xxxx0000",
                        amount_cents=6_000_000, tool="payment.initiate",
                        request_id="req-ex1")
        assert reverify_money_grant(db, g2) == "spend_cap_exceeded"


def test_reverify_denies_blocked_after_approval(dbs, agent):
    """HOLD 3: payee blocked after approval → consumption denied."""
    with dbs.config.session() as db:
        rule_id = _money_rule_id(db)
        mid = _mandate_id(db, agent["agent_id"])
        svc = AllowlistService(db)
        svc.add(payee_key="ach:vendor:xxxx1111", label="Vendor",
                verification_state=STATE_VERIFIED, verified_by="admin")
        row = svc.lookup(None, "ach:vendor:xxxx1111")
        grant = _mint_money_grant(db, agent["agent_id"], mid, 1_000,
                                  "ach:vendor:xxxx1111", rule_id,
                                  record_version=row.record_version,
                                  suffix="blk")
        assert reverify_money_grant(db, grant) is None
        # Operator blocks the payee post-approval.
        svc.set_verification(namespace_id=None,
                             payee_key="ach:vendor:xxxx1111",
                             verification_state=STATE_BLOCKED,
                             verified_by="admin")
        assert reverify_money_grant(db, grant) == "counterparty_blocked"


def test_reverify_denies_record_version_drift(dbs, agent):
    """HOLD 3: allowlist edit (record_version bump) after approval →
    consumption denied as stale context."""
    with dbs.config.session() as db:
        rule_id = _money_rule_id(db)
        mid = _mandate_id(db, agent["agent_id"])
        svc = AllowlistService(db)
        svc.add(payee_key="ach:vendor:xxxx2222", label="Vendor2",
                verification_state=STATE_VERIFIED, verified_by="admin")
        row = svc.lookup(None, "ach:vendor:xxxx2222")
        grant = _mint_money_grant(db, agent["agent_id"], mid, 1_000,
                                  "ach:vendor:xxxx2222", rule_id,
                                  record_version=row.record_version,
                                  suffix="drv")
        assert reverify_money_grant(db, grant) is None
        # Any verification edit bumps record_version (stale context).
        svc.set_verification(namespace_id=None,
                             payee_key="ach:vendor:xxxx2222",
                             verification_state=STATE_VERIFIED,
                             verified_by="admin2")
        assert reverify_money_grant(db, grant) == "money_context_changed"


def test_reverify_denies_removed_payee(dbs, agent):
    """HOLD 3: payee removed from the allowlist after approval →
    consumption denied."""
    with dbs.config.session() as db:
        rule_id = _money_rule_id(db)
        mid = _mandate_id(db, agent["agent_id"])
        svc = AllowlistService(db)
        svc.add(payee_key="ach:vendor:xxxx3333", label="Vendor3",
                verification_state=STATE_VERIFIED, verified_by="admin")
        row = svc.lookup(None, "ach:vendor:xxxx3333")
        grant = _mint_money_grant(db, agent["agent_id"], mid, 1_000,
                                  "ach:vendor:xxxx3333", rule_id,
                                  record_version=row.record_version,
                                  suffix="rmv")
        # Simulate removal: delete the row directly.
        db.delete(row)
        db.commit()
        assert reverify_money_grant(db, grant) == "money_context_changed"


def test_grant_check_wires_reverify(dbs, settings, agent):
    """The grant checker denies a cap-exceeded money grant at
    consumption (fail-closed), wired through GrantService.check."""
    with dbs.config.session() as cdb, dbs.audit.session() as adb:
        rule_id = _money_rule_id(cdb)
        mid = _mandate_id(cdb, agent["agent_id"])
        _mint_money_grant(cdb, agent["agent_id"], mid, 6_000_000,
                          "ach:irs:xxxx0000", rule_id,
                          record_version=1, suffix="w1")
        g2 = _mint_money_grant(cdb, agent["agent_id"], mid, 6_000_000,
                               "ach:irs:xxxx0000", rule_id,
                               record_version=1, suffix="w2")
        audit = AuditLog(adb)
        svc = GrantService(cdb, audit)
        res = svc.check(agent["agent_id"], "payment.initiate",
                        g2.argument_hash)
        assert res is not None
        assert res.allowed is False
        assert res.deny_reason == "spend_cap_exceeded"


def test_card_reflects_committed_budget(dbs, agent):
    """HOLD 2 (card): the approval card's remaining daily budget nets
    out committed (approved, unconsumed) grants."""
    with dbs.config.session() as db:
        rule_id = _money_rule_id(db)
        mid = _mandate_id(db, agent["agent_id"])
        _mint_money_grant(db, agent["agent_id"], mid, 6_000_000,
                          "ach:irs:xxxx0000", rule_id,
                          record_version=1, suffix="card")
        # A new $30k request: 100k cap − 0 spent − 60k committed − 30k
        # = $10,000.00 remaining.
        d = evaluate(
            db=db, agent=_FakeAgent(), tool="payment.initiate",
            args={"amount_cents": 3_000_000, "payee_key": "ach:irs:xxxx0000"},
            amount_cents=3_000_000, payee_key="ach:irs:xxxx0000",
            rule=_FakeRule(), block=dict(BLOCK),
        )
    assert d.decision == "require_approval"  # $30k < $100k cap
    assert d.card["remaining_daily"] == "$10,000.00"

# ---------------------------------------------------------------------
# Fix 4: GATEWAY_MONEY_DRY_RUN wiring
# ---------------------------------------------------------------------

def test_money_dry_run_setting_from_env(monkeypatch, tmp_path):
    monkeypatch.setenv("GATEWAY_MONEY_DRY_RUN", "1")
    s = Settings(
        config_db_path=str(tmp_path / "c.db"),
        audit_db_path=str(tmp_path / "a.db"),
        hmac_key=HMAC_KEY,
        money_enabled=True,
    )
    assert s.money_dry_run is True
    monkeypatch.delenv("GATEWAY_MONEY_DRY_RUN")
    s2 = Settings(
        config_db_path=str(tmp_path / "c.db"),
        audit_db_path=str(tmp_path / "a.db"),
        hmac_key=HMAC_KEY,
        money_enabled=True,
    )
    assert s2.money_dry_run is False


def test_force_dry_run_forces_dry_run_receipt():
    """HOLD 4: the kill switch forces dry_run on every initiate."""
    conn = PaymentSandboxConnector(force_dry_run=True)
    assert conn.force_dry_run is True

    class _Ctx:
        derived_token = None
        agent_id = "ag_x"
        mandate = None
        request_id = "req-dry"

    out = conn._initiate(
        _Ctx(),
        {"amount_cents": 1_000, "currency": "USD",
         "payee_key": "ach:x:0000"},
    )
    assert out["receipt"]["dry_run"] is True


# ---------------------------------------------------------------------
# Fix 5: issue-store path traversal
# ---------------------------------------------------------------------

def test_check_repo_rejects_traversal():
    from gateway.connectors.issue_store import _check_repo
    import pytest as _pt
    for bad in ("../..", "a/../b", "./x", "a/.", "a/", "/b", "", "a/b/c"):
        with _pt.raises(ValueError):
            _check_repo(bad)
    # Legitimate names still pass.
    for good in ("owner/repo", "my-org/my.repo", "a1/b-2_c.3"):
        _check_repo(good)


def test_local_store_traversal_blocked(tmp_path):
    """End to end: a traversal repo never reaches the filesystem."""
    from gateway.connectors.issue_store import LocalIssueStore
    store = LocalIssueStore(str(tmp_path))
    with pytest.raises(ValueError):
        store.open_issue(repo="../..", title="t", body="b", labels=[])
    # Nothing escaped the root.
    assert [p.name for p in tmp_path.iterdir()] == []


# ---------------------------------------------------------------------
# Fix 6: grant-mismatch ordering
# ---------------------------------------------------------------------

def test_concurrent_approvals_no_false_mismatch(
    dbs, settings, ring, registry, agent
):
    """Required fix 6: two live grants for the same (agent, tool) with
    different args — re-invoking the first (matching hash) must NOT
    false-deny with grant_argument_mismatch.

    (The request-time mismatch guard still blocks a *new* payment while
    a grant is live — pre-existing behavior, unchanged. This tests the
    re-invoke path where the old check order falsely denied.)
    """
    a1 = _args(60_000, "ach:irs:xxxx0000")
    out1, svc1 = _run(dbs, settings, ring, registry, agent,
                      "payment.initiate", dict(a1))
    apr1 = out1.error.details["approval_request_id"]
    svc1.decide(apr1, decision="approve", admin_id="admin_ken")
    # A second live grant with different args (simulates a concurrent
    # approval that bypassed the request-time guard).
    with dbs.config.session() as db:
        rule_id = _money_rule_id(db)
        mid = _mandate_id(db, agent["agent_id"])
        _mint_money_grant(db, agent["agent_id"], mid, 30_000,
                          "ach:irs:xxxx0000", rule_id,
                          record_version=1, suffix="conc")
    # Re-invoke the FIRST payment with identical args: its own grant
    # matches → executes, no grant_argument_mismatch.
    out3, _ = _run(dbs, settings, ring, registry, agent,
                   "payment.initiate", dict(a1))
    assert out3.error is None, out3.error
    assert out3.context.decision == "allowed_via_approval"


def test_tampered_reinvoke_still_denied(dbs, settings, ring, registry, agent):
    """The swapped order must not weaken tamper detection: re-invoke
    with altered args (no matching grant) still denies."""
    a1 = _args(60_000, "ach:irs:xxxx0000")
    out1, svc1 = _run(dbs, settings, ring, registry, agent,
                      "payment.initiate", dict(a1))
    apr1 = out1.error.details["approval_request_id"]
    svc1.decide(apr1, decision="approve", admin_id="admin_ken")
    with dbs.config.session() as db:
        rule_id = _money_rule_id(db)
        mid = _mandate_id(db, agent["agent_id"])
        _mint_money_grant(db, agent["agent_id"], mid, 30_000,
                          "ach:irs:xxxx0000", rule_id,
                          record_version=1, suffix="tamp")
    tampered = dict(a1, amount_cents=60_001)
    out2, _ = _run(dbs, settings, ring, registry, agent,
                   "payment.initiate", tampered)
    assert out2.error is not None
    assert out2.error.code == "grant_argument_mismatch"


# ---------------------------------------------------------------------
# Fix 7: payment.cancel consumes its grant
# ---------------------------------------------------------------------

def test_cancel_reinvoke_consumes_grant(dbs, settings, ring, registry, agent):
    """Required fix 7: an approved cancel re-invoked with identical
    args consumes the grant instead of minting a new approval."""
    args = {"payment_id": "pay_abc123"}
    out1, svc = _run(dbs, settings, ring, registry, agent,
                     "payment.cancel", dict(args))
    assert out1.error is not None  # first call → approval required
    apr_id = out1.error.details["approval_request_id"]
    svc.decide(apr_id, decision="approve", admin_id="admin_ken")
    out2, _ = _run(dbs, settings, ring, registry, agent,
                    "payment.cancel", dict(args))
    assert out2.error is None, out2.error
    # No second approval request was minted.
    assert out2.context.approval_request_id in (None, apr_id)


# ---------------------------------------------------------------------
# Fix 8: AgentCredentials repr
# ---------------------------------------------------------------------

def test_agent_credentials_repr_hides_secret():
    from agents.mcp_client import AgentCredentials
    creds = AgentCredentials(
        agent_key="redteam", credential_id="cid-1",
        raw_secret="supersecret-value-123")
    r = repr(creds)
    assert "supersecret-value-123" not in r
    assert "cid-1" in r
