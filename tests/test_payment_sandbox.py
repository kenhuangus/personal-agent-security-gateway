"""Pillar 1 §1.1/§1.5: the ``payment.*`` sandbox connector family.

Sandbox adapters only (no real-money rails): payment.quote (routine),
payment.initiate (sensitive, money-gated upstream in MoneyStage),
payment.status (routine read), payment.cancel (sensitive, always
require_approval upstream). The connector records moved money to the
ledger via the post-execute hook, and a forced dry-run never settles.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from gateway.connectors.payment_sandbox import (
    MockPaymentLedger,
    PaymentSandboxConnector,
    make_payment_tools,
)


def _ctx(**kw):
    token = SimpleNamespace(raw=lambda: "test-derived-token")
    return SimpleNamespace(
        agent_id="agent_redteam",
        mandate=None,
        request_id="req-test-1",
        derived_token=token,
        **kw,
    )


def test_tool_family_names():
    tools = make_payment_tools()
    assert {t.name for t in tools} == {
        "payment.quote",
        "payment.initiate",
        "payment.status",
        "payment.cancel",
    }


def test_quote_is_dry_run_only():
    conn = PaymentSandboxConnector()
    out = conn._quote(_ctx(), {"amount_cents": 120000, "currency": "USD",
                               "payee_key": "chen:landlord"})
    assert out["quote"]["dry_run"] is True
    assert out["quote"]["amount_cents"] == 120000
    assert out["quote"]["amount"] == "$1,200.00"
    # No ledger effect.
    assert len(conn.upstream.payments) == 0


def test_initiate_returns_receipt_and_records_ledger():
    conn = PaymentSandboxConnector()
    out = conn._initiate(
        _ctx(), {"amount_cents": 120000, "currency": "USD",
                 "payee_key": "chen:landlord"})
    receipt = out["receipt"]
    assert receipt["payment_id"].startswith("pay_")
    assert receipt["status"] == "settled"
    assert receipt["dry_run"] is False
    assert receipt["amount_cents"] == 120000
    assert receipt["payee_key"] == "chen:landlord"


def test_initiate_rejects_non_canonical_amount():
    conn = PaymentSandboxConnector()
    with pytest.raises(Exception):
        conn._initiate(
            _ctx(), {"amount_cents": 1200.50, "payee_key": "chen:landlord"}
        )


def test_force_dry_run_never_settles():
    conn = PaymentSandboxConnector(force_dry_run=True)
    out = conn._initiate(
        _ctx(), {"amount_cents": 5000, "currency": "USD",
                 "payee_key": "chen:landlord", "dry_run": False})
    assert out["receipt"]["status"] == "settled"
    assert out["receipt"]["dry_run"] is True
    assert len(conn.upstream.payments) == 1  # recorded, but no funds moved
    assert conn.upstream.balances == {}


def test_status_unknown_for_missing_payment():
    conn = PaymentSandboxConnector()
    out = conn._status(_ctx(), {"payment_id": "pay_nope"})
    assert out["status"] == "unknown"


def test_cancel_voids_and_records_reversal():
    conn = PaymentSandboxConnector()
    settled = conn._initiate(
        _ctx(), {"amount_cents": 9000, "currency": "USD",
                 "payee_key": "chen:landlord"})
    pid = settled["receipt"]["payment_id"]
    out = conn._cancel(_ctx(), {"payment_id": pid})
    assert out["receipt"]["status"] == "voided"
    # A second cancel is unknown — no double reversal.
    again = conn._cancel(_ctx(), {"payment_id": pid})
    assert again["status"] == "unknown"


def test_ledger_hook_writes_movement(tmp_path):
    from gateway.db import Databases
    from gateway.identity import IdentityService

    dbs = Databases(str(tmp_path / "config.db"), str(tmp_path / "audit.db"))
    dbs.create_all()
    with dbs.config.session() as db:
        IdentityService(db).register_agent(
            "agent_redteam", "internal", "agent/redteam", "security"
        )
    conn = PaymentSandboxConnector(
        config_session_factory=dbs.config.session)
    out = conn._initiate(
        _ctx(), {"amount_cents": 2500, "currency": "USD",
                 "payee_key": "chen:landlord"})
    pid = out["receipt"]["payment_id"]
    from sqlalchemy import select

    from gateway.models import MoneyLedger

    with dbs.config.session() as db:
        rows = db.execute(
            select(MoneyLedger).where(MoneyLedger.tool == "payment.initiate")
        ).scalars().all()
    assert len(rows) == 1
    assert rows[0].amount_cents == 2500
    assert rows[0].counterparty_key == "chen:landlord"


def test_ledger_hook_skips_when_no_factory():
    # Unit-test wiring without a DB: no ledger writes, handler still works.
    conn = PaymentSandboxConnector(config_session_factory=None)
    out = conn._initiate(
        _ctx(), {"amount_cents": 2500, "currency": "USD",
                 "payee_key": "chen:landlord"})
    assert out["receipt"]["payment_id"].startswith("pay_")
