"""Pillar 1: the threshold ladder (§1.5 a–f) and money-block validation.

The ladder order is fixed: hard stops before soft. Each test asserts
the exact verdict + safe-vocabulary reason for a controlled setup.
"""

from __future__ import annotations

import pytest

from gateway.money.limits import evaluate, validate_money_block


BLOCK = {
    "per_call_hard_cents": 1_000_000,
    "per_call_soft_cents": 50_000,
    "per_day_cents": 250_000,
    "per_month_cents": 5_000_000,
    "max_payments_per_window": {"n": 3, "window_minutes": 60},
    "max_payments_per_day": 10,
    "max_new_counterparties_per_day": 2,
    "quorum": 2,
    "quorum_min_cents": 100_000,
    "cooldown_after_deny_minutes": 60,
}


class _FakeAgent:
    id = "agent_test"
    household_role = "family"


class _FakeRule:
    id = 1


class _FakeState:
    """A MoneyState double with the fields evaluate() reads."""

    def __init__(self, **kw):
        self.spent_today_cents = kw.get("spent_today_cents", 0)
        self.spent_month_cents = kw.get("spent_month_cents", 0)
        self.payments_last_hour = kw.get("payments_last_hour", 0)
        self.payments_today = kw.get("payments_today", 0)
        self.payee_payments_last_hour = kw.get("payee_payments_last_hour", 0)
        self.new_counterparties_today = kw.get("new_counterparties_today", 0)
        self.is_new_counterparty = kw.get("is_new_counterparty", False)


def _ladder(monkeypatch, state_kw, amount_cents, allowlist_state="verified"):
    """Run evaluate() with a stubbed state builder + allowlist."""
    from gateway.money import limits as lim

    class _Builder:
        def __init__(self, db):
            pass

        def build(self, *a, **k):
            return _FakeState(**state_kw)

    class _Row:
        verification_state = allowlist_state

    class _Svc:
        def __init__(self, db):
            pass

        def lookup(self, ns, key):
            return _Row()

        def keys(self, ns):
            return set()

        @staticmethod
        def as_of(row):
            return {"listed": True, "verification_state": row.verification_state}

    monkeypatch.setattr(lim, "MoneyStateBuilder", _Builder)
    monkeypatch.setattr(lim, "AllowlistService", _Svc)
    return lim.evaluate(
        db=None, agent=_FakeAgent(), tool="payment.initiate",
        args={"amount_cents": amount_cents, "payee_key": "ach:x:0000"},
        amount_cents=amount_cents, payee_key="ach:x:0000",
        rule=_FakeRule(), block=dict(BLOCK),
    )


def test_ladder_hard_ceiling_first(monkeypatch):
    d = _ladder(monkeypatch, {}, 1_000_000)
    assert d.decision == "deny"
    assert d.reason == "amount_over_hard_ceiling"


def test_ladder_blocked_payee(monkeypatch):
    d = _ladder(monkeypatch, {}, 10_000, allowlist_state="blocked")
    assert d.decision == "deny"
    assert d.reason == "counterparty_blocked"


def test_ladder_spend_cap(monkeypatch):
    d = _ladder(monkeypatch, {"spent_today_cents": 240_000}, 20_000)
    assert d.decision == "deny"
    assert d.reason == "spend_cap_exceeded"


def test_ladder_velocity(monkeypatch):
    d = _ladder(monkeypatch, {"payments_last_hour": 3}, 10_000)
    assert d.decision == "deny"
    assert d.reason == "velocity_limit_exceeded"


def test_ladder_new_counterparty_velocity(monkeypatch):
    d = _ladder(
        monkeypatch,
        {"is_new_counterparty": True, "new_counterparties_today": 2},
        10_000, allowlist_state="pending",
    )
    assert d.decision == "deny"
    assert d.reason == "velocity_limit_exceeded"


def test_ladder_step_up_soft_line(monkeypatch):
    d = _ladder(monkeypatch, {}, 50_000)
    assert d.decision == "require_approval"
    assert d.reason is None
    assert d.quorum_required == 1


def test_ladder_step_up_unlisted_payee(monkeypatch):
    d = _ladder(monkeypatch, {"is_new_counterparty": True}, 10_000,
              allowlist_state="pending")
    assert d.decision == "require_approval"
    assert d.new_counterparty is True


def test_ladder_quorum_at_quorum_min(monkeypatch):
    d = _ladder(monkeypatch, {}, 100_000)
    assert d.decision == "require_approval"
    assert d.quorum_required == 2


def test_ladder_allow_verified_under_soft(monkeypatch):
    d = _ladder(monkeypatch, {}, 10_000)
    assert d.decision == "allow"
    assert d.reason is None


def test_validate_money_block_rejects_unknown_keys():
    with pytest.raises(ValueError, match="unknown keys"):
        validate_money_block({**BLOCK, "bogus": 1})


def test_validate_money_block_rejects_inverted_thresholds():
    bad = dict(BLOCK, per_call_hard_cents=10_000, per_call_soft_cents=50_000)
    with pytest.raises(ValueError, match="hard_cents"):
        validate_money_block(bad)


def test_validate_money_block_applies_defaults():
    out = validate_money_block({"per_call_soft_cents": 1_000,
                                "per_call_hard_cents": 10_000})
    assert out["quorum"] == 2  # the default quorum
    assert out["per_day_cents"] == 10_000_000
