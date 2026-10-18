"""Pillar 1: canonical amount handling (MF-4).

Integer cents only: floats, numeric strings, zero, negatives, and
non-USD are rejected. Formatting is integer-only (no float math).
"""

from __future__ import annotations

import pytest

from gateway.money.amounts import AmountError, canonicalize_amount, format_cents


def test_canonicalize_int_cents():
    assert canonicalize_amount({"amount_cents": 120000, "currency": "USD"}) == 120000


def test_canonicalize_rejects_float():
    with pytest.raises(AmountError):
        canonicalize_amount({"amount_cents": 120000.0})


def test_canonicalize_rejects_numeric_string():
    with pytest.raises(AmountError):
        canonicalize_amount({"amount_cents": "120000"})


def test_canonicalize_rejects_zero_and_negative():
    with pytest.raises(AmountError):
        canonicalize_amount({"amount_cents": 0})
    with pytest.raises(AmountError):
        canonicalize_amount({"amount_cents": -5})


def test_canonicalize_rejects_non_usd():
    with pytest.raises(AmountError):
        canonicalize_amount({"amount_cents": 100, "currency": "EUR"})


def test_canonicalize_missing_currency_rejected():
    # No default: the caller must name the currency (fail closed).
    with pytest.raises(AmountError):
        canonicalize_amount({"amount_cents": 100})


def test_canonicalize_missing_amount():
    with pytest.raises(AmountError):
        canonicalize_amount({})


def test_format_cents_integer_only():
    assert format_cents(120000) == "$1,200.00"
    assert format_cents(1) == "$0.01"
    # No float math: 1/3 of a cent is impossible by construction.
    with pytest.raises((AmountError, TypeError)):
        format_cents(10.5)  # type: ignore[arg-type]
