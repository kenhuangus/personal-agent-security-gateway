"""Amount canonicalization (Pillar 1 §1.1).

All amounts are integers in cents, USD only. ``canonicalize_amount``
runs in ``ValidateInputsStage`` (MF-4 ordering: schema failure →
``invalid_input``, no approval created) and rejects: floats, numeric
strings ("12000"), negative/zero, missing currency,
``currency != "USD"``. Fail closed.

Amounts are NEVER floats anywhere in the money pack: rendering uses
integer division, so $48,000.00 is exact.
"""

from __future__ import annotations

from typing import Any


class AmountError(ValueError):
    """Raised for non-canonical amounts; the caller maps to invalid_input."""


def canonicalize_amount(args: dict[str, Any]) -> int:
    """Return the amount in integer cents, or raise AmountError.

    The schema layer already enforces ``amount_cents: integer ≥ 1``
    and ``currency: const USD``; this is the defense-in-depth second
    check that also catches programmatic callers bypassing the schema.
    """
    amount = args.get("amount_cents")
    if isinstance(amount, bool) or not isinstance(amount, int):
        # bool is an int subclass — reject explicitly; floats, numeric
        # strings, and None all fail closed here too.
        raise AmountError("amount_cents must be an integer number of cents")
    if amount <= 0:
        raise AmountError("amount_cents must be positive")
    currency = args.get("currency")
    if currency != "USD":
        raise AmountError("currency must be USD")
    return amount


def format_cents(amount_cents: int) -> str:
    """Render integer cents as ``$48,000.00`` — never via floats."""
    if not isinstance(amount_cents, int) or isinstance(amount_cents, bool):
        raise AmountError("format_cents requires integer cents")
    sign = "-" if amount_cents < 0 else ""
    cents = abs(amount_cents)
    dollars, rem = divmod(cents, 100)
    return f"{sign}${dollars:,}.{rem:02d}"
