"""Sandbox payment connector (Pillar 1 §1.1).

Adapter family ``payment.*`` against SYNTHETIC money only — the
gateway is the policy layer, never the custodian; it does not hold
money, clear payments, or operate real-money rails. No production
adapter ships in this pillar.

Tools (registered via ``ConnectorRegistry.register``, same as
email/calendar):
- ``payment.quote`` (routine): read-only estimate, no ledger effect.
- ``payment.initiate`` (sensitive): money-gated (§1.3); appends a
  ``money_ledger`` row on success (post-execute, via ``record_movement``).
- ``payment.status`` (routine): policy-gated read, no ledger effect.
- ``payment.cancel`` (sensitive): always ``require_approval`` (single
  approver); appends a reversal marker row.

Receipt contract (adapter → gateway), enforced here and asserted in
tests: ``PaymentReceipt`` (payment_id ``pay_`` + 32 hex, echoed
amount/payee, status settled|pending|failed|voided, dry_run flag).

``dry_run=True``: returns a receipt with ``dry_run=True`` and
``status="settled"`` without mutating sandbox balances; the gateway
still writes the ``money_ledger`` row flagged ``dry_run=1`` (dry-run
replays exercise the full pipeline including velocity accounting).
``GATEWAY_MONEY_DRY_RUN=1`` forces dry_run on every initiate (demo
safety) — a deployment property applied at the adapter, invisible to
the argument hash.

Unknown-outcome handling: an adapter timeout on ``payment.initiate``
→ the existing ``UnknownOutcomeService.record_block`` (keyed by
(agent, tool, argument_hash)); the console resolves via
``payment.status`` or an explicit void. No blind retry.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Any, Callable, Optional

from sqlalchemy.orm import Session

from ..ids import new_payment_id
from ..money.amounts import AmountError, canonicalize_amount, format_cents
from ..money.state import LEDGER_TOOLS, record_movement
from ..pipeline import ToolDescriptor
from .base import Connector, HealthStatus

PAYMENT_SCHEMA = {
    "type": "object",
    "properties": {
        "amount_cents": {"type": "integer", "minimum": 1},
        "currency": {"type": "string", "const": "USD"},
        "payee_key": {"type": "string", "minLength": 1, "maxLength": 256},
        "memo": {"type": "string", "maxLength": 280},
        "dry_run": {"type": "boolean", "default": False},
        "idempotency_key": {"type": "string", "maxLength": 128},
    },
    "required": ["amount_cents", "currency", "payee_key"],
    # Load-bearing: there is NO namespace argument — a namespace
    # smuggled in args fails validation (invalid_input, MF-4 ordering,
    # no approval created). Namespace resolution is mandate-side only.
    "additionalProperties": False,
}

PAYMENT_STATUS_SCHEMA = {
    "type": "object",
    "properties": {
        "payment_id": {"type": "string", "minLength": 1, "maxLength": 64},
    },
    "required": ["payment_id"],
    "additionalProperties": False,
}

PAYMENT_CANCEL_SCHEMA = {
    "type": "object",
    "properties": {
        "payment_id": {"type": "string", "minLength": 1, "maxLength": 64},
        "reason": {"type": "string", "maxLength": 280},
    },
    "required": ["payment_id"],
    "additionalProperties": False,
}


@dataclass(frozen=True)
class PaymentReceipt:
    """The adapter → gateway receipt contract (§1.1)."""

    payment_id: str      # "pay_" + 32 hex chars (same CSPRNG discipline)
    amount_cents: int    # echoes the canonicalized request amount
    payee_key: str       # echoes the request payee_key
    status: str          # "settled" | "pending" | "failed" | "voided"
    dry_run: bool        # True when the adapter moved no synthetic funds

    def to_dict(self) -> dict[str, Any]:
        return {
            "payment_id": self.payment_id,
            "amount_cents": self.amount_cents,
            "payee_key": self.payee_key,
            "status": self.status,
            "dry_run": self.dry_run,
        }


class MockPaymentLedger:
    """In-memory synthetic balances for the sandbox adapter.

    Mock-only: no network, no real rails. ``fail_next`` forces the
    next initiate to raise TimeoutError (unknown-outcome tests).
    """

    def __init__(self) -> None:
        self.payments: dict[str, PaymentReceipt] = {}
        self.fail_next: bool = False
        # Synthetic per-payee balances (cents), for the demo's realism.
        self.balances: dict[str, int] = {}

    def initiate(
        self, *, amount_cents: int, payee_key: str, dry_run: bool
    ) -> PaymentReceipt:
        if self.fail_next:
            self.fail_next = False
            raise TimeoutError("sandbox adapter timed out (synthetic)")
        receipt = PaymentReceipt(
            payment_id=new_payment_id(),
            amount_cents=amount_cents,
            payee_key=payee_key,
            status="settled",
            dry_run=dry_run,
        )
        if not dry_run:
            self.balances[payee_key] = self.balances.get(payee_key, 0) + amount_cents
        self.payments[receipt.payment_id] = receipt
        return receipt

    def status(self, payment_id: str) -> Optional[PaymentReceipt]:
        return self.payments.get(payment_id)

    def cancel(self, payment_id: str) -> Optional[PaymentReceipt]:
        receipt = self.payments.get(payment_id)
        if receipt is None or receipt.status != "settled":
            return None
        voided = PaymentReceipt(
            payment_id=receipt.payment_id,
            amount_cents=receipt.amount_cents,
            payee_key=receipt.payee_key,
            status="voided",
            dry_run=receipt.dry_run,
        )
        self.payments[payment_id] = voided
        if not receipt.dry_run:
            self.balances[receipt.payee_key] = (
                self.balances.get(receipt.payee_key, 0) - receipt.amount_cents
            )
        return voided


class PaymentSandboxConnector(Connector):
    """Sandbox payment adapter (synthetic dollars, real policy)."""

    name = "payment"

    def __init__(
        self,
        upstream: Optional[MockPaymentLedger] = None,
        config_session_factory: Optional[Callable[[], Session]] = None,
        force_dry_run: bool = False,
    ) -> None:
        self.upstream = upstream or MockPaymentLedger()
        # Post-execute ledger hook (§1.5): the handler appends the
        # money_ledger row on success. None = no ledger writes (the
        # stage still enforces limits; used by unit tests that wire
        # their own DB assertions).
        self.config_session_factory = config_session_factory
        self.force_dry_run = force_dry_run
        self.last_token_seen: str | None = None

    def _token(self, ctx: Any) -> str:
        token = ctx.derived_token.raw() if ctx.derived_token is not None else ""
        self.last_token_seen = token
        return token

    def _record(
        self,
        ctx: Any,
        receipt: PaymentReceipt,
        tool: str,
        dry_run: bool,
    ) -> None:
        if self.config_session_factory is None:
            return
        if tool not in LEDGER_TOOLS:
            return
        with self.config_session_factory() as db:
            amount = receipt.amount_cents
            if tool == "payment.cancel":
                # Reversal marker: negates the original movement so
                # budget sums net correctly.
                amount = -receipt.amount_cents
            record_movement(
                db,
                agent_id=ctx.agent_id,
                namespace_id=None,  # pre-namespace (§5 lands the column)
                mandate_id=ctx.mandate.id if ctx.mandate is not None else "",
                counterparty_key=receipt.payee_key,
                amount_cents=amount,
                tool=tool,
                request_id=ctx.request_id,
                dry_run=dry_run,
            )

    # -- handlers ------------------------------------------------------

    def _quote(self, ctx: Any, args: dict[str, Any]) -> Any:
        self._token(ctx)
        try:
            amount_cents = canonicalize_amount(args)
        except AmountError:
            # Unreachable after ValidateInputsStage (MF-4); belt and braces.
            amount_cents = 0
        return {
            "quote": {
                "amount_cents": amount_cents,
                "amount": format_cents(amount_cents) if amount_cents else "$0.00",
                "currency": "USD",
                "payee_key": args.get("payee_key"),
                "estimated_settlement": "T+1 (synthetic)",
                "dry_run": True,
            }
        }

    def _initiate(self, ctx: Any, args: dict[str, Any]) -> Any:
        self._token(ctx)
        amount_cents = canonicalize_amount(args)  # validated upstream; fail closed
        payee_key = str(args["payee_key"])
        dry_run = bool(args.get("dry_run", False)) or self.force_dry_run
        receipt = self.upstream.initiate(
            amount_cents=amount_cents, payee_key=payee_key, dry_run=dry_run
        )
        # Post-execute hook: only moved (or dry-run-replayed) money
        # lands in the ledger. A TimeoutError above propagates to
        # ExecuteStage → UnknownOutcomeService.record_block (no ledger
        # row, no blind retry).
        self._record(ctx, receipt, "payment.initiate", dry_run)
        return {"receipt": receipt.to_dict()}

    def _status(self, ctx: Any, args: dict[str, Any]) -> Any:
        self._token(ctx)
        receipt = self.upstream.status(str(args["payment_id"]))
        if receipt is None:
            return {"payment_id": args["payment_id"], "status": "unknown"}
        return {"receipt": receipt.to_dict()}

    def _cancel(self, ctx: Any, args: dict[str, Any]) -> Any:
        self._token(ctx)
        receipt = self.upstream.cancel(str(args["payment_id"]))
        if receipt is None:
            return {
                "payment_id": args["payment_id"],
                "status": "unknown",
                "note": "no settled payment with this id (synthetic)",
            }
        self._record(ctx, receipt, "payment.cancel", receipt.dry_run)
        return {"receipt": receipt.to_dict()}

    # -- Connector interface --------------------------------------------

    @property
    def tools(self) -> list[ToolDescriptor]:
        def bind(fn: Callable[[Any, dict[str, Any]], Any]) -> Callable[[Any, dict[str, Any]], Any]:
            return lambda ctx, args: fn(ctx, args)

        return [
            ToolDescriptor(
                name="payment.quote",
                description=(
                    "Read-only payment estimate (synthetic dollars). "
                    "No ledger effect."
                ),
                input_schema=PAYMENT_SCHEMA,
                sensitivity="routine",
                handler=bind(self._quote),
            ),
            ToolDescriptor(
                name="payment.initiate",
                description=(
                    "SENSITIVE: initiate a synthetic payment. Money-gated: "
                    "limits, velocity, and counterparty allowlist enforced "
                    "by the money pack; above-threshold calls pause for "
                    "human (quorum) approval."
                ),
                input_schema=PAYMENT_SCHEMA,
                sensitivity="sensitive",
                handler=bind(self._initiate),
            ),
            ToolDescriptor(
                name="payment.status",
                description="Policy-gated read of a payment receipt by id.",
                input_schema=PAYMENT_STATUS_SCHEMA,
                sensitivity="routine",
                handler=bind(self._status),
            ),
            ToolDescriptor(
                name="payment.cancel",
                description=(
                    "SENSITIVE: void a settled synthetic payment. Always "
                    "requires step-up approval (single approver)."
                ),
                input_schema=PAYMENT_CANCEL_SCHEMA,
                sensitivity="sensitive",
                handler=bind(self._cancel),
            ),
        ]

    @property
    def upstream_scopes(self) -> list[str]:
        return ["payments:sandbox"]

    def health_check(self) -> HealthStatus:
        return HealthStatus(
            connector=self.name,
            credential_valid=True,
            api_reachable=True,
            detail="sandbox adapter: in-memory synthetic ledger, no real rails",
        )

    def ssrf_checklist(self) -> dict[str, Any]:
        return {
            "egress_allowlist": True,
            "no_open_url_fetch": True,
            "metadata_endpoints_blocked": True,
            "no_credentials_in_args": True,
            "notes": (
                "Mock-only adapter: in-process synthetic ledger, no "
                "network egress. No tool accepts URLs or credentials. "
                "Real-money rails are deliberately absent (design §1)."
            ),
        }


def make_payment_tools(
    config_session_factory: Optional[Callable[[], Session]] = None,
    force_dry_run: bool = False,
) -> list[ToolDescriptor]:
    """Build the payment.* tool descriptors (money-pack registration)."""
    return PaymentSandboxConnector(
        config_session_factory=config_session_factory,
        force_dry_run=force_dry_run,
    ).tools
