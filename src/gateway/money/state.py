"""Money state: the per-call spend snapshot (Pillar 1 §1.4).

Decision: SQLite table (``money_ledger``), not in-memory. Precedent:
``RateCounter`` persists in SQLite "so a restart does not reset
limits" — spend limits have the same requirement, more so.

``MoneyStateBuilder.build`` returns one snapshot per call: three
indexed aggregate queries over ``money_ledger``. Rolling windows are
computed server-side from UTC ``occurred_at`` (no client time
trusted). ``dry_run=1`` rows are excluded from budget sums but
included in velocity counts — a dry-run flood is still a flood.

``record_movement`` is the post-execute hook (called from the money
stage after a successful ``payment.initiate``/``payment.cancel``):
denied/failed calls write no ledger row — only moved money consumes
budget.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Any, Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import MoneyLedger, as_utc, utcnow

#: Money tools whose successful execution appends a ledger row.
LEDGER_TOOLS: frozenset[str] = frozenset({"payment.initiate", "payment.cancel"})


@dataclass(frozen=True)
class MoneyState:
    """One spend snapshot for (agent, namespace, payee) at a timestamp."""

    spent_today_cents: int
    spent_month_cents: int
    payments_last_hour: int
    payments_today: int
    payee_payments_last_hour: int
    new_counterparties_today: int
    is_new_counterparty: bool


def _sum_since(
    db: Session,
    agent_id: str,
    namespace_id: Optional[str],
    since: dt.datetime,
    *,
    exclude_dry_run: bool = True,
) -> int:
    q = (
        select(func.coalesce(func.sum(MoneyLedger.amount_cents), 0))
        .where(
            MoneyLedger.agent_id == agent_id,
            MoneyLedger.occurred_at >= since,
        )
    )
    if namespace_id is None:
        q = q.where(MoneyLedger.namespace_id.is_(None))
    else:
        q = q.where(MoneyLedger.namespace_id == namespace_id)
    if exclude_dry_run:
        q = q.where(MoneyLedger.dry_run.is_(False))
    return int(db.execute(q).scalar() or 0)


def _count_since(
    db: Session,
    agent_id: str,
    namespace_id: Optional[str],
    since: dt.datetime,
    *,
    payee_key: Optional[str] = None,
) -> int:
    q = (
        select(func.count())
        .select_from(MoneyLedger)
        .where(
            MoneyLedger.agent_id == agent_id,
            MoneyLedger.occurred_at >= since,
        )
    )
    if namespace_id is None:
        q = q.where(MoneyLedger.namespace_id.is_(None))
    else:
        q = q.where(MoneyLedger.namespace_id == namespace_id)
    if payee_key is not None:
        q = q.where(MoneyLedger.counterparty_key == payee_key)
    return int(db.execute(q).scalar() or 0)


class MoneyStateBuilder:
    """Builds the per-call ``MoneyState`` snapshot."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def build(
        self,
        agent_id: str,
        namespace_id: Optional[str],
        payee_key: str,
        now: dt.datetime,
        *,
        allowlisted_keys: Optional[set[str]] = None,
    ) -> MoneyState:
        now = as_utc(now) or now
        day_start = now - dt.timedelta(days=1)
        month_start = now - dt.timedelta(days=30)
        hour_start = now - dt.timedelta(hours=1)
        allowlisted_keys = allowlisted_keys or set()

        spent_today = _sum_since(self.db, agent_id, namespace_id, day_start)
        spent_month = _sum_since(self.db, agent_id, namespace_id, month_start)
        payments_hour = _count_since(self.db, agent_id, namespace_id, hour_start)
        payments_today = _count_since(self.db, agent_id, namespace_id, day_start)
        payee_hour = _count_since(
            self.db, agent_id, namespace_id, hour_start, payee_key=payee_key
        )

        # New-counterparty accounting: a payee is new when no real
        # (non-dry-run) ledger row precedes it and it is not allowlisted.
        history = (
            self.db.execute(
                select(MoneyLedger.counterparty_key)
                .where(
                    MoneyLedger.agent_id == agent_id,
                    MoneyLedger.dry_run.is_(False),
                )
            )
            .scalars()
            .all()
        )
        known = {str(k) for k in history} | allowlisted_keys
        is_new = payee_key not in known
        # New-counterparty accounting: distinct payees in the window
        # minus those seen before the window (real money rows only —
        # dry runs don't establish history). Conservative; capped at 0.
        before_window = (
            self.db.execute(
                select(func.count(func.distinct(MoneyLedger.counterparty_key)))
                .where(
                    MoneyLedger.agent_id == agent_id,
                    MoneyLedger.occurred_at < day_start,
                    MoneyLedger.dry_run.is_(False),
                )
            ).scalar()
            or 0
        )
        in_window = (
            self.db.execute(
                select(func.count(func.distinct(MoneyLedger.counterparty_key)))
                .where(
                    MoneyLedger.agent_id == agent_id,
                    MoneyLedger.occurred_at >= day_start,
                    MoneyLedger.dry_run.is_(False),
                )
            ).scalar()
            or 0
        )
        new_counterparties_today = max(0, in_window - before_window)

        return MoneyState(
            spent_today_cents=spent_today,
            spent_month_cents=spent_month,
            payments_last_hour=payments_hour,
            payments_today=payments_today,
            payee_payments_last_hour=payee_hour,
            new_counterparties_today=new_counterparties_today,
            is_new_counterparty=is_new,
        )


def record_movement(
    db: Session,
    *,
    agent_id: str,
    namespace_id: Optional[str],
    mandate_id: str,
    counterparty_key: str,
    amount_cents: int,
    tool: str,
    request_id: str,
    dry_run: bool = False,
    now: Optional[dt.datetime] = None,
) -> MoneyLedger:
    """Append the ledger row for a successfully executed money call."""
    row = MoneyLedger(
        agent_id=agent_id,
        namespace_id=namespace_id,
        mandate_id=mandate_id,
        counterparty_key=counterparty_key,
        amount_cents=amount_cents,
        tool=tool,
        request_id=request_id,
        dry_run=dry_run,
        occurred_at=now or utcnow(),
    )
    db.add(row)
    db.commit()
    return row


def prune_ledger(db: Session, retention_days: int) -> int:
    """Prune ledger rows older than the retention horizon (§8).

    Windows never exceed 30 days and retention defaults to 90, so
    pruning is safe. Returns the pruned row count.
    """
    cutoff = utcnow() - dt.timedelta(days=retention_days)
    res = db.execute(
        MoneyLedger.__table__.delete().where(MoneyLedger.occurred_at < cutoff)
    )
    db.commit()
    return res.rowcount or 0
