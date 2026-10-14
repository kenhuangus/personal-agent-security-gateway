"""Per-agent rate limiting (M5; FR-028; 00 §7 param 4; 03 §7).

Budgets (tunable via Settings):
- tool calls: ``rate_limit_per_minute`` (default 60) and
  ``rate_limit_per_day`` (default 1000) per agent;
- ``gateway.approval_status`` polls: their OWN separate budget
  (``approval_status_polls_per_minute``, default 60/min per agent, per
  02 §2.5) — polling for a decision never consumes the tool-call
  budget.

Counters live in the config DB (``RateCounter`` rows), so a restart
does not reset limits (03 §5). Exhaustion returns ``rate_limited``
with ``retry_after`` seconds in the error details (02 §2.7).
"""

from __future__ import annotations

import datetime as dt
from typing import Optional

from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..config import Settings
from ..errors import GatewayError, make_error
from ..models import RateCounter

# The meta tool whose polls draw from the separate poll budget (02 §2.5).
APPROVAL_STATUS_TOOL = "gateway.approval_status"

# Extra window label for the poll budget (RateCounter.window is a
# String(16); "poll_minute" fits).
POLL_WINDOW = "poll_minute"


def _minute_start(now: dt.datetime) -> dt.datetime:
    return now.replace(second=0, microsecond=0)


def _day_start(now: dt.datetime) -> dt.datetime:
    return now.replace(hour=0, minute=0, second=0, microsecond=0)


def _retry_after_seconds(now: dt.datetime, window_start: dt.datetime, window: str) -> int:
    if window == "day":
        nxt = window_start + dt.timedelta(days=1)
    else:  # "minute" and "poll_minute" are minute windows
        nxt = window_start + dt.timedelta(minutes=1)
    return max(1, int((nxt - now).total_seconds()) + 1)


class RateLimiter:
    """Enforces per-agent call budgets against persisted counters."""

    def __init__(self, db: Session, settings: Settings) -> None:
        self.db = db
        self.settings = settings

    # -- public API ----------------------------------------------------

    def check(
        self, agent_id: str, tool: str, request_id: str
    ) -> Optional[GatewayError]:
        """Check budgets for one call attempt.

        Returns ``None`` when the call may proceed (the attempt is
        counted), or a ``rate_limited`` error with ``retry_after``.
        Rejected attempts do NOT consume budget.
        """
        self._prune()
        now = dt.datetime.now(dt.timezone.utc)
        if tool == APPROVAL_STATUS_TOOL:
            return self._check_window(
                agent_id, POLL_WINDOW, _minute_start(now),
                self.settings.approval_status_polls_per_minute,
                request_id, tool, now,
            )
        err = self._check_window(
            agent_id, "minute", _minute_start(now),
            self.settings.rate_limit_per_minute, request_id, tool, now,
        )
        if err is not None:
            return err
        return self._check_window(
            agent_id, "day", _day_start(now),
            self.settings.rate_limit_per_day, request_id, tool, now,
        )

    # -- internals -----------------------------------------------------

    def _check_window(
        self,
        agent_id: str,
        window: str,
        window_start: dt.datetime,
        limit: int,
        request_id: str,
        tool: str,
        now: dt.datetime,
    ) -> Optional[GatewayError]:
        if limit <= 0:
            return None  # budget disabled by configuration
        new_count = self._increment(agent_id, window, window_start, limit)
        if new_count is None:
            retry_after = _retry_after_seconds(now, window_start, window)
            return make_error(
                "rate_limited",
                f"{tool}: rate limit exceeded ({window} budget); "
                f"retry after {retry_after}s",
                request_id,
                {"retry_after": retry_after, "tool": tool, "window": window},
            )
        return None

    def _increment(
        self,
        agent_id: str,
        window: str,
        window_start: dt.datetime,
        limit: int,
    ) -> Optional[int]:
        """Atomically increment a counter when under budget (issue #10).

        A single conditional ``UPDATE ... SET count = count + 1 ...
        WHERE count < limit ... RETURNING count``: the budget check and
        the increment happen in one statement, so concurrent sessions
        can never interleave a read-read-write-write lost update and
        admit more than ``limit`` callers. A rejected attempt never
        consumes budget.

        Row creation on the first attempt of a window is guarded by the
        ``uq_rate_counter`` unique constraint: the loser of a concurrent
        INSERT rolls back and retries the atomic UPDATE.
        """
        upd = (
            update(RateCounter)
            .where(
                RateCounter.agent_id == agent_id,
                RateCounter.window == window,
                RateCounter.window_start == window_start,
                RateCounter.count < limit,
            )
            .values(count=RateCounter.count + 1)
            .returning(RateCounter.count)
        )
        new_count = self.db.execute(upd).scalar_one_or_none()
        if new_count is not None:
            self.db.commit()
            return new_count
        # No row incremented: the counter row does not exist yet, or the
        # budget is already exhausted. Insert first (count=1); a
        # concurrent insert fires the unique constraint → roll back and
        # retry the atomic UPDATE, which now sees the existing row.
        self.db.add(
            RateCounter(
                agent_id=agent_id, window=window,
                window_start=window_start, count=1,
            )
        )
        try:
            self.db.flush()
        except IntegrityError:
            self.db.rollback()
            new_count = self.db.execute(upd).scalar_one_or_none()
            self.db.commit()
            return new_count  # None → budget exhausted
        self.db.commit()
        return 1

    def _prune(self) -> None:
        """Drop counter rows older than 48h (bounded table growth)."""
        cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=48)
        self.db.execute(delete(RateCounter).where(RateCounter.window_start < cutoff))
        self.db.commit()

    # -- introspection (tests / console) --------------------------------

    def count(
        self, agent_id: str, window: str, window_start: dt.datetime
    ) -> int:
        stmt = (
            select(RateCounter)
            .where(RateCounter.agent_id == agent_id)
            .where(RateCounter.window == window)
            .where(RateCounter.window_start == window_start)
        )
        row = self.db.execute(stmt).scalar_one_or_none()
        return row.count if row is not None else 0
