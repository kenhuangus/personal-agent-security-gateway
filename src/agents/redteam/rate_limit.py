"""Agent-side token buckets for the red-team runner (Pillar 2 §3.3).

``GATEWAY_REDATEAM_MAX_ATTEMPTS_HOUR`` (default 60) /
``GATEWAY_REDATEAM_MAX_ATTEMPTS_DAY`` (default 500): one token per
scenario ``execute()`` call. Exhaustion pauses the run (status
``rate_limited``, resumes next scheduled run). Gateway-side
per-agent limits apply independently — belt and suspenders.
"""

from __future__ import annotations

import datetime as dt


class TokenBucket:
    """Sliding-window token bucket (in-memory; the runner is one process)."""

    def __init__(self, max_per_hour: int, max_per_day: int) -> None:
        self.max_per_hour = max_per_hour
        self.max_per_day = max_per_day
        self._uses: list[dt.datetime] = []

    def _prune(self, now: dt.datetime) -> None:
        cutoff = now - dt.timedelta(days=1)
        self._uses = [t for t in self._uses if t >= cutoff]

    def consume(self, now: Optional[dt.datetime] = None) -> bool:
        """Take one token; False when the bucket is exhausted."""
        now = now or dt.datetime.now(dt.timezone.utc)
        self._prune(now)
        hour_uses = sum(1 for t in self._uses if t >= now - dt.timedelta(hours=1))
        if hour_uses >= self.max_per_hour or len(self._uses) >= self.max_per_day:
            return False
        self._uses.append(now)
        return True

    @property
    def used_today(self) -> int:
        self._prune(dt.datetime.now(dt.timezone.utc))
        return len(self._uses)
