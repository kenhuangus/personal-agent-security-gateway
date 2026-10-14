"""Judge-backend reachability supervision (GH #31).

The judge cascade is built per pipeline call, so a backend instance
cannot accumulate health state itself. This module keeps a small
process-wide registry keyed by backend name: every cascade records a
success or a ``JudgeUnavailable`` failure, and when a backend has been
continuously unreachable for ``alert_after_s`` the registry logs one
CRITICAL readiness alert per outage (the deploy's log monitor keys on
it). Recovery logs at INFO and resets the alert latch.

Deliberately-disabled backends (``DisabledBackend``, name ``"none"``)
are never recorded — "off" is not an outage.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Any

log = logging.getLogger(__name__)

#: Backend names that mean "deliberately off", never an outage.
_SILENT_NAMES = frozenset({"none"})


@dataclass
class BackendHealth:
    """Reachability state for one named judge backend."""

    name: str
    consecutive_failures: int = 0
    first_failure_at: float | None = None  # monotonic, of the current streak
    last_failure_at: float | None = None  # monotonic
    last_success_at: float | None = None  # monotonic
    alerted: bool = False  # CRITICAL already logged for the current streak


_registry: dict[str, BackendHealth] = {}
_lock = threading.Lock()


def _get(name: str) -> BackendHealth:
    health = _registry.get(name)
    if health is None:
        health = _registry[name] = BackendHealth(name=name)
    return health


def record_failure(name: str, alert_after_s: float = 300.0) -> BackendHealth:
    """Record a ``JudgeUnavailable`` from *name*.

    When the current failure streak reaches ``alert_after_s`` seconds,
    logs one CRITICAL readiness alert (per streak). Returns the health
    record.
    """
    if name in _SILENT_NAMES:
        return BackendHealth(name=name)
    now = time.monotonic()
    with _lock:
        health = _get(name)
        if health.consecutive_failures == 0:
            health.first_failure_at = now
        health.consecutive_failures += 1
        health.last_failure_at = now
        if (
            not health.alerted
            and alert_after_s >= 0
            and health.first_failure_at is not None
            and now - health.first_failure_at >= alert_after_s
        ):
            health.alerted = True
            log.critical(
                "judge backend %r unreachable for %.1f minutes "
                "(%d consecutive failures) — judge hooks are failing "
                "closed; manipulation-detection and risk-scoring coverage "
                "is down",
                name,
                (now - health.first_failure_at) / 60.0,
                health.consecutive_failures,
            )
        return health


def record_success(name: str) -> BackendHealth:
    """Record a successful decide from *name*; resets the streak."""
    if name in _SILENT_NAMES:
        return BackendHealth(name=name)
    now = time.monotonic()
    with _lock:
        health = _get(name)
        if health.consecutive_failures:
            log.info(
                "judge backend %r recovered after %d consecutive failures",
                name,
                health.consecutive_failures,
            )
        health.consecutive_failures = 0
        health.first_failure_at = None
        health.last_success_at = now
        health.alerted = False
        return health


def health_snapshot() -> dict[str, dict[str, Any]]:
    """Point-in-time view of every tracked backend (console/health use)."""
    with _lock:
        return {
            name: {
                "consecutive_failures": h.consecutive_failures,
                "alerted": h.alerted,
                "last_failure_at": h.last_failure_at,
                "last_success_at": h.last_success_at,
            }
            for name, h in _registry.items()
        }


def reset() -> None:
    """Clear the registry. Test support only."""
    with _lock:
        _registry.clear()
