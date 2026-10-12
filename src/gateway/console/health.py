"""Connector health checks (00 §7 param 16; FR-038).

Credential-valid + API-reachable per connector, every 5 minutes via a
daemon background thread. The console renders a banner on any failure.

State is in-process (MVP single process, NFR-REL-001). ``run_all()``
is callable on demand (console "Run checks now" action, tests).
"""

from __future__ import annotations

import datetime as dt
import threading
import time
from typing import Any, Optional

CHECK_INTERVAL_SECONDS = 5 * 60  # 00 §7 param 16


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class HealthMonitor:
    """Runs connector health checks and remembers the last result."""

    def __init__(self, interval_seconds: int = CHECK_INTERVAL_SECONDS) -> None:
        self.interval_seconds = interval_seconds
        self._connectors: list[Any] = []
        self._lock = threading.Lock()
        # name -> {healthy, credential_valid, api_reachable, detail, checked_at}
        self._status: dict[str, dict[str, Any]] = {}
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def register(self, connector: Any) -> None:
        with self._lock:
            self._connectors.append(connector)

    def run_all(self) -> dict[str, dict[str, Any]]:
        """Run every connector's health check now; returns the snapshot."""
        with self._lock:
            connectors = list(self._connectors)
        out: dict[str, dict[str, Any]] = {}
        for connector in connectors:
            name = getattr(connector, "name", None) or type(connector).__name__
            try:
                status = connector.health_check()
                out[name] = {
                    "healthy": bool(status.healthy),
                    "credential_valid": bool(status.credential_valid),
                    "api_reachable": bool(status.api_reachable),
                    "detail": status.detail,
                    "checked_at": _utcnow(),
                }
            except Exception as exc:  # noqa: BLE001 — a failed probe is data
                out[name] = {
                    "healthy": False,
                    "credential_valid": False,
                    "api_reachable": False,
                    "detail": f"health check raised: {exc}",
                    "checked_at": _utcnow(),
                }
        with self._lock:
            self._status.update(out)
        return out

    def snapshot(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            return dict(self._status)

    def any_unhealthy(self) -> bool:
        with self._lock:
            return any(not s["healthy"] for s in self._status.values())

    def start_background(self) -> None:
        if self._thread is not None:
            return
        self._stop.clear()

        def _loop() -> None:
            while not self._stop.wait(self.interval_seconds):
                try:
                    self.run_all()
                except Exception:  # noqa: BLE001 — keep the loop alive
                    pass

        self._thread = threading.Thread(
            target=_loop, name="connector-health", daemon=True
        )
        self._thread.start()

    def stop_background(self) -> None:
        self._stop.set()
        self._thread = None
