"""In-memory latency instrumentation for the AC-11 story (hackathon demo).

A small, thread-safe ring buffer records per-stage latency spans:

- ``policy``: the OPA ``decide`` call (recorded in ``policy.py`` around
  the sidecar request; label = the decision effect —
  ``allow`` / ``deny`` / ``require_approval``, or the fail-closed
  marker ``opa_unavailable`` / ``opa_error``).
- ``inspection``: the output-inspection stage (recorded in
  ``pipeline.py`` from the stage's existing timing span — no second
  timer; label = the stage outcome, ``ok`` or the halting error code).
- ``judge``: the advisory judge cascade (recorded in
  ``judge/cascade.py`` reusing ``CascadeResult.latency_ms`` — no
  second timer; label = the backend path, e.g. ``kev`` or
  ``kev|glimmer:escalated``). Nothing is recorded when the judge is
  disabled (the cascade is never called).

The buffer is bounded (``collections.deque`` with ``maxlen``) and the
recording cost is a couple of ``perf_counter``/``time`` calls plus a
lock acquisition — negligible against the 100 ms AC-11 budget. All
numbers surfaced to the console are computed from the buffer at read
time (never hard-coded); an empty buffer is an honest "no data yet".
"""

from __future__ import annotations

import collections
import math
import threading
import time
from dataclasses import dataclass
from typing import Optional

#: AC-11 per-stage latency budget (ms) the console judges stages against.
AC11_BUDGET_MS = 100.0

#: Stages recorded by the gateway. Unknown stage names are accepted
#: (the buffer is keyed dynamically) but these are the three the
#: pipeline instruments.
STAGES: tuple[str, ...] = ("policy", "inspection", "judge")

#: Per-stage sample cap. ~1000 samples per stage of small dataclasses
#: is a bounded, negligible footprint.
_MAX_SAMPLES_PER_STAGE = 1000


@dataclass(frozen=True)
class LatencySpan:
    """One measured span: (stage, latency_ms, timestamp, label).

    ``label`` is a decision/effect label (e.g. the policy effect, the
    inspection outcome, or the judge backend path) so the console can
    show what the slow spans were doing — never agent input or secret
    material.
    """

    stage: str
    latency_ms: float
    timestamp: float  # time.time() — wall clock, for "last sample" display
    label: str = ""


class LatencyRecorder:
    """Bounded, thread-safe ring buffer of :class:`LatencySpan`.

    The server is multi-threaded; every mutation takes the lock.
    Statistics are nearest-rank percentiles over the recorded samples
    of a stage (p50 / p95 / max / count).
    """

    def __init__(self, maxlen: int = _MAX_SAMPLES_PER_STAGE) -> None:
        self._maxlen = maxlen
        self._lock = threading.Lock()
        self._spans: dict[str, collections.deque[LatencySpan]] = {}

    def record(
        self, stage: str, latency_ms: float, label: str = ""
    ) -> LatencySpan:
        """Append one span. Cheap: two time calls + a lock acquisition."""
        span = LatencySpan(
            stage=stage,
            latency_ms=float(latency_ms),
            timestamp=time.time(),
            label=label,
        )
        with self._lock:
            buf = self._spans.get(stage)
            if buf is None:
                buf = self._spans[stage] = collections.deque(maxlen=self._maxlen)
            buf.append(span)
        return span

    def clear(self) -> None:
        """Drop all spans (tests; the console demo starts from real traffic)."""
        with self._lock:
            self._spans.clear()

    def count(self, stage: str) -> int:
        with self._lock:
            buf = self._spans.get(stage)
            return len(buf) if buf is not None else 0

    def _samples(self, stage: str) -> list[float]:
        with self._lock:
            buf = self._spans.get(stage)
            return [s.latency_ms for s in buf] if buf is not None else []

    @staticmethod
    def _percentile(sorted_values: list[float], pct: float) -> float:
        """Nearest-rank percentile: rank = ceil(p/100 * n), 1-indexed."""
        n = len(sorted_values)
        if n == 0:
            raise ValueError("no samples")
        rank = min(n, max(1, math.ceil((pct / 100.0) * n)))
        return sorted_values[rank - 1]

    def stats(self, stage: str) -> Optional[dict[str, float]]:
        """p50 / p95 / max / count for a stage, or None when empty."""
        samples = self._samples(stage)
        if not samples:
            return None
        ordered = sorted(samples)
        return {
            "p50": self._percentile(ordered, 50),
            "p95": self._percentile(ordered, 95),
            "max": ordered[-1],
            "count": len(ordered),
        }

    def stats_all(self) -> dict[str, dict[str, float]]:
        """Stats for every stage that has samples (empty dict = no data)."""
        with self._lock:
            stages = list(self._spans.keys())
        out: dict[str, dict[str, float]] = {}
        for stage in stages:
            s = self.stats(stage)
            if s is not None:
                out[stage] = s
        return out

    def labels(self, stage: str) -> dict[str, int]:
        """Label histogram for a stage (what the samples were doing)."""
        with self._lock:
            buf = self._spans.get(stage)
            hist: dict[str, int] = {}
            if buf is None:
                return hist
            for s in buf:
                hist[s.label] = hist.get(s.label, 0) + 1
            return hist


#: The process-wide recorder. The pipeline stages, the OPA path, and
#: the judge cascade all record here; the console reads here.
recorder = LatencyRecorder()


def record(stage: str, latency_ms: float, label: str = "") -> LatencySpan:
    """Record one span on the process-wide recorder."""
    return recorder.record(stage, latency_ms, label=label)
