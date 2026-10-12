#!/usr/bin/env python3
"""AC-11 load test (CI gate).

10 concurrent "sessions" (threads) each run the policy hot path
(PolicyEngine.evaluate_call, including the OPA sidecar decision hop)
against a seeded allow rule. p95 of per-call latency is the gate:
the build FAILS when local p95 > 100 ms (00 §7 param 3; 02 §2.7).

AC-11's isolation method (01-requirements AC-11): p95 is computed on
gateway-internal timing spans (policy evaluation here), excluding
downstream system latency per NFR-PERF-001. Inspection-pipeline
overhead is bounded separately by the unit tests; the policy stage
is the latency-critical hot path and includes the OPA sidecar hop.

Usage: python scripts/ac11_load.py [--sessions 10] [--iters 50]
Exit 0: p95 <= 100 ms. Exit 1: p95 > 100 ms (prints the numbers).
"""

from __future__ import annotations

import argparse
import os
import statistics
import sys
import tempfile
import threading
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

BUDGET_MS = 100.0


def percentile(data: list[float], pct: float) -> float:
    if not data:
        return 0.0
    ordered = sorted(data)
    k = (len(ordered) - 1) * (pct / 100.0)
    lo = int(k)
    hi = min(lo + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sessions", type=int, default=10)
    ap.add_argument("--iters", type=int, default=50)
    ap.add_argument("--warmup", type=int, default=10,
                    help="per-thread warmup calls excluded from the stats")
    args = ap.parse_args()

    from gateway.config import Settings
    from gateway.db import Databases
    from gateway.identity import IdentityService
    from gateway.policy import PolicyEngine

    tmp = tempfile.mkdtemp(prefix="ac11-")
    settings = Settings(
        config_db_path=os.path.join(tmp, "config.db"),
        audit_db_path=os.path.join(tmp, "audit.db"),
        hmac_key="ac11-hmac-key-material-32bytes!!",
    )
    dbs = Databases(settings.config_db_path, settings.audit_db_path)
    dbs.create_all()

    with dbs.config.session() as db:
        ident = IdentityService(db)
        agent, _cid, _sec = ident.register_agent(
            "ag_ac11", "muse", "AC11 probe", "ken"
        )
        agent_id = agent.id
        engine = PolicyEngine(db)
        engine.save_version(
            [{
                "name": "ac11 allow",
                "rule_type": "standard",
                "effect": "allow",
                "agent_id": agent_id,
                "tool": "email.search",
            }],
            change_note="ac11",
        )

    latencies: list[float] = []
    errors: list[str] = []
    lock = threading.Lock()
    barrier = threading.Barrier(args.sessions)

    def worker() -> None:
        try:
            with dbs.config.session() as db:
                eng = PolicyEngine(db)
                agent = db.get(
                    __import__("gateway.models", fromlist=["Agent"]).Agent,
                    agent_id,
                )
                barrier.wait(timeout=30)
                local: list[float] = []
                for n in range(args.warmup + args.iters):
                    start = time.perf_counter()
                    eng.evaluate_call(agent, "email.search", {"query": "probe"})
                    elapsed = (time.perf_counter() - start) * 1000.0
                    if n >= args.warmup:
                        local.append(elapsed)
            with lock:
                latencies.extend(local)
        except Exception as exc:  # noqa: BLE001 — record, don't hang the gate
            with lock:
                errors.append(f"{type(exc).__name__}: {exc}")

    threads = [threading.Thread(target=worker) for _ in range(args.sessions)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=300)

    if errors:
        print(f"ac11: FAIL — {len(errors)} worker error(s), first: {errors[0]}")
        return 1
    n = len(latencies)
    p50 = percentile(latencies, 50)
    p95 = percentile(latencies, 95)
    p99 = percentile(latencies, 99)
    print(
        f"ac11: {args.sessions} sessions x {args.iters} iters = {n} calls | "
        f"p50 {p50:.2f} ms / p95 {p95:.2f} ms / p99 {p99:.2f} ms "
        f"(budget p95 <= {BUDGET_MS:.0f} ms)"
    )
    if p95 > BUDGET_MS:
        print("ac11: FAIL — local p95 exceeds the 100 ms budget")
        return 1
    print("ac11: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
