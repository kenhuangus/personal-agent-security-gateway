#!/usr/bin/env python3
"""CVE scan gate (AC-10).

Runs ``pip-audit`` over the installed environment using the
CycloneDX JSON format (which carries per-vulnerability severity
ratings from OSV) and FAILS the build when any HIGH or CRITICAL
vulnerability is reported. This is the AC-10 "no HIGH+ CVEs in the
MCP path" gate; medium/low findings are printed as warnings and do
not fail the build.

Usage: python scripts/check_cve.py
Exit 0: no HIGH+ CVEs (warnings may be printed).
Exit 1: HIGH/CRITICAL CVE(s) found (lists them).
Exit 2: the scan itself could not run (e.g. no network for the OSV
vulnerability database) — reported plainly.
"""

from __future__ import annotations

import json
import subprocess
import sys

BLOCKING = {"HIGH", "CRITICAL"}


def main() -> int:
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pip_audit", "--format=cyclonedx-json",
             "--desc=off"],
            capture_output=True, text=True, timeout=600,
        )
    except FileNotFoundError:
        print("check_cve: pip-audit is not installed (pip install pip-audit)")
        return 2
    except subprocess.TimeoutExpired:
        print("check_cve: pip-audit timed out (no network for the OSV DB?)")
        return 2
    if proc.returncode not in (0, 1):
        print("check_cve: pip-audit failed to run:")
        print(proc.stderr[-2000:])
        return 2
    # pip-audit prints a human line before the JSON on stdout; the JSON
    # document starts at the first "{".
    out = proc.stdout
    start = out.find("{")
    if start < 0:
        print("check_cve: could not find JSON in pip-audit output")
        return 2
    try:
        bom = json.loads(out[start:])
    except json.JSONDecodeError:
        print("check_cve: could not parse pip-audit CycloneDX output")
        return 2
    blocking: list[dict] = []
    warnings: list[dict] = []
    for vuln in bom.get("vulnerabilities", []) or []:
        severities = {
            str(r.get("severity", "")).upper()
            for r in (vuln.get("ratings") or [])
            if r.get("severity")
        }
        affects = [
            a.get("ref", "?")
            for a in (vuln.get("affects") or [])
        ]
        entry = {
            "id": vuln.get("id"),
            "severities": sorted(severities) or ["UNKNOWN"],
            "affects": affects,
        }
        if severities & BLOCKING:
            blocking.append(entry)
        else:
            warnings.append(entry)
    for w in warnings:
        print(f"check_cve: warning — {w['id']} {w['severities']} on {w['affects']}")
    if blocking:
        print(f"check_cve: FAIL — {len(blocking)} HIGH/CRITICAL CVE(s):")
        for b in blocking:
            print(f"  {b['id']} {b['severities']} on {b['affects']}")
        return 1
    print("check_cve: PASS — no HIGH+ CVEs reported by pip-audit.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
