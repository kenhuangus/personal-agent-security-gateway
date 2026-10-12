#!/usr/bin/env python3
"""SDK-floor assertion (FR-005 / AC-10, GHSA-qx49-fqc8-xw99).

Fails the build when the installed ``mcp`` package is below the
fixed releases (1.30.0 / 2.2.0 lineage). The pre-fix versions carry
the OAuth account-takeover flaw (malicious server could exfiltrate
client secrets, auth codes, and PKCE verifiers).

Usage: python scripts/check_sdk_floor.py
Exit 0: floor satisfied. Exit 1: below the floor (or mcp missing).
"""

from __future__ import annotations

import sys

FLOORS = {1: (1, 30, 0), 2: (2, 2, 0)}


def _parse(version: str) -> tuple[int, ...]:
    parts = []
    for piece in version.split("."):
        digits = "".join(c for c in piece if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def main() -> int:
    try:
        from importlib.metadata import version as pkg_version

        installed = pkg_version("mcp")
    except Exception:  # noqa: BLE001
        print("check_sdk_floor: FAIL — the 'mcp' package is not installed")
        return 1
    parsed = _parse(installed)
    major = parsed[0] if parsed else 0
    floor = FLOORS.get(major)
    if floor is None:
        print(
            f"check_sdk_floor: FAIL — mcp {installed} is outside the known "
            f"1.x/2.x lineages (floors: 1.30.0, 2.2.0)"
        )
        return 1
    if parsed < floor:
        want = ".".join(map(str, floor))
        print(
            f"check_sdk_floor: FAIL — mcp {installed} is below the floor "
            f"{want} (GHSA-qx49-fqc8-xw99)"
        )
        return 1
    print(f"check_sdk_floor: PASS — mcp {installed} >= {'.'.join(map(str, floor))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
