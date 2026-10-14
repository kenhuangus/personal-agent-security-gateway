#!/usr/bin/env python3
"""Pin the policy-bundle fingerprint (GH #17).

Computes the content fingerprint of ``src/gateway/policies/v1/`` and
writes it to ``src/gateway/policies/v1/bundle_info.json``. OPA serves
JSON data files as data documents, so the deployed (external) OPA
exposes the fingerprint at ``data.gateway.bundle.info`` — the
gateway's OpaClient fetches it in GATEWAY_OPA_URL mode and refuses to
serve decisions on mismatch (fail closed).

The fingerprint covers every file in policies/v1 EXCEPT
bundle_info.json itself (which carries the fingerprint). Re-run this
script whenever the bundle changes and commit the result.

Usage:
    python3 scripts/pin_bundle_fingerprint.py [--check]
    --check: exit 1 when the committed fingerprint is stale (CI gate).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from gateway.opa_client import bundle_fingerprint, default_policies_dir  # noqa: E402

BUNDLE_INFO_NAME = "bundle_info.json"


def write_bundle_info(policies_dir: Path) -> str:
    fingerprint = bundle_fingerprint(policies_dir)
    doc = {
        "gateway": {
            "bundle": {
                "info": {
                    "name": "personal-agent-security-gateway policy bundle",
                    "policies_dir": "v1",
                    "fingerprint": fingerprint,
                    "pinned_by": "scripts/pin_bundle_fingerprint.py "
                                 "(re-run after any bundle change)",
                }
            }
        }
    }
    target = policies_dir / BUNDLE_INFO_NAME
    target.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return fingerprint


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if the committed fingerprint is stale")
    args = ap.parse_args()
    policies_dir = default_policies_dir()
    if args.check:
        info_path = policies_dir / BUNDLE_INFO_NAME
        if not info_path.exists():
            print(f"missing {info_path}")
            return 1
        committed = json.loads(info_path.read_text(encoding="utf-8"))
        committed_fp = committed["gateway"]["bundle"]["info"]["fingerprint"]
        current = bundle_fingerprint(policies_dir)
        if committed_fp != current:
            print(f"stale bundle fingerprint: committed {committed_fp[:16]}… "
                  f"!= current {current[:16]}…; re-run scripts/pin_bundle_fingerprint.py")
            return 1
        print(f"bundle fingerprint current ({current[:16]}…)")
        return 0
    fingerprint = write_bundle_info(policies_dir)
    print(f"pinned bundle fingerprint {fingerprint} -> {policies_dir / BUNDLE_INFO_NAME}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
