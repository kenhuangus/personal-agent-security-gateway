#!/usr/bin/env python3
"""Seed the one-command demo: agent identity, mandates, policy rules.

Idempotent: re-running with an existing demo agent is a no-op (exit 0).
Runs inside the gateway container (``docker compose exec gateway
python scripts/seed_demo.py``) or locally from the repo root.

What it creates:
1. Demo agent ``demo-agent`` (platform ``meta-muse``, household role
   ``owner``) with its ONE OAuth credential (Fix A). The raw
   client_id/client_secret are written to
   ``<config-db-dir>/demo-credentials.env`` (mode 0600) — shown once,
   never stored.
2. The default read-only standing mandate (PAA01) plus a demo mandate
   covering ``demo.read`` / ``demo.write`` / ``gateway.*``.
3. Policy version 1: an explicit allow rule for
   (demo-agent, demo.read). ``demo.write`` is deliberately left
   uncovered so it hits the pinned default-deny.
4. OPA bundle check: waits for OPA readiness, then self-checks both
   decisions through the real PolicyEngine (demo.read -> allow,
   demo.write -> deny) before reporting success.

Needs OPA reachable: in compose ``GATEWAY_OPA_URL=http://opa:8181`` is
set and the seed waits for it; locally it uses the vendored sidecar
binary (``scripts/verify_opa.sh`` checks the pin).
"""

from __future__ import annotations

import os
import shlex
import sys
import time
from pathlib import Path


DEMO_AGENT_ID = "demo-agent"


def _die(msg: str) -> None:
    print(f"seed_demo: FATAL: {msg}", file=sys.stderr)
    sys.exit(1)


def main() -> int:
    from gateway.config import load_settings
    from gateway.db import Databases
    from gateway.identity import IdentityService
    from gateway.mandates import MandateService
    from gateway.models import Agent
    from gateway.opa_client import OpaClient, OpaUnavailable
    from gateway.policy import PolicyEngine

    settings = load_settings()
    dbs = Databases(settings.config_db_path, settings.audit_db_path)
    dbs.create_all()

    # 1. OPA readiness (bundle check): the policy engine is stateless —
    # every input document carries the rules — so "bundle loaded" means
    # the OPA server is up and serving decisions.
    client = OpaClient()
    mode = f"external {client.external_url}" if client._external else "sidecar"
    last_err: Exception | None = None
    for attempt in range(1, 4):
        try:
            client.ensure_running()
            last_err = None
            break
        except OpaUnavailable as exc:
            last_err = exc
            print(
                f"seed_demo: OPA not ready ({mode}), attempt {attempt}/3: {exc}",
                file=sys.stderr,
            )
            time.sleep(5)
    if last_err is not None:
        _die(f"OPA unreachable ({mode}): {last_err}")
    print(f"seed_demo: OPA ready ({mode})")

    with dbs.config.session() as db:
        identity = IdentityService(db)
        existing = db.get(Agent, DEMO_AGENT_ID)
        if existing is not None:
            print(f"seed_demo: agent {DEMO_AGENT_ID!r} already exists — nothing to do")
            return 0

        # 2. Demo agent identity (Fix A: exactly one credential, OAuth primary).
        agent, client_id, client_secret = identity.register_agent(
            DEMO_AGENT_ID, "meta-muse", "Demo Agent", "owner"
        )
        print(f"seed_demo: registered agent {DEMO_AGENT_ID!r} (oauth credential issued)")

        # 3. Standing mandates (PAA01): the default read-only mandate at
        # registration, plus a demo-scoped mandate for the demo tools.
        mandates = MandateService(db)
        mandates.create_default_mandate(agent)
        mandates.create_mandate(
            agent.id,
            "Demo mandate: explore the gateway's allow/deny policy decisions",
            ["demo.read", "demo.write", "gateway.*"],
            created_by="seed_demo",
        )
        print("seed_demo: mandates created (default read-only + demo scope)")

        # 4. Policy version 1: explicit allow for demo.read; demo.write
        # intentionally uncovered -> pinned default-deny.
        engine = PolicyEngine(db)
        version = engine.save_version(
            [
                {
                    "name": "demo: allow demo.read for the demo agent",
                    "effect": "allow",
                    "agent_id": DEMO_AGENT_ID,
                    "tool": "demo.read",
                },
            ],
            change_note="demo seed: allow demo.read; demo.write left to default-deny",
            created_by="seed_demo",
        )
        print(f"seed_demo: policy version {version} saved")

        # 5. Self-check through the real engine: one ALLOW, one DENY.
        allow_res = engine.evaluate_call(agent, "demo.read", {}, version)
        deny_res = engine.evaluate_call(agent, "demo.write", {}, version)
        if allow_res.decision != "allow":
            _die(f"self-check failed: demo.read -> {allow_res.decision} (want allow)")
        if deny_res.decision != "deny":
            _die(f"self-check failed: demo.write -> {deny_res.decision} (want deny)")
        print(
            "seed_demo: self-check OK "
            f"(demo.read -> allow via {allow_res.matched_rule_id!r}; "
            f"demo.write -> deny via {deny_res.matched_rule_id!r})"
        )

        # 6. Credentials file (0600), next to the config DB. The raw
        # secret is shown once here and never persisted elsewhere.
        creds_path = Path(settings.config_db_path).parent / "demo-credentials.env"
        creds_path.write_text(
            "DEMO_AGENT_ID="
            + shlex.quote(DEMO_AGENT_ID)
            + "\nDEMO_CLIENT_ID="
            + shlex.quote(client_id)
            + "\nDEMO_CLIENT_SECRET="
            + shlex.quote(client_secret)
            + "\n"
        )
        os.chmod(creds_path, 0o600)
        print(f"seed_demo: credentials written to {creds_path} (0600)")

    print("seed_demo: SEED_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
