#!/usr/bin/env python3
"""Seed the finance demo (Pillar 1 §10): the 4-act Chens demo.

Creates (idempotent — skips existing rows):
- agent/wealth-1: Ken's household finance agent (household_role "family").
- mnd_chen_wealth: the finance mandate (wealth-1's allowlist covers
  payment.* + the read tools it needs).
- One money rule for wealth-1: per_call_soft_cents $500,
  per_call_hard_cents $10,000, per_day $2,500, quorum 2 at/above
  $1,000 (quorum_min_cents), 60-minute denial cooldown, 30-day
  checkpoints.
- The allowlist: verified (IRS quarterly estimated tax, last-4 0000),
  pending (the fake "Acme Bookkeeping" vendor the spoofed email
  pushes), blocked (the old bookkeeper account, rotated after a
  phishing attempt).
- A second admin account (must-reset) so quorum approvals can be
  satisfied by two distinct logins.

The raw agent credential prints once (paste into the agent's env);
the second admin's password must be reset at first login.

Usage:
    PYTHONPATH=src GATEWAY_MONEY_ENABLED=1 python scripts/seed_finance_demo.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def seed_demo(databases, settings) -> dict:
    """Seed the finance demo data. Idempotent. Returns {"agent_secret": ...|None}."""
    from gateway.audit import AuditLog
    from gateway.db import Databases
    from gateway.identity import IdentityService
    from gateway.mandates import MandateService
    from gateway.models import AdminUser, Agent, Mandate
    from gateway.money.allowlist import (
        STATE_BLOCKED, STATE_PENDING, STATE_VERIFIED, AllowlistService,
    )
    from gateway.policy import PolicyEngine
    from sqlalchemy import select

    secret: str | None = None
    with databases.config.session() as db, databases.audit.session() as adb:
        ident = IdentityService(db)
        mandates = MandateService(db)
        audit = AuditLog(adb)

        agent = db.get(Agent, "agent_wealth_1")
        if agent is None:
            agent, _cid, secret = ident.register_agent(
                "agent_wealth_1", "internal", "agent/wealth-1", "family"
            )
            print("seed: registered agent_wealth_1 (agent/wealth-1)")
        else:
            print("seed: agent_wealth_1 exists — skipping registration")

        allowlist = [
            "payment.quote", "payment.initiate", "payment.status",
            "payment.cancel", "email.read", "email.search",
            "sandbox.event_receive",
            "calendar.read", "gateway.approval_status",
        ]
        existing = (
            db.execute(
                select(Mandate).where(
                    Mandate.agent_id == "agent_wealth_1",
                    Mandate.status == "active",
                )
            )
            .scalars()
            .all()
        )
        if not existing:
            mandates.create_mandate(
                "agent_wealth_1",
                "Household finance: pay the quarterly estimated tax, "
                "track household bills, and stage (never silently send) "
                "other payments. Every payment over $500 needs Ken's "
                "approval; payments at/above $1,000 need two approvers.",
                allowlist,
                created_by="admin",
                purpose_key="family_finance",
            )
            print("seed: mnd_chen_wealth mandate created")
        else:
            print("seed: mandate for agent_wealth_1 exists — skipping")

        # Money rule for wealth-1 (always MATERIAL).
        engine = PolicyEngine(db)
        money_block = {
            "per_call_hard_cents": 1_000_000,   # $10,000
            "per_call_soft_cents": 50_000,       # $500
            "per_day_cents": 250_000,            # $2,500
            "per_month_cents": 5_000_000,        # $50,000
            "max_payments_per_window": {"n": 3, "window_minutes": 60},
            "max_payments_per_day": 10,
            "max_new_counterparties_per_day": 2,
            "quorum": 2,
            "quorum_min_cents": 100_000,         # $1,000 → two approvers
            "cooldown_after_deny_minutes": 60,
        }
        from gateway.money.limits import validate_money_block

        validate_money_block(money_block)
        rules = engine.version_rules_as_dicts()
        have = any(
            (r.get("agent_id") == "agent_wealth_1"
             and (r.get("conditions") or {}).get("money"))
            for r in rules
        )
        if not have:
            rules.append({
                "name": "wealth-1 money rule (demo)",
                "rule_type": "standard",
                "effect": "allow",  # nominal; the ladder is authoritative
                "agent_id": "agent_wealth_1",
                "tool": "payment.*",
                "conditions": {"money": money_block},
                "description": "Finance demo: $500 soft / $10k hard, quorum 2 ≥ $1k",
            })
            version = engine.save_version(
                rules,
                change_note="Finance demo seed: wealth-1 money rule",
                created_by="admin_ken",
                material_change=True,
            )
            audit.append(
                agent_id="admin", tool="policy.save", decision="allowed",
                action="seed",
                redacted_args={"policy_version": version,
                               "note": "finance demo seed (Pillar 1)"},
            )
            print(f"seed: money rule saved (policy v{version}, material)")
        else:
            print("seed: money rule for wealth-1 exists — skipping")

        # Standard read rules: payment.quote / payment.status are
        # policy-gated reads (the money ladder only runs on initiate);
        # sandbox.event_receive is the MVP event-intake read.
        read_rules = [
            {"name": "wealth-1 payment.quote (demo)", "effect": "allow",
             "agent_id": "agent_wealth_1", "tool": "payment.quote",
             "description": "Finance demo: quotes are read-only"},
            {"name": "wealth-1 payment.status (demo)", "effect": "allow",
             "agent_id": "agent_wealth_1", "tool": "payment.status",
             "description": "Finance demo: status is read-only"},
            {"name": "wealth-1 event intake (demo)", "effect": "allow",
             "agent_id": "agent_wealth_1", "tool": "sandbox.event_receive",
             "description": "Finance demo: MVP event intake (sandbox verdict)"},
        ]
        rules = engine.version_rules_as_dicts()
        missing = [
            r for r in read_rules
            if not any(x.get("agent_id") == r["agent_id"] and x.get("tool") == r["tool"]
                       for x in rules)
        ]
        if missing:
            version = engine.save_version(
                rules + missing,
                change_note="Finance demo seed: payment read rules",
                created_by="admin_ken",
                material_change=False,
            )
            print(f"seed: payment read rules saved (policy v{version})")
        else:
            print("seed: payment read rules exist — skipping")

        # Counterparty allowlist.
        svc = AllowlistService(db)
        seeds = [
            ("ach:irs:xxxx0000", "0000", STATE_VERIFIED, "IRS quarterly estimated tax"),
            ("ach:acme-bookkeeping:xxxx1234", "1234", STATE_PENDING,
             "Acme Bookkeeping — invoice received by email, unverified"),
            ("ach:old-bookkeeper:xxxx5678", "5678", STATE_BLOCKED,
             "Old bookkeeper account — rotated after a phishing attempt"),
        ]
        for payee_key, last4, state, label in seeds:
            row = svc.lookup(None, payee_key)
            if row is None:
                row = svc.add(
                    payee_key=payee_key, label=label,
                    details_snapshot={"account_last4": last4},
                    notes=label,
                )
                row = svc.set_verification(
                    namespace_id=None, payee_key=payee_key,
                    verification_state=state, verified_by="admin_ken",
                )
                print(f"seed: allowlist {payee_key} → {state}")
            else:
                print(f"seed: allowlist {payee_key} exists — skipping")

        # Admins for quorum demos: admin_ken (the operator) and a
        # second admin (must-reset). Quorum 2 needs two distinct admin
        # accounts to exist.
        from gateway.console.admin_auth import hash_password

        for admin_id in ("admin_ken", "admin_maya"):
            admin = db.get(AdminUser, admin_id)
            if admin is None:
                db.add(AdminUser(
                    id=admin_id,
                    password_hash=hash_password("CHANGE-ME-AT-FIRST-LOGIN"),
                    totp_secret=None,
                ))
                db.commit()
                print(f"seed: admin '{admin_id}' created (must reset password)")
            else:
                print(f"seed: {admin_id} exists — skipping")
    return {"agent_secret": secret}


def main() -> int:
    from gateway.config import load_settings
    from gateway.db import Databases

    settings = load_settings()
    databases = Databases(settings.config_db_path, settings.audit_db_path)
    databases.create_all()

    result = seed_demo(databases, settings)
    secret = result["agent_secret"]
    if secret:
        print()
        print("=" * 70)
        print("AGENT CREDENTIAL — shown ONCE. Paste into the agent's env var.")
        print("=" * 70)
        print("  agent/wealth-1: set GATEWAY_AGENT_WEALTH_1_CREDENTIAL=")
        print(f"    {secret}")
        print("=" * 70)
    print("seed: finance demo ready")
    return 0


if __name__ == "__main__":
    sys.exit(main())
