"""Seed the security agents (Pillar 2 §2.2): ``python -m agents.seed``.

Idempotent — skips existing rows. Steps:
1. Registers the four agents via ``IdentityService.register_agent``
   (prints each raw secret once with "paste into
   ``GATEWAY_AGENT_<NAME>_CREDENTIAL``" instructions; never stored).
2. Creates one mandate per agent via ``MandateService.create_mandate``
   with the §2.1 allowlists, purpose text stating the non-goals, and
   ``purpose_key="security"``. Each creation passes through
   ``validate_security_mandate`` — the seed fails closed on violation.
3. Creates ``agent_schedules`` rows with ``enabled=False``
   (default-off: the operator enables each schedule in the console).
4. Seeds policy allow rules for the four agents' tools (material
   policy change, audit-logged, operator-visible in the Policies page).

Stealth: mandate purpose text refers to the candidate OWASP project
only as "candidate OWASP project".
"""

from __future__ import annotations

import sys

# ---------------------------------------------------------------------
# Seed allowlists (Pillar 2 §2.1). Narrow on purpose: the red-team
# agent additionally gets payment.initiate so RT-04 probes the real
# money pack (counterparty control); code.pr.open is deliberately
# excluded (RT-06 probes it as out-of-mandate).
# ---------------------------------------------------------------------

NON_GOALS = (
    "Security agent for the candidate OWASP project controls. "
    "Observes, drafts, and escalates; never pauses agents, blocks "
    "payees, revokes credentials, changes policy, or engages global stop."
)

SEED_ALLOWLISTS: dict[str, list[str]] = {
    "agent_redteam": [
        "audit.search",
        "policy.inspect",
        "sandbox.echo",
        "sandbox.payment_initiate",
        "sandbox.event_receive",
        "payment.initiate",  # RT-04 probes the money pack directly
        "codehost.issue_open",
        "gateway.approval_status",
    ],
    "agent_sentinel": [
        "audit.search",
        "gateway.approval_status",
    ],
    "agent_policy_assistant": [
        "policy.inspect",
        "policy.dry_run",
        "code.file.read",
        "code.pr.open",
        "gateway.approval_status",
    ],
    "agent_incident": [
        "audit.search",
        "approval.read",
        "mandate.read",
        "incident.write",
        "gateway.approval_status",
    ],
}

AGENT_META: dict[str, tuple[str, str]] = {
    # agent_id: (display_name, description)
    "agent_redteam": ("agent/redteam", "Scheduled attack-scenario prober. " + NON_GOALS),
    "agent_sentinel": ("agent/sentinel", "Continuous audit-pattern watcher. " + NON_GOALS),
    "agent_policy_assistant": (
        "agent/policy-assistant", "On-demand policy drafter. " + NON_GOALS
    ),
    "agent_incident": (
        "agent/incident", "On-demand incident timeline builder. " + NON_GOALS
    ),
}

#: agent_id → (credential env var, schedule cron, schedule tz).
AGENT_SCHEDULES: dict[str, tuple[str, str, str]] = {
    "agent_redteam": ("GATEWAY_AGENT_REDATEAM_CREDENTIAL", "0 2 * * *", "America/New_York"),
    "agent_sentinel": ("GATEWAY_AGENT_SENTINEL_CREDENTIAL", "interval", "UTC"),
    "agent_policy_assistant": ("GATEWAY_AGENT_POLICY_ASSISTANT_CREDENTIAL", "", ""),
    "agent_incident": ("GATEWAY_AGENT_INCIDENT_CREDENTIAL", "", ""),
}

#: Tools the seed policy allows outright (household_role="security"
#: scoped — the hard restriction for sandbox.*). codehost.issue_open
#: and sandbox.payment_initiate are require_approval (sensitive-gated,
#: approval-per-issue is the default).
_ALLOW_TOOLS = {
    "agent_redteam": ["audit.search", "policy.inspect", "sandbox.echo",
                      "sandbox.event_receive", "gateway.approval_status"],
    "agent_sentinel": ["audit.search", "gateway.approval_status"],
    "agent_policy_assistant": ["policy.inspect", "code.file.read",
                               "gateway.approval_status"],
    "agent_incident": ["audit.search", "gateway.approval_status"],
}
_ASK_TOOLS = {
    "agent_redteam": ["sandbox.payment_initiate", "codehost.issue_open"],
    "agent_policy_assistant": ["code.pr.open"],
}


def main() -> int:
    from gateway.audit import AuditLog
    from gateway.config import load_settings
    from gateway.db import Databases
    from gateway.identity import IdentityService
    from gateway.mandates import MandateService
    from gateway.models import Agent, AgentSchedule, Mandate
    from gateway.policy import PolicyEngine
    from sqlalchemy import select

    from .mandates import validate_security_mandate

    settings = load_settings()
    databases = Databases(settings.config_db_path, settings.audit_db_path)
    databases.create_all()

    with databases.config.session() as db, databases.audit.session() as adb:
        ident = IdentityService(db)
        mandates = MandateService(db)
        audit = AuditLog(adb)
        secrets_issued: list[tuple[str, str]] = []

        for agent_id, (display_name, purpose) in AGENT_META.items():
            agent = db.get(Agent, agent_id)
            if agent is None:
                agent, _cid, secret = ident.register_agent(
                    agent_id, "internal", display_name, "security"
                )
                secrets_issued.append((agent_id, secret))
                print(f"seed: registered {agent_id} ({display_name})")
            else:
                print(f"seed: agent {agent_id} exists — skipping registration")

            allowlist = SEED_ALLOWLISTS[agent_id]
            # The seed fails closed on violation (defense in depth).
            validate_security_mandate(allowlist)

            existing = (
                db.execute(
                    select(Mandate).where(
                        Mandate.agent_id == agent_id, Mandate.status == "active"
                    )
                )
                .scalars()
                .all()
            )
            if not existing:
                mandates.create_mandate(
                    agent_id, purpose, allowlist,
                    created_by="admin", purpose_key="security",
                )
                print(f"seed: mandate created for {agent_id}")
            else:
                print(f"seed: mandate for {agent_id} exists — skipping")

            schedule = db.get(AgentSchedule, agent_id)
            if schedule is None:
                _cred_var, cron_expr, tz = AGENT_SCHEDULES[agent_id]
                interval = None
                if cron_expr == "interval":
                    interval = int(settings.sentinel_interval_s)
                    cron_expr = ""
                db.add(
                    AgentSchedule(
                        agent_id=agent_id, enabled=False,
                        cron_expr=cron_expr, timezone=tz or "UTC",
                        interval_seconds=interval,
                        config={
                            "scenarios": ["RT-01", "RT-02", "RT-03", "RT-04",
                                          "RT-05", "RT-06", "RT-07"],
                            "severity_threshold": settings.redteam_issue_threshold,
                            "daily_issue_cap": settings.redteam_daily_issue_cap,
                        } if agent_id == "agent_redteam" else {},
                    )
                )
                db.commit()
                print(f"seed: schedule created for {agent_id} (enabled=False)")
            else:
                print(f"seed: schedule for {agent_id} exists — skipping")

        # Policy rules (material change, audit-logged).
        engine = PolicyEngine(db)
        rules: list[dict] = []
        for agent_id, tools in _ALLOW_TOOLS.items():
            for tool in tools:
                rules.append({
                    "name": f"security agent allow: {agent_id} {tool}",
                    "effect": "allow", "agent_id": agent_id, "tool": tool,
                    "household_role": "security",
                    "description": "Pillar 2 seed: least-privilege read/target tools",
                })
        for agent_id, tools in _ASK_TOOLS.items():
            for tool in tools:
                rules.append({
                    "name": f"security agent ask: {agent_id} {tool}",
                    "effect": "require_approval", "agent_id": agent_id, "tool": tool,
                    "household_role": "security",
                    "description": (
                        "Pillar 2 seed: sensitive-gated (approval-per-issue default)"
                    ),
                })
        # Merge with the CURRENT version's rules (the seed is additive;
        # it never wipes the operator's policy).
        current = engine.version_rules_as_dicts()
        have = {(r.get("agent_id"), r.get("tool"), r.get("effect")) for r in current}
        new_rules = [
            r for r in rules
            if (r["agent_id"], r["tool"], r["effect"]) not in have
        ]
        if new_rules:
            version = engine.save_version(
                current + new_rules,
                change_note="Pillar 2 seed: security-agent tool allow/ask rules",
                created_by="admin",
            )
            audit.append(
                agent_id="admin", tool="policy.save", decision="allowed",
                action="seed",
                redacted_args={
                    "policy_version": version,
                    "rules_added": len(new_rules),
                    "note": "security-agent seed (Pillar 2)",
                },
            )
            print(f"seed: policy v{version} saved ({len(new_rules)} security-agent rules)")
        else:
            print("seed: security-agent policy rules already present — skipping")

        if secrets_issued:
            print()
            print("=" * 70)
            print("AGENT CREDENTIALS — shown ONCE. Paste each into its env var")
            print("on the agents-runner host. They are NEVER stored by the seed.")
            print("=" * 70)
            for agent_id, secret in secrets_issued:
                var, _cron, _tz = AGENT_SCHEDULES[agent_id]
                print(f"  {agent_id}: set {var}=<the secret below>")
                print(f"    {secret}")
            print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
