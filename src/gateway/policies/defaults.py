"""Default policy content (Python-canonical) + seeding.

The four preset families (work/personal separation, spending
thresholds, social-send approval, household boundaries) are seeded
through the live ontology preset machinery
(:func:`gateway.ontology.apply_preset`) — presets are the enforcement
source of truth (idempotent, material-classified versions).

``PAA10_RULES`` is the Python-canonical form of the PAA10-derived
default rules (mirroring ``policies/v1/paa10.rego`` rule-for-rule);
``seed_defaults`` saves them as a material-classified version after
the presets.

Decision-equivalence between this file and the Rego defaults is
enforced by tests/test_rego.py on representative inputs: the Rego
files are the versioned, immutable specification; this module is the
seed path.
"""

from __future__ import annotations

from typing import Any, Optional

from sqlalchemy.orm import Session

#: PAA10-derived default rules (mirrors v1/paa10.rego).
PAA10_RULES: list[dict[str, Any]] = [
    {
        "name": "default:paa10:destructive_calendar_delete",
        "effect": "require_approval",
        "rule_type": "standard",
        "tool": "calendar.delete",
        "conditions": {},
        "description": "PAA06/PAA10: destructive actions need step-up approval.",
    },
    {
        "name": "default:paa10:recovery_settings_write",
        "effect": "require_approval",
        "rule_type": "standard",
        "tool": "email.settings.write",
        "conditions": {},
        "description": (
            "PAA02: forwarding/filter changes can reroute account "
            "recovery; need approval."
        ),
    },
    {
        "name": "default:paa10:code_pr_open",
        "effect": "require_approval",
        "rule_type": "standard",
        "tool": "code.pr.open",
        "conditions": {},
        "description": (
            "PAA05/PAA06: opening a PR is commitment-adjacent; needs approval."
        ),
    },
    {
        "name": "default:paa10:work_email_read",
        "effect": "allow",
        "rule_type": "standard",
        "tool": "email.read",
        "purpose": "work",
        "conditions": {},
        "description": (
            "PAA03: purpose-bound read; a personal-purpose call never matches."
        ),
    },
    {
        "name": "default:paa10:spouse_calendar",
        "effect": "allow",
        "rule_type": "standard",
        "tool": "calendar.read",
        "household_role": "spouse",
        "conditions": {},
        "description": (
            "PAA08: household-role scoped; never matches another member's agent."
        ),
    },
    {
        "name": "default:paa10:weekly_status_notice",
        "effect": "allow",
        "rule_type": "notice",
        "tool": "email.send",
        "conditions": {
            "notice": {
                "audience": ["team@example.com"],
                "schedule": {"days": ["mon", "tue", "wed", "thu", "fri"]},
                "subject_pattern": "^Weekly status:",
                "body_pattern": "Status update for week \\d+",
                "max_body_length": 5000,
            }
        },
        "description": (
            "PAA07: the recurring status mail is a standing policy rule; "
            "one-off sends need their own approval."
        ),
    },
]


def seed_defaults(
    engine: Any,
    db: Session,
    owner_display_name: str = "Owner",
    member_display_names: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Seed the default policies: 4 presets + PAA10 rules.

    Applies the four ontology presets (each seeds its ontology
    entities and saves a material-classified policy version), then
    saves the PAA10-derived rules as a final material version.
    Idempotent (presets are; the PAA10 save replaces prior
    ``default:paa10:*`` rules).
    """
    from ..ontology import apply_preset

    members = list(member_display_names or [])
    versions: dict[str, Any] = {}
    for preset in (
        "work_personal_separation",
        "spending_thresholds",
        "social_send_approval",
        "household_boundaries",
    ):
        summary = apply_preset(
            preset,
            db=db,
            engine=engine,
            owner_display_name=owner_display_name,
            member_display_names=members,
        )
        versions[preset] = summary.get("policy_version")

    prefix = "default:paa10:"
    kept = [
        r for r in engine.version_rules_as_dicts()
        if not str(r.get("name", "")).startswith(prefix)
    ]
    paa10_version = engine.save_version(
        [*kept, *PAA10_RULES],
        change_note="default PAA10-derived policy rules (v1)",
        created_by="policy.defaults",
        material_change=True,
    )
    versions["paa10"] = paa10_version
    return {"versions": versions, "paa10_version": paa10_version}
