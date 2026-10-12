# Default policy: PAA10-derived controls.
#
# Package: data.gateway.defaults.paa10
# Standing rules derived from the OWASP Top 10 for Personal AI Agents
# mapping (docs/05-paa10-mapping.md). These complement the four preset
# families with controls that are policy-shaped (not process-shaped):
#
# - PAA02 (account/recovery takeover): recovery-affecting settings
#   changes need approval.
# - PAA05 (counterparty deception): commitment-adjacent actions need
#   approval (the per-payee new/changed assessment itself stays
#   Python-side in the sensitivity escalator).
# - PAA06 (unauthorized spending/commitments): destructive actions
#   need approval.
# - PAA07 (unauthorized social representation): template-bound notice
#   rule for the recurring status mail.
# - PAA03 (private-life context exposure): purpose-bound reads.
# - PAA08 (household/bystander consent): household-role scoped access.
#
# Versioned and immutable: v1 frozen expression of the default.

package gateway.defaults.paa10

rules := [
	{
		"id": "default:paa10:destructive_calendar_delete",
		"name": "Calendar deletes need approval",
		"effect": "require_approval",
		"rule_type": "standard",
		"agent_id": null,
		"tool": "calendar.delete",
		"household_role": null,
		"purpose": null,
		"conditions": {},
		"description": "PAA06/PAA10: destructive actions need step-up approval.",
	},
	{
		"id": "default:paa10:recovery_settings_write",
		"name": "Recovery-affecting settings need approval",
		"effect": "require_approval",
		"rule_type": "standard",
		"agent_id": null,
		"tool": "email.settings.write",
		"household_role": null,
		"purpose": null,
		"conditions": {},
		"description": "PAA02: forwarding/filter changes can reroute account recovery; need approval.",
	},
	{
		"id": "default:paa10:code_pr_open",
		"name": "PR opens need approval",
		"effect": "require_approval",
		"rule_type": "standard",
		"agent_id": null,
		"tool": "code.pr.open",
		"household_role": null,
		"purpose": null,
		"conditions": {},
		"description": "PAA05/PAA06: opening a PR is commitment-adjacent; needs approval.",
	},
	{
		"id": "default:paa10:work_email_read",
		"name": "Work email read (purpose-bound)",
		"effect": "allow",
		"rule_type": "standard",
		"agent_id": null,
		"tool": "email.read",
		"household_role": null,
		"purpose": "work",
		"conditions": {},
		"description": "PAA03: purpose-bound read; a personal-purpose call never matches.",
	},
	{
		"id": "default:paa10:spouse_calendar",
		"name": "Spouse calendar (role-scoped)",
		"effect": "allow",
		"rule_type": "standard",
		"agent_id": null,
		"tool": "calendar.read",
		"household_role": "spouse",
		"purpose": null,
		"conditions": {},
		"description": "PAA08: household-role scoped; never matches another member's agent.",
	},
	{
		"id": "default:paa10:weekly_status_notice",
		"name": "Weekly status notice (template-bound)",
		"effect": "allow",
		"rule_type": "notice",
		"agent_id": null,
		"tool": "email.send",
		"household_role": null,
		"purpose": null,
		"conditions": {"notice": {
			"audience": ["team@example.com"],
			"schedule": {"days": ["mon", "tue", "wed", "thu", "fri"]},
			"subject_pattern": "^Weekly status:",
			"body_pattern": "Status update for week \\d+",
			"max_body_length": 5000,
		}},
		"description": "PAA07: the recurring status mail is a standing policy rule; one-off sends need their own approval.",
	},
]
