# Default policy: spending thresholds.
#
# Package: data.gateway.defaults.spending
# Mirrors the `spending_thresholds` ontology preset: every payment.*
# call requires step-up approval, and personal-purpose shopping is
# allowed by rule but escalated to approval by the spend guard
# (PAA06 — unauthorized spending).
#
# Versioned and immutable: v1 frozen expression of the default.

package gateway.defaults.spending

rules := [
	{
		"id": "default:spending:payments",
		"name": "Payments need approval",
		"effect": "require_approval",
		"rule_type": "standard",
		"agent_id": null,
		"tool": "payment.*",
		"household_role": null,
		"purpose": null,
		"conditions": {},
		"description": "Default: any payment.* call requires approval.",
	},
	{
		"id": "default:spending:personal_shopping",
		"name": "Personal shopping",
		"effect": "allow",
		"rule_type": "standard",
		"agent_id": null,
		"tool": "shopping.*",
		"household_role": null,
		"purpose": null,
		"conditions": {"ontology": {"dimension": {"purpose": "personal"}}},
		"description": "Default: personal-purpose shopping is allowed but the spend guard escalates it to require_approval.",
	},
]

dimension_groups := [{
	"id": "default:spending:personal_spend",
	"name": "preset_personal_spend",
	"dimensions": {"purpose": "personal"},
}]

preference_groups := [{
	"id": "default:spending:spend_guard",
	"name": "preset_spend_guard",
	"dimension_group_id": "default:spending:personal_spend",
	"constraints": {"require_approval": ["payment.*", "shopping.*"]},
}]
