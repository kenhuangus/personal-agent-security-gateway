# Default policy: work/personal separation.
#
# Package: data.gateway.defaults.work_personal
# Mirrors the `work_personal_separation` ontology preset: purpose and
# location dimensions, work vs personal slices, and the personal-time
# guard (preference group) that escalates personal-purpose sends and
# denies code access outright.
#
# Versioned and immutable: this file is the v1 frozen expression of the
# default. Changes ship as a new version directory, never an edit.
#
# `rules` is data in the frozen JSON-rule schema, evaluated by
# data.gateway.authz. `dimension_groups` / `preference_groups` are the
# ontology slice the rules assume (seeded by the preset).

package gateway.defaults.work_personal

rules := [
	{
		"id": "default:work_personal:work_email",
		"name": "Work email",
		"effect": "allow",
		"rule_type": "standard",
		"agent_id": null,
		"tool": "email.send",
		"household_role": null,
		"purpose": null,
		"conditions": {"ontology": {"dimension": {"purpose": "work"}}},
		"description": "Default: email.send allowed in work purpose.",
	},
	{
		"id": "default:work_personal:personal_email",
		"name": "Personal email",
		"effect": "allow",
		"rule_type": "standard",
		"agent_id": null,
		"tool": "email.send",
		"household_role": null,
		"purpose": null,
		"conditions": {"ontology": {"dimension": {"purpose": "personal"}}},
		"description": "Default: email.send allowed in personal purpose — the personal-time guard escalates it to require_approval.",
	},
	{
		"id": "default:work_personal:personal_calendar",
		"name": "Personal calendar read",
		"effect": "allow",
		"rule_type": "standard",
		"agent_id": null,
		"tool": "calendar.read",
		"household_role": null,
		"purpose": null,
		"conditions": {"ontology": {"dimension": {"purpose": "personal"}}},
		"description": "Default: calendar.read allowed in personal purpose.",
	},
]

dimension_groups := [
	{
		"id": "default:work_personal:work_hours",
		"name": "preset_work_hours",
		"dimensions": {"purpose": "work"},
	},
	{
		"id": "default:work_personal:personal_time",
		"name": "preset_personal_time",
		"dimensions": {"purpose": "personal"},
	},
]

preference_groups := [{
	"id": "default:work_personal:personal_guard",
	"name": "preset_personal_guard",
	"dimension_group_id": "default:work_personal:personal_time",
	"constraints": {
		"require_approval": ["email.send"],
		"deny": ["code.*"],
	},
}]
