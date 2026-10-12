# Default policy: social-send approval.
#
# Package: data.gateway.defaults.social_send
# Mirrors the `social_send_approval` ontology preset: social.* posts
# and email.send require step-up approval (PAA07 — unauthorized social
# representation), with the public-voice guard as the ontology backstop.
#
# Versioned and immutable: v1 frozen expression of the default.

package gateway.defaults.social_send

rules := [
	{
		"id": "default:social_send:social_post",
		"name": "Social posts need approval",
		"effect": "require_approval",
		"rule_type": "standard",
		"agent_id": null,
		"tool": "social.*",
		"household_role": null,
		"purpose": null,
		"conditions": {},
		"description": "Default: social.* posts require approval.",
	},
	{
		"id": "default:social_send:external_email",
		"name": "Email sends need approval",
		"effect": "require_approval",
		"rule_type": "standard",
		"agent_id": null,
		"tool": "email.send",
		"household_role": null,
		"purpose": null,
		"conditions": {},
		"description": "Default: email.send requires approval.",
	},
]

dimension_groups := [{
	"id": "default:social_send:public_voice",
	"name": "preset_public_voice",
	"dimensions": {"purpose": "personal"},
}]

preference_groups := [{
	"id": "default:social_send:social_guard",
	"name": "preset_social_guard",
	"dimension_group_id": "default:social_send:public_voice",
	"constraints": {"require_approval": ["social.*", "email.send"]},
}]
