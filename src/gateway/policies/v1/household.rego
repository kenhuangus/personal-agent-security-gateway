# Default policy: household data boundaries.
#
# Package: data.gateway.defaults.household
# Mirrors the `household_boundaries` ontology preset (PAA08): household
# members may access family data in the family purpose, but only with
# owner approval (requires: owner_approval step-up). Non-members get
# the pinned default-deny.
#
# `rules_for(owner_id)` takes the owner principal id because it is
# allocated at seed time (the preset's seed_household return).
#
# Versioned and immutable: v1 frozen expression of the default.

package gateway.defaults.household

rules_for(owner_id) := [{
	"id": "default:household:family_data",
	"name": "Family data needs owner approval",
	"effect": "allow",
	"rule_type": "standard",
	"agent_id": null,
	"tool": "photos.*",
	"household_role": null,
	"purpose": null,
	"conditions": {"ontology": {
		"dimension_group": "preset_family_context",
		"relationship": {"type": "household_member_of", "target": owner_id},
		"requires": "owner_approval",
	}},
	"description": "Default: household members may read family photos in the family purpose, but only with owner approval.",
}]

dimension_groups := [{
	"id": "default:household:family_context",
	"name": "preset_family_context",
	"dimensions": {"purpose": "family"},
}]

preference_groups := [{
	"id": "default:household:household_guard",
	"name": "preset_household_guard",
	"dimension_group_id": "default:household:family_context",
	"constraints": {"require_approval": ["photos.*", "files.read"]},
}]
