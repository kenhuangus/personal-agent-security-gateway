# opa test suite for the household-boundaries default policy.

package gateway.defaults.household_test

import data.gateway.authz
import data.gateway.defaults.household as hh

owner_id := "ont_owner"

member_snap := {
	"principal_id": "ont_member",
	"principal": {"id": "ont_member", "kind": "person", "display_name": "Sam"},
	"dimensions": {"purpose": "family"},
	"dimension_groups": hh.dimension_groups,
	"preference_groups": hh.preference_groups,
	"relationships": [{"source": "ont_member", "type": "household_member_of", "target": owner_id}],
}

# A non-member: no household_member_of relationship to the owner.
outsider_snap := {
	"principal_id": "ont_outsider",
	"principal": {"id": "ont_outsider", "kind": "person", "display_name": "Out"},
	"dimensions": {"purpose": "family"},
	"dimension_groups": hh.dimension_groups,
	"preference_groups": hh.preference_groups,
	"relationships": [],
}

base_input(action, snap) := {
	"schema_version": "intent-policy-input/v1",
	"policy_version": 1,
	"data_snapshot_id": "test",
	"agent": {"id": "ag_member", "household_role": "spouse"},
	"intent": {
		"agent_id": "ag_member",
		"principal_on_whose_behalf": snap.principal_id,
		"action": action,
		"resource_type": "photos",
		"resource_id": null,
		"params": {"album": "family"},
		"purpose": "family",
		"ontology_context": {"principal_id": snap.principal_id, "dimensions": snap.dimensions},
		"mandate_refs": [],
		"grant_refs": [],
	},
	"ontology_snapshot": snap,
	"mandates": [],
	"grants": [],
	"rules": hh.rules_for(owner_id),
	"now": "2026-10-12T21:00:00Z",
	"now_by_tz": {"UTC": {"iso": "2026-10-12T21:00:00+00:00", "weekday": "mon", "minutes": 1260}},
}

test_member_family_access_steps_up_to_owner if {
	# The rule allows; the family-slice guard escalates to ask (cited) —
	# exactly like the Python engine: the guard's require_approval fires
	# before the rule's requires:owner_approval, which routes the
	# approval to the owner.
	d := authz.decision with input as base_input("photos.read", member_snap)
	d.effect == "ask"
	d.rule == "default:household:family_data"
	d.ontology_ref == {"entry_id": "default:household:household_guard", "entry_kind": "preference_group"}
}

test_owner_approval_cited_without_guard if {
	# Without an applicable preference group, the rule's own
	# requires:owner_approval step-up cites the owner principal.
	snap := object.union(member_snap, {"preference_groups": []})
	d := authz.decision with input as base_input("photos.read", snap)
	d.effect == "ask"
	d.ontology_ref == {"entry_id": owner_id, "entry_kind": "principal"}
}

test_outsider_default_deny if {
	d := authz.decision with input as base_input("photos.read", outsider_snap)
	d == {"effect": "deny", "rule": "default_deny"}
}

test_member_outside_family_purpose_denied if {
	snap := object.union(member_snap, {"dimensions": {"purpose": "work"}})
	d := authz.decision with input as base_input("photos.read", snap)
	d == {"effect": "deny", "rule": "default_deny"}
}
