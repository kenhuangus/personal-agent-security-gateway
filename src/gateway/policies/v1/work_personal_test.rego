# opa test suite for the work/personal separation default policy.
# Run: opa test src/gateway/policies/v1/ -v

package gateway.defaults.work_personal_test

import data.gateway.authz
import data.gateway.defaults.work_personal as wp

snap(dimensions) := {
	"principal_id": "ont_owner",
	"principal": {"id": "ont_owner", "kind": "person", "display_name": "Ken"},
	"dimensions": dimensions,
	"dimension_groups": wp.dimension_groups,
	"preference_groups": wp.preference_groups,
	"relationships": [],
}

base_input(action, dimensions) := {
	"schema_version": "intent-policy-input/v1",
	"policy_version": 1,
	"data_snapshot_id": "test",
	"agent": {"id": "ag_ken", "household_role": "ken"},
	"intent": {
		"agent_id": "ag_ken",
		"principal_on_whose_behalf": "ont_owner",
		"action": action,
		"resource_type": "email",
		"resource_id": null,
		"params": {},
		"purpose": dimensions.purpose,
		"ontology_context": {"principal_id": "ont_owner", "dimensions": dimensions},
		"mandate_refs": [],
		"grant_refs": [],
	},
	"ontology_snapshot": snap(dimensions),
	"mandates": [],
	"grants": [],
	"rules": wp.rules,
	"now": "2026-10-12T21:00:00Z",
	"now_by_tz": {"UTC": {"iso": "2026-10-12T21:00:00+00:00", "weekday": "mon", "minutes": 1260}},
}

decide(action, dimensions) := d if {
	d := authz.decision with input as base_input(action, dimensions)
}

test_work_email_allowed if {
	d := decide("email.send", {"purpose": "work"})
	d.effect == "allow"
	d.rule == "default:work_personal:work_email"
}

test_personal_email_escalated_to_ask if {
	# The personal-time guard escalates the allowed personal send.
	d := decide("email.send", {"purpose": "personal"})
	d.effect == "ask"
	d.ontology_ref.entry_kind == "preference_group"
}

test_personal_code_denied_by_guard if {
	# The guard restricts an otherwise-allowed tool: personal code.read
	# matches the extra allow rule, then the guard denies it.
	extra := [{
		"id": "test:code_allow", "effect": "allow", "rule_type": "standard",
		"tool": "code.*", "conditions": {},
	}]
	inp := base_input("code.read", {"purpose": "personal"})
	inp2 := object.union(inp, {"rules": array.concat(wp.rules, extra)})
	d := authz.decision with input as inp2
	d.effect == "deny"
	d.ontology_ref.entry_id == "default:work_personal:personal_guard"
}

test_work_code_allowed_when_rule_exists if {
	# Same allow rule in work purpose: no guard applies.
	extra := [{
		"id": "test:code_allow", "effect": "allow", "rule_type": "standard",
		"tool": "code.*", "conditions": {},
	}]
	inp := base_input("code.read", {"purpose": "work"})
	inp2 := object.union(inp, {"rules": array.concat(wp.rules, extra)})
	d := authz.decision with input as inp2
	d.effect == "allow"
}

test_personal_calendar_allowed if {
	d := decide("calendar.read", {"purpose": "personal"})
	d.effect == "allow"
}
