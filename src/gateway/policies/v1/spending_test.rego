# opa test suite for the spending-thresholds default policy.

package gateway.defaults.spending_test

import data.gateway.authz
import data.gateway.defaults.spending as sp

snap(dimensions) := {
	"principal_id": "ont_owner",
	"principal": {"id": "ont_owner", "kind": "person", "display_name": "Ken"},
	"dimensions": dimensions,
	"dimension_groups": sp.dimension_groups,
	"preference_groups": sp.preference_groups,
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
		"resource_type": "payment",
		"resource_id": null,
		"params": {"amount": 25, "currency": "USD"},
		"purpose": dimensions.purpose,
		"ontology_context": {"principal_id": "ont_owner", "dimensions": dimensions},
		"mandate_refs": [],
		"grant_refs": [],
	},
	"ontology_snapshot": snap(dimensions),
	"mandates": [],
	"grants": [],
	"rules": sp.rules,
	"now": "2026-10-12T21:00:00Z",
	"now_by_tz": {"UTC": {"iso": "2026-10-12T21:00:00+00:00", "weekday": "mon", "minutes": 1260}},
}

decide(action, dimensions) := d if {
	d := authz.decision with input as base_input(action, dimensions)
}

test_payment_always_needs_approval if {
	# Work purpose: the rule itself requires approval.
	d := decide("payment.initiate", {"purpose": "work"})
	d.effect == "ask"
	d.rule == "default:spending:payments"
}

test_payment_personal_needs_approval if {
	# Personal purpose: rule + spend guard agree on ask.
	d := decide("payment.initiate", {"purpose": "personal"})
	d.effect == "ask"
}

test_personal_shopping_escalated if {
	d := decide("shopping.buy", {"purpose": "personal"})
	d.effect == "ask"
	d.ontology_ref.entry_id == "default:spending:spend_guard"
}

test_work_shopping_default_deny if {
	# The shopping rule is personal-purpose scoped; work has no rule.
	d := decide("shopping.buy", {"purpose": "work"})
	d == {"effect": "deny", "rule": "default_deny"}
}
