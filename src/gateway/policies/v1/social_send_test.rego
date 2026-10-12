# opa test suite for the social-send default policy.

package gateway.defaults.social_send_test

import data.gateway.authz
import data.gateway.defaults.social_send as ss

snap(dimensions) := {
	"principal_id": "ont_owner",
	"principal": {"id": "ont_owner", "kind": "person", "display_name": "Ken"},
	"dimensions": dimensions,
	"dimension_groups": ss.dimension_groups,
	"preference_groups": ss.preference_groups,
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
		"resource_type": "social",
		"resource_id": null,
		"params": {"text": "hello world"},
		"purpose": dimensions.purpose,
		"ontology_context": {"principal_id": "ont_owner", "dimensions": dimensions},
		"mandate_refs": [],
		"grant_refs": [],
	},
	"ontology_snapshot": snap(dimensions),
	"mandates": [],
	"grants": [],
	"rules": ss.rules,
	"now": "2026-10-12T21:00:00Z",
	"now_by_tz": {"UTC": {"iso": "2026-10-12T21:00:00+00:00", "weekday": "mon", "minutes": 1260}},
}

decide(action, dimensions) := d if {
	d := authz.decision with input as base_input(action, dimensions)
}

test_social_post_needs_approval if {
	d := decide("social.post", {"purpose": "work"})
	d.effect == "ask"
	d.rule == "default:social_send:social_post"
}

test_email_send_needs_approval if {
	d := decide("email.send", {"purpose": "work"})
	d.effect == "ask"
	d.rule == "default:social_send:external_email"
}

test_social_post_personal_needs_approval if {
	d := decide("social.post", {"purpose": "personal"})
	d.effect == "ask"
}

test_unrelated_tool_default_deny if {
	d := decide("calendar.list", {"purpose": "work"})
	d == {"effect": "deny", "rule": "default_deny"}
}
