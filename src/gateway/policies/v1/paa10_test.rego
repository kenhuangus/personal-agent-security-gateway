# opa test suite for the PAA10-derived default policy.

package gateway.defaults.paa10_test

import data.gateway.authz
import data.gateway.defaults.paa10 as p10

base_input(action, params, purpose, household_role) := {
	"schema_version": "intent-policy-input/v1",
	"policy_version": 1,
	"data_snapshot_id": "test",
	"agent": {"id": "ag_ken", "household_role": household_role},
	"intent": {
		"agent_id": "ag_ken",
		"principal_on_whose_behalf": null,
		"action": action,
		"resource_type": "calendar",
		"resource_id": null,
		"params": params,
		"purpose": purpose,
		"ontology_context": {"principal_id": null, "dimensions": {}},
		"mandate_refs": [],
		"grant_refs": [],
	},
	"ontology_snapshot": null,
	"mandates": [],
	"grants": [],
	"rules": p10.rules,
	"now": "2026-10-12T21:00:00Z",
	"now_by_tz": {"UTC": {"iso": "2026-10-12T21:00:00+00:00", "weekday": "mon", "minutes": 1260}},
}

decide(action, params, purpose, household_role) := d if {
	d := authz.decision with input as base_input(action, params, purpose, household_role)
}

test_destructive_calendar_delete_asks if {
	d := decide("calendar.delete", {"event_id": "e1"}, "work", "ken")
	d.effect == "ask"
	d.rule == "default:paa10:destructive_calendar_delete"
}

test_recovery_settings_write_asks if {
	d := decide("email.settings.write", {"section": "forwarding"}, "work", "ken")
	d.effect == "ask"
	d.rule == "default:paa10:recovery_settings_write"
}

test_pr_open_asks if {
	d := decide("code.pr.open", {"repo": "x/y"}, "work", "ken")
	d.effect == "ask"
	d.rule == "default:paa10:code_pr_open"
}

test_purpose_bound_read_matches if {
	d := decide("email.read", {"message_id": "m1"}, "work", "ken")
	d.effect == "allow"
	d.rule == "default:paa10:work_email_read"
}

test_purpose_bound_read_miss if {
	d := decide("email.read", {"message_id": "m1"}, "personal", "ken")
	d == {"effect": "deny", "rule": "default_deny"}
}

test_role_scoped_rule_matches if {
	d := decide("calendar.read", {}, "work", "spouse")
	d.effect == "allow"
	d.rule == "default:paa10:spouse_calendar"
}

test_role_scoped_rule_rejects_other_role if {
	d := decide("calendar.read", {}, "work", "ken")
	d == {"effect": "deny", "rule": "default_deny"}
}

test_notice_matching_allowed if {
	d := decide(
		"email.send", {
			"to": ["team@example.com"],
			"subject": "Weekly status: Oct 12",
			"body": "Status update for week 42.",
		},
		"work", "ken",
	)
	d.effect == "allow"
	d.rule == "default:paa10:weekly_status_notice"
}

test_notice_one_off_denied if {
	d := decide(
		"email.send", {
			"to": ["friend@example.com"],
			"subject": "Weekly status: Oct 12",
			"body": "Status update for week 42.",
		},
		"work", "ken",
	)
	d == {"effect": "deny", "rule": "default_deny"}
}
