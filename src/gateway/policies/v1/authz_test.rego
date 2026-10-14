# opa test suite for data.gateway.authz (the decision library).
# Run: opa test src/gateway/policies/v1/ -v
# These tests pin the decision contract and the ported rule semantics.

package gateway.authz_test

import data.gateway.authz

# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

base_input(rules) := {
	"schema_version": "intent-policy-input/v1",
	"policy_version": 1,
	"data_snapshot_id": "test",
	"agent": {"id": "ag_ken", "household_role": "ken"},
	"intent": {
		"agent_id": "ag_ken",
		"principal_on_whose_behalf": null,
		"action": "email.send",
		"resource_type": "email",
		"resource_id": null,
		"params": {
			"to": ["team@example.com"],
			"subject": "Weekly status: Oct 12",
			"body": "Status update for week 42.",
		},
		"purpose": "work",
		"ontology_context": {"principal_id": null, "dimensions": {}},
		"mandate_refs": [],
		"grant_refs": [],
	},
	"ontology_snapshot": null,
	"mandates": [],
	"grants": [],
	"rules": rules,
	"now": "2026-10-12T21:00:00Z",
	"now_by_tz": {"UTC": {"iso": "2026-10-12T21:00:00+00:00", "weekday": "mon", "minutes": 1260}},
}

decide(rules) := d if {
	d := authz.decision with input as base_input(rules)
}

decide_input(inp) := d if {
	d := authz.decision with input as inp
}

with_params(rules, params) := d if {
	inp := base_input(rules)
	inp2 := object.union(inp, {"intent": object.union(inp.intent, {"params": params})})
	d := authz.decision with input as inp2
}

# ---------------------------------------------------------------------
# Default-deny and first-match priority
# ---------------------------------------------------------------------

test_default_deny_no_rules if {
	decide([]) == {"effect": "deny", "rule": "default_deny"}
}

test_default_deny_no_match if {
	decide([{"id": 1, "effect": "allow", "tool": "calendar.list", "conditions": {}}]) == {"effect": "deny", "rule": "default_deny"}
}

test_first_match_allow_beats_later_deny if {
	d := decide([
		{"id": 1, "effect": "allow", "tool": "email.send", "conditions": {}},
		{"id": 2, "effect": "deny", "tool": "email.send", "conditions": {}},
	])
	d.effect == "allow"
	d.rule == 1
}

test_first_match_deny_beats_later_allow if {
	d := decide([
		{"id": 1, "effect": "deny", "tool": "email.send", "conditions": {}},
		{"id": 2, "effect": "allow", "tool": "email.send", "conditions": {}},
	])
	d.effect == "deny"
	d.rule == 1
}

test_require_approval_maps_to_ask if {
	d := decide([{"id": 7, "effect": "require_approval", "tool": "email.send", "conditions": {}}])
	d == {"effect": "ask", "rule": 7}
}

test_unknown_effect_fails_closed_to_deny if {
	# Unknown effect: rule does not decide allow; the pinned deny is the outcome.
	d := decide([{"id": 9, "effect": "quarantine", "tool": "email.send", "conditions": {}}])
	d.effect == "deny"
}

# ---------------------------------------------------------------------
# Selectors
# ---------------------------------------------------------------------

test_agent_id_selector if {
	d := decide([{"id": 1, "effect": "allow", "agent_id": "ag_other", "tool": "email.send", "conditions": {}}])
	d.rule == "default_deny"
}

test_agent_list_selector if {
	d := decide([{"id": 1, "effect": "allow", "tool": "email.send", "conditions": {"agents": ["ag_ken"]}}])
	d.effect == "allow"
}

test_tool_wildcard if {
	d := decide([{"id": 1, "effect": "allow", "tool": "email.*", "conditions": {}}])
	d.effect == "allow"
}

test_household_role_scoping if {
	rules := [{"id": 1, "effect": "allow", "tool": "email.send", "household_role": "spouse", "conditions": {}}]
	decide(rules).rule == "default_deny"
}

# ---------------------------------------------------------------------
# Purpose binding (FR-PAA03-002)
# ---------------------------------------------------------------------

test_purpose_bound_rule_matches if {
	d := decide([{"id": 1, "effect": "allow", "tool": "email.send", "purpose": "work", "conditions": {}}])
	d.effect == "allow"
}

test_purpose_mismatch_denied if {
	d := decide([{"id": 1, "effect": "allow", "tool": "email.send", "purpose": "personal", "conditions": {}}])
	d.rule == "default_deny"
}

test_undeclared_purpose_never_matches_bound_rule if {
	inp := base_input([{"id": 1, "effect": "allow", "tool": "email.send", "purpose": "work", "conditions": {}}])
	inp2 := object.union(inp, {"intent": object.union(inp.intent, {"purpose": null})})
	decide_input(inp2).rule == "default_deny"
}

# ---------------------------------------------------------------------
# Time windows
# ---------------------------------------------------------------------

test_time_window_match if {
	# Noon UTC on a Monday: inside the 09:00-18:00 window.
	inp := base_input([{
		"id": 1, "effect": "allow", "tool": "email.send",
		"conditions": {"time_window": {"days": ["mon"], "start": "09:00", "end": "18:00", "tz": "UTC"}},
	}])
	inp2 := object.union(inp, {"now_by_tz": {"UTC": {"iso": "2026-10-12T12:00:00+00:00", "weekday": "mon", "minutes": 720}}})
	decide_input(inp2).effect == "allow"
}

test_time_window_day_miss if {
	d := decide([{
		"id": 1, "effect": "allow", "tool": "email.send",
		"conditions": {"time_window": {"days": ["tue"], "start": "09:00", "end": "18:00"}},
	}])
	d.rule == "default_deny"
}

test_time_window_clock_miss if {
	d := decide([{
		"id": 1, "effect": "allow", "tool": "email.send",
		"conditions": {"time_window": {"days": ["mon"], "start": "09:00", "end": "10:00"}},
	}])
	d.rule == "default_deny"
}

test_empty_days_never_matches if {
	d := decide([{
		"id": 1, "effect": "allow", "tool": "email.send",
		"conditions": {"time_window": {"days": []}},
	}])
	d.rule == "default_deny"
}

test_overnight_window_wraps if {
	# 21:00 UTC is inside 22:00-06:00? No: 21:00 < 22:00 and > 06:00 -> miss.
	d := decide([{
		"id": 1, "effect": "allow", "tool": "email.send",
		"conditions": {"time_window": {"start": "22:00", "end": "06:00"}},
	}])
	d.rule == "default_deny"

	# 21:00 UTC is inside 20:00-06:00 (overnight wrap).
	d2 := decide([{
		"id": 1, "effect": "allow", "tool": "email.send",
		"conditions": {"time_window": {"start": "20:00", "end": "06:00"}},
	}])
	d2.effect == "allow"
}

test_tz_wall_clock_used if {
	inp := base_input([{
		"id": 1, "effect": "allow", "tool": "email.send",
		"conditions": {"time_window": {"start": "16:00", "end": "18:00", "tz": "America/New_York"}},
	}])

	# 21:00 UTC = 17:00 EDT -> inside 16:00-18:00 America/New_York.
	inp2 := object.union(inp, {"now_by_tz": {
		"UTC": {"iso": "2026-10-12T21:00:00+00:00", "weekday": "mon", "minutes": 1260},
		"America/New_York": {"iso": "2026-10-12T17:00:00-04:00", "weekday": "mon", "minutes": 1020},
	}})
	decide_input(inp2).effect == "allow"
}

# ---------------------------------------------------------------------
# Argument constraints
# ---------------------------------------------------------------------

test_equals_constraint if {
	d := with_params(
		[{
			"id": 1, "effect": "allow", "tool": "email.send",
			"conditions": {"argument_constraints": {"subject": {"equals": "Weekly status: Oct 12"}}},
		}],
		{"to": ["x@y.com"], "subject": "Weekly status: Oct 12", "body": "b"},
	)
	d.effect == "allow"
}

test_missing_field_fails_closed if {
	d := with_params(
		[{
			"id": 1, "effect": "allow", "tool": "email.send",
			"conditions": {"argument_constraints": {"nosuch": {"equals": "x"}}},
		}],
		{"to": ["x@y.com"]},
	)
	d.rule == "default_deny"
}

test_all_domains_in if {
	d := with_params(
		[{
			"id": 1, "effect": "allow", "tool": "email.send",
			"conditions": {"argument_constraints": {"to": {"all_domains_in": ["example.com"]}}},
		}],
		{"to": ["a@example.com", "b@example.com"]},
	)
	d.effect == "allow"
	d2 := with_params(
		[{
			"id": 1, "effect": "allow", "tool": "email.send",
			"conditions": {"argument_constraints": {"to": {"all_domains_in": ["example.com"]}}},
		}],
		{"to": ["a@example.com", "evil@other.com"]},
	)
	d2.rule == "default_deny"
}

test_any_domain_not_in if {
	d := with_params(
		[{
			"id": 1, "effect": "allow", "tool": "email.send",
			"conditions": {"argument_constraints": {"to": {"any_domain_not_in": ["example.com"]}}},
		}],
		{"to": ["a@example.com", "evil@other.com"]},
	)
	d.effect == "allow"
}

test_matches_regex if {
	d := with_params(
		[{
			"id": 1, "effect": "allow", "tool": "email.send",
			"conditions": {"argument_constraints": {"subject": {"matches": "^Weekly"}}},
		}],
		{"subject": "Weekly status: Oct 12"},
	)
	d.effect == "allow"
}

test_unknown_operator_never_matches if {
	d := with_params(
		[{
			"id": 1, "effect": "allow", "tool": "email.send",
			"conditions": {"argument_constraints": {"subject": {"frobnicates": "x"}}},
		}],
		{"subject": "x"},
	)
	d.rule == "default_deny"
}

# ---------------------------------------------------------------------
# Notice rules (FR-PAA07-005)
# ---------------------------------------------------------------------

notice_rule := {
	"id": 3, "effect": "allow", "rule_type": "notice", "tool": "email.send",
	"conditions": {"notice": {
		"audience": ["team@example.com"],
		"schedule": {"days": ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]},
		"subject_pattern": "^Weekly status:",
		"body_pattern": "Status update for week \\d+",
		"max_body_length": 5000,
	}},
}

test_notice_matching_allowed if {
	decide([notice_rule]).effect == "allow"
}

test_notice_audience_expansion_denied if {
	d := with_params([notice_rule], {
		"to": ["team@example.com", "outsider@evil.com"],
		"subject": "Weekly status: Oct 12", "body": "Status update for week 42.",
	})
	d.rule == "default_deny"
}

test_notice_content_mismatch_denied if {
	d := with_params([notice_rule], {
		"to": ["team@example.com"],
		"subject": "Unrelated", "body": "Status update for week 42.",
	})
	d.rule == "default_deny"
}

test_notice_body_too_long_denied if {
	d := with_params([notice_rule], {
		"to": ["team@example.com"],
		"subject": "Weekly status: Oct 12", "body": "Status update for week 42. xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	})
	d.rule == "default_deny"
}

# ---------------------------------------------------------------------
# Ontology clauses + preference groups
# ---------------------------------------------------------------------

snap_input(rules, snap) := out if {
	inp := base_input(rules)
	out := object.union(inp, {"ontology_snapshot": snap})
}

snap_fixture := {
	"principal_id": "ont_owner",
	"principal": {"id": "ont_owner", "kind": "person", "display_name": "Ken"},
	"dimensions": {"purpose": "work"},
	"dimension_groups": [
		{"id": "dg_work", "name": "preset_work_hours", "dimensions": {"purpose": "work"}},
		{"id": "dg_personal", "name": "preset_personal_time", "dimensions": {"purpose": "personal"}},
	],
	"preference_groups": [{
		"id": "pg_guard", "name": "preset_personal_guard", "dimension_group_id": "dg_personal",
		"constraints": {"require_approval": ["email.send"], "deny": ["code.*"]},
	}],
	"relationships": [{"source": "ont_member", "type": "household_member_of", "target": "ont_owner"}],
}

test_dimension_clause_match if {
	rules := [{
		"id": 1, "effect": "allow", "tool": "email.send",
		"conditions": {"ontology": {"dimension": {"purpose": "work"}}},
	}]
	d := decide_input(snap_input(rules, snap_fixture))
	d.effect == "allow"
	d.ontology_shaped == true
}

# GH #25: a deny-effect rule with a matching ontology clause is
# ontology-shaped too — the decision carries the entry citation and
# snapshot refs for the Python PAA04 capture.
test_deny_with_ontology_clause_is_shaped if {
	rules := [{
		"id": 1, "effect": "deny", "tool": "email.send",
		"conditions": {"ontology": {"dimension": {"purpose": "work"}}},
	}]
	d := decide_input(snap_input(rules, snap_fixture))
	d.effect == "deny"
	d.ontology_shaped == true
}

test_dimension_clause_miss_falls_through if {
	rules := [{
		"id": 1, "effect": "allow", "tool": "email.send",
		"conditions": {"ontology": {"dimension": {"purpose": "personal"}}},
	}]
	d := decide_input(snap_input(rules, snap_fixture))
	d.rule == "default_deny"
}

test_ontology_rule_needs_snapshot if {
	# An ontology-scoped rule with no snapshot never matches (fail closed).
	rules := [{
		"id": 1, "effect": "allow", "tool": "email.send",
		"conditions": {"ontology": {"dimension": {"purpose": "work"}}},
	}]
	decide(rules).rule == "default_deny"
}

test_dimension_group_clause if {
	rules := [{
		"id": 1, "effect": "allow", "tool": "email.send",
		"conditions": {"ontology": {"dimension_group": "preset_work_hours"}},
	}]
	d := decide_input(snap_input(rules, snap_fixture))
	d.effect == "allow"
}

test_relationship_clause if {
	snap := object.union(snap_fixture, {"principal_id": "ont_member"})
	rules := [{
		"id": 1, "effect": "allow", "tool": "email.send",
		"conditions": {"ontology": {"relationship": {"type": "household_member_of", "target": "ont_owner"}}},
	}]
	d := decide_input(snap_input(rules, snap))
	d.effect == "allow"
}

test_owner_approval_step_up_cites_principal if {
	snap := object.union(snap_fixture, {"principal_id": "ont_member"})
	rules := [{
		"id": 1, "effect": "allow", "tool": "photos.read",
		"conditions": {"ontology": {
			"relationship": {"type": "household_member_of", "target": "ont_owner"},
			"requires": "owner_approval",
		}},
	}]
	inp := snap_input(rules, snap)
	inp2 := object.union(inp, {"intent": object.union(inp.intent, {"action": "photos.read"})})
	d := decide_input(inp2)
	d.effect == "ask"
	d.ontology_ref == {"entry_id": "ont_owner", "entry_kind": "principal"}
}

test_pref_deny_restricts_and_cites if {
	snap := object.union(snap_fixture, {"dimensions": {"purpose": "personal"}})
	rules := [{"id": 1, "effect": "allow", "tool": "code.read", "conditions": {}}]
	inp := snap_input(rules, snap)
	inp2 := object.union(inp, {"intent": object.union(inp.intent, {"action": "code.read"})})
	d := decide_input(inp2)
	d.effect == "deny"
	d.rule == 1
	d.ontology_ref == {"entry_id": "pg_guard", "entry_kind": "preference_group"}
}

test_pref_ask_escalates if {
	snap := object.union(snap_fixture, {"dimensions": {"purpose": "personal"}})
	rules := [{"id": 1, "effect": "allow", "tool": "email.send", "conditions": {}}]
	d := decide_input(snap_input(rules, snap))
	d.effect == "ask"
	d.ontology_ref == {"entry_id": "pg_guard", "entry_kind": "preference_group"}
}

test_pref_never_widens if {
	# A preference group cannot turn a deny rule into an allow.
	rules := [{"id": 1, "effect": "deny", "tool": "email.send", "conditions": {}}]
	d := decide_input(snap_input(rules, snap_fixture))
	d.effect == "deny"
}

# ---------------------------------------------------------------------
# rule_problems (save-time validation)
# ---------------------------------------------------------------------

test_problems_empty_for_valid_rule if {
	authz.rule_problems({"effect": "allow", "tool": "email.send", "conditions": {}}) == set()
}

test_problems_unknown_effect if {
	count(authz.rule_problems({"effect": "bogus", "conditions": {}})) > 0
}

test_problems_unknown_constraint_op if {
	p := authz.rule_problems({
		"effect": "allow",
		"conditions": {"argument_constraints": {"to": {"frobnicates": "x"}}},
	})
	count(p) > 0
}

test_problems_invalid_regex if {
	p := authz.rule_problems({
		"effect": "allow",
		"conditions": {"argument_constraints": {"subject": {"matches": "(unclosed"}}},
	})
	count(p) > 0
}

test_problems_notice_violations if {
	p := authz.rule_problems({
		"effect": "deny", "rule_type": "notice",
		"conditions": {"notice": {"audience": []}},
	})
	count(p) >= 3
}

test_problems_ontology_keys if {
	p := authz.rule_problems({
		"effect": "allow",
		"conditions": {"ontology": {"bogus_key": "x"}},
	})
	count(p) > 0
}
