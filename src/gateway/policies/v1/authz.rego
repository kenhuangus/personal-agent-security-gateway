# Decision library for the Personal Agent Security Gateway.
#
# Package: data.gateway.authz
# Input schema: "intent-policy-input/v1" (frozen; see docs/build-log.md,
# "ONTOLOGY -> INTENT -> OPEN POLICY pivot").
#
# The input document carries EVERYTHING the decision needs (the sidecar
# is stateless — no standing data, no DB):
#
#   {
#     "schema_version": "intent-policy-input/v1",
#     "policy_version": <int|null>,      # evaluated version (null = none saved)
#     "data_snapshot_id": <string>,      # "pv<N>/rules:<sha>/ont:<ref|none>"
#     "agent": {"id": <string>, "household_role": <string|null>},
#     "intent": {
#       "agent_id": <string>,
#       "principal_on_whose_behalf": <string|null>,
#       "action": <string>,              # the tool name, e.g. "email.send"
#       "resource_type": <string|null>,  # connector prefix, e.g. "email"
#       "resource_id": <string|null>,    # ontology resource, when mapped
#       "params": {<arg>: <value>},      # the call arguments
#       "purpose": <string|null>,        # declared purpose (mandate purpose_key)
#       "ontology_context": {"principal_id": ..., "dimensions": {...}},
#       "mandate_refs": [<mnd_...>],
#       "grant_refs": [<apr_...>]
#     },
#     "ontology_snapshot": null | {
#       "principal_id": <string|null>,
#       "principal": {"id","kind","display_name"} | null,
#       "dimensions": {<name>: <value>},
#       "dimension_groups": [{"id","name","dimensions": {...}}],
#       "preference_groups": [{"id","name","dimension_group_id",
#                              "constraints": {"deny": [...], "require_approval": [...]}}],
#       "relationships": [{"source","type","target"}]
#     },
#     "mandates": [{"id","status","purpose_key","tools","expires_at"}],
#     "grants": [],                       # informational; grants short-circuit
#                                         # Python-side before OPA (Fix B, MF-7)
#     "rules": [ <ordered rule objects> ],# generated from the JSON rule
#                                         # schema at save time; top-down,
#                                         # first match wins (02 §5 field 6)
#     "now": <RFC3339 UTC>,               # call time (reference)
#     "now_by_tz": {<tz>: {"iso": <RFC3339>, "weekday": "mon",
#                          "minutes": <0..1439>}}
#                                         # per-tz wall clock, precomputed
#                                         # by the caller (Rego has no tz
#                                         # database); seconds truncated,
#                                         # matching the Python semantics
#   }
#
# Decision contract:
#   data.gateway.authz.decision ==
#     {"effect": "allow"|"deny"|"ask",
#      "rule": <rule id>|"default_deny",
#      "ontology_ref": {"entry_id": ..., "entry_kind": ...}?,   # deny/ask only,
#                                                              # cites the ontology
#                                                              # entry that decided
#      "ontology_shaped": true?,            # the ontology shaped the decision;
#                                           # the caller captures the PAA04 snapshot
#      "dimension_group_ids": [...]?, "preference_group_ids": [...]?}
#
# "ask" maps to the existing require_approval Fix-B flow UNCHANGED.
#
# Fail-closed: any missing field means the enclosing rule does not
# match; no rule matching means the pinned default-deny. There is no
# path to "allow" without a matching allow rule.
#
# Rego authoring note (spike lesson): first-match-wins is expressed as
# an ordered rule array + a "no earlier rule matched" guard, mirroring
# the top-down semantics of 02 §5 field 6 exactly.

package gateway.authz

import rego.v1

# ---------------------------------------------------------------------
# Top-level decision
# ---------------------------------------------------------------------

# Pinned default-deny (FR-017): the implicit final row of every
# version. Never a stored rule; never allow by default.
default decision := {"effect": "deny", "rule": "default_deny"}

decision := d if {
	some i
	r := input.rules[i]
	rule_match(r)
	not earlier_match(i)
	d := decision_for(r)
}

# First-match-wins: rule i decides only when no earlier rule matched.
earlier_match(i) if {
	some j
	j < i
	rule_match(input.rules[j])
}

# ---------------------------------------------------------------------
# Per-rule decision (ontology escalation applies to allows only)
# ---------------------------------------------------------------------

# Preference-group deny (restrict-only): an applicable group's deny
# selector matched the tool. Cites the deciding group.
decision_for(rule) := out if {
	rule_effect(rule) == "allow"
	pref_deny
	g := deciding_pref_group
	out := object.union(
		{
			"effect": "deny", "rule": rule.id,
			"ontology_ref": {"entry_id": g.id, "entry_kind": "preference_group"},
		},
		trace_info(rule),
	)
} else := out if {
	rule_effect(rule) == "allow"
	pref_ask
	g := deciding_pref_group
	out := object.union(
		{
			"effect": "ask", "rule": rule.id,
			"ontology_ref": {"entry_id": g.id, "entry_kind": "preference_group"},
		},
		trace_info(rule),
	)
} else := out if {
	# requires: owner_approval (PAA08): the allow becomes a step-up
	# approval. Cites the relationship's target principal (the owner).
	rule_effect(rule) == "allow"
	owner_approval_required(rule)
	out := object.union(
		{
			"effect": "ask", "rule": rule.id,
			"ontology_ref": {"entry_id": owner_approval_target(rule), "entry_kind": "principal"},
		},
		trace_info(rule),
	)
} else := out if {
	out := object.union(base_decision(rule), trace_info(rule))
}

base_decision(rule) := {"effect": "allow", "rule": rule.id} if {
	rule_effect(rule) == "allow"
} else := {"effect": "deny", "rule": rule.id} if {
	rule_effect(rule) == "deny"
} else := {"effect": "ask", "rule": rule.id} if {
	rule_effect(rule) == "require_approval"
}

# Missing/unknown effect fails closed to deny (never allow).
rule_effect(rule) := e if {
	e := object.get(rule, "effect", "deny")
	e in {"allow", "deny", "require_approval"}
} else := "deny"

# Traceability for the PAA04 decision snapshot: present only when the
# ontology shaped the decision (an ontology clause on the deciding
# rule, or an applicable preference group) — on allow AND deny effects
# (GH #25: ontology-driven denies get the entry citation and snapshot
# too), mirroring the Python engine's capture condition exactly.
trace_info(rule) := {
	"ontology_shaped": true,
	"dimension_group_ids": [g.id | some g in dim_groups_applicable],
	"preference_group_ids": [g.id | some g in applicable_pref_groups],
} if {
	input.ontology_snapshot != null
	rule_effect(rule) in {"allow", "deny"}
	ontology_shaped(rule)
} else := {}

# ---------------------------------------------------------------------
# Rule matching: every selector and condition must hold (top-down).
# ---------------------------------------------------------------------

rule_match(rule) if {
	agent_selector_match(rule)
	tool_selector_matches(object.get(rule, "tool", null), input.intent.action)
	household_role_match(rule)
	purpose_match(rule)
	time_window_ok(object.get(rule_conditions(rule), "time_window", null))
	arg_constraints_ok(rule)
	notice_ok(rule)
	ontology_clause_ok(rule)
}

ontology_shaped(rule) if {
	object.get(rule_conditions(rule), "ontology", null) != null
}

ontology_shaped(rule) if {
	count([g | some g in applicable_pref_groups]) > 0
}

owner_approval_required(rule) if {
	input.ontology_snapshot != null
	clause := object.get(rule_conditions(rule), "ontology", null)
	clause != null
	object.get(clause, "requires", null) == "owner_approval"
}

owner_approval_target(rule) := t if {
	clause := object.get(rule_conditions(rule), "ontology", null)
	rel := object.get(clause, "relationship", null)
	rel != null
	t := object.get(rel, "target", null)
} else := null

# Rule conditions, always an object (the generator normalizes missing
# conditions to {}); missing-field access fails closed to no-match.
rule_conditions(rule) := c if {
	c := object.get(rule, "conditions", null)
	is_object(c)
} else := {}

agent_selector_match(rule) if {
	object.get(rule, "agent_id", null) in {null, input.agent.id}
	agents := object.get(rule_conditions(rule), "agents", null)
	agents == null
} else if {
	object.get(rule, "agent_id", null) in {null, input.agent.id}
	agents := object.get(rule_conditions(rule), "agents", null)
	agents != null
	input.agent.id in agents
}

tool_selector_matches(selector, tool) if {
	selector == null
} else if {
	endswith(selector, ".*")
	startswith(tool, trim_suffix(selector, "*"))
} else if {
	selector == tool
}

household_role_match(rule) if {
	object.get(rule, "household_role", null) in {null, input.agent.household_role}
}

# Purpose binding (FR-PAA03-002): a purpose-bound rule matches only a
# call whose declared purpose equals it. Undeclared purpose never
# matches a bound rule (fail closed).
purpose_match(rule) if {
	object.get(rule, "purpose", null) in {null, input.intent.purpose}
	input.intent.purpose != null
} else if {
	object.get(rule, "purpose", null) == null
	input.intent.purpose == null
}

# ---------------------------------------------------------------------
# Time windows
# ---------------------------------------------------------------------

time_window_ok(spec) if {
	spec == null
}

time_window_ok(spec) if {
	spec != null
	days_ok(spec)
	clock_ok(spec)
}

days_ok(spec) if {
	object.get(spec, "days", null) == null
}

days_ok(spec) if {
	days := object.get(spec, "days", null)
	days != null

	# Spec days are 3-letter lowercase ("mon"); an empty list never
	# matches (deterministic, testable).
	spec_now(spec).weekday in {lower(d) | some d in days}
}

clock_ok(spec) if {
	start := object.get(spec, "start", null)
	start == null
}

clock_ok(spec) if {
	end := object.get(spec, "end", null)
	end == null
}

clock_ok(spec) if {
	start := object.get(spec, "start", null)
	end := object.get(spec, "end", null)
	start != null
	end != null
	window_contains(hhmm_minutes(start), hhmm_minutes(end), spec_now(spec).minutes)
}

# Inside the window, boundaries inclusive; overnight windows wrap.
window_contains(s, e, t) if {
	s <= e
	s <= t
	t <= e
}

window_contains(s, e, t) if {
	s > e
	t >= s
}

window_contains(s, e, t) if {
	s > e
	t <= e
}

# The call time in the window's timezone, precomputed by the caller
# (Python zoneinfo; Rego has no tz database). Falls back to UTC.
spec_now(spec) := p if {
	tz := object.get(spec, "tz", "UTC")
	p := object.get(input.now_by_tz, tz, null)
	p != null
} else := p if {
	p := object.get(input.now_by_tz, "UTC", null)
	p != null
}

hhmm_minutes(s) := (h * 60) + m if {
	parts := split(s, ":")
	h := to_number(parts[0])
	m := to_number(parts[1])
}

# ---------------------------------------------------------------------
# Argument constraints
# ---------------------------------------------------------------------

arg_constraints_ok(rule) if {
	object.get(rule_conditions(rule), "argument_constraints", null) == null
}

arg_constraints_ok(rule) if {
	constraints := object.get(rule_conditions(rule), "argument_constraints", null)
	constraints != null
	every field, spec in constraints {
		constraint_field_ok(field, spec)
	}
}

# A missing field fails closed: the rule does not match rather than
# matching vacuously.
constraint_field_ok(field, spec) if {
	object.keys(input.intent.params)[_] == field
	value := input.intent.params[field]
	every op, operand in spec {
		constraint_op_ok(op, operand, value)
	}
}

constraint_op_ok("equals", operand, value) if {
	value == operand
}

constraint_op_ok("in", operand, value) if {
	value in operand
}

constraint_op_ok("not_in", operand, value) if {
	not value in operand
}

constraint_op_ok("contains", operand, value) if {
	is_string(value)
	contains(value, operand)
}

constraint_op_ok("matches", operand, value) if {
	is_string(value)
	regex.match(operand, value)
}

constraint_op_ok("all_domains_in", operand, value) if {
	addrs := to_addr_list(value)
	count(addrs) > 0
	allowed := {lower(d) | some d in operand}
	every a in addrs {
		email_domain(a) in allowed
	}
}

constraint_op_ok("any_domain_not_in", operand, value) if {
	addrs := to_addr_list(value)
	count(addrs) > 0
	denied := {lower(d) | some d in operand}
	some a in addrs
	not addr_domain_ok(a, denied)
}

to_addr_list(value) := value if {
	is_array(value)
} else := [value]

email_domain(addr) := d if {
	is_string(addr)
	contains(addr, "@")
	parts := split(addr, "@")
	d := lower(parts[count(parts) - 1])
}

addr_domain_ok(a, denied) if {
	d := email_domain(a)
	d in denied
}

# ---------------------------------------------------------------------
# Template-bound notice rules (FR-PAA07-005)
# ---------------------------------------------------------------------

notice_ok(rule) if {
	object.get(rule, "rule_type", "standard") != "notice"
}

notice_ok(rule) if {
	rule.rule_type == "notice"
	spec := object.get(rule_conditions(rule), "notice", null)
	spec != null
	notice_audience_ok(spec)
	notice_schedule_ok(spec)
	notice_subject_ok(spec)
	notice_body_ok(spec)
	notice_length_ok(spec)
}

notice_recipients contains r if {
	some field in ["to", "cc", "bcc"]
	v := object.get(input.intent.params, field, null)
	v != null
	v != ""
	v != []
	some r in to_addr_list(v)
	r != ""
}

# Audience expansion -> the rule does not match.
notice_audience_ok(spec) if {
	audience := {lower(a) | some a in object.get(spec, "audience", [])}
	recipients := [r | some r in notice_recipients]
	count(recipients) > 0
	every r in recipients {
		lower(r) in audience
	}
}

notice_schedule_ok(spec) if {
	sched := object.get(spec, "schedule", null)
	sched == null
}

notice_schedule_ok(spec) if {
	sched := object.get(spec, "schedule", null)
	sched != null
	days_ok(sched)
	clock_ok(sched)
}

notice_subject_ok(spec) if {
	object.get(spec, "subject_pattern", null) == null
}

notice_subject_ok(spec) if {
	pat := object.get(spec, "subject_pattern", null)
	pat != null
	sub := object.get(input.intent.params, "subject", "")
	is_string(sub)
	regex.match(pat, sub)
}

# The (?s) flag reproduces Python's re.DOTALL for the body pattern.
notice_body_ok(spec) if {
	object.get(spec, "body_pattern", null) == null
}

notice_body_ok(spec) if {
	pat := object.get(spec, "body_pattern", null)
	pat != null
	body := object.get(input.intent.params, "body", "")
	is_string(body)
	regex.match(sprintf("(?s)%s", [pat]), body)
}

notice_length_ok(spec) if {
	object.get(spec, "max_body_length", null) == null
}

notice_length_ok(spec) if {
	max_len := object.get(spec, "max_body_length", null)
	max_len != null
	body := object.get(input.intent.params, "body", "")
	is_string(body)
	count(body) <= max_len
}

# ---------------------------------------------------------------------
# Ontology clauses (dimension / dimension_group / relationship)
# ---------------------------------------------------------------------

ontology_clause_ok(rule) if {
	object.get(rule_conditions(rule), "ontology", null) == null
}

ontology_clause_ok(rule) if {
	clause := object.get(rule_conditions(rule), "ontology", null)
	clause != null
	snap := input.ontology_snapshot
	snap != null
	ont_dims_ok(clause, snap)
	ont_group_ok(clause, snap)
	ont_rel_ok(clause, snap)
}

ont_dims_ok(clause, snap) if {
	object.get(clause, "dimension", null) == null
}

ont_dims_ok(clause, snap) if {
	dims := object.get(clause, "dimension", null)
	dims != null
	every k, v in dims {
		snap.dimensions[k] == v
	}
}

ont_group_ok(clause, snap) if {
	object.get(clause, "dimension_group", null) == null
}

ont_group_ok(clause, snap) if {
	name := object.get(clause, "dimension_group", null)
	name != null
	some g in snap.dimension_groups
	g.name == name
	every k, v in g.dimensions {
		snap.dimensions[k] == v
	}
}

ont_rel_ok(clause, snap) if {
	object.get(clause, "relationship", null) == null
}

ont_rel_ok(clause, snap) if {
	rel := object.get(clause, "relationship", null)
	rel != null
	snap.principal_id != null
	rel.type in {"household_member_of", "owns", "delegates_to", "acts_for"}
	{"source": snap.principal_id, "type": rel.type, "target": rel.target} in snap.relationships
}

# ---------------------------------------------------------------------
# Preference groups ("scenario slices"): restrict-only, never widen.
# ---------------------------------------------------------------------

dim_groups_applicable contains g if {
	input.ontology_snapshot != null
	some g in input.ontology_snapshot.dimension_groups
	every k, v in g.dimensions {
		input.ontology_snapshot.dimensions[k] == v
	}
}

applicable_pref_groups contains g if {
	input.ontology_snapshot != null
	some g in input.ontology_snapshot.preference_groups
	dims := pref_group_dims(g)
	every k, v in dims {
		input.ontology_snapshot.dimensions[k] == v
	}
}

pref_group_dims(g) := d if {
	some dg in input.ontology_snapshot.dimension_groups
	dg.id == g.dimension_group_id
	d := dg.dimensions
}

pref_group_denies(g) if {
	some sel in object.get(g.constraints, "deny", [])
	tool_selector_matches(sel, input.intent.action)
}

pref_group_asks(g) if {
	some sel in object.get(g.constraints, "require_approval", [])
	tool_selector_matches(sel, input.intent.action)
}

pref_deny if {
	some g in applicable_pref_groups
	pref_group_denies(g)
}

pref_ask if {
	not pref_deny
	some g in applicable_pref_groups
	pref_group_asks(g)
}

# The deciding group (for the ontology_ref citation): deny wins over
# ask; deterministic order = the snapshot's group order.
deciding_pref_group := cands[0] if {
	cands := [c | some c in applicable_pref_groups; pref_group_denies(c)]
	count(cands) > 0
} else := cands[0] if {
	cands := [c | some c in applicable_pref_groups; pref_group_asks(c)]
	count(cands) > 0
}

# ---------------------------------------------------------------------
# Save-time rule validation (replaces validate_rule_dict as the
# authority at save; the generator emits package gateway.savecheck).
# rule_problems(rule) is the set of problem strings; empty = valid.
# ---------------------------------------------------------------------

rule_problems(rule) := union({
	problem_effect(rule),
	problem_rule_type(rule),
	problem_notice(rule),
	problem_constraint_ops(rule),
	problem_regexes(rule),
	problem_ontology(rule),
	problem_time_window(rule),
	problem_tool_selector(rule),
})

problem_effect(rule) := {m |
	not rule_effect_valid(rule)
	m := sprintf("unknown effect %v; want allow|deny|require_approval", [object.get(rule, "effect", null)])
}

rule_effect_valid(rule) if {
	object.get(rule, "effect", null) in {"allow", "deny", "require_approval"}
}

problem_rule_type(rule) := {m |
	not object.get(rule, "rule_type", "standard") in {"standard", "notice"}
	m := sprintf("unknown rule_type %v; want standard|notice", [object.get(rule, "rule_type", null)])
}

problem_notice(rule) := union({
	problem_notice_effect(rule),
	problem_notice_spec(rule),
	problem_notice_audience(rule),
	problem_notice_content(rule),
})

problem_notice_effect(rule) := {m |
	rule.rule_type == "notice"
	rule_effect(rule) != "allow"
	m := "notice rules must have effect 'allow'"
}

problem_notice_spec(rule) := {m |
	rule.rule_type == "notice"
	object.get(rule_conditions(rule), "notice", null) == null
	m := "notice rules require conditions.notice"
}

problem_notice_audience(rule) := {m |
	rule.rule_type == "notice"
	spec := object.get(rule_conditions(rule), "notice", null)
	spec != null
	count([a | some a in object.get(spec, "audience", [])]) == 0
	m := "notice rules require a non-empty audience list"
}

problem_notice_content(rule) := {m |
	rule.rule_type == "notice"
	spec := object.get(rule_conditions(rule), "notice", null)
	spec != null
	object.get(spec, "subject_pattern", null) == null
	object.get(spec, "body_pattern", null) == null
	object.get(spec, "max_body_length", null) == null
	m := "notice rules require at least one template content constraint"
}

problem_constraint_ops(rule) := {m |
	constraints := object.get(rule_conditions(rule), "argument_constraints", null)
	constraints != null
	some field, fspec in constraints
	some op in object.keys(fspec)
	not op in {"equals", "in", "not_in", "contains", "matches", "all_domains_in", "any_domain_not_in"}
	m := sprintf("unknown constraint operator %v on field %v", [op, field])
}

problem_regexes(rule) := {m |
	some pat in regex_patterns(rule)
	not regex.is_valid(pat)
	m := sprintf("invalid regex pattern %v", [pat])
}

problem_ontology(rule) := union({
	problem_ontology_keys(rule),
	problem_ontology_relationship(rule),
	problem_ontology_requires(rule),
})

problem_ontology_keys(rule) := {m |
	clause := object.get(rule_conditions(rule), "ontology", null)
	clause != null
	some k in object.keys(clause)
	not k in {"dimension", "dimension_group", "relationship", "requires"}
	m := sprintf("unknown ontology clause key %v", [k])
}

problem_ontology_relationship(rule) := {m |
	clause := object.get(rule_conditions(rule), "ontology", null)
	clause != null
	rel := object.get(clause, "relationship", null)
	rel != null
	not rel.type in {"household_member_of", "owns", "delegates_to", "acts_for"}
	m := sprintf("unknown relationship type %v", [rel.type])
}

problem_ontology_requires(rule) := {m |
	clause := object.get(rule_conditions(rule), "ontology", null)
	clause != null
	req := object.get(clause, "requires", null)
	req != null
	req != "owner_approval"
	m := sprintf("unknown ontology 'requires' value %v", [req])
}

# GH #26: a malformed time_window (e.g. "start": "9", "days": ["funday"])
# silently never matches — fail-closed but undebuggable. Reject the
# shape at save time, mirroring validate_rule_dict in policy.py.
problem_time_window(rule) := {m |
	spec := object.get(rule_conditions(rule), "time_window", null)
	spec != null
	not time_window_shape_ok(spec)
	m := "conditions.time_window: start/end must be HH:MM (24-hour) and days must be weekday names (mon..sun)"
}

time_window_shape_ok(spec) if {
	_hhmm_ok(object.get(spec, "start", null))
	_hhmm_ok(object.get(spec, "end", null))
	_days_ok(object.get(spec, "days", null))
}

_hhmm_ok(v) if {
	v == null
}

_hhmm_ok(v) if {
	regex.match(`^([01][0-9]|2[0-3]):[0-5][0-9]$`, v)
}

_days_ok(days) if {
	days == null
}

_days_ok(days) if {
	is_array(days)
	every d in days {
		lower(d) in {"mon", "tue", "wed", "thu", "fri", "sat", "sun"}
	}
}

# GH #26: a bare "*" (or misplaced wildcard) tool selector silently
# never matches — only exact names and "prefix.*" work. Reject at save
# time, mirroring validate_rule_dict in policy.py.
problem_tool_selector(rule) := {m |
	sel := object.get(rule, "tool", null)
	sel != null
	not tool_selector_shape_ok(sel)
	m := sprintf("rule tool selector %v never matches: use an exact tool name or 'prefix.*'", [sel])
}

tool_selector_shape_ok(sel) if {
	is_string(sel)
	not contains(sel, "*")
}

tool_selector_shape_ok(sel) if {
	is_string(sel)
	endswith(sel, "*")
	startswith(sel, trim_suffix(sel, "*"))

	# The wildcard must be the trailing ".*" with a non-empty,
	# wildcard-free prefix: "email.*".
	trimmed := trim_suffix(sel, "*")
	endswith(trimmed, ".")
	count(trimmed) > 1
	not contains(trim_suffix(trimmed, "."), "*")
}

# Every regex-bearing field, for validity checking at save time.
regex_patterns(rule) := {p |
	some _, fspec in object.get(rule_conditions(rule), "argument_constraints", {})
	p := object.get(fspec, "matches", null)
	p != null
} | {p |
	spec := object.get(rule_conditions(rule), "notice", null)
	spec != null
	some p2 in [object.get(spec, "subject_pattern", null), object.get(spec, "body_pattern", null)]
	p := p2
	p != null
}
