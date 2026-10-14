"""Policy engine (M2, OPA pivot): Rego evaluation over JSON rules (03 §8 as amended).

The rule AUTHORING surface is unchanged: Ken's console rule builder
produces JSON rule dicts (02 §5 — no DSL), versions stay immutable in
the DB, material/non-material classification, dry-run, and the pinned
default-deny are all preserved.

What changed (ONTOLOGY -> INTENT -> OPEN POLICY pivot, 2026-10-12):
every call is normalized to an :class:`gateway.intent.Intent`, the
stored JSON rules are compiled to the frozen input document
(``intent-policy-input/v1``), and the decision is computed by the
versioned Rego library ``gateway/policies/v1/authz.rego`` running in
a supervised OPA sidecar (:class:`gateway.opa_client.OpaClient`).

Fix-B ordering is preserved: grants + mandate-liveness are evaluated
Python-side BEFORE the OPA call (high-churn DB state; the spike's
recommendation). The sidecar is stateless — the input document
carries rules, intent, and the ontology snapshot — so a restart loses
nothing. Fail-closed (03 §7): any sidecar failure denies via the
pinned default-deny, never passes through.

Rule fields (02 §5 rule builder):
- name, agent selector (agent_id or conditions.agents), tool selector
  (tool, supports "prefix.*" wildcards), effect
  (allow/deny/require_approval), conditions: time window, argument
  constraints, purpose binding (FR-PAA03-002), household-role scoping
  (FR-PAA08-001), ontology clause (dimension / dimension_group /
  relationship / requires, resolved against the ontology snapshot);
  rule_type "notice" for template-bound notice rules (FR-PAA07-005).

Evaluation: top-down, first match wins (02 §5 field 6); the pinned
visible default-deny is the implicit final row (FR-017) and is never a
stored rule.

Versions: immutable — every save creates a new version; every save
records a material/non-material classification (02 §5, FR-PAA04-003)
AND runs ``opa check`` + the ``rule_problems`` evaluation over the
generated rule data (invalid rules never reach storage, FR-PAA04-002).

``dry_run`` re-evaluates a policy version against audit history
(AC-12, 02 §2.6); a hand-written synthetic per-tool corpus covers the
cold-start case.

Grant-before-rule short-circuit (Fix B, MF-7): ``PolicyEngine`` takes
``grant_checker``; the M3 GrantService wires the real grant store.

The Python match helpers below (``rule_matches``,
``time_window_matches``, ...) are the REFERENCE implementation of the
rule semantics. The engine evaluates via OPA; the reference
implementation is kept for the Python-vs-Rego cross-check tests and
as executable documentation of the ported semantics.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import logging
import re
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, NamedTuple, Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import select
from sqlalchemy.orm import Session

from .errors import make_error, policy_denied
from .intent import Intent, intent_from_parts, normalize_intent
from .judge.risk import apply_risk_step_up
from .latency import record
from .models import Agent, Mandate, PolicyRule, PolicyVersion
from .ontology import integration as _ontology
from .ontology.models import (
    OntologyDimensionGroup,
    OntologyPreferenceGroup,
    OntologyPrincipal,
    OntologyRelationship,
)
from .ontology.snapshots import SnapshotInput, capture_snapshot
from .opa_client import OPA_VERSION, OpaClient, OpaUnavailable, default_policies_dir
from .pipeline import timing_span

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

EFFECTS: tuple[str, ...] = ("allow", "deny", "require_approval")

#: Legacy M1 effect value, normalized to require_approval on read.
_LEGACY_EFFECTS = {"sensitive": "require_approval"}

RULE_TYPES: tuple[str, ...] = ("standard", "notice")

#: The pinned default-deny row's internal id (never agent-visible;
#: denials use the safe-vocabulary reason "no_allow_rule").


# ---------------------------------------------------------------------
# Hot-path rule cache (M6 hardening, AC-11).
#
# Policy versions are IMMUTABLE (save_version only inserts; nothing is
# ever edited in place — 02 §5). The rule data for a version therefore
# never changes, so it is safe to cache process-wide. The cache key
# includes the database URL: tests and processes use distinct SQLite
# files whose version numbers collide, and only the (db, version) pair
# is stable. The current-version *pointer* (is_current) is NOT cached:
# every call re-resolves it with one indexed query, so a newly saved
# version takes effect on the very next call. Console/dry-run paths
# keep using the uncached load_rules(); only the per-call hot path
# (evaluate_intent) reads the cache.
# ---------------------------------------------------------------------

_RULES_CACHE: dict[tuple[str, int], list[dict[str, Any]]] = {}
_RULES_CACHE_LOCK = threading.Lock()


def _db_cache_key(db: Any) -> str:
    try:
        bind = db.get_bind()
        return str(bind.url) if bind is not None else f"unbound:{id(db)}"
    except Exception:  # noqa: BLE001 — fall back to the session identity
        return f"session:{id(db)}"


def _cached_rules_data(
    db: Any, version_number: int
) -> Optional[list[dict[str, Any]]]:
    """The generated Rego input data for a (db, version), if cached."""
    key = (_db_cache_key(db), version_number)
    with _RULES_CACHE_LOCK:
        entry = _RULES_CACHE.get(key)
        return list(entry) if entry is not None else None


def _store_rules_data(
    db: Any, version_number: int, rules_data: list[dict[str, Any]]
) -> None:
    key = (_db_cache_key(db), version_number)
    with _RULES_CACHE_LOCK:
        _RULES_CACHE[key] = list(rules_data)


def clear_rules_cache() -> None:
    """Drop the hot-path cache (tests; the cache is append-only otherwise)."""
    with _RULES_CACHE_LOCK:
        _RULES_CACHE.clear()
DEFAULT_DENY_ID = "default_deny"

#: Constraint operators supported in conditions.argument_constraints
#: (02 §5 field 5 — argument constraints).
CONSTRAINT_OPS: tuple[str, ...] = (
    "equals",
    "in",
    "not_in",
    "contains",
    "matches",  # regex search on a string field
    "all_domains_in",  # every email address's domain is in the list
    "any_domain_not_in",  # at least one email address's domain is outside the list
)


# ---------------------------------------------------------------------
# Evaluation result
# ---------------------------------------------------------------------

class EvaluationResult(NamedTuple):
    """Result of ``PolicyEngine.evaluate_call``.

    ``decision`` is "allow" | "deny" | "require_approval".
    ``matched_rule_id`` is the PolicyRule.id that decided, or None for
    the pinned default-deny (no stored rule matched).
    ``requires_approval`` mirrors decision == "require_approval".
    ``policy_version`` is the version number that was evaluated.
    ``scope_rule`` is the internal scope-rule label for the audit row
    (FR-PAA01-007) — never agent-visible.
    ``via_grant`` marks the M3 grant-before-rule short-circuit.
    ``ontology_snapshot_ref`` is the content-addressed snapshot ref
    ("key_id:hexdigest") captured at decision time when an ontology
    clause or preference group shaped the decision (PAA04
    traceability); None otherwise. The audit row carries it in its own
    ``ontology_snapshot_ref`` field.
    ``data_snapshot_id`` identifies the policy data behind the
    decision ("pv<N>/rules:<sha>/ont:<ref|none>"); None when no OPA
    evaluation ran (meta-tool allow, grant short-circuit). The audit
    row carries it additively for input-document versioning.
    """

    decision: str
    matched_rule_id: Optional[int]
    requires_approval: bool
    policy_version: Optional[int] = None
    scope_rule: Optional[str] = None
    via_grant: bool = False
    ontology_snapshot_ref: Optional[str] = None
    # -- M3 additions (all defaulted; M2 call sites unaffected) --------
    # The apr_ id whose grant authorized the call (via_grant only).
    approval_request_id: Optional[str] = None
    # Safe-vocabulary deny reason supplied by the grant checker
    # (mandate_withdrawn / mandate_expired / mandate_paused /
    # policy_superseded) when a grant lookup denies.
    deny_reason: Optional[str] = None
    # Terminal agent-visible code (already_executed) when the grant
    # checker refuses with a non-policy_denied code.
    terminal_code: Optional[str] = None
    # Counterparty escalation reason (new_payee / changed_details)
    # when the sensitivity escalator converts allow → require_approval.
    escalation_reason: Optional[str] = None
    # Ontology citation for deny/ask decisions shaped by the ontology:
    # {"entry_id", "entry_kind", "snapshot_ref"} — names the specific
    # ontology entry that decided (directive: deny/ask reasons cite the
    # entry). Additive; the M6 pipeline wiring copies it into the
    # policy_denied / approval_required error details.
    ontology_ref: Optional[dict[str, Any]] = None
    # Input-document versioning: "pv<N>/rules:<sha>/ont:<ref|none>".
    # None when no OPA evaluation ran (meta-tool allow, grant
    # short-circuit). Recorded additively on the audit row.
    data_snapshot_id: Optional[str] = None


#: Agent-visible meta tools (02 §2.5). ``gateway.approval_status`` is
#: routine by design: it reveals only the caller's own request
#: statuses, has its own rate budget, and is exempt from per-call
#: audit rows (except denied/expired/not-found). The engine allows it
#: before rule evaluation so no policy edit can break the Fix-B
#: poll loop; mandate scope still applies (the default mandate
#: carries ``gateway.*``).
META_TOOLS: tuple[str, ...] = ("gateway.approval_status",)


# ---------------------------------------------------------------------
# Condition evaluation — REFERENCE IMPLEMENTATION.
#
# These Python helpers are the executable specification of the rule
# semantics. The engine evaluates via OPA (policies/v1/authz.rego);
# tests/test_rego.py cross-checks the two on generated cases. Keep
# them in sync with the Rego when the semantics change.
# ---------------------------------------------------------------------

def _parse_hhmm(value: str) -> dt.time:
    hour, minute = value.split(":")[:2]
    return dt.time(int(hour), int(minute))


def time_window_matches(spec: dict[str, Any], now: dt.datetime) -> bool:
    """Evaluate a time-window condition (02 §5 field 5).

    spec: {"days": ["mon", ...], "start": "09:00", "end": "18:00",
           "tz": "UTC"}. Missing keys mean "no constraint on that axis".
    An empty "days" list never matches (deterministic, testable).
    """
    tz = ZoneInfo(spec.get("tz") or "UTC")
    local = now.astimezone(tz)
    days = spec.get("days")
    if days is not None:
        wanted = {str(d).lower() for d in days}
        if local.strftime("%a").lower() not in wanted:
            return False
    start = spec.get("start")
    end = spec.get("end")
    if start and end:
        s, e = _parse_hhmm(start), _parse_hhmm(end)
        t = local.time().replace(second=0, microsecond=0)
        if s <= e:
            inside = s <= t <= e
        else:  # overnight window, e.g. 22:00–06:00
            inside = t >= s or t <= e
        if not inside:
            return False
    return True


def _email_domain(value: Any) -> Optional[str]:
    if not isinstance(value, str) or "@" not in value:
        return None
    return value.rsplit("@", 1)[1].lower()


def constraint_matches(spec: dict[str, Any], value: Any) -> bool:
    """Evaluate one field's constraint spec against the argument value.

    Missing/None values fail every operator (fail closed: the rule does
    not match rather than matching vacuously).
    """
    for op, operand in spec.items():
        if op not in CONSTRAINT_OPS:
            raise ValueError(f"unknown constraint operator {op!r}")
        if op == "equals":
            if value != operand:
                return False
        elif op == "in":
            if value not in operand:
                return False
        elif op == "not_in":
            if value in operand:
                return False
        elif op == "contains":
            if not isinstance(value, str) or operand not in value:
                return False
        elif op == "matches":
            if not isinstance(value, str) or not re.search(operand, value):
                return False
        elif op == "all_domains_in":
            addrs = value if isinstance(value, list) else [value]
            if not addrs:
                return False
            allowed = {str(d).lower() for d in operand}
            for addr in addrs:
                domain = _email_domain(addr)
                if domain is None or domain not in allowed:
                    return False
        elif op == "any_domain_not_in":
            addrs = value if isinstance(value, list) else [value]
            if not addrs:
                return False
            denied = {str(d).lower() for d in operand}
            if not any(
                (d := _email_domain(addr)) is None or d not in denied for addr in addrs
            ):
                return False
    return True


def argument_constraints_match(
    constraints: dict[str, Any], args: dict[str, Any]
) -> bool:
    """All declared argument constraints must hold (02 §5 field 5)."""
    for field_name, spec in constraints.items():
        if not isinstance(spec, dict):
            raise ValueError(
                f"constraint for field {field_name!r} must be an object"
            )
        if field_name not in args:
            return False  # fail closed on missing fields
        if not constraint_matches(spec, args[field_name]):
            return False
    return True


def notice_rule_matches(
    spec: dict[str, Any], args: dict[str, Any], now: dt.datetime
) -> bool:
    """Template-bound notice rule match (FR-PAA07-005, 02 §5).

    Binds the audience list, the template (as content constraints), and
    the schedule. Execution is allowed ONLY if the rendered content
    matches the template within the declared constraints; any deviation
    means the rule does not match (→ deny or another rule decides).
    """
    audience = {str(a).lower() for a in spec.get("audience", [])}
    recipients: list[str] = []
    for field_name in ("to", "cc", "bcc"):
        value = args.get(field_name)
        if value:
            recipients.extend(value if isinstance(value, list) else [value])
    if not recipients:
        return False
    if any(str(r).lower() not in audience for r in recipients):
        return False  # audience expansion → rule does not match
    schedule = spec.get("schedule")
    if schedule and not time_window_matches(schedule, now):
        return False
    subject_pattern = spec.get("subject_pattern")
    if subject_pattern and not re.search(
        subject_pattern, str(args.get("subject") or "")
    ):
        return False
    body_pattern = spec.get("body_pattern")
    if body_pattern and not re.search(
        body_pattern, str(args.get("body") or ""), re.DOTALL
    ):
        return False
    max_body_length = spec.get("max_body_length")
    if max_body_length is not None and len(str(args.get("body") or "")) > int(
        max_body_length
    ):
        return False
    return True


# ---------------------------------------------------------------------
# Rule matching
# ---------------------------------------------------------------------

def _tool_selector_matches(selector: Optional[str], tool: str) -> bool:
    if selector is None:
        return True
    if selector.endswith(".*"):
        return tool.startswith(selector[:-1])
    return selector == tool


def _agent_selector_matches(rule: PolicyRule, agent: Any) -> bool:
    if rule.agent_id is not None and rule.agent_id != agent.id:
        return False
    agents = (rule.conditions or {}).get("agents")
    if agents is not None and agent.id not in agents:
        return False
    return True


def rule_matches(
    rule: PolicyRule,
    agent: Any,
    tool: str,
    args: dict[str, Any],
    purpose: Optional[str],
    now: dt.datetime,
) -> bool:
    """Top-down first-match: every selector and condition must hold.

    agent: anything with ``.id`` and ``.household_role`` (Agent model
    or a test stand-in).
    purpose: the call's declared purpose (mandate.purpose_key);
    a rule with a purpose only matches an equal declared purpose
    (FR-PAA03-002).
    """
    conditions = rule.conditions or {}
    if not _agent_selector_matches(rule, agent):
        return False
    if not _tool_selector_matches(rule.tool, tool):
        return False
    # Household-role scoping (FR-PAA08-001): a rule scoped to one
    # member's role never matches another member's agent.
    if rule.household_role is not None and rule.household_role != getattr(
        agent, "household_role", None
    ):
        return False
    # Purpose binding (FR-PAA03-002): a purpose-bound rule matches only
    # a call whose declared purpose equals it.
    if rule.purpose is not None and rule.purpose != purpose:
        return False
    time_window = conditions.get("time_window")
    if time_window and not time_window_matches(time_window, now):
        return False
    arg_constraints = conditions.get("argument_constraints")
    if arg_constraints and not argument_constraints_match(arg_constraints, args):
        return False
    if rule.rule_type == "notice":
        notice = conditions.get("notice")
        if not notice:
            return False
        if not notice_rule_matches(notice, args, now):
            return False
    return True


def normalize_effect(effect: str) -> str:
    """Normalize the effect vocabulary; legacy "sensitive" → require_approval."""
    if effect in EFFECTS:
        return effect
    if effect in _LEGACY_EFFECTS:
        return _LEGACY_EFFECTS[effect]
    raise ValueError(f"unknown rule effect {effect!r}; want one of {EFFECTS}")


# ---------------------------------------------------------------------
# Rule validation (on save)
# ---------------------------------------------------------------------

# ---------------------------------------------------------------------
# Rule shape validation (GH #26)
# ---------------------------------------------------------------------

#: HH:MM, 24-hour clock — the shape time_window start/end must have.
#: Anything else (e.g. "9") silently never matches at evaluation time.
_HHMM_RE = re.compile(r"^([01][0-9]|2[0-3]):[0-5][0-9]$")

#: Weekday vocabulary for time_window days (the Rego lowercases at
#: evaluation, so validation is case-insensitive).
_WEEKDAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


def _validate_time_window_shape(spec: dict[str, Any]) -> None:
    """Reject malformed ``conditions.time_window`` at save time.

    A malformed window (``"start": "9"``, ``"days": ["funday"]``) is
    fail-closed but undebuggable: the rule looks fine in the console and
    can never fire. Raises ValueError.
    """
    for key in ("start", "end"):
        val = spec.get(key)
        if val is not None and (not isinstance(val, str) or not _HHMM_RE.match(val)):
            raise ValueError(
                f"conditions.time_window.{key} must be HH:MM (24-hour), "
                f"got {val!r}"
            )
    days = spec.get("days")
    if days is not None:
        if not isinstance(days, list):
            raise ValueError("conditions.time_window.days must be a list")
        for day in days:
            if not isinstance(day, str) or day.lower() not in _WEEKDAYS:
                raise ValueError(
                    f"conditions.time_window.days: unknown weekday {day!r}; "
                    f"want one of {list(_WEEKDAYS)}"
                )
        # Normalize to the vocabulary the Rego matches against.
        spec["days"] = [d.lower() for d in days]


def _validate_tool_selector_shape(selector: Any) -> None:
    """Reject tool selectors that can never match at save time.

    The matcher understands exact names and ``"prefix.*"`` wildcards
    only — a bare ``"*"`` (or any other misplaced wildcard) silently
    matches nothing. Raises ValueError.
    """
    if not isinstance(selector, str) or not selector:
        raise ValueError(
            f"rule tool selector must be a non-empty string, got {selector!r}"
        )
    if "*" not in selector:
        return  # exact tool name
    prefix, _, suffix = selector.rpartition("*")
    if suffix == "" and prefix.endswith(".") and "*" not in prefix[:-1] and len(prefix) > 1:
        return  # well-formed "prefix.*" wildcard
    raise ValueError(
        f"rule tool selector {selector!r} never matches: use an exact "
        "tool name or 'prefix.*'"
    )


def validate_rule_dict(rule: dict[str, Any]) -> dict[str, Any]:
    """Validate a rule dict from the builder/raw mode (02 §5).

    Returns a normalized copy. Raises ValueError on any problem —
    invalid rules never reach storage (FR-PAA04-002: no untrusted
    content becomes authority).
    """
    r = dict(rule)
    effect = normalize_effect(str(r.get("effect", "")))
    r["effect"] = effect
    rule_type = str(r.get("rule_type", "standard"))
    if rule_type not in RULE_TYPES:
        raise ValueError(f"unknown rule_type {rule_type!r}; want one of {RULE_TYPES}")
    r["rule_type"] = rule_type
    conditions = r.get("conditions") or {}
    if not isinstance(conditions, dict):
        raise ValueError("conditions must be an object")
    # Validate constraint operators eagerly.
    arg_constraints = conditions.get("argument_constraints") or {}
    if not isinstance(arg_constraints, dict):
        raise ValueError("conditions.argument_constraints must be an object")
    for field_name, spec in arg_constraints.items():
        if not isinstance(spec, dict):
            raise ValueError(
                f"argument constraint for {field_name!r} must be an object"
            )
        for op in spec:
            if op not in CONSTRAINT_OPS:
                raise ValueError(f"unknown constraint operator {op!r}")
    time_window = conditions.get("time_window")
    if time_window is not None:
        if not isinstance(time_window, dict):
            raise ValueError("conditions.time_window must be an object")
        tz = time_window.get("tz") or "UTC"
        try:
            ZoneInfo(tz)
        except ZoneInfoNotFoundError:
            raise ValueError(f"conditions.time_window.tz: unknown timezone {tz!r}")
        # GH #26: validate the window shape — a malformed window
        # silently never matches (fail-closed but undebuggable).
        _validate_time_window_shape(time_window)
        schedule = (conditions.get("notice") or {}).get("schedule")
        if isinstance(schedule, dict):
            stz = schedule.get("tz") or "UTC"
            try:
                ZoneInfo(stz)
            except ZoneInfoNotFoundError:
                raise ValueError(
                    f"conditions.notice.schedule.tz: unknown timezone {stz!r}"
                )
    # Ontology clause (personal-ontology integration, additive): structural
    # validation only — store-aware checks (dimension names, group names,
    # principal ids) are validate_ontology_conditions(), called by the
    # console before save. Unknown keys/operators never reach storage.
    ontology_clause = conditions.get("ontology")
    if ontology_clause is not None:
        _ontology.validate_ontology_clause(ontology_clause)
    agents = conditions.get("agents")
    if agents is not None and not isinstance(agents, list):
        raise ValueError("conditions.agents must be a list")
    # GH #26: a bare "*" (or misplaced wildcard) silently never matches —
    # reject it at save time so the admin gets feedback.
    if r.get("tool") is not None:
        _validate_tool_selector_shape(r["tool"])
    if rule_type == "notice":
        # A notice rule is a standing POLICY RULE (FR-PAA07-005), not a
        # grant: it authorizes matching executions, nothing else.
        if effect != "allow":
            raise ValueError("notice rules must have effect 'allow'")
        notice = conditions.get("notice")
        if not isinstance(notice, dict):
            raise ValueError("notice rules require conditions.notice")
        if not notice.get("audience"):
            raise ValueError("notice rules require a non-empty audience list")
        if not any(
            notice.get(k)
            for k in ("subject_pattern", "body_pattern", "max_body_length")
        ):
            raise ValueError(
                "notice rules require at least one template content constraint "
                "(subject_pattern, body_pattern, or max_body_length)"
            )
    r["conditions"] = conditions
    return r


# ---------------------------------------------------------------------
# Material / non-material classification (02 §5, FR-PAA04-003)
# ---------------------------------------------------------------------

def _rule_semantic_signature(rule: dict[str, Any]) -> str:
    """Signature of everything EXCEPT name/description/order.

    Per 02 §5, non-material changes are "notes, display names, ordering
    with identical semantics". Anything else in the rule set is material.
    """
    slim = {
        "effect": rule.get("effect"),
        "rule_type": rule.get("rule_type", "standard"),
        "agent_id": rule.get("agent_id"),
        "tool": rule.get("tool"),
        "action_class": rule.get("action_class"),
        "household_role": rule.get("household_role"),
        "purpose": rule.get("purpose"),
        "conditions": rule.get("conditions") or {},
    }
    return json.dumps(slim, sort_keys=True)


def classify_change(
    old_rules: list[dict[str, Any]], new_rules: list[dict[str, Any]]
) -> bool:
    """True = material, False = non-material.

    Any semantic difference in the rule set (add, remove, or change to
    selectors/effect/conditions) is material. Pure renames, description
    edits, and reordering with identical semantics are non-material.
    """
    old_sigs = sorted(_rule_semantic_signature(r) for r in old_rules)
    new_sigs = sorted(_rule_semantic_signature(r) for r in new_rules)
    return old_sigs != new_sigs


def diff_versions(
    old_rules: list[dict[str, Any]], new_rules: list[dict[str, Any]]
) -> dict[str, list[dict[str, Any]]]:
    """Before/after diff for the console confirm step (FR-PAA04-004)."""
    old_by_sig = {_rule_semantic_signature(r): r for r in old_rules}
    new_by_sig = {_rule_semantic_signature(r): r for r in new_rules}
    return {
        "added": [r for s, r in new_by_sig.items() if s not in old_by_sig],
        "removed": [r for s, r in old_by_sig.items() if s not in new_by_sig],
    }


# ---------------------------------------------------------------------
# Rego generation: JSON rules -> input-document rule data.
#
# REGO AUTHORING CHOICE (documented per the pivot task): generate from
# the JSON rule schema rather than hand-authoring Rego. Rationale:
# 02 §5 mandates "No DSL" — Ken builds rules from a structured form
# and raw JSON/YAML is the escape hatch, not raw Rego. Generating
# keeps the console rule builder, the immutable-version model, the
# material/non-material classification, and dry_run untouched (they
# all speak JSON rule dicts), and it keeps every existing JSON-rule
# test authoring-compatible. The hand-rolled evaluator's retirement
# cost (03 §8's "dependency-free" rationale) is paid once, here,
# instead of once per rule author.
#
# The generated rule data flows into the sidecar as input.rules (the
# sidecar stays stateless); `opa check` + the `rule_problems`
# evaluation run at save time (replacing validate_rule_dict as the
# authority — validate_rule_dict remains the builder-facing
# structural pre-check).
# ---------------------------------------------------------------------

#: Frozen input-document schema version.
INPUT_SCHEMA_VERSION = "intent-policy-input/v1"


def rule_to_input_data(rule: PolicyRule) -> dict[str, Any]:
    """Compile one stored rule to the frozen input-document rule shape."""
    return {
        "id": rule.id,
        "name": rule.name or "",
        "effect": normalize_effect(rule.effect),
        "rule_type": rule.rule_type or "standard",
        "agent_id": rule.agent_id,
        "tool": rule.tool,
        "action_class": rule.action_class,
        "household_role": rule.household_role,
        "purpose": rule.purpose,
        "conditions": rule.conditions or {},
    }


def rules_timezones(rules_data: list[dict[str, Any]]) -> set[str]:
    """Distinct timezones referenced by a version's time windows."""
    tzs = {"UTC"}
    for r in rules_data:
        conds = r.get("conditions") or {}
        tw = conds.get("time_window") or {}
        if tw.get("tz"):
            tzs.add(tw["tz"])
        notice = conds.get("notice") or {}
        sched = notice.get("schedule") or {}
        if sched.get("tz"):
            tzs.add(sched["tz"])
    return tzs


class _InputBuildError(Exception):
    """The input document cannot be built: fail closed (deny)."""


def now_by_tz(now: dt.datetime, tzs: set[str]) -> dict[str, dict[str, Any]]:
    """Per-tz wall clock for time windows (Rego has no tz database).

    Seconds are truncated (matching the Python reference semantics);
    weekday is 3-letter lowercase ("mon").
    """
    out: dict[str, dict[str, Any]] = {}
    for tz in sorted(tzs):
        try:
            zone = ZoneInfo(tz)
        except ZoneInfoNotFoundError as exc:
            raise _InputBuildError(f"unknown timezone {tz!r}") from exc
        local = now.astimezone(zone)
        out[tz] = {
            "iso": local.isoformat(),
            "weekday": local.strftime("%a").lower(),
            "minutes": local.hour * 60 + local.minute,
        }
    return out


def data_snapshot_id(
    policy_version: Optional[int],
    rules_data: list[dict[str, Any]],
    ontology_snapshot: Optional[dict[str, Any]],
) -> str:
    """Fingerprint the policy data behind a decision (input versioning).

    ``"pv<N>/rules:<sha>/ont:<sha|none>"``: the policy version, the
    sha256 of the canonical rule data, and the sha256 of the ontology
    input slice (or ``"none"``). Identical inputs -> identical ids, so
    an audit row's ``data_snapshot_id`` reproduces exactly what the
    sidecar judged. The *decision* snapshot (PAA04, captured
    post-decision) travels separately as ``ontology_snapshot_ref``.
    """

    def _sha(obj: Any) -> str:
        canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()[:16]

    rules_sha = _sha(rules_data)
    ont_sha = _sha(ontology_snapshot) if ontology_snapshot is not None else "none"
    return f"pv{policy_version}/rules:{rules_sha}/ont:{ont_sha}"


def opa_check_rules(rules: list[dict[str, Any]]) -> list[str]:
    """Save-time gate: ``opa check`` + ``rule_problems`` evaluation.

    Generates package gateway.savecheck over the rule data and runs
    the pinned OPA binary: first ``opa check`` (syntax/types against
    the decision library), then ``opa eval`` of
    ``data.gateway.savecheck.problems`` (semantic problems). Returns
    the problem strings (empty = valid). Raises OpaUnavailable when
    the binary cannot run — the save fails closed (loud), never
    silently.
    """
    from .opa_client import resolve_binary

    binary = resolve_binary()  # raises OpaUnavailable when missing
    policies_dir = default_policies_dir()
    module = (
        "package gateway.savecheck\n"
        "import data.gateway.authz\n"
        f"rules := {json.dumps(rules)}\n"
        "problems := union({authz.rule_problems(r) | some r in rules})\n"
    )
    with tempfile.TemporaryDirectory(prefix="gateway-savecheck-") as td:
        gen = Path(td) / "savecheck.rego"
        gen.write_text(module)
        check = subprocess.run(
            [str(binary), "check", str(policies_dir), td],
            capture_output=True, text=True, timeout=60,
        )
        if check.returncode != 0:
            raise ValueError(
                "opa check rejected the generated policy "
                f"(OPA v{OPA_VERSION}): {check.stderr.strip()[-2000:]}"
            )
        ev = subprocess.run(
            [
                str(binary), "eval",
                "-d", str(policies_dir), "-d", td,
                "--format", "json",
                "data.gateway.savecheck.problems",
            ],
            capture_output=True, text=True, timeout=60,
        )
        if ev.returncode != 0:
            raise OpaUnavailable(
                f"opa eval failed at rule-save time: {ev.stderr.strip()[-1000:]}"
            )
        try:
            payload = json.loads(ev.stdout)
            problems = payload["result"][0]["expressions"][0]["value"]
        except (KeyError, IndexError, ValueError) as exc:
            raise OpaUnavailable(
                f"opa eval returned an unparseable result: {exc}"
            ) from exc
        return sorted(str(p_) for p_ in problems)


# ---------------------------------------------------------------------
# Shared sidecar client (one supervised opa process per gateway
# process — the spike's recommendation). Engines take an explicit
# client when the caller manages lifecycle (tests, servers); otherwise
# they share this one, started lazily on first evaluation.
# ---------------------------------------------------------------------

_shared_opa: Optional[OpaClient] = None
_shared_opa_lock = threading.Lock()


def shared_opa_client() -> OpaClient:
    """Process-shared OPA sidecar client (lazy start on first decide)."""
    global _shared_opa
    with _shared_opa_lock:
        if _shared_opa is None or not _shared_opa.running:
            _shared_opa = OpaClient()
        return _shared_opa


# ---------------------------------------------------------------------
# Policy engine
# ---------------------------------------------------------------------


def _policy_effect_label(decision: Any) -> str:
    """Latency-span label for an OPA decision.

    The Rego vocabulary is ``allow`` | ``deny`` | ``ask``; the span
    label uses the gateway's decision vocabulary (``ask`` ->
    ``require_approval``) so the latency page reads consistently with
    the audit log. Anything unexpected is labeled verbatim — a span
    label is observability only, never a decision input.
    """
    effect = decision.get("effect") if isinstance(decision, dict) else None
    if effect == "ask":
        return "require_approval"
    return str(effect) if effect else "unknown"

# M3 seam: grant_checker(agent_id, tool, argument_hash, db) ->
# Optional[Union[str, GrantCheckResult]].
# Returns a grant reference when an active one-time grant covers the
# call; None otherwise. M2 passes None (no grants exist yet). The M3
# GrantService returns a GrantCheckResult (approvals.py); a plain str
# keeps the M2 shape working (treated as an allowed grant ref).
GrantChecker = Callable[[str, str, str, Session], Optional[Any]]


class PolicyEngine:
    """Loads policy versions and evaluates calls (FR-016–FR-020)."""

    def __init__(
        self,
        db: Session,
        grant_checker: Optional[GrantChecker] = None,
        hmac_ring: Optional[Any] = None,
        sensitivity_escalator: Optional[Callable[[str, str, dict], Optional[str]]] = None,
        opa_client: Optional[OpaClient] = None,
    ):
        self.db = db
        self.grant_checker = grant_checker
        # HMAC key ring for ontology decision snapshots (PAA04). None =
        # snapshots are not captured (ontology enforcement still applies).
        self.hmac_ring = hmac_ring
        # M3: (agent_id, tool, args) -> "new_payee" | "changed_details" |
        # None. Converts an "allow" into "require_approval" for
        # commitment-adjacent actions to new/changed counterparties
        # (FR-PAA05-002). None = no escalation (M2 behavior).
        self.sensitivity_escalator = sensitivity_escalator
        # OPA sidecar client. None = the process-shared client, started
        # lazily on first evaluation (one supervised opa process per
        # gateway process). Pass an explicit client to manage lifecycle
        # (tests, server boot).
        self.opa_client = opa_client

    # -- versions ----------------------------------------------------

    def current_version_number(self) -> Optional[int]:
        row = self.db.execute(
            select(PolicyVersion).where(PolicyVersion.is_current.is_(True))
        ).scalar_one_or_none()
        return row.version if row else None

    def _version_row(self, policy_version: Optional[int]) -> Optional[PolicyVersion]:
        if policy_version is None:
            return self.db.execute(
                select(PolicyVersion).where(PolicyVersion.is_current.is_(True))
            ).scalar_one_or_none()
        return self.db.execute(
            select(PolicyVersion).where(PolicyVersion.version == policy_version)
        ).scalar_one_or_none()

    def load_rules(self, policy_version: Optional[int] = None) -> list[PolicyRule]:
        row = self._version_row(policy_version)
        if row is None:
            return []
        rules = self.db.execute(
            select(PolicyRule)
            .where(PolicyRule.policy_version_id == row.id)
            .order_by(PolicyRule.rule_order, PolicyRule.id)
        ).scalars().all()
        return list(rules)

    def version_rules_as_dicts(
        self, policy_version: Optional[int] = None
    ) -> list[dict[str, Any]]:
        out = []
        for r in self.load_rules(policy_version):
            out.append(
                {
                    "name": r.name,
                    "rule_type": r.rule_type,
                    "effect": normalize_effect(r.effect),
                    "agent_id": r.agent_id,
                    "tool": r.tool,
                    "action_class": r.action_class,
                    "household_role": r.household_role,
                    "purpose": r.purpose,
                    "conditions": r.conditions or {},
                    "description": r.description,
                }
            )
        return out

    @staticmethod
    def default_deny_row() -> dict[str, Any]:
        """The pinned, visible default-deny (02 §4.3, FR-017).

        Not a stored rule: it can never be deleted, reordered, or
        edited — it is the implicit final row of every version.
        """
        return {
            "rule_id": DEFAULT_DENY_ID,
            "name": "Default deny (pinned)",
            "rule_type": "standard",
            "effect": "deny",
            "agent_id": None,
            "tool": None,
            "pinned": True,
            "description": (
                "A call with no matching allow rule is denied and logged "
                "(FR-017). This row is pinned and cannot be removed."
            ),
        }

    def list_rules_with_default_deny(
        self, policy_version: Optional[int] = None
    ) -> list[dict[str, Any]]:
        """Console listing: stored rules in priority order + the pinned
        default-deny final row."""
        rows = self.version_rules_as_dicts(policy_version)
        return [*rows, self.default_deny_row()]

    def save_version(
        self,
        rules: list[dict[str, Any]],
        change_note: str = "",
        created_by: str = "admin",
        material_change: Optional[bool] = None,
    ) -> int:
        """Save a new IMMUTABLE policy version (02 §5).

        Nothing is edited in place; rollback = a new version copying old
        content. Every save records the material/non-material
        classification — auto-classified against the current version
        unless explicitly overridden.
        """
        validated = [validate_rule_dict(r) for r in rules]
        # Save-time OPA gate (replaces validate_rule_dict as the
        # authority): opa check + rule_problems over the generated
        # rule data. Invalid rules never reach storage (FR-PAA04-002).
        problems = opa_check_rules(validated)
        if problems:
            raise ValueError(
                "policy version rejected by OPA rule validation: "
                + "; ".join(problems[:10])
            )
        old_rules = self.version_rules_as_dicts()
        if material_change is None:
            material_change = classify_change(old_rules, validated)
        current = self.db.execute(
            select(PolicyVersion).where(PolicyVersion.is_current.is_(True))
        ).scalar_one_or_none()
        next_version = (current.version + 1) if current else 1
        if current:
            current.is_current = False
        row = PolicyVersion(
            version=next_version,
            material_change=bool(material_change),
            change_note=change_note,
            created_by=created_by,
            is_current=True,
        )
        self.db.add(row)
        self.db.flush()  # assign row.id for the rule FK
        for order, r in enumerate(validated):
            self.db.add(
                PolicyRule(
                    policy_version_id=row.id,
                    name=r.get("name", ""),
                    rule_type=r.get("rule_type", "standard"),
                    effect=r["effect"],
                    agent_id=r.get("agent_id"),
                    tool=r.get("tool"),
                    action_class=r.get("action_class"),
                    household_role=r.get("household_role"),
                    purpose=r.get("purpose"),
                    conditions=r.get("conditions") or {},
                    description=r.get("description", ""),
                    rule_order=order,
                    created_by=r.get("created_by", created_by),
                    provenance=r.get("provenance", "explicit"),
                )
            )
        self.db.commit()
        return next_version

    # -- evaluation ---------------------------------------------------

    def evaluate_call(
        self,
        agent: Any,
        tool: str,
        args: dict[str, Any],
        policy_version: Optional[int] = None,
        purpose: Optional[str] = None,
        now: Optional[dt.datetime] = None,
        ontology_ctx: Optional[dict[str, Any]] = None,
        argument_hash: Optional[str] = None,
    ) -> EvaluationResult:
        """Evaluate one call: intent -> OPA (Rego), top-down first match (02 §5).

        agent: Agent model (or a stand-in with .id / .household_role).
        purpose: the call's declared purpose (mandate.purpose_key).
        ontology_ctx: optional ``{"principal_id": ..., "dimensions": {...}}``
            for the personal-ontology integration (used as given; the
            principal falls back to the agent->principal binding).
        argument_hash: HMAC-SHA256 of the canonical args (02 §2.8 step
            3). Required for grant matching; when None the grant
            checker is skipped (fail toward rule evaluation).
        Returns (decision, matched_rule_id|None, requires_approval).

        Signature and behavior contract unchanged by the OPA pivot;
        only the evaluator internals moved to Rego.
        """
        intent = intent_from_parts(
            agent_id=getattr(agent, "id", "") or "",
            tool=tool,
            args=args,
            purpose=purpose,
            ontology_ctx=ontology_ctx,
            db=self.db,
            agent=agent,
        )
        return self.evaluate_intent(
            intent, agent, policy_version=policy_version, now=now,
            argument_hash=argument_hash,
        )

    def evaluate_intent(
        self,
        intent: Intent,
        agent: Any,
        policy_version: Optional[int] = None,
        now: Optional[dt.datetime] = None,
        argument_hash: Optional[str] = None,
    ) -> EvaluationResult:
        """Evaluate a normalized intent via the OPA sidecar.

        Fix-B order preserved: meta-tool allow, grant-before-rule
        short-circuit, and the ontology pre-checks (dimension/principal
        validation + scoped views) all run Python-side BEFORE the OPA
        call. The sidecar then judges the versioned input document;
        "ask" maps to require_approval. Any sidecar failure denies
        (03 §7 fail-closed).
        """
        now = now or dt.datetime.now(dt.timezone.utc)
        row = self._version_row(policy_version)
        version_number = row.version if row else policy_version
        tool = intent.action
        agent_id = intent.agent_id

        # Meta tools (02 §2.5): gateway.approval_status is routine by
        # design — allowed before rules, with its own rate budget and
        # audit carve-out handled at the tool/pipeline layer.
        if tool in META_TOOLS:
            return EvaluationResult(
                "allow", None, False,
                policy_version=version_number,
                scope_rule=f"meta:{tool}",
            )

        # Grant-before-rule short-circuit (Fix B, MF-7) — Python-side.
        if self.grant_checker is not None and row is not None and argument_hash is not None:
            grant_ref = self.grant_checker(agent_id, tool, argument_hash, self.db)
            if grant_ref is not None:
                if isinstance(grant_ref, str):
                    # Legacy M2 shape: plain grant reference → allow.
                    return EvaluationResult(
                        "allow", None, False,
                        policy_version=version_number,
                        scope_rule=f"grant:{grant_ref}",
                        via_grant=True,
                    )
                # M3 shape: GrantCheckResult (approvals.py).
                if grant_ref.allowed:
                    return EvaluationResult(
                        "allow", None, False,
                        policy_version=version_number,
                        scope_rule=f"grant:{grant_ref.approval_request_id}",
                        via_grant=True,
                        approval_request_id=grant_ref.approval_request_id,
                    )
                if grant_ref.terminal_code is not None:
                    return EvaluationResult(
                        "deny", None, False,
                        policy_version=version_number,
                        terminal_code=grant_ref.terminal_code,
                    )
                return EvaluationResult(
                    "deny", None, False,
                    policy_version=version_number,
                    deny_reason=grant_ref.deny_reason,
                )

        # --- Ontology pre-checks (Python-side, fail-closed) -------------
        # Hot-path rule cache (M6, AC-11): versions are immutable, so the
        # generated rule data is cached process-wide per (db, version).
        # The version-pointer query above stays uncached (one indexed
        # read), so a newly saved version applies on the next call.
        rules_data = (
            _cached_rules_data(self.db, version_number)
            if version_number is not None
            else None
        )
        if rules_data is None:
            rules_data = [
                rule_to_input_data(r) for r in self.load_rules(version_number)
            ]
            if version_number is not None:
                _store_rules_data(self.db, version_number, rules_data)
        id_to_name = {r["id"]: (r.get("name") or "") for r in rules_data}

        ont_state = None
        ontology_snapshot: Optional[dict[str, Any]] = None
        if intent.ontology_context is not None:
            ont_state, ont_invalid = _ontology.resolve_ctx(
                self.db, intent.ontology_context, agent
            )
            if ont_invalid:
                # Unknown dimension name/value or unknown principal:
                # default-deny, never a silent pass.
                return EvaluationResult(
                    "deny", None, False, policy_version=version_number,
                    data_snapshot_id=data_snapshot_id(
                        version_number, rules_data, None
                    ),
                )
            ontology_snapshot = self._ontology_snapshot_data(ont_state)
            # Per-agent scoped views (PAA08): a bound agent may only
            # resolve principals / dimension values / resources inside
            # its own slice. Outside the view → fail closed, citing
            # the ontology entry that defines the boundary.
            if agent_id:
                _scoped_state, scoped_invalid, scoped_ref = (
                    _ontology.resolve_ctx_for_agent(
                        self.db,
                        intent.ontology_context,
                        agent_id,
                        mandate_purpose_keys=(
                            [intent.purpose] if intent.purpose else None
                        ),
                    )
                )
                if scoped_invalid:
                    ref = dict(scoped_ref or {})
                    ref["snapshot_ref"] = self._ontology_scope_snapshot(
                        agent_id, intent.ontology_context, intent.purpose,
                        version_number,
                    )
                    return EvaluationResult(
                        "deny", None, False,
                        policy_version=version_number,
                        ontology_ref=ref,
                        data_snapshot_id=data_snapshot_id(
                            version_number, rules_data, ontology_snapshot
                        ),
                    )

        # --- Versioned input document -----------------------------------
        try:
            input_doc = self._build_input_document(
                intent, agent, version_number, now, rules_data,
                ontology_snapshot,
            )
        except _InputBuildError as exc:
            log.warning("policy input build failed (fail closed): %s", exc)
            return EvaluationResult(
                "deny", None, False, policy_version=version_number,
                scope_rule="input_build_error",
                data_snapshot_id=data_snapshot_id(
                    version_number, rules_data, ontology_snapshot
                ),
            )
        snapshot_id = input_doc["data_snapshot_id"]

        # --- OPA decision (fail-closed) ----------------------------------
        # AC-11 latency instrumentation: time ONLY the OPA decide call
        # (the policy-path budget); the span is labeled with the
        # decision effect, or the fail-closed marker when the call
        # itself failed. Recording is advisory — it never changes the
        # decision, ordering, or error handling below.
        opa = self.opa_client or shared_opa_client()
        _t0 = time.perf_counter()
        try:
            decision = opa.decide(input_doc)
        except OpaUnavailable as exc:
            record(
                "policy", (time.perf_counter() - _t0) * 1000.0,
                label="opa_unavailable",
            )
            # 03 §7: policy-engine failure -> default-deny (FR-017).
            # The agent-visible reason stays the safe "no_allow_rule";
            # scope_rule="opa_unavailable" is internal-only (audit).
            log.warning("OPA sidecar unavailable (fail closed): %s", exc)
            return EvaluationResult(
                "deny", None, False, policy_version=version_number,
                scope_rule="opa_unavailable",
                data_snapshot_id=snapshot_id,
            )
        except Exception:  # noqa: BLE001 — any unexpected error denies
            record(
                "policy", (time.perf_counter() - _t0) * 1000.0,
                label="opa_error",
            )
            log.exception("OPA decide raised unexpectedly (fail closed)")
            return EvaluationResult(
                "deny", None, False, policy_version=version_number,
                scope_rule="opa_unavailable",
                data_snapshot_id=snapshot_id,
            )
        record(
            "policy", (time.perf_counter() - _t0) * 1000.0,
            label=_policy_effect_label(decision),
        )

        return self._result_from_decision(
            decision, input_doc, ont_state, id_to_name, intent, agent, tool,
            argument_hash,
        )

    # -- input document -------------------------------------------------

    def _ontology_scope_snapshot(
        self,
        agent_id: str,
        ontology_ctx: dict[str, Any],
        purpose: Optional[str],
        version_number: Optional[int],
    ) -> Optional[str]:
        """Snapshot the scoped-view slice behind a scope denial (PAA04).

        Returns the content-addressed ref, or None when no HMAC ring is
        configured (snapshots are not captured then — enforcement still
        applies).
        """
        if self.hmac_ring is None:
            return None
        view = _ontology.scoped_view(
            self.db,
            agent_id,
            mandate_purpose_keys=[purpose] if purpose else None,
        )
        return capture_snapshot(
            self.db,
            self.hmac_ring,
            SnapshotInput(
                principal_id=view.bound_principal_id,
                dimensions=dict((ontology_ctx.get("dimensions") or {})),
                dimension_group_ids=sorted(view.dimension_group_ids),
                preference_group_ids=[],
                matched_rule_id=None,
                policy_version=version_number,
            ),
        )

    def _build_input_document(
        self,
        intent: Intent,
        agent: Any,
        version_number: Optional[int],
        now: dt.datetime,
        rules_data: list[dict[str, Any]],
        ontology_snapshot: Optional[dict[str, Any]],
    ) -> dict[str, Any]:
        """Assemble the frozen ``intent-policy-input/v1`` document."""
        doc: dict[str, Any] = {
            "schema_version": INPUT_SCHEMA_VERSION,
            "policy_version": version_number,
            "data_snapshot_id": "",  # filled below
            "agent": {
                "id": intent.agent_id,
                "household_role": getattr(agent, "household_role", None),
            },
            "intent": {
                "agent_id": intent.agent_id,
                "principal_on_whose_behalf": intent.principal_on_whose_behalf,
                "action": intent.action,
                "resource_type": intent.resource_type,
                "resource_id": intent.resource_id,
                "params": intent.params,
                "purpose": intent.purpose,
                "ontology_context": intent.ontology_context,
                "mandate_refs": list(intent.mandate_refs),
                "grant_refs": list(intent.grant_refs),
            },
            "ontology_snapshot": ontology_snapshot,
            "mandates": self._mandates_data(intent.agent_id),
            "grants": [],
            "rules": rules_data,
            "now": now.isoformat(),
            "now_by_tz": now_by_tz(now, rules_timezones(rules_data)),
        }
        # NOTE: the ontology *decision* snapshot ref is captured after
        # the decision (it depends on which groups shaped it); the
        # input carries the slice, not the ref. The data_snapshot_id
        # fingerprints the rule data + ontology input slice here; the
        # decision snapshot ref is recorded separately on the audit row
        # (ontology_snapshot_ref).
        doc["data_snapshot_id"] = data_snapshot_id(
            version_number, rules_data, ontology_snapshot
        )
        return doc

    def _ontology_snapshot_data(self, ont_state: Optional[Any]) -> Optional[dict[str, Any]]:
        """The resolved ontology slice for the Rego input.

        All dimension groups / preference groups travel in full; Rego
        computes applicability (pure, testable). Enforcement of scoped
        views and dimension validation stays Python-side (pre-checks).
        """
        if ont_state is None:
            return None
        principal = None
        relationships: list[dict[str, str]] = []
        if ont_state.principal_id is not None:
            prow = self.db.get(OntologyPrincipal, ont_state.principal_id)
            if prow is not None:
                principal = {
                    "id": prow.id,
                    "kind": prow.kind,
                    "display_name": prow.display_name,
                }
            rels = self.db.execute(
                select(OntologyRelationship).where(
                    (OntologyRelationship.source_principal_id == ont_state.principal_id)
                    | (OntologyRelationship.target_principal_id == ont_state.principal_id)
                )
            ).scalars().all()
            relationships = [
                {
                    "source": r.source_principal_id,
                    "type": r.relation_type,
                    "target": r.target_principal_id,
                }
                for r in rels
            ]
            relationships.sort(key=lambda d: (d["source"], d["type"], d["target"]))
        dim_groups = [
            {"id": g.id, "name": g.name, "dimensions": dict(g.dimensions or {})}
            for g in self.db.execute(
                select(OntologyDimensionGroup).order_by(OntologyDimensionGroup.id)
            ).scalars().all()
        ]
        pref_groups = [
            {
                "id": g.id,
                "name": g.name,
                "dimension_group_id": g.dimension_group_id,
                "constraints": dict(g.constraints or {}),
            }
            for g in self.db.execute(
                select(OntologyPreferenceGroup).order_by(OntologyPreferenceGroup.id)
            ).scalars().all()
        ]
        return {
            "principal_id": ont_state.principal_id,
            "principal": principal,
            "dimensions": dict(ont_state.dimensions),
            "dimension_groups": dim_groups,
            "preference_groups": pref_groups,
            "relationships": relationships,
        }

    def _mandates_data(self, agent_id: str) -> list[dict[str, Any]]:
        """Live mandates for the input document (informational context).

        Mandate LIVENESS is enforced Python-side (MandateStage, grant
        consumption re-check) — never by Rego. The array lets rules see
        mandate state without consulting the DB.
        """
        if not agent_id:
            return []
        from .mandates import MandateService

        out = []
        for m in MandateService(self.db).live_mandates(agent_id):
            out.append(
                {
                    "id": m.id,
                    "status": m.status,
                    "purpose_key": m.purpose_key,
                    "tools": list(m.allowed_classes or []),
                    "expires_at": (
                        m.expires_at.isoformat() if m.expires_at else None
                    ),
                }
            )
        return out

    # -- decision mapping -----------------------------------------------

    def _result_from_decision(
        self,
        decision: dict[str, Any],
        input_doc: dict[str, Any],
        ont_state: Optional[Any],
        id_to_name: dict[Any, str],
        intent: Intent,
        agent: Any,
        tool: str,
        argument_hash: Optional[str],
    ) -> EvaluationResult:
        """Map the Rego decision contract to an EvaluationResult."""
        version_number = input_doc["policy_version"]
        snapshot_id = input_doc["data_snapshot_id"]
        effect = decision.get("effect")
        rule_ref = decision.get("rule")

        matched_rule_id: Optional[int] = None
        if isinstance(rule_ref, int):
            matched_rule_id = rule_ref
        elif rule_ref != "default_deny":
            # Defensive: the contract says int|"default_deny". Anything
            # else fails closed (deny) rather than misattributing.
            log.warning("OPA decision bad rule ref %r (fail closed)", rule_ref)
            return EvaluationResult(
                "deny", None, False, policy_version=version_number,
                scope_rule="opa_bad_decision",
                data_snapshot_id=snapshot_id,
            )

        # PAA04: capture the ontology decision snapshot when the
        # ontology shaped the decision — the Rego sets ontology_shaped
        # on allow AND deny effects (GH #25) whenever the deciding rule
        # had an ontology clause or a preference group was applicable.
        # The snapshot (and the ontology_ref entry citation) is therefore
        # present for ontology-driven denies too, not just allows.
        snapshot_ref: Optional[str] = None
        if decision.get("ontology_shaped") and self.hmac_ring is not None:
            snapshot_ref = capture_snapshot(
                self.db,
                self.hmac_ring,
                SnapshotInput(
                    principal_id=(
                        ont_state.principal_id if ont_state else None
                    ),
                    dimensions=dict(ont_state.dimensions) if ont_state else {},
                    dimension_group_ids=list(
                        decision.get("dimension_group_ids") or []
                    ),
                    preference_group_ids=list(
                        decision.get("preference_group_ids") or []
                    ),
                    matched_rule_id=matched_rule_id,
                    policy_version=version_number,
                ),
            )

        # Deny/ask reasons cite the ontology/policy entry: the Rego
        # supplies {entry_id, entry_kind}; Python attaches the decision
        # snapshot ref (it owns the HMAC ring).
        ontology_ref: Optional[dict[str, Any]] = None
        raw_ref = decision.get("ontology_ref")
        if isinstance(raw_ref, dict) and raw_ref.get("entry_id") is not None:
            ontology_ref = {
                "entry_id": raw_ref.get("entry_id"),
                "entry_kind": raw_ref.get("entry_kind"),
                "snapshot_ref": snapshot_ref,
            }
        elif decision.get("ontology_shaped") and matched_rule_id is not None:
            # GH #25: the Rego cites an ontology entry only on the
            # preference-group / owner-approval paths. For a plain
            # ontology-clause rule (allow or deny), synthesize the
            # citation from the deciding rule — otherwise the entry
            # citation is missing for ontology-driven decisions.
            ontology_ref = {
                "entry_id": f"rule:{matched_rule_id}",
                "entry_kind": "rule",
                "snapshot_ref": snapshot_ref,
            }

        if effect == "allow":
            name = id_to_name.get(matched_rule_id, "")
            return self._maybe_escalate(
                EvaluationResult(
                    "allow", matched_rule_id, False,
                    policy_version=version_number,
                    scope_rule=(
                        f"rule:{matched_rule_id}:{name or tool or 'unnamed'}"
                        if matched_rule_id is not None else None
                    ),
                    ontology_snapshot_ref=snapshot_ref,
                    # GH #24: the entry citation travels on allows too, so
                    # a counterparty escalation (allow → require_approval)
                    # can carry it into the approval record.
                    ontology_ref=ontology_ref,
                    data_snapshot_id=snapshot_id,
                ),
                agent, tool, intent.params,
            )
        if effect == "deny":
            return EvaluationResult(
                "deny", matched_rule_id, False,
                policy_version=version_number,
                ontology_snapshot_ref=snapshot_ref,
                ontology_ref=ontology_ref,
                data_snapshot_id=snapshot_id,
            )
        if effect == "ask":
            # "ask" maps to the existing require_approval Fix-B flow
            # UNCHANGED (the pipeline/approval stages see
            # require_approval exactly as before).
            return EvaluationResult(
                "require_approval", matched_rule_id, True,
                policy_version=version_number,
                ontology_snapshot_ref=snapshot_ref,
                ontology_ref=ontology_ref,
                data_snapshot_id=snapshot_id,
            )
        # Unreachable: the client validates the effect. Belt and braces.
        log.warning("OPA decision bad effect %r (fail closed)", effect)
        return EvaluationResult(
            "deny", None, False, policy_version=version_number,
            scope_rule="opa_bad_decision",
            data_snapshot_id=snapshot_id,
        )

    def _maybe_escalate(
        self, result: EvaluationResult, agent: Any, tool: str, args: dict[str, Any]
    ) -> EvaluationResult:
        """M3 counterparty escalation (FR-PAA05-002).

        A commitment-adjacent action to a new payee (or with details
        changed vs the recorded record) is classified sensitive
        automatically: an "allow" becomes "require_approval" carrying
        the escalation reason for the approval card. Deny/require_approval
        decisions pass through untouched.
        """
        if result.decision != "allow" or self.sensitivity_escalator is None:
            return result
        try:
            reason = self.sensitivity_escalator(agent.id, tool, args or {})
        except Exception:  # noqa: BLE001 — escalator failure fails CLOSED
            reason = "escalator_error"
        if reason is None:
            return result
        # GH #24: carry the traceability fields into the escalated result.
        # The approval record and audit row for an escalated call must not
        # lose which rule allowed it (FR-PAA01-007 scope_rule), the PAA04
        # ontology snapshot ref / entry citation, or the input-document
        # version — escalated calls are exactly the highest-risk ones.
        return EvaluationResult(
            "require_approval", result.matched_rule_id, True,
            policy_version=result.policy_version,
            scope_rule=result.scope_rule,
            ontology_snapshot_ref=result.ontology_snapshot_ref,
            ontology_ref=result.ontology_ref,
            data_snapshot_id=result.data_snapshot_id,
            escalation_reason=reason,
        )


# ---------------------------------------------------------------------
# The M2 pipeline stage (replaces the pipeline.py M1 stub at the
# "policy" position via build_pipeline()).
# ---------------------------------------------------------------------

class PolicyStage:
    """Step 4: real policy evaluation (M2; M3 wires the approval flow).

    Replaces the M1 default-deny stub. Fail-closed: any evaluation
    problem denies. Denials use the safe-vocabulary reasons only
    (02 §2.7) — no rule text or ids leak to the agent.

    M2 behavior (default): ``require_approval`` halts here with the
    ``approval_required`` error shape.
    M3 behavior (``defer_approval=True``, set when an ApprovalService
    is wired): ``require_approval`` sets ``ctx.needs_approval`` and
    passes through so the ApprovalStage (step 5) runs the 02 §2.8
    step-3 lookup chain and creates the ``apr_`` request. The decision
    vocabulary is unchanged.

    JUDGE risk advisor (``risk_scorer``; default None = off): an
    optional ``(intent, ctx) -> RiskScore | None`` consulted AFTER the
    policy decision, on allowed calls only. A "high" rating steps the
    call up to approval (allow→ask). It can never turn a deny into an
    allow and never runs in front of policy evaluation.
    """

    name = "policy"

    def __init__(
        self,
        db: Session,
        grant_checker: Optional[GrantChecker] = None,
        hmac_ring: Optional[Any] = None,
        defer_approval: bool = False,
        sensitivity_escalator: Optional[Callable[[str, str, dict], Optional[str]]] = None,
        unknown_outcome_gate: Any = None,
        risk_scorer: Optional[Callable[[Any, Any], Any]] = None,
    ):
        self.engine = PolicyEngine(
            db, grant_checker=grant_checker, hmac_ring=hmac_ring,
            sensitivity_escalator=sensitivity_escalator,
        )
        self.hmac_ring = hmac_ring
        self.defer_approval = defer_approval
        self.unknown_outcome_gate = unknown_outcome_gate
        self.risk_scorer = risk_scorer

    def run(self, ctx: Any) -> Any:  # CallContext; typed loosely to avoid a cycle
        # FR-PAA06-003: an unresolved unknown-outcome block stops the
        # retry BEFORE grant/rule evaluation — even a live grant does
        # not bypass it.
        if self.unknown_outcome_gate is not None and ctx.argument_hash is not None:
            block = self.unknown_outcome_gate.find_unresolved(
                ctx.agent_id, ctx.tool, ctx.argument_hash
            )
            if block is not None:
                return make_error(
                    "upstream_failure",
                    f"{ctx.tool}: retry blocked — unknown outcome pending "
                    "console resolution (status check first)",
                    ctx.request_id,
                    {"tool": ctx.tool, "unknown_outcome": True, "retry_blocked": True},
                )
        with timing_span(ctx, "policy"):
            if ctx.agent is None:
                # Unreachable after AuthenticateStage; fail closed.
                return policy_denied(
                    ctx.request_id, "no_allow_rule",
                    f"{ctx.tool}: denied by default-deny (no allow rule)",
                    tool=ctx.tool,
                )
            # ONTOLOGY -> INTENT -> OPEN POLICY: normalize the call to
            # an intent (M6 checklist (a): the ontology context comes
            # from the agent->principal binding + the mandate's purpose;
            # unbound agents keep the legacy path), then evaluate.
            intent = normalize_intent(ctx, self.engine.db)
            result = self.engine.evaluate_intent(
                intent, ctx.agent, argument_hash=ctx.argument_hash,
            )
            ctx.policy_version = result.policy_version or ctx.policy_version
            # M6 checklist (b): traceability fields for the audit row.
            ctx.data_snapshot_id = result.data_snapshot_id
            ctx.ontology_snapshot_ref = result.ontology_snapshot_ref
            ctx.ontology_ref = result.ontology_ref
        if result.terminal_code == "already_executed":
            # The grant was already consumed (lost a concurrent race):
            # terminal, no new request, no re-execution (02 §2.8 step 9).
            return make_error(
                "already_executed",
                f"{ctx.tool}: this exact call already executed",
                ctx.request_id,
                {"tool": ctx.tool, "reason": "already_executed"},
            )
        if result.decision == "deny":
            reason = result.deny_reason or (
                "explicit_deny" if result.matched_rule_id is not None else "no_allow_rule"
            )
            ctx.scope_rule = None
            message = (
                f"{ctx.tool}: denied by policy"
                if reason == "explicit_deny"
                else f"{ctx.tool}: {reason}"
            )
            # M6 checklist (c): deny reasons cite the ontology/policy
            # entry (opaque ont_ ids only — safe vocabulary unchanged).
            return policy_denied(
                ctx.request_id, reason, message, tool=ctx.tool,
                ontology_ref=result.ontology_ref,
            )
        if result.decision == "require_approval":
            ctx.scope_rule = None
            if self.defer_approval:
                # M3: the ApprovalStage (step 5) creates the apr_
                # request via the step-3 lookup chain. The ontology
                # citation rides on ctx for the approval record.
                ctx.needs_approval = True
                ctx.escalation_reason = result.escalation_reason
                return None
            return make_error(
                "approval_required",
                f"{ctx.tool}: sensitive action requires step-up approval",
                ctx.request_id,
                {"tool": ctx.tool},
            )
        if result.via_grant:
            ctx.via_grant = True
            ctx.approval_request_id = result.approval_request_id
        # Judge risk advisor (advisory; allow→ask only). Consulted
        # AFTER the policy decision — never in front of it — and can
        # only ADD friction: a "high" rating on an allowed call steps
        # up to approval. Deny / require_approval / grant paths are
        # untouched, and the advisor can never turn a deny into an
        # allow. Default off (risk_scorer=None): behavior identical.
        if self.risk_scorer is not None and not result.via_grant:
            with timing_span(ctx, "policy.judge_risk"):
                try:
                    risk = self.risk_scorer(intent, ctx)
                except Exception:  # noqa: BLE001 — advisory: never break the policy path
                    risk = None
            if risk is not None and apply_risk_step_up(ctx, result.decision, risk):
                # Stepped up: allow → ask. With deferral the
                # ApprovalStage (step 5) creates the apr_ request; in
                # M2 mode the call halts with approval_required, exactly
                # like a policy require_approval.
                ctx.escalation_reason = ctx.escalation_reason or "judge_high_risk"
                if self.defer_approval:
                    return None
                return make_error(
                    "approval_required",
                    f"{ctx.tool}: sensitive action requires step-up approval",
                    ctx.request_id,
                    {"tool": ctx.tool, "judge_step_up": True},
                )
        ctx.scope_rule = result.scope_rule
        return None


# ---------------------------------------------------------------------
# History dry-run (AC-12, 02 §2.6)
# ---------------------------------------------------------------------

#: Synthetic per-tool corpus for the cold-start case (00 §7 param 17).
#: Hand-written, labeled "synthetic" in the output (02 §2.6).
SYNTHETIC_CORPUS: list[dict[str, Any]] = [
    {"tool": "email.search", "args": {"query": "invoice", "limit": 10}},
    {"tool": "email.read", "args": {"message_id": "msg_synth_001"}},
    {
        "tool": "email.send",
        "args": {
            "to": ["ken@example.com"],
            "subject": "Synthetic notice",
            "body": "This is a synthetic dry-run call.",
        },
    },
    {
        "tool": "email.draft",
        "args": {
            "to": ["ken@example.com"],
            "subject": "Synthetic draft",
            "body": "This is a synthetic dry-run call.",
        },
    },
    {"tool": "email.settings.read", "args": {"section": "forwarding"}},
    {
        "tool": "email.settings.write",
        "args": {"section": "forwarding", "settings": {"enabled": False}},
    },
    {
        "tool": "calendar.list",
        "args": {"start": "2026-10-12T00:00:00Z", "end": "2026-10-13T00:00:00Z"},
    },
    {
        "tool": "calendar.create",
        "args": {
            "title": "Synthetic meeting",
            "start": "2026-10-13T10:00:00Z",
            "end": "2026-10-13T10:30:00Z",
        },
    },
    {
        "tool": "calendar.update",
        "args": {"event_id": "evt_synth_001", "title": "Renamed synthetic meeting"},
    },
    {"tool": "calendar.delete", "args": {"event_id": "evt_synth_001"}},
    {
        "tool": "code.file.read",
        "args": {"repo": "kenhuangus/example", "path": "README.md"},
    },
    {
        "tool": "code.pr.open",
        "args": {
            "repo": "kenhuangus/example",
            "title": "Synthetic PR",
            "head": "feature/synthetic",
            "base": "main",
            "body": "Synthetic dry-run call.",
        },
    },
]

#: Recorded audit decisions → dry-run outcome classes.
_RECORDED_TO_OUTCOME = {
    "allowed": "allow",
    "allowed_via_approval": "allow",
    "approved": "allow",
    "denied": "deny",
    "denied_decision": "deny",
    "approval_required": "require_approval",
}


def dry_run(
    config_db: Session,
    audit_db: Session,
    policy_version: int,
    window_days: int = 7,
    known_tools: Optional[set[str]] = None,
) -> dict[str, Any]:
    """Replay a policy version against history (AC-12, 02 §2.6).

    Returns {"counts": {would_allow, would_deny, would_require_approval},
    "changed_calls": [...], "corpus": "history"|"synthetic"}.

    History rows are re-evaluated on their REDACTED args (the audit log
    never holds plaintext — an acknowledged approximation). Rows for
    unknown tools, unknown agents, or unmapped decisions are skipped.
    Cold start (no usable history): the hand-written synthetic corpus,
    labeled as such.
    """
    from .audit import AuditLog  # local import: audit does not import policy

    engine = PolicyEngine(config_db)
    audit = AuditLog(audit_db)
    since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=window_days)
    rows = audit.search(since=since, limit=100000)

    counts = {"would_allow": 0, "would_deny": 0, "would_require_approval": 0}
    changed_calls: list[dict[str, Any]] = []
    usable = 0

    for row in rows:
        recorded = _RECORDED_TO_OUTCOME.get(row.decision)
        if recorded is None:
            continue  # error/expired rows have no allow/deny baseline
        if known_tools is not None and row.tool not in known_tools:
            continue
        agent = config_db.get(Agent, row.agent_id)
        if agent is None:
            continue
        purpose = None
        if row.mandate_id:
            mandate = config_db.get(Mandate, row.mandate_id)
            if mandate is not None:
                purpose = mandate.purpose_key
        result = engine.evaluate_call(
            agent, row.tool, row.redacted_args or {}, policy_version, purpose=purpose
        )
        usable += 1
        counts[f"would_{result.decision}"] += 1
        if result.decision != recorded:
            changed_calls.append(
                {
                    "request_id": row.request_id,
                    "agent_id": row.agent_id,
                    "tool": row.tool,
                    "recorded": recorded,
                    "would_be": result.decision,
                    "timestamp": row.timestamp.isoformat() if row.timestamp else None,
                }
            )

    if usable:
        return {
            "counts": counts,
            "changed_calls": changed_calls,
            "corpus": "history",
        }

    # Cold start: synthetic corpus (00 §7 param 17), labeled as such.
    synthetic_agent = _SyntheticAgent()
    for call in SYNTHETIC_CORPUS:
        result = engine.evaluate_call(
            synthetic_agent, call["tool"], call["args"], policy_version
        )
        counts[f"would_{result.decision}"] += 1
        changed_calls.append(
            {
                "request_id": None,
                "agent_id": synthetic_agent.id,
                "tool": call["tool"],
                "recorded": None,
                "would_be": result.decision,
                "synthetic": True,
            }
        )
    return {"counts": counts, "changed_calls": changed_calls, "corpus": "synthetic"}


class _SyntheticAgent:
    """Stand-in agent for the synthetic dry-run corpus."""

    id = "synthetic"
    household_role = "synthetic"
