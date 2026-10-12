"""M2 policy-engine tests — Personal Agent Security Gateway.

Covers (per the M2 task):
- allow/deny end-to-end per agent/tool (engine + pipeline)
- default-deny AC-03 (no allow rule → deny + logged with reason)
- explicit deny + first-match priority
- pinned visible default-deny row
- purpose binding (FR-PAA03-002)
- household-role scoping (FR-PAA08-001)
- time windows + argument constraints
- require_approval decisions
- immutable versions + material/non-material classification
- dry-run counts + changed_calls + synthetic cold-start corpus
- template-bound notice rules (FR-PAA07-005)
- denial rows logged with safe-vocabulary reasons (no rule text/ids)
"""

from __future__ import annotations

import datetime as dt
import json
from types import SimpleNamespace

import pytest

from gateway.audit import AuditLog
from gateway.config import Settings
from gateway.db import Databases
from gateway.errors import SAFE_REASONS
from gateway.identity import IdentityService
from gateway.mandates import MandateService
from gateway.pipeline import (
    AuthenticateStage,
    ConnectorRegistry,
    ToolDescriptor,
    build_pipeline,
)
from gateway.policy import (
    PolicyEngine,
    classify_change,
    dry_run,
    validate_rule_dict,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

HMAC_KEY = "test-hmac-key-material-32bytes!"


@pytest.fixture()
def settings(tmp_path):
    return Settings(
        config_db_path=str(tmp_path / "config.db"),
        audit_db_path=str(tmp_path / "audit.db"),
        hmac_key=HMAC_KEY,
    )


@pytest.fixture()
def dbs(settings):
    d = Databases(settings.config_db_path, settings.audit_db_path)
    d.create_all()
    return d


@pytest.fixture()
def config_db(dbs):
    with dbs.config.session() as s:
        yield s


@pytest.fixture()
def audit_db(dbs):
    with dbs.audit.session() as s:
        yield s


def _register(config_db, agent_id, household_role):
    ident = IdentityService(config_db)
    agent, client_id, client_secret = ident.register_agent(
        agent_id, "muse", f"Agent {agent_id}", household_role
    )
    return agent, client_secret


@pytest.fixture()
def ken_agent(config_db):
    agent, secret = _register(config_db, "ag_ken", "ken")
    MandateService(config_db).create_mandate(
        agent.id, "test mandate", ["test.echo"], purpose_key="work"
    )
    return {"agent": agent, "secret": secret}


@pytest.fixture()
def spouse_agent(config_db):
    agent, secret = _register(config_db, "ag_spouse", "spouse")
    MandateService(config_db).create_mandate(
        agent.id, "test mandate", ["test.echo"], purpose_key="personal"
    )
    return {"agent": agent, "secret": secret}


@pytest.fixture()
def echo_registry():
    registry = ConnectorRegistry()

    def echo(ctx, args):
        return {"echo": args}

    registry.register(
        "test",
        [
            ToolDescriptor(
                name="test.echo",
                description="echo",
                input_schema={"type": "object"},
                sensitivity="routine",
                handler=echo,
            )
        ],
    )
    return registry


def _pipeline(dbs, settings, registry, agent_id, secret):
    with dbs.config.session() as config_db, dbs.audit.session() as audit_db:
        pipeline, reg, auth_stage = build_pipeline(
            config_db, audit_db, settings, registry=registry
        )
        auth_stage.presented[agent_id] = secret
        return pipeline, reg, auth_stage, config_db, audit_db


def _save(config_db, rules, note="", material=None):
    return PolicyEngine(config_db).save_version(
        rules, change_note=note, material_change=material
    )


# ---------------------------------------------------------------------------
# Engine: allow/deny/default-deny
# ---------------------------------------------------------------------------

class TestEvaluation:
    def test_allow_per_agent_tool(self, config_db, ken_agent):
        v = _save(config_db, [
            {"name": "ken echo", "effect": "allow",
             "agent_id": "ag_ken", "tool": "test.echo"},
        ])
        eng = PolicyEngine(config_db)
        res = eng.evaluate_call(ken_agent["agent"], "test.echo", {}, v)
        assert res.decision == "allow"
        assert res.matched_rule_id is not None
        assert res.requires_approval is False
        assert res.policy_version == v
        assert res.scope_rule is not None

    def test_default_deny_no_rules(self, config_db, ken_agent):
        eng = PolicyEngine(config_db)
        res = eng.evaluate_call(ken_agent["agent"], "test.echo", {}, None)
        assert res.decision == "deny"
        assert res.matched_rule_id is None  # pinned row: no stored rule matched
        assert res.requires_approval is False

    def test_default_deny_no_matching_rule(self, config_db, ken_agent):
        _save(config_db, [
            {"name": "other tool", "effect": "allow", "tool": "other.tool"},
        ])
        eng = PolicyEngine(config_db)
        res = eng.evaluate_call(ken_agent["agent"], "test.echo", {}, None)
        assert (res.decision, res.matched_rule_id) == ("deny", None)

    def test_explicit_deny_first_match_wins(self, config_db, ken_agent):
        _save(config_db, [
            {"name": "deny echo", "effect": "deny", "tool": "test.echo"},
            {"name": "allow echo", "effect": "allow", "tool": "test.echo"},
        ])
        eng = PolicyEngine(config_db)
        res = eng.evaluate_call(ken_agent["agent"], "test.echo", {}, None)
        assert res.decision == "deny"
        assert res.matched_rule_id is not None

    def test_allow_first_match_wins_over_later_deny(self, config_db, ken_agent):
        _save(config_db, [
            {"name": "allow echo", "effect": "allow", "tool": "test.echo"},
            {"name": "deny echo", "effect": "deny", "tool": "test.echo"},
        ])
        eng = PolicyEngine(config_db)
        res = eng.evaluate_call(ken_agent["agent"], "test.echo", {}, None)
        assert res.decision == "allow"

    def test_tool_wildcard(self, config_db, ken_agent):
        _save(config_db, [
            {"name": "all test", "effect": "allow", "tool": "test.*"},
        ])
        eng = PolicyEngine(config_db)
        assert eng.evaluate_call(ken_agent["agent"], "test.echo", {}, None).decision == "allow"
        assert eng.evaluate_call(ken_agent["agent"], "other.echo", {}, None).decision == "deny"

    def test_agent_list_selector(self, config_db, ken_agent, spouse_agent):
        _save(config_db, [
            {"name": "both", "effect": "allow", "tool": "test.echo",
             "conditions": {"agents": ["ag_ken", "ag_spouse"]}},
        ])
        eng = PolicyEngine(config_db)
        assert eng.evaluate_call(ken_agent["agent"], "test.echo", {}, None).decision == "allow"
        assert eng.evaluate_call(spouse_agent["agent"], "test.echo", {}, None).decision == "allow"

    def test_pinned_default_deny_visible(self, config_db, ken_agent):
        _save(config_db, [
            {"name": "ken echo", "effect": "allow", "tool": "test.echo"},
        ])
        rows = PolicyEngine(config_db).list_rules_with_default_deny()
        assert rows[-1]["pinned"] is True
        assert rows[-1]["rule_id"] == "default_deny"
        assert rows[-1]["effect"] == "deny"

    def test_legacy_sensitive_normalized(self, config_db, ken_agent):
        _save(config_db, [
            {"name": "legacy", "effect": "sensitive", "tool": "test.echo"},
        ])
        eng = PolicyEngine(config_db)
        res = eng.evaluate_call(ken_agent["agent"], "test.echo", {}, None)
        assert (res.decision, res.requires_approval) == ("require_approval", True)


# ---------------------------------------------------------------------------
# FR-PAA03-002 purpose binding
# ---------------------------------------------------------------------------

class TestPurposeBinding:
    def test_purpose_bound_rule_matches_equal_purpose(self, config_db, ken_agent):
        _save(config_db, [
            {"name": "work echo", "effect": "allow", "tool": "test.echo",
             "purpose": "work"},
        ])
        eng = PolicyEngine(config_db)
        res = eng.evaluate_call(ken_agent["agent"], "test.echo", {}, None, purpose="work")
        assert res.decision == "allow"

    def test_call_outside_purpose_denied(self, config_db, ken_agent):
        _save(config_db, [
            {"name": "work echo", "effect": "allow", "tool": "test.echo",
             "purpose": "work"},
        ])
        eng = PolicyEngine(config_db)
        res = eng.evaluate_call(ken_agent["agent"], "test.echo", {}, None, purpose="personal")
        assert res.decision == "deny"  # tool allowed, purpose not → deny

    def test_undeclared_purpose_never_matches_bound_rule(self, config_db, ken_agent):
        _save(config_db, [
            {"name": "work echo", "effect": "allow", "tool": "test.echo",
             "purpose": "work"},
        ])
        eng = PolicyEngine(config_db)
        res = eng.evaluate_call(ken_agent["agent"], "test.echo", {}, None, purpose=None)
        assert res.decision == "deny"

    def test_unbound_rule_ignores_purpose(self, config_db, ken_agent):
        _save(config_db, [
            {"name": "any echo", "effect": "allow", "tool": "test.echo"},
        ])
        eng = PolicyEngine(config_db)
        assert eng.evaluate_call(ken_agent["agent"], "test.echo", {}, None, purpose="personal").decision == "allow"


# ---------------------------------------------------------------------------
# FR-PAA08-001 household-role scoping
# ---------------------------------------------------------------------------

class TestHouseholdRoles:
    def test_role_scoped_rule_matches_same_role(self, config_db, ken_agent):
        _save(config_db, [
            {"name": "ken echo", "effect": "allow", "tool": "test.echo",
             "household_role": "ken"},
        ])
        eng = PolicyEngine(config_db)
        assert eng.evaluate_call(ken_agent["agent"], "test.echo", {}, None).decision == "allow"

    def test_role_scoped_rule_rejects_other_role(self, config_db, ken_agent, spouse_agent):
        _save(config_db, [
            {"name": "ken echo", "effect": "allow", "tool": "test.echo",
             "household_role": "ken"},
        ])
        eng = PolicyEngine(config_db)
        res = eng.evaluate_call(spouse_agent["agent"], "test.echo", {}, None)
        assert res.decision == "deny"  # one member's agent never satisfies another's rules

    def test_unscoped_rule_matches_any_role(self, config_db, ken_agent, spouse_agent):
        _save(config_db, [
            {"name": "any echo", "effect": "allow", "tool": "test.echo"},
        ])
        eng = PolicyEngine(config_db)
        assert eng.evaluate_call(ken_agent["agent"], "test.echo", {}, None).decision == "allow"
        assert eng.evaluate_call(spouse_agent["agent"], "test.echo", {}, None).decision == "allow"


# ---------------------------------------------------------------------------
# Conditions: time windows + argument constraints
# ---------------------------------------------------------------------------

class TestConditions:
    MON_NOON = dt.datetime(2026, 10, 12, 12, 0, tzinfo=dt.timezone.utc)  # a Monday

    def test_time_window_match(self, config_db, ken_agent):
        _save(config_db, [
            {"name": "work hours", "effect": "allow", "tool": "test.echo",
             "conditions": {"time_window": {
                 "days": ["mon"], "start": "09:00", "end": "18:00", "tz": "UTC"}}},
        ])
        eng = PolicyEngine(config_db)
        res = eng.evaluate_call(ken_agent["agent"], "test.echo", {}, None, now=self.MON_NOON)
        assert res.decision == "allow"

    def test_time_window_miss(self, config_db, ken_agent):
        _save(config_db, [
            {"name": "tue only", "effect": "allow", "tool": "test.echo",
             "conditions": {"time_window": {"days": ["tue"], "tz": "UTC"}}},
        ])
        eng = PolicyEngine(config_db)
        res = eng.evaluate_call(ken_agent["agent"], "test.echo", {}, None, now=self.MON_NOON)
        assert res.decision == "deny"

    def test_empty_days_never_matches(self, config_db, ken_agent):
        _save(config_db, [
            {"name": "never", "effect": "allow", "tool": "test.echo",
             "conditions": {"time_window": {"days": []}}},
        ])
        eng = PolicyEngine(config_db)
        res = eng.evaluate_call(ken_agent["agent"], "test.echo", {}, None, now=self.MON_NOON)
        assert res.decision == "deny"

    def test_argument_domain_constraint(self, config_db, ken_agent):
        _save(config_db, [
            {"name": "internal mail only", "effect": "allow", "tool": "test.echo",
             "conditions": {"argument_constraints": {
                 "to": {"all_domains_in": ["example.com"]}}}},
        ])
        eng = PolicyEngine(config_db)
        ok = eng.evaluate_call(
            ken_agent["agent"], "test.echo", {"to": ["a@example.com"]}, None)
        assert ok.decision == "allow"
        bad = eng.evaluate_call(
            ken_agent["agent"], "test.echo", {"to": ["a@external.com"]}, None)
        assert bad.decision == "deny"

    def test_argument_equals_and_contains(self, config_db, ken_agent):
        _save(config_db, [
            {"name": "constrained", "effect": "allow", "tool": "test.echo",
             "conditions": {"argument_constraints": {
                 "mode": {"equals": "fast"},
                 "note": {"contains": "ok"}}}},
        ])
        eng = PolicyEngine(config_db)
        assert eng.evaluate_call(
            ken_agent["agent"], "test.echo", {"mode": "fast", "note": "all ok"}, None
        ).decision == "allow"
        assert eng.evaluate_call(
            ken_agent["agent"], "test.echo", {"mode": "slow", "note": "all ok"}, None
        ).decision == "deny"

    def test_unknown_constraint_operator_rejected_on_save(self, config_db):
        with pytest.raises(ValueError, match="unknown constraint operator"):
            validate_rule_dict({
                "name": "bad", "effect": "allow", "tool": "test.echo",
                "conditions": {"argument_constraints": {"to": {"bogus_op": 1}}},
            })


# ---------------------------------------------------------------------------
# require_approval decisions
# ---------------------------------------------------------------------------

class TestRequireApproval:
    def test_require_approval_decision(self, config_db, ken_agent):
        _save(config_db, [
            {"name": "approve echo", "effect": "require_approval", "tool": "test.echo"},
        ])
        eng = PolicyEngine(config_db)
        res = eng.evaluate_call(ken_agent["agent"], "test.echo", {}, None)
        assert res.decision == "require_approval"
        assert res.requires_approval is True
        assert res.matched_rule_id is not None


# ---------------------------------------------------------------------------
# Versions: immutability + material/non-material classification
# ---------------------------------------------------------------------------

class TestVersioning:
    def test_versions_immutable(self, config_db, ken_agent):
        v1 = _save(config_db, [
            {"name": "v1 rule", "effect": "allow", "tool": "test.echo"},
        ], note="first")
        v2 = _save(config_db, [
            {"name": "v1 rule", "effect": "deny", "tool": "test.echo"},
        ], note="second")
        assert (v1, v2) == (1, 2)
        eng = PolicyEngine(config_db)
        assert eng.current_version_number() == 2
        # v1 content unchanged: still allows.
        assert eng.evaluate_call(ken_agent["agent"], "test.echo", {}, 1).decision == "allow"
        assert eng.evaluate_call(ken_agent["agent"], "test.echo", {}, 2).decision == "deny"
        # current (None) == v2.
        assert eng.evaluate_call(ken_agent["agent"], "test.echo", {}, None).decision == "deny"

    def test_widening_is_material(self, config_db):
        v1_rules = [{"name": "r", "effect": "allow", "tool": "test.echo"}]
        v2_rules = v1_rules + [{"name": "r2", "effect": "allow", "tool": "other.tool"}]
        assert classify_change(v1_rules, v2_rules) is True

    def test_note_only_change_is_non_material(self, config_db):
        v1_rules = [{"name": "r", "effect": "allow", "tool": "test.echo",
                     "description": "old"}]
        v2_rules = [{"name": "r renamed", "effect": "allow", "tool": "test.echo",
                     "description": "new"}]
        assert classify_change(v1_rules, v2_rules) is False

    def test_reorder_only_is_non_material(self, config_db):
        v1_rules = [
            {"name": "a", "effect": "allow", "tool": "test.echo"},
            {"name": "b", "effect": "deny", "tool": "other.tool"},
        ]
        assert classify_change(v1_rules, list(reversed(v1_rules))) is False

    def test_auto_classification_recorded_on_save(self, config_db):
        _save(config_db, [{"name": "r", "effect": "allow", "tool": "test.echo"}])
        v2 = _save(config_db, [
            {"name": "r", "effect": "allow", "tool": "test.echo"},
            {"name": "r2", "effect": "allow", "tool": "other.tool"},
        ])
        from gateway.models import PolicyVersion
        row = config_db.query(PolicyVersion).filter_by(version=v2).one()
        assert row.material_change is True

    def test_explicit_override_respected(self, config_db):
        _save(config_db, [{"name": "r", "effect": "allow", "tool": "test.echo"}])
        v2 = _save(
            config_db,
            [{"name": "r", "effect": "allow", "tool": "test.echo"},
             {"name": "r2", "effect": "allow", "tool": "other.tool"}],
            material=False,
        )
        from gateway.models import PolicyVersion
        row = config_db.query(PolicyVersion).filter_by(version=v2).one()
        assert row.material_change is False

    def test_notice_rule_requires_allow_and_audience(self, config_db):
        with pytest.raises(ValueError, match="must have effect 'allow'"):
            validate_rule_dict({
                "name": "n", "effect": "deny", "rule_type": "notice",
                "tool": "email.send",
                "conditions": {"notice": {"audience": ["a@x.com"],
                                          "subject_pattern": "x"}},
            })
        with pytest.raises(ValueError, match="non-empty audience"):
            validate_rule_dict({
                "name": "n", "effect": "allow", "rule_type": "notice",
                "tool": "email.send",
                "conditions": {"notice": {"audience": [],
                                          "subject_pattern": "x"}},
            })


# ---------------------------------------------------------------------------
# Template-bound notice rules (FR-PAA07-005)
# ---------------------------------------------------------------------------

NOTICE_RULE = {
    "name": "Weekly status notice",
    "effect": "allow",
    "rule_type": "notice",
    "tool": "email.send",
    "description": "Standing policy rule, not a grant: weekly status to a fixed list.",
    "conditions": {
        "notice": {
            "audience": ["team@example.com"],
            "schedule": {"days": ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]},
            "subject_pattern": r"^Weekly status:",
            "body_pattern": r"Status update for week \d+",
            "max_body_length": 5000,
        }
    },
}

NOTICE_ARGS = {
    "to": ["team@example.com"],
    "subject": "Weekly status: Oct 12",
    "body": "Status update for week 42. All systems nominal.",
}


class TestNoticeRules:
    def test_matching_notice_allowed(self, config_db, ken_agent):
        _save(config_db, [NOTICE_RULE])
        eng = PolicyEngine(config_db)
        res = eng.evaluate_call(ken_agent["agent"], "email.send", NOTICE_ARGS, None)
        assert res.decision == "allow"

    def test_audience_expansion_denied(self, config_db, ken_agent):
        _save(config_db, [NOTICE_RULE])
        eng = PolicyEngine(config_db)
        args = dict(NOTICE_ARGS, to=["team@example.com", "outsider@evil.com"])
        res = eng.evaluate_call(ken_agent["agent"], "email.send", args, None)
        assert res.decision == "deny"  # deviation → rule does not match

    def test_content_mismatch_denied(self, config_db, ken_agent):
        _save(config_db, [NOTICE_RULE])
        eng = PolicyEngine(config_db)
        args = dict(NOTICE_ARGS, subject="Unrelated subject")
        res = eng.evaluate_call(ken_agent["agent"], "email.send", args, None)
        assert res.decision == "deny"

    def test_body_too_long_denied(self, config_db, ken_agent):
        _save(config_db, [NOTICE_RULE])
        eng = PolicyEngine(config_db)
        args = dict(NOTICE_ARGS, body="Status update for week 42. " + "x" * 6000)
        res = eng.evaluate_call(ken_agent["agent"], "email.send", args, None)
        assert res.decision == "deny"

    def test_outside_schedule_denied(self, config_db, ken_agent):
        rule = json.loads(json.dumps(NOTICE_RULE))
        rule["conditions"]["notice"]["schedule"] = {"days": []}  # never
        _save(config_db, [rule])
        eng = PolicyEngine(config_db)
        res = eng.evaluate_call(ken_agent["agent"], "email.send", NOTICE_ARGS, None)
        assert res.decision == "deny"

    def test_one_off_send_not_authorized_by_notice(self, config_db, ken_agent):
        # A notice rule never authorizes a one-off send to a new audience.
        _save(config_db, [NOTICE_RULE])
        eng = PolicyEngine(config_db)
        args = {
            "to": ["friend@example.com"],
            "subject": "Weekly status: Oct 12",
            "body": "Status update for week 42.",
        }
        res = eng.evaluate_call(ken_agent["agent"], "email.send", args, None)
        assert res.decision == "deny"


# ---------------------------------------------------------------------------
# Pipeline end-to-end: allow/deny, denial rows, safe vocabulary
# ---------------------------------------------------------------------------

class TestPipelineEndToEnd:
    def test_allowed_call_executes(self, dbs, settings, echo_registry, ken_agent):
        with dbs.config.session() as cdb:
            _save(cdb, [{"name": "allow", "effect": "allow", "tool": "test.echo"}])
        pipeline, _, auth_stage, cdb2, adb2 = _pipeline(
            dbs, settings, echo_registry, "ag_ken", ken_agent["secret"])
        with cdb2, adb2:
            outcome = pipeline.execute("ag_ken", "test.echo", {"q": "hi"})
        assert outcome.ok, outcome.error.to_text() if outcome.error else ""
        assert outcome.context.result == {"echo": {"q": "hi"}}
        assert outcome.context.decision == "allowed"
        assert outcome.context.scope_rule is not None
        # audit row carries the scope rule (FR-PAA01-007)
        rows = AuditLog(adb2).search(agent_id="ag_ken")
        assert rows and rows[0].decision == "allowed"
        assert rows[0].scope_rule == outcome.context.scope_rule

    def test_denied_call_ac03(self, dbs, settings, echo_registry, ken_agent):
        # No policy versions at all: visible default-deny (AC-03).
        pipeline, _, auth_stage, cdb2, adb2 = _pipeline(
            dbs, settings, echo_registry, "ag_ken", ken_agent["secret"])
        with cdb2, adb2:
            outcome = pipeline.execute("ag_ken", "test.echo", {"q": "hi"})
        assert not outcome.ok
        assert outcome.error.code == "policy_denied"
        assert outcome.error.details["reason"] == "no_allow_rule"
        assert outcome.error.details["reason"] in SAFE_REASONS
        assert outcome.halted_at == "policy"
        # denial logged with the reason
        rows = AuditLog(adb2).search(agent_id="ag_ken")
        assert rows and rows[0].decision == "denied"
        assert rows[0].reason == "no_allow_rule"

    def test_explicit_deny_reason_and_no_leak(self, dbs, settings, echo_registry, ken_agent):
        with dbs.config.session() as cdb:
            _save(cdb, [{"name": "TOP SECRET RULE NAME", "effect": "deny",
                         "tool": "test.echo"}])
        pipeline, _, auth_stage, cdb2, adb2 = _pipeline(
            dbs, settings, echo_registry, "ag_ken", ken_agent["secret"])
        with cdb2, adb2:
            outcome = pipeline.execute("ag_ken", "test.echo", {})
        assert outcome.error.code == "policy_denied"
        assert outcome.error.details["reason"] == "explicit_deny"
        text = outcome.error.to_text()
        assert "TOP SECRET RULE NAME" not in text  # no rule text leaks

    def test_require_approval_halts(self, dbs, settings, echo_registry, ken_agent):
        with dbs.config.session() as cdb:
            _save(cdb, [{"name": "needs ok", "effect": "require_approval",
                         "tool": "test.echo"}])
        pipeline, _, auth_stage, cdb2, adb2 = _pipeline(
            dbs, settings, echo_registry, "ag_ken", ken_agent["secret"])
        with cdb2, adb2:
            outcome = pipeline.execute("ag_ken", "test.echo", {})
        assert not outcome.ok
        assert outcome.error.code == "approval_required"
        assert outcome.halted_at == "policy"
        rows = AuditLog(adb2).search(agent_id="ag_ken")
        assert rows and rows[0].decision == "approval_required"

    def test_purpose_binding_end_to_end(self, dbs, settings, echo_registry):
        # ken_agent fixture has purpose_key="work"; a purpose="personal"
        # rule must deny even though the tool is otherwise allowed.
        with dbs.config.session() as cdb:
            ident = IdentityService(cdb)
            agent, _client_id, secret = ident.register_agent("ag_w", "muse", "W", "ken")
            MandateService(cdb).create_mandate(
                agent.id, "work mandate", ["test.echo"], purpose_key="work")
            _save(cdb, [{"name": "personal only", "effect": "allow",
                         "tool": "test.echo", "purpose": "personal"}])
        pipeline, _, auth_stage, cdb2, adb2 = _pipeline(
            dbs, settings, echo_registry, "ag_w", secret)
        with cdb2, adb2:
            outcome = pipeline.execute("ag_w", "test.echo", {})
        assert not outcome.ok
        assert outcome.error.details["reason"] == "no_allow_rule"


# ---------------------------------------------------------------------------
# dry_run (AC-12, 02 §2.6)
# ---------------------------------------------------------------------------

class TestDryRun:
    def _seed_history(self, config_db, audit_db, ken_secret):
        """Seed audit history: 3 allowed email.search, 1 denied email.send."""
        log = AuditLog(audit_db)
        mandate = MandateService(config_db).live_mandates("ag_ken")[0]
        for i in range(3):
            log.append(
                agent_id="ag_ken", tool="email.search", decision="allowed",
                request_id=f"req_hist_{i}", redacted_args={"query": "x"},
                mandate_id=mandate.id,
            )
        log.append(
            agent_id="ag_ken", tool="email.send", decision="denied",
            request_id="req_hist_d", redacted_args={"to": ["a@b.c"]},
            mandate_id=mandate.id, reason="no_allow_rule",
        )

    def test_dry_run_history_counts_and_changed(self, dbs, settings, config_db, audit_db, ken_agent):
        self._seed_history(config_db, audit_db, ken_agent["secret"])
        known = {"email.search", "email.send"}
        v1 = _save(config_db, [
            {"name": "allow search", "effect": "allow", "tool": "email.search"},
        ])
        v2 = _save(config_db, [
            {"name": "deny search now", "effect": "deny", "tool": "email.search"},
        ])
        result = dry_run(config_db, audit_db, v2, window_days=7, known_tools=known)
        assert result["corpus"] == "history"
        assert result["counts"]["would_deny"] == 4  # 3 search + 1 send
        assert result["counts"]["would_allow"] == 0
        changed = result["changed_calls"]
        assert len(changed) == 3  # the 3 previously-allowed searches
        assert {c["request_id"] for c in changed} == {"req_hist_0", "req_hist_1", "req_hist_2"}
        assert all(c["recorded"] == "allow" and c["would_be"] == "deny" for c in changed)
        # v1 against the same history: nothing changes.
        stable = dry_run(config_db, audit_db, v1, window_days=7, known_tools=known)
        assert stable["changed_calls"] == []
        assert stable["counts"] == {"would_allow": 3, "would_deny": 1, "would_require_approval": 0}

    def test_dry_run_require_approval_counted(self, dbs, settings, config_db, audit_db, ken_agent):
        self._seed_history(config_db, audit_db, ken_agent["secret"])
        v = _save(config_db, [
            {"name": "send needs approval", "effect": "require_approval", "tool": "email.send"},
            {"name": "allow search", "effect": "allow", "tool": "email.search"},
        ])
        result = dry_run(config_db, audit_db, v, window_days=7,
                         known_tools={"email.search", "email.send"})
        assert result["counts"]["would_require_approval"] == 1
        assert result["counts"]["would_allow"] == 3

    def test_dry_run_synthetic_cold_start(self, config_db, audit_db):
        # Empty audit history → synthetic corpus, labeled as such.
        v = _save(config_db, [
            {"name": "allow reads", "effect": "allow", "tool": "email.*"},
        ])
        result = dry_run(config_db, audit_db, v, window_days=7)
        assert result["corpus"] == "synthetic"
        total = sum(result["counts"].values())
        assert total == 12  # one hand-written call per tool
        assert all(c.get("synthetic") is True for c in result["changed_calls"])
        # email.* matches all six email tools (wildcard = prefix match).
        assert result["counts"]["would_allow"] == 6
        assert result["counts"]["would_deny"] == 6

    def test_dry_run_skips_unknown_tools(self, config_db, audit_db, ken_agent):
        log = AuditLog(audit_db)
        log.append(agent_id="ag_ken", tool="audit.export", decision="allowed",
                   request_id="req_x", redacted_args={})
        v = _save(config_db, [])
        result = dry_run(config_db, audit_db, v, window_days=7,
                         known_tools={"email.search"})
        # audit.export is not a registered tool → skipped, not counted.
        assert result["corpus"] == "synthetic"

