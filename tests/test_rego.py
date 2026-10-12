"""Rego/OPA pivot tests — Personal Agent Security Gateway.

Covers:
- the decision contract via the sidecar (allow/deny/ask, pinned
  default-deny, deny citations, fail-closed paths)
- the frozen input-document schema + data_snapshot_id
- Python-reference vs Rego cross-check on generated rule cases
  (the ported semantics stay identical)
- decision-equivalence between the preset-generated JSON rules and
  the versioned Rego defaults (v1/*.rego)
- seed_defaults end-to-end
- audit traceability (data_snapshot_id on every row)
- the CI shape: opa fmt --fail, opa check, opa test via subprocess
"""

from __future__ import annotations

import datetime as dt
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from gateway.audit import AuditLog
from gateway.config import Settings
from gateway.db import Databases
from gateway.identity import IdentityService
from gateway.intent import intent_from_parts
from gateway.mandates import MandateService
from gateway.opa_client import OpaClient, OpaUnavailable, default_policies_dir, resolve_binary
from gateway.ontology.store import OntologyStore
from gateway.ontology import apply_preset
from gateway.pipeline import CallContext, AuditStage
from gateway.policies.defaults import PAA10_RULES, seed_defaults
from gateway.policy import (
    INPUT_SCHEMA_VERSION,
    PolicyEngine,
    PolicyStage,
    data_snapshot_id,
    now_by_tz,
    rule_matches,
    rule_to_input_data,
    validate_rule_dict,
)
from gateway.models import PolicyRule


OPA_BIN = resolve_binary()
POLICIES_DIR = default_policies_dir()

# Monday 2026-10-12 12:00 UTC (matches the real calendar).
MON_NOON = dt.datetime(2026, 10, 12, 12, 0, tzinfo=dt.timezone.utc)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def opa():
    client = OpaClient()
    client.start()
    yield client
    client.stop()


@pytest.fixture()
def dbs(tmp_path):
    s = Settings(
        config_db_path=str(tmp_path / "config.db"),
        audit_db_path=str(tmp_path / "audit.db"),
        hmac_key="test-hmac-key-material-32bytes!",
    )
    d = Databases(s.config_db_path, s.audit_db_path)
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


def _register(config_db, agent_id="ag_ken", role="ken", purpose="work"):
    ident = IdentityService(config_db)
    agent, _, _ = ident.register_agent(agent_id, "muse", f"Agent {agent_id}", role)
    MandateService(config_db).create_mandate(
        agent.id, "test mandate", ["email.send", "calendar.read"], purpose_key=purpose
    )
    return agent


@pytest.fixture()
def ken_agent(config_db):
    return _register(config_db)


def _engine(config_db, opa, **kw):
    return PolicyEngine(config_db, opa_client=opa, **kw)


def _save(config_db, rules):
    return PolicyEngine(config_db).save_version(rules)


# ---------------------------------------------------------------------------
# Input-document builders (test-local, mirroring the engine)
# ---------------------------------------------------------------------------

def _rule_data(d, rid=1):
    r = dict(d)
    r["id"] = rid
    r["name"] = r.get("name", "")
    eff = r.get("effect", "allow")
    r["effect"] = {"sensitive": "require_approval"}.get(eff, eff)
    r["rule_type"] = r.get("rule_type", "standard")
    for k in ("agent_id", "tool", "action_class", "household_role", "purpose"):
        r.setdefault(k, None)
    r["conditions"] = r.get("conditions") or {}
    return r


def _input_doc(rules, tool="email.send", args=None, purpose="work",
               agent_id="ag_ken", role="ken", now=MON_NOON,
               ontology_snapshot=None):
    return {
        "schema_version": INPUT_SCHEMA_VERSION,
        "policy_version": 1,
        "data_snapshot_id": "test",
        "agent": {"id": agent_id, "household_role": role},
        "intent": {
            "agent_id": agent_id,
            "principal_on_whose_behalf": None,
            "action": tool,
            "resource_type": tool.split(".", 1)[0] if "." in tool else None,
            "resource_id": None,
            "params": dict(args or {}),
            "purpose": purpose,
            "ontology_context": None,
            "mandate_refs": [],
            "grant_refs": [],
        },
        "ontology_snapshot": ontology_snapshot,
        "mandates": [],
        "grants": [],
        "rules": rules,
        "now": now.isoformat(),
        "now_by_tz": now_by_tz(now, {"UTC"}),
    }


# ---------------------------------------------------------------------------
# Decision contract via the sidecar
# ---------------------------------------------------------------------------

class TestDecisionContract:
    def test_allow(self, opa):
        d = opa.decide(_input_doc([_rule_data({"effect": "allow", "tool": "email.send"})]))
        assert d["effect"] == "allow" and d["rule"] == 1

    def test_deny_default_pinned(self, opa):
        d = opa.decide(_input_doc([]))
        assert d == {"effect": "deny", "rule": "default_deny"}

    def test_explicit_deny_first_match(self, opa):
        d = opa.decide(_input_doc([
            _rule_data({"effect": "deny", "tool": "email.send"}, rid=1),
            _rule_data({"effect": "allow", "tool": "email.send"}, rid=2),
        ]))
        assert d["effect"] == "deny" and d["rule"] == 1

    def test_ask_maps_require_approval(self, opa):
        d = opa.decide(_input_doc([_rule_data({"effect": "require_approval", "tool": "email.send"})]))
        assert d["effect"] == "ask" and d["rule"] == 1

    def test_missing_fields_fail_closed(self, opa):
        # Empty input object: no rule can match -> pinned default-deny.
        d = opa.decide({})
        assert d == {"effect": "deny", "rule": "default_deny"}

    def test_unknown_dimension_denied_python_side(self, config_db, opa, ken_agent):
        # Unknown dimension names fail CLOSED before OPA (resolve_ctx).
        eng = _engine(config_db, opa)
        _save(config_db, [{"name": "r", "effect": "allow", "tool": "email.send"}])
        res = eng.evaluate_call(
            ken_agent, "email.send", {}, purpose="work",
            ontology_ctx={"dimensions": {"nosuchdim": "x"}},
        )
        assert res.decision == "deny"
        assert res.matched_rule_id is None

    def test_sidecar_down_denies_fail_closed(self, config_db, ken_agent):
        client = OpaClient()
        client.start()
        # Make it unrestartable, then kill it: decide must deny.
        client.binary = Path("/nonexistent/opa")
        client.stop()
        eng = PolicyEngine(config_db, opa_client=client)
        _save(config_db, [{"name": "r", "effect": "allow", "tool": "email.send"}])
        res = eng.evaluate_call(ken_agent, "email.send", {}, purpose="work")
        assert res.decision == "deny"
        assert res.matched_rule_id is None
        assert res.scope_rule == "opa_unavailable"

    def test_malformed_decision_denies(self, config_db, ken_agent):
        # A sidecar returning a malformed decision (unknown effect,
        # missing fields) must fail CLOSED at the engine boundary.
        eng = PolicyEngine(config_db)
        _save(config_db, [{"name": "r", "effect": "allow", "tool": "email.send"}])

        class BadClient:
            def decide(self, doc):
                return {"effect": "maybe", "rule": 1}

        eng.opa_client = BadClient()
        res = eng.evaluate_call(ken_agent, "email.send", {}, purpose="work")
        assert res.decision == "deny"
        assert res.matched_rule_id is None

        class EmptyClient:
            def decide(self, doc):
                return {}

        eng.opa_client = EmptyClient()
        res = eng.evaluate_call(ken_agent, "email.send", {}, purpose="work")
        assert res.decision == "deny"


class TestEngineEndToEnd:
    def test_allow_ask_deny(self, config_db, opa, ken_agent):
        eng = _engine(config_db, opa)
        _save(config_db, [
            {"name": "ask pay", "effect": "require_approval", "tool": "payment.*"},
            {"name": "allow send", "effect": "allow", "tool": "email.send"},
        ])
        r = eng.evaluate_call(ken_agent, "email.send", {}, purpose="work")
        assert (r.decision, r.matched_rule_id, r.requires_approval) == ("allow", 2, False)
        assert r.scope_rule == "rule:2:allow send"
        assert r.data_snapshot_id.startswith("pv1/rules:")
        assert r.data_snapshot_id.endswith("/ont:none")
        r = eng.evaluate_call(ken_agent, "payment.x", {}, purpose="work")
        assert (r.decision, r.requires_approval) == ("require_approval", True)
        r = eng.evaluate_call(ken_agent, "calendar.delete", {}, purpose="work")
        assert r.decision == "deny" and r.matched_rule_id is None

    def test_ask_maps_to_require_approval_result(self, config_db, opa, ken_agent):
        eng = _engine(config_db, opa)
        _save(config_db, [
            {"name": "ask", "effect": "require_approval", "tool": "email.send"},
        ])
        r = eng.evaluate_call(ken_agent, "email.send", {}, purpose="work")
        assert r.decision == "require_approval"
        assert r.requires_approval is True

    def test_data_snapshot_id_deterministic(self, config_db, opa, ken_agent):
        eng = _engine(config_db, opa)
        _save(config_db, [{"name": "r", "effect": "allow", "tool": "email.send"}])
        a = eng.evaluate_call(ken_agent, "email.send", {"x": 1}, purpose="work")
        b = eng.evaluate_call(ken_agent, "email.send", {"x": 2}, purpose="work")
        # Same policy data -> same id (args are not policy data).
        assert a.data_snapshot_id == b.data_snapshot_id
        _save(config_db, [
            {"name": "r", "effect": "allow", "tool": "email.send"},
            {"name": "r2", "effect": "deny", "tool": "calendar.delete"},
        ])
        c = eng.evaluate_call(ken_agent, "email.send", {"x": 1}, purpose="work")
        assert c.data_snapshot_id != a.data_snapshot_id
        assert c.data_snapshot_id.startswith("pv2/rules:")

    def test_invalid_rule_rejected_at_save(self, config_db):
        eng = PolicyEngine(config_db)
        with pytest.raises(ValueError, match="unknown constraint operator"):
            eng.save_version([{
                "name": "bad", "effect": "allow", "tool": "email.send",
                "conditions": {"argument_constraints": {"to": {"frob": "x"}}},
            }])
        with pytest.raises(ValueError, match="invalid regex"):
            eng.save_version([{
                "name": "bad", "effect": "allow", "tool": "email.send",
                "conditions": {"argument_constraints": {"subject": {"matches": "(unclosed"}}},
            }])
        # Nothing was saved: still no versions.
        assert eng.current_version_number() is None

    def test_valid_rules_still_save(self, config_db):
        eng = PolicyEngine(config_db)
        v = eng.save_version([{"name": "r", "effect": "allow", "tool": "email.send"}])
        assert v == 1


# ---------------------------------------------------------------------------
# Frozen input schema
# ---------------------------------------------------------------------------

class TestInputSchema:
    def test_frozen_top_level_keys(self, config_db, opa, ken_agent):
        eng = _engine(config_db, opa)
        _save(config_db, [{"name": "r", "effect": "allow", "tool": "email.send"}])
        intent = intent_from_parts(
            agent_id=ken_agent.id, tool="email.send", args={},
            purpose="work", db=config_db,
        )
        doc = eng._build_input_document(
            intent, ken_agent, 1, MON_NOON,
            [rule_to_input_data(r) for r in eng.load_rules()],
            None,
        )
        assert doc["schema_version"] == "intent-policy-input/v1"
        assert set(doc) == {
            "schema_version", "policy_version", "data_snapshot_id",
            "agent", "intent", "ontology_snapshot", "mandates", "grants",
            "rules", "now", "now_by_tz",
        }
        assert set(doc["intent"]) == {
            "agent_id", "principal_on_whose_behalf", "action",
            "resource_type", "resource_id", "params", "purpose",
            "ontology_context", "mandate_refs", "grant_refs",
        }
        assert set(doc["agent"]) == {"id", "household_role"}
        assert doc["now_by_tz"]["UTC"]["weekday"] == "mon"
        assert doc["now_by_tz"]["UTC"]["minutes"] == 720


# ---------------------------------------------------------------------------
# Python-reference vs Rego cross-check (generated cases)
# ---------------------------------------------------------------------------

def _py_rule(d, rid=1):
    return PolicyRule(
        id=rid,
        name=d.get("name", ""),
        effect=d.get("effect", "allow"),
        rule_type=d.get("rule_type", "standard"),
        agent_id=d.get("agent_id"),
        tool=d.get("tool"),
        household_role=d.get("household_role"),
        purpose=d.get("purpose"),
        conditions=d.get("conditions") or {},
    )


def _cases():
    """(rule dict, tool, args, purpose, now, role, expect_match)."""
    noon = MON_NOON
    night = dt.datetime(2026, 10, 12, 3, 0, tzinfo=dt.timezone.utc)  # 03:00
    return [
        ({"effect": "allow", "tool": "email.send"}, "email.send", {}, "work", noon, "ken", True),
        ({"effect": "allow", "tool": "email.send"}, "calendar.list", {}, "work", noon, "ken", False),
        ({"effect": "allow", "tool": "email.*"}, "email.send", {}, "work", noon, "ken", True),
        ({"effect": "allow", "tool": "email.*"}, "calendar.list", {}, "work", noon, "ken", False),
        ({"effect": "allow", "tool": "email.send", "agent_id": "ag_ken"}, "email.send", {}, "work", noon, "ken", True),
        ({"effect": "allow", "tool": "email.send", "agent_id": "ag_x"}, "email.send", {}, "work", noon, "ken", False),
        ({"effect": "allow", "tool": "email.send", "conditions": {"agents": ["ag_ken"]}}, "email.send", {}, "work", noon, "ken", True),
        ({"effect": "allow", "tool": "email.send", "conditions": {"agents": ["ag_x"]}}, "email.send", {}, "work", noon, "ken", False),
        ({"effect": "allow", "tool": "email.send", "household_role": "ken"}, "email.send", {}, "work", noon, "ken", True),
        ({"effect": "allow", "tool": "email.send", "household_role": "spouse"}, "email.send", {}, "work", noon, "ken", False),
        ({"effect": "allow", "tool": "email.send", "purpose": "work"}, "email.send", {}, "work", noon, "ken", True),
        ({"effect": "allow", "tool": "email.send", "purpose": "personal"}, "email.send", {}, "work", noon, "ken", False),
        ({"effect": "allow", "tool": "email.send", "purpose": "work"}, "email.send", {}, None, noon, "ken", False),
        ({"effect": "allow", "tool": "email.send",
          "conditions": {"time_window": {"days": ["mon"], "start": "09:00", "end": "18:00"}}},
         "email.send", {}, "work", noon, "ken", True),
        ({"effect": "allow", "tool": "email.send",
          "conditions": {"time_window": {"days": ["tue"], "start": "09:00", "end": "18:00"}}},
         "email.send", {}, "work", noon, "ken", False),
        ({"effect": "allow", "tool": "email.send",
          "conditions": {"time_window": {"start": "09:00", "end": "18:00"}}},
         "email.send", {}, "work", night, "ken", False),
        ({"effect": "allow", "tool": "email.send",
          "conditions": {"time_window": {"start": "22:00", "end": "06:00"}}},
         "email.send", {}, "work", night, "ken", True),
        ({"effect": "allow", "tool": "email.send",
          "conditions": {"time_window": {"days": []}}},
         "email.send", {}, "work", noon, "ken", False),
        ({"effect": "allow", "tool": "email.send",
          "conditions": {"argument_constraints": {"to": {"equals": "a@b.com"}}}},
         "email.send", {"to": "a@b.com"}, "work", noon, "ken", True),
        ({"effect": "allow", "tool": "email.send",
          "conditions": {"argument_constraints": {"to": {"equals": "a@b.com"}}}},
         "email.send", {"to": "x@y.com"}, "work", noon, "ken", False),
        ({"effect": "allow", "tool": "email.send",
          "conditions": {"argument_constraints": {"to": {"equals": "a@b.com"}}}},
         "email.send", {}, "work", noon, "ken", False),
        ({"effect": "allow", "tool": "email.send",
          "conditions": {"argument_constraints": {"n": {"in": [1, 2]}}}},
         "email.send", {"n": 2}, "work", noon, "ken", True),
        ({"effect": "allow", "tool": "email.send",
          "conditions": {"argument_constraints": {"n": {"not_in": [1, 2]}}}},
         "email.send", {"n": 3}, "work", noon, "ken", True),
        ({"effect": "allow", "tool": "email.send",
          "conditions": {"argument_constraints": {"s": {"contains": "abc"}}}},
         "email.send", {"s": "xxabcxx"}, "work", noon, "ken", True),
        ({"effect": "allow", "tool": "email.send",
          "conditions": {"argument_constraints": {"s": {"matches": "^a+$"}}}},
         "email.send", {"s": "aaa"}, "work", noon, "ken", True),
        ({"effect": "allow", "tool": "email.send",
          "conditions": {"argument_constraints": {"s": {"matches": "^a+$"}}}},
         "email.send", {"s": "aab"}, "work", noon, "ken", False),
        ({"effect": "allow", "tool": "email.send",
          "conditions": {"argument_constraints": {"to": {"all_domains_in": ["example.com"]}}}},
         "email.send", {"to": ["a@example.com", "b@example.com"]}, "work", noon, "ken", True),
        ({"effect": "allow", "tool": "email.send",
          "conditions": {"argument_constraints": {"to": {"all_domains_in": ["example.com"]}}}},
         "email.send", {"to": ["a@example.com", "x@evil.com"]}, "work", noon, "ken", False),
        ({"effect": "allow", "tool": "email.send",
          "conditions": {"argument_constraints": {"to": {"any_domain_not_in": ["example.com"]}}}},
         "email.send", {"to": ["a@example.com", "x@evil.com"]}, "work", noon, "ken", True),
        ({"effect": "allow", "tool": "email.send",
          "conditions": {"argument_constraints": {"to": {"any_domain_not_in": ["example.com"]}}}},
         "email.send", {"to": ["a@example.com"]}, "work", noon, "ken", False),
    ]


NOTICE_XCASES = [
    # (params, expect_match)
    ({"to": ["team@example.com"], "subject": "Weekly status: Oct 12",
      "body": "Status update for week 42."}, True),
    ({"to": ["team@example.com", "outsider@evil.com"], "subject": "Weekly status: Oct 12",
      "body": "Status update for week 42."}, False),
    ({"to": ["team@example.com"], "subject": "Unrelated",
      "body": "Status update for week 42."}, False),
    ({"to": ["team@example.com"], "subject": "Weekly status: Oct 12",
      "body": "Status update for week 42." + "x" * 6000}, False),
]

NOTICE_RULE = {
    "effect": "allow", "rule_type": "notice", "tool": "email.send",
    "conditions": {"notice": {
        "audience": ["team@example.com"],
        "schedule": {"days": ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]},
        "subject_pattern": "^Weekly status:",
        "body_pattern": "Status update for week \\d+",
        "max_body_length": 5000,
    }},
}


class TestPythonRegoCrossCheck:
    @pytest.mark.parametrize("case", _cases())
    def test_case(self, opa, case):
        rule_d, tool, args, purpose, now, role, expect = case
        py_rule = _py_rule(rule_d)
        agent = SimpleNamespace(id="ag_ken", household_role=role)
        py_match = rule_matches(py_rule, agent, tool, args, purpose, now)
        assert py_match == expect, f"reference impl disagrees with expectation: {rule_d}"
        rego_d = opa.decide(_input_doc(
            [_rule_data(rule_d)], tool=tool, args=args, purpose=purpose,
            role=role, now=now,
        ))
        rego_match = rego_d["effect"] == "allow" and rego_d["rule"] == 1
        assert rego_match == py_match, (
            f"Rego/Python divergence on {rule_d} {tool} {args}: "
            f"python={py_match} rego={rego_match}"
        )

    @pytest.mark.parametrize("params,expect", NOTICE_XCASES)
    def test_notice_cases(self, opa, params, expect):
        py_rule = _py_rule(NOTICE_RULE)
        agent = SimpleNamespace(id="ag_ken", household_role="ken")
        py_match = rule_matches(py_rule, agent, "email.send", params, "work", MON_NOON)
        assert py_match == expect
        rego_d = opa.decide(_input_doc(
            [_rule_data(NOTICE_RULE)], tool="email.send", args=params,
            purpose="work", now=MON_NOON,
        ))
        rego_match = rego_d["effect"] == "allow"
        assert rego_match == py_match, f"notice divergence on {params}"


# ---------------------------------------------------------------------------
# Defaults equivalence: preset JSON rules vs versioned Rego defaults
# ---------------------------------------------------------------------------

def _rego_eval(expr):
    out = subprocess.run(
        [str(OPA_BIN), "eval", "-d", str(POLICIES_DIR),
         "--format", "json", expr],
        capture_output=True, text=True, timeout=60,
    )
    assert out.returncode == 0, out.stderr
    payload = json.loads(out.stdout)
    return payload["result"][0]["expressions"][0]["value"]


def _preset_rules(config_db, engine, preset, owner="Owner", members=None):
    summary = apply_preset(
        preset, db=config_db, engine=engine,
        owner_display_name=owner, member_display_names=members or [],
    )
    prefix = f"preset:{preset}:"
    dicts = [
        r for r in engine.version_rules_as_dicts()
        if str(r.get("name", "")).startswith(prefix)
    ]
    return dicts, summary


def _snapshot_for(config_db, engine, agent, dimensions, principal_id=None):
    from gateway.ontology import integration as oint
    ctx = {"principal_id": principal_id, "dimensions": dict(dimensions)}
    state, invalid = oint.resolve_ctx(config_db, ctx, agent)
    assert not invalid
    return engine._ontology_snapshot_data(state)


class TestDefaultsEquivalence:
    """The v1/*.rego defaults decide identically to the preset rules."""

    @pytest.mark.parametrize("preset,pkg", [
        ("work_personal_separation", "gateway.defaults.work_personal"),
        ("spending_thresholds", "gateway.defaults.spending"),
        ("social_send_approval", "gateway.defaults.social_send"),
    ])
    def test_family_equivalence(self, config_db, opa, ken_agent, preset, pkg):
        eng = PolicyEngine(config_db, opa_client=opa)
        dicts, _ = _preset_rules(config_db, eng, preset)
        assert dicts, f"preset {preset} produced no rules"
        rego_rules = _rego_eval(f"data.{pkg}.rules")
        assert len(rego_rules) == len(dicts)
        preset_data = [_rule_data(d, rid=i) for i, d in enumerate(dicts)]
        rego_data = [_rule_data(d, rid=i) for i, d in enumerate(rego_rules)]

        probes = [
            ("email.send", {"purpose": "work"}),
            ("email.send", {"purpose": "personal"}),
            ("calendar.read", {"purpose": "personal"}),
            ("payment.initiate", {"purpose": "personal"}),
            ("shopping.buy", {"purpose": "personal"}),
            ("social.post", {"purpose": "work"}),
        ]
        for action, dimensions in probes:
            snap = _snapshot_for(config_db, eng, ken_agent, dimensions)
            d1 = opa.decide(_input_doc(
                preset_data, tool=action, purpose=dimensions.get("purpose"),
                ontology_snapshot=snap,
            ))
            d2 = opa.decide(_input_doc(
                rego_data, tool=action, purpose=dimensions.get("purpose"),
                ontology_snapshot=snap,
            ))
            assert (d1["effect"], d1.get("ontology_ref", {}).get("entry_kind")) == \
                   (d2["effect"], d2.get("ontology_ref", {}).get("entry_kind")), (
                f"{preset}: divergence on {action} {dimensions}: "
                f"preset={d1} rego={d2}"
            )

    def test_paa10_equivalence(self, config_db, opa):
        # Python-canonical PAA10_RULES vs v1/paa10.rego.
        rego_rules = _rego_eval("data.gateway.defaults.paa10.rules")
        assert len(rego_rules) == len(PAA10_RULES)
        py_data = [_rule_data(d, rid=i) for i, d in enumerate(PAA10_RULES)]
        rego_data = [_rule_data(d, rid=i) for i, d in enumerate(rego_rules)]
        probes = [
            ("calendar.delete", {}, "work", "ken"),
            ("email.settings.write", {}, "work", "ken"),
            ("code.pr.open", {}, "work", "ken"),
            ("email.read", {}, "work", "ken"),
            ("email.read", {}, "personal", "ken"),
            ("calendar.read", {}, "work", "spouse"),
            ("calendar.read", {}, "work", "ken"),
        ]
        for action, args, purpose, role in probes:
            d1 = opa.decide(_input_doc(py_data, tool=action, args=args, purpose=purpose, role=role))
            d2 = opa.decide(_input_doc(rego_data, tool=action, args=args, purpose=purpose, role=role))
            assert (d1["effect"], d1["rule"]) == (d2["effect"], d2["rule"]), (
                f"paa10 divergence on {action}: py={d1} rego={d2}"
            )


# ---------------------------------------------------------------------------
# seed_defaults + audit traceability
# ---------------------------------------------------------------------------

class TestSeedDefaults:
    def test_seed_defaults(self, config_db, opa):
        eng = PolicyEngine(config_db, opa_client=opa)
        summary = seed_defaults(eng, config_db, owner_display_name="Ken",
                                member_display_names=["Spouse"])
        assert set(summary["versions"]) == {
            "work_personal_separation", "spending_thresholds",
            "social_send_approval", "household_boundaries", "paa10",
        }
        # Spot-check enforced behavior: payments need approval (PAA06).
        agent = _register(config_db, "ag_seed", "ken", "work")
        r = eng.evaluate_call(agent, "payment.initiate", {"amount": 5}, purpose="work")
        assert r.decision == "require_approval"
        # PAA10 destructive default.
        r = eng.evaluate_call(agent, "calendar.delete", {"event_id": "e1"}, purpose="work")
        assert r.decision == "require_approval"


class TestAuditTraceability:
    def test_row_carries_data_snapshot_id(self, config_db, audit_db, opa):
        # Minimal: drive the policy stage + audit stage directly.
        eng = PolicyEngine(config_db, opa_client=opa)
        eng.save_version([{"name": "r", "effect": "allow", "tool": "test.echo"}])
        agent = _register(config_db)
        ctx = CallContext(agent_id=agent.id, tool="test.echo", args={"x": 1})
        ctx.agent = agent
        stage = PolicyStage(config_db)
        stage.engine.opa_client = opa
        assert stage.run(ctx) is None
        assert ctx.data_snapshot_id is not None
        assert ctx.data_snapshot_id.startswith("pv1/rules:")
        audit = AuditLog(audit_db)
        AuditStage(audit).run(ctx)
        row = audit.search(agent_id=agent.id, tool="test.echo")[0]
        assert row.data_snapshot_id == ctx.data_snapshot_id
        assert row.ontology_snapshot_ref is None

    def test_ontology_shaped_row_carries_both_refs(self, config_db, audit_db, opa):
        from gateway.hmac_util import HmacKeyRing
        ring = HmacKeyRing.from_env_string("k1", "test-hmac-key-material-32bytes!")
        eng = PolicyEngine(config_db, opa_client=opa, hmac_ring=ring)
        store = OntologyStore(config_db)
        owner = store.create_principal("person", "Ken")
        store.upsert_dimension("purpose", ["work", "personal"])
        store.bind_agent("ag_ken", owner.id)
        eng.save_version([{
            "name": "work send", "effect": "allow", "tool": "email.send",
            "conditions": {"ontology": {"dimension": {"purpose": "work"}}},
        }])
        agent = _register(config_db)
        res = eng.evaluate_call(
            agent, "email.send", {"to": ["a@b.com"]}, purpose="work",
            ontology_ctx={"principal_id": owner.id, "dimensions": {"purpose": "work"}},
        )
        assert res.decision == "allow"
        assert res.ontology_snapshot_ref is not None
        assert "/ont:" in res.data_snapshot_id and not res.data_snapshot_id.endswith("/ont:none")
        audit = AuditLog(audit_db)
        entry = audit.append(
            agent_id=agent.id, tool="email.send", decision="allowed",
            redacted_args={}, ontology_snapshot_ref=res.ontology_snapshot_ref,
            data_snapshot_id=res.data_snapshot_id,
        )
        assert entry.data_snapshot_id == res.data_snapshot_id
        assert entry.ontology_snapshot_ref == res.ontology_snapshot_ref


# ---------------------------------------------------------------------------
# CI shape: opa fmt / check / test via subprocess
# ---------------------------------------------------------------------------

class TestOpaSuites:
    def test_fmt_clean(self):
        out = subprocess.run(
            [str(OPA_BIN), "fmt", "--fail", str(POLICIES_DIR)],
            capture_output=True, text=True, timeout=60,
        )
        assert out.returncode == 0, out.stderr

    def test_check_clean(self):
        out = subprocess.run(
            [str(OPA_BIN), "check", str(POLICIES_DIR)],
            capture_output=True, text=True, timeout=60,
        )
        assert out.returncode == 0, out.stderr

    def test_opa_test_suites_pass(self):
        out = subprocess.run(
            [str(OPA_BIN), "test", str(POLICIES_DIR)],
            capture_output=True, text=True, timeout=120,
        )
        assert out.returncode == 0, out.stderr
        assert "FAIL" not in out.stdout
