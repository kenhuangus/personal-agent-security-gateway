"""Personal-ontology governance tests.

Covers (per the ontology build task):
- model validation (kinds, dangling references, dimension value sets)
- CRUD round-trips for every entity
- relationship queries (household seeding → PAA08)
- policy integration: dimension-scoped allow/deny, household
  relationship + owner_approval → require_approval, preference-group
  restriction upgrades, default-deny on unknown dimensions
- decision snapshots: determinism, immutability, tamper-evidence,
  reference integrity with audit rows
- rule-schema validation for the ontology clause
- admin-action audit logging of every mutation
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from sqlalchemy import update

from gateway.audit import AuditLog
from gateway.config import Settings
from gateway.db import Databases
from gateway.hmac_util import HmacKeyRing
from gateway.ontology import (
    OntologyError,
    OntologyStore,
    SnapshotInput,
    capture_snapshot,
    get_snapshot,
    validate_ontology_clause,
    validate_ontology_conditions,
    verify_snapshot,
)
from gateway.ontology.models import OntologySnapshot
from gateway.policy import PolicyEngine, validate_rule_dict

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


@pytest.fixture()
def audit_log(audit_db):
    return AuditLog(audit_db)


@pytest.fixture()
def store(config_db, audit_log):
    return OntologyStore(config_db, audit_log)


@pytest.fixture()
def ring():
    return HmacKeyRing.from_env_string("k1", HMAC_KEY)


@pytest.fixture()
def engine(config_db, ring):
    return PolicyEngine(config_db, hmac_ring=ring)


@pytest.fixture()
def seeded(store):
    """Dimensions + household seed shared by policy tests."""
    store.upsert_dimension("purpose", ["work", "personal", "family"])
    store.upsert_dimension("location", ["home", "office", "travel"])
    household = store.seed_household("Ken", ["Spouse"])
    return household


def _agent(agent_id):
    return SimpleNamespace(id=agent_id, household_role="ken")


# ---------------------------------------------------------------------------
# Model validation
# ---------------------------------------------------------------------------

class TestValidation:
    def test_bad_principal_kind(self, store):
        with pytest.raises(OntologyError):
            store.create_principal("robot", "R2D2")

    def test_empty_display_name(self, store):
        with pytest.raises(OntologyError):
            store.create_principal("person", "  ")

    def test_relationship_dangling_source(self, store):
        ken = store.create_principal("person", "Ken")
        with pytest.raises(OntologyError):
            store.add_relationship("ont_nonexistent", "owns", ken.id)

    def test_relationship_dangling_target(self, store):
        ken = store.create_principal("person", "Ken")
        with pytest.raises(OntologyError):
            store.add_relationship(ken.id, "owns", "ont_nonexistent")

    def test_relationship_bad_type(self, store):
        ken = store.create_principal("person", "Ken")
        with pytest.raises(OntologyError):
            store.add_relationship(ken.id, "married_to", ken.id)

    def test_resource_bad_label(self, store):
        ken = store.create_principal("person", "Ken")
        with pytest.raises(OntologyError):
            store.create_resource("mailbox", "Inbox", "secret", ken.id)

    def test_resource_dangling_owner(self, store):
        with pytest.raises(OntologyError):
            store.create_resource("mailbox", "Inbox", "private", "ont_nobody")

    def test_dimension_group_unknown_dimension(self, store):
        with pytest.raises(OntologyError):
            store.create_dimension_group("at_office", {"purpose": "work"})

    def test_dimension_group_bad_value(self, store):
        store.upsert_dimension("purpose", ["work", "personal"])
        with pytest.raises(OntologyError):
            store.create_dimension_group("at_office", {"purpose": "evil"})

    def test_preference_group_unknown_dimension_group(self, store):
        with pytest.raises(OntologyError):
            store.create_preference_group(
                "prefs", "ont_nonexistent", {"deny": ["email.send"]}
            )

    def test_preference_group_bad_constraint_key(self, store):
        store.upsert_dimension("purpose", ["work", "personal"])
        g = store.create_dimension_group("work", {"purpose": "work"})
        with pytest.raises(OntologyError):
            store.create_preference_group(
                "prefs", g.id, {"maybe_allow": ["email.send"]}
            )

    def test_delete_principal_refused_while_referenced(self, store):
        ken = store.create_principal("person", "Ken")
        spouse = store.create_principal("person", "Spouse")
        store.add_relationship(spouse.id, "household_member_of", ken.id)
        with pytest.raises(OntologyError):
            store.delete_principal(ken.id)
        # Removing the relationship unblocks the delete.
        assert store.remove_relationship(
            spouse.id, "household_member_of", ken.id
        ) is True
        store.delete_principal(ken.id)
        assert store.get_principal(ken.id) is None

    def test_delete_dimension_refused_while_referenced(self, store):
        store.upsert_dimension("purpose", ["work", "personal"])
        g = store.create_dimension_group("work", {"purpose": "work"})
        with pytest.raises(OntologyError):
            store.delete_dimension("purpose")
        store.delete_dimension_group(g.id)
        assert store.delete_dimension("purpose") is True


# ---------------------------------------------------------------------------
# CRUD round-trips
# ---------------------------------------------------------------------------

class TestCrud:
    def test_principal_round_trip(self, store):
        p = store.create_principal("agent", "Muse")
        assert store.get_principal(p.id).display_name == "Muse"
        assert len(store.list_principals()) == 1
        assert len(store.list_principals(kind="agent")) == 1
        assert store.list_principals(kind="person") == []
        store.update_principal(p.id, display_name="Muse v2")
        assert store.get_principal(p.id).display_name == "Muse v2"
        store.delete_principal(p.id)
        assert store.get_principal(p.id) is None

    def test_resource_round_trip(self, store):
        ken = store.create_principal("person", "Ken")
        r = store.create_resource("mailbox", "Ken inbox", "private", ken.id)
        assert store.get_resource(r.id).label_class == "private"
        assert len(store.list_resources(owner_principal_id=ken.id)) == 1
        assert len(store.list_resources(label_class="work")) == 0
        assert store.delete_resource(r.id) is True
        assert store.delete_resource(r.id) is False

    def test_action_round_trip(self, store):
        a = store.create_action("email.send", "sensitive")
        assert store.list_actions()[0].name == "email.send"
        with pytest.raises(OntologyError):
            store.create_action("email.send")  # duplicate name
        assert store.delete_action(a.id) is True

    def test_dimension_round_trip(self, store):
        store.upsert_dimension("purpose", ["work", "personal"])
        assert store.get_dimension("purpose").allowed_values == ["work", "personal"]
        store.upsert_dimension("purpose", ["work", "personal", "family"])
        assert "family" in store.get_dimension("purpose").allowed_values
        assert len(store.list_dimensions()) == 1

    def test_agent_binding(self, store):
        ken = store.create_principal("person", "Ken")
        store.bind_agent("ag_ken", ken.id)
        assert store.principal_for_agent("ag_ken") == ken.id
        assert store.unbind_agent("ag_ken") is True
        assert store.principal_for_agent("ag_ken") is None


# ---------------------------------------------------------------------------
# Relationship queries (PAA08 household)
# ---------------------------------------------------------------------------

class TestRelationships:
    def test_seed_household(self, store):
        household = store.seed_household("Ken", ["Spouse", "Kid"])
        owner = household["owner"]
        members = store.related_principals(owner.id, "household_member_of")
        assert {m.display_name for m in members} == {"Spouse", "Kid"}
        assert store.has_relationship(
            household["Spouse"].id, "household_member_of", owner.id
        )
        # Idempotent: re-seeding does not duplicate.
        store.seed_household("Ken", ["Spouse", "Kid"])
        assert len(store.related_principals(owner.id, "household_member_of")) == 2

    def test_relationships_of_directions(self, store):
        ken = store.create_principal("person", "Ken")
        svc = store.create_principal("service", "Gmail")
        store.add_relationship(ken.id, "owns", svc.id)
        assert len(store.relationships_of(ken.id, "out")) == 1
        assert len(store.relationships_of(svc.id, "in")) == 1
        assert len(store.relationships_of(ken.id, "both")) == 1
        assert store.relationships_of(svc.id, "out") == []


# ---------------------------------------------------------------------------
# Rule-schema validation
# ---------------------------------------------------------------------------

class TestRuleSchema:
    def test_validate_rule_dict_accepts_ontology_clause(self):
        rule = validate_rule_dict(
            {
                "name": "work calendar",
                "effect": "allow",
                "tool": "calendar.read",
                "conditions": {"ontology": {"dimension": {"purpose": "work"}}},
            }
        )
        assert rule["conditions"]["ontology"]["dimension"] == {"purpose": "work"}

    def test_validate_rule_dict_rejects_unknown_clause_key(self):
        with pytest.raises(ValueError):
            validate_rule_dict(
                {
                    "effect": "allow",
                    "conditions": {"ontology": {"mood": "happy"}},
                }
            )

    def test_validate_rule_dict_rejects_bad_relationship_type(self):
        with pytest.raises(ValueError):
            validate_rule_dict(
                {
                    "effect": "allow",
                    "conditions": {
                        "ontology": {
                            "relationship": {"type": "married_to", "target": "x"}
                        }
                    },
                }
            )

    def test_validate_rule_dict_rejects_bad_requires(self):
        with pytest.raises(ValueError):
            validate_rule_dict(
                {
                    "effect": "allow",
                    "conditions": {"ontology": {"requires": "pinkie_promise"}},
                }
            )

    def test_validate_ontology_conditions_store_aware(self, store, seeded):
        owner = seeded["owner"]
        validate_ontology_conditions(
            store.db,
            {"ontology": {"dimension": {"purpose": "work"}}},
        )
        with pytest.raises(OntologyError):  # unknown dimension
            validate_ontology_conditions(
                store.db, {"ontology": {"dimension": {"mood": "happy"}}}
            )
        with pytest.raises(OntologyError):  # bad value
            validate_ontology_conditions(
                store.db, {"ontology": {"dimension": {"purpose": "evil"}}}
            )
        with pytest.raises(OntologyError):  # unknown dimension group
            validate_ontology_conditions(
                store.db, {"ontology": {"dimension_group": "nowhere"}}
            )
        with pytest.raises(OntologyError):  # unknown principal target
            validate_ontology_conditions(
                store.db,
                {"ontology": {"relationship": {
                    "type": "household_member_of", "target": "ont_nobody"}}},
            )
        # Known principal target passes.
        validate_ontology_conditions(
            store.db,
            {"ontology": {"relationship": {
                "type": "household_member_of", "target": owner.id}}},
        )
        # Standalone structural helper agrees on shape errors.
        with pytest.raises(ValueError):
            validate_ontology_clause({"bogus": 1})


# ---------------------------------------------------------------------------
# Policy integration
# ---------------------------------------------------------------------------

class TestPolicyIntegration:
    def test_dimension_scoped_rule_allows_and_denies(
        self, engine, seeded
    ):
        engine.save_version(
            [
                {
                    "name": "work calendar reads",
                    "effect": "allow",
                    "tool": "calendar.read",
                    "conditions": {"ontology": {"dimension": {"purpose": "work"}}},
                }
            ]
        )
        agent = _agent("ag_ken")
        ok = engine.evaluate_call(
            agent, "calendar.read", {},
            ontology_ctx={"dimensions": {"purpose": "work"}},
        )
        assert ok.decision == "allow" and ok.matched_rule_id is not None

        denied = engine.evaluate_call(
            agent, "calendar.read", {},
            ontology_ctx={"dimensions": {"purpose": "personal"}},
        )
        # Unmatched dimension scope → pinned default-deny, never silent pass.
        assert denied.decision == "deny" and denied.matched_rule_id is None

    def test_ontology_rule_needs_context_to_match(self, engine, seeded):
        engine.save_version(
            [
                {
                    "name": "work-only",
                    "effect": "allow",
                    "tool": "calendar.read",
                    "conditions": {"ontology": {"dimension": {"purpose": "work"}}},
                }
            ]
        )
        # No ontology_ctx at all: the ontology-scoped rule cannot match →
        # default-deny, exactly as before this feature existed.
        result = engine.evaluate_call(_agent("ag_ken"), "calendar.read", {})
        assert result.decision == "deny" and result.matched_rule_id is None

    def test_unknown_dimension_denies(self, engine, seeded):
        engine.save_version(
            [{"name": "allow all", "effect": "allow", "tool": "calendar.read"}]
        )
        result = engine.evaluate_call(
            _agent("ag_ken"), "calendar.read", {},
            ontology_ctx={"dimensions": {"mood": "happy"}},
        )
        assert result.decision == "deny" and result.matched_rule_id is None

    def test_unknown_dimension_value_denies(self, engine, seeded):
        engine.save_version(
            [{"name": "allow all", "effect": "allow", "tool": "calendar.read"}]
        )
        result = engine.evaluate_call(
            _agent("ag_ken"), "calendar.read", {},
            ontology_ctx={"dimensions": {"purpose": "evil"}},
        )
        assert result.decision == "deny" and result.matched_rule_id is None

    def test_household_relationship_with_owner_approval(
        self, engine, store, seeded, ring
    ):
        owner = seeded["owner"]
        spouse = seeded["Spouse"]
        store.bind_agent("ag_spouse", spouse.id)
        store.bind_agent("ag_ken", owner.id)
        engine.save_version(
            [
                {
                    "name": "owner data for household",
                    "effect": "allow",
                    "tool": "email.read",
                    "conditions": {
                        "ontology": {
                            "relationship": {
                                "type": "household_member_of",
                                "target": owner.id,
                            },
                            "requires": "owner_approval",
                        }
                    },
                }
            ]
        )
        # Spouse IS a household member → rule matches, but owner approval
        # is required → surfaces as require_approval (feeds M3's queue).
        result = engine.evaluate_call(
            _agent("ag_spouse"), "email.read", {}, ontology_ctx={"dimensions": {}}
        )
        assert result.decision == "require_approval"
        assert result.requires_approval is True
        assert result.matched_rule_id is not None
        assert result.ontology_snapshot_ref is not None
        assert result.ontology_snapshot_ref.startswith("k1:")

        # The owner is not a household member of themselves → clause fails
        # → default-deny.
        denied = engine.evaluate_call(
            _agent("ag_ken"), "email.read", {}, ontology_ctx={"dimensions": {}}
        )
        assert denied.decision == "deny" and denied.matched_rule_id is None

    def test_explicit_principal_id_in_ctx(self, engine, store, seeded):
        owner = seeded["owner"]
        spouse = seeded["Spouse"]
        engine.save_version(
            [
                {
                    "name": "member rule",
                    "effect": "allow",
                    "tool": "email.read",
                    "conditions": {
                        "ontology": {
                            "relationship": {
                                "type": "household_member_of",
                                "target": owner.id,
                            }
                        }
                    },
                }
            ]
        )
        result = engine.evaluate_call(
            _agent("ag_anyone"),
            "email.read",
            {},
            ontology_ctx={"principal_id": spouse.id, "dimensions": {}},
        )
        assert result.decision == "allow"

        # Unknown principal id → fail closed.
        denied = engine.evaluate_call(
            _agent("ag_anyone"),
            "email.read",
            {},
            ontology_ctx={"principal_id": "ont_nobody", "dimensions": {}},
        )
        assert denied.decision == "deny"

    def test_dimension_group_clause(self, engine, store, seeded):
        store.create_dimension_group(
            "at_office", {"purpose": "work", "location": "office"}
        )
        engine.save_version(
            [
                {
                    "name": "office writes",
                    "effect": "allow",
                    "tool": "calendar.create",
                    "conditions": {"ontology": {"dimension_group": "at_office"}},
                }
            ]
        )
        agent = _agent("ag_ken")
        ok = engine.evaluate_call(
            agent, "calendar.create", {},
            ontology_ctx={"dimensions": {"purpose": "work", "location": "office"}},
        )
        assert ok.decision == "allow"
        denied = engine.evaluate_call(
            agent, "calendar.create", {},
            ontology_ctx={"dimensions": {"purpose": "work", "location": "home"}},
        )
        assert denied.decision == "deny"

    def test_preference_group_restricts(self, engine, store, seeded):
        group = store.create_dimension_group(
            "at_office", {"purpose": "work", "location": "office"}
        )
        store.create_preference_group(
            "office prefs",
            group.id,
            {
                "require_approval": ["email.send"],
                "deny": ["code.pr.open"],
            },
        )
        engine.save_version(
            [
                {"name": "send", "effect": "allow", "tool": "email.send"},
                {"name": "pr", "effect": "allow", "tool": "code.pr.open"},
                {"name": "read", "effect": "allow", "tool": "calendar.read"},
            ]
        )
        agent = _agent("ag_ken")
        office = {"dimensions": {"purpose": "work", "location": "office"}}
        home = {"dimensions": {"purpose": "personal", "location": "home"}}

        # In the office slice: send escalates, pr.open denies.
        r = engine.evaluate_call(agent, "email.send", {}, ontology_ctx=office)
        assert r.decision == "require_approval" and r.requires_approval
        r = engine.evaluate_call(agent, "code.pr.open", {}, ontology_ctx=office)
        assert r.decision == "deny"
        # Unlisted tools are untouched by the slice.
        r = engine.evaluate_call(agent, "calendar.read", {}, ontology_ctx=office)
        assert r.decision == "allow"
        # Outside the slice: plain rules apply unchanged.
        r = engine.evaluate_call(agent, "email.send", {}, ontology_ctx=home)
        assert r.decision == "allow"
        r = engine.evaluate_call(agent, "code.pr.open", {}, ontology_ctx=home)
        assert r.decision == "allow"

    def test_preference_group_wildcard(self, engine, store, seeded):
        group = store.create_dimension_group(
            "personal_time", {"purpose": "personal", "location": "home"}
        )
        store.create_preference_group(
            "home prefs", group.id, {"require_approval": ["email.*"]}
        )
        engine.save_version([{"name": "send", "effect": "allow", "tool": "email.send"}])
        r = engine.evaluate_call(
            _agent("ag_ken"), "email.send", {},
            ontology_ctx={"dimensions": {"purpose": "personal", "location": "home"}},
        )
        assert r.decision == "require_approval"

    def test_snapshot_captured_on_preference_upgrade(
        self, engine, store, seeded, config_db
    ):
        group = store.create_dimension_group(
            "at_office", {"purpose": "work", "location": "office"}
        )
        pref = store.create_preference_group(
            "office prefs", group.id, {"deny": ["email.send"]}
        )
        engine.save_version(
            [{"name": "send", "effect": "allow", "tool": "email.send"}]
        )
        result = engine.evaluate_call(
            _agent("ag_ken"), "email.send", {},
            ontology_ctx={"dimensions": {"purpose": "work", "location": "office"}},
        )
        assert result.decision == "deny"
        ref = result.ontology_snapshot_ref
        assert ref is not None
        snap = get_snapshot(config_db, ref)
        assert snap is not None
        assert pref.id in [
            p["id"] for p in snap.payload["preference_groups"]
        ]


# ---------------------------------------------------------------------------
# Snapshots: immutability, tamper-evidence, reference integrity
# ---------------------------------------------------------------------------

class TestSnapshots:
    def _input(self, store, seeded):
        group = store.create_dimension_group(
            "at_office", {"purpose": "work", "location": "office"}
        )
        return SnapshotInput(
            principal_id=seeded["owner"].id,
            dimensions={"purpose": "work", "location": "office"},
            dimension_group_ids=[group.id],
            preference_group_ids=[],
            matched_rule_id=7,
            policy_version=3,
        )

    def test_capture_is_deterministic(self, config_db, store, seeded, ring):
        snap_in = self._input(store, seeded)
        ref1 = capture_snapshot(config_db, ring, snap_in)
        ref2 = capture_snapshot(config_db, ring, snap_in)
        assert ref1 == ref2
        assert ref1.startswith("k1:")

    def test_payload_round_trip(self, config_db, store, seeded, ring):
        ref = capture_snapshot(config_db, ring, self._input(store, seeded))
        snap = get_snapshot(config_db, ref)
        assert snap.payload["principal"]["id"] == seeded["owner"].id
        assert snap.payload["dimensions"] == {
            "purpose": "work",
            "location": "office",
        }
        assert snap.payload["matched_rule_id"] == 7
        assert snap.payload["policy_version"] == 3
        # Relationships of the principal are captured.
        rel_types = {r["type"] for r in snap.payload["relationships"]}
        assert "household_member_of" in rel_types

    def test_verify_true_and_tamper_false(self, config_db, store, seeded, ring):
        ref = capture_snapshot(config_db, ring, self._input(store, seeded))
        assert verify_snapshot(config_db, ring, ref) is True
        # Tamper with the stored payload: verification must fail.
        config_db.execute(
            update(OntologySnapshot)
            .where(OntologySnapshot.id == ref)
            .values(payload={"schema": "ontology-snapshot/v1", "tampered": True})
        )
        config_db.commit()
        assert verify_snapshot(config_db, ring, ref) is False
        assert verify_snapshot(config_db, ring, "k1:" + "0" * 64) is False

    def test_audit_row_carries_snapshot_ref(
        self, audit_log, audit_db, config_db, store, seeded, ring
    ):
        ref = capture_snapshot(config_db, ring, self._input(store, seeded))
        row = audit_log.append(
            agent_id="ag_ken",
            tool="email.send",
            decision="denied",
            reason="explicit_deny",
            ontology_snapshot_ref=ref,
        )
        assert row.ontology_snapshot_ref == ref
        found = audit_log.search(agent_id="ag_ken")
        assert found[0].ontology_snapshot_ref == ref

    def test_no_snapshot_without_ring(self, config_db, seeded):
        store = OntologyStore(config_db)
        store.upsert_dimension("purpose", ["work", "personal", "family"])
        engine = PolicyEngine(config_db)  # no hmac_ring
        engine.save_version(
            [
                {
                    "name": "work rule",
                    "effect": "allow",
                    "tool": "calendar.read",
                    "conditions": {"ontology": {"dimension": {"purpose": "work"}}},
                }
            ]
        )
        result = engine.evaluate_call(
            _agent("ag_ken"), "calendar.read", {},
            ontology_ctx={"dimensions": {"purpose": "work"}},
        )
        # Enforcement still applies; only the snapshot capture is skipped.
        assert result.decision == "allow"
        assert result.ontology_snapshot_ref is None


# ---------------------------------------------------------------------------
# Admin-action audit logging
# ---------------------------------------------------------------------------

class TestAdminAudit:
    def test_mutations_are_audit_logged(self, store, audit_log):
        ken = store.create_principal("person", "Ken")
        store.upsert_dimension("purpose", ["work", "personal"])
        store.create_dimension_group("work", {"purpose": "work"})
        rows = audit_log.search(tool="ontology.admin")
        actions = {r.action for r in rows}
        assert {
            "principal.create",
            "dimension.upsert",
            "dimension_group.create",
        } <= actions
        assert all(r.decision == "allowed" for r in rows)
        assert all(r.agent_id == "admin" for r in rows)
