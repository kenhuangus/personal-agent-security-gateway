"""Ontology "beyond" directives (2026-10-12 refinement).

Covers the five deltas over the first ontology build:
1. discovery/bootstrap (inferred candidates, confirm/reject, no auto-promotion)
2. per-agent scoped views (PAA08 household separation, fail-closed)
3. living ontology (feedback loop -> review queue, never silent mutation)
4. presets/templates (idempotent, material-classified, documented behavior)
5. enforcement-first citations (ontology_ref in deny/ask reasons)
"""

from __future__ import annotations

import datetime as dt
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from gateway.audit import AuditLog
from gateway.config import Settings
from gateway.db import Databases
from gateway.errors import SAFE_REASONS, policy_denied
from gateway.hmac_util import HmacKeyRing
from gateway.models import PolicyVersion
from gateway.ontology import (
    OntologyError,
    OntologyStore,
    apply_preset,
    detect_conflicts,
    discover_from_accounts,
    discover_from_audit,
    list_presets,
    record_correction,
    record_decision_outcome,
    record_mandate_event,
    resolve_ctx_for_agent,
    scoped_view,
    sweep_stale,
)
from gateway.policy import PolicyEngine

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


def _agent(agent_id):
    return SimpleNamespace(id=agent_id, household_role="tester")


# ---------------------------------------------------------------------------
# 1. Discovery / bootstrap
# ---------------------------------------------------------------------------

class TestDiscovery:
    def test_discover_from_accounts(self, store):
        created = discover_from_accounts(
            store,
            [
                {
                    "source": "gmail",
                    "account_id": "ken@example.com",
                    "display_name": "Ken",
                    "kind": "mailbox",
                    "label_class": "private",
                }
            ],
        )
        assert len(created) == 2
        kinds = sorted(c.kind for c in created)
        assert kinds == ["principal", "resource"]
        for c in created:
            assert c.status == "pending_confirmation"
            assert c.provenance == "inferred:gmail"
            assert 0.0 <= c.confidence <= 1.0
        # Nothing is authority yet: no real principals/resources exist.
        assert store.list_principals() == []
        assert store.list_resources() == []

    def test_discover_from_audit(self, store, audit_db, audit_log):
        ken = store.create_principal("person", "Ken")
        store.bind_agent("ag1", ken.id)
        for _ in range(4):
            audit_log.append(
                agent_id="ag1", tool="email.send", decision="allowed",
                mandate_id="mnd_1",
            )
        created = discover_from_audit(
            store,
            audit_db,
            min_occurrences=3,
            mandate_purpose_of=lambda mid: {"mnd_1": "work"}.get(mid),
        )
        by_kind = {}
        for c in created:
            by_kind.setdefault(c.kind, []).append(c)
        # Recurring (agent, tool) -> candidate resource owned by the
        # bound principal, and a purpose dimension candidate.
        assert "resource" in by_kind
        res = by_kind["resource"][0]
        assert res.payload["owner_id"] == ken.id
        assert res.provenance == "inferred:audit-log"
        assert "dimension" in by_kind
        dim = by_kind["dimension"][0]
        assert dim.payload["name"] == "purpose"
        assert "work" in dim.payload["allowed_values"]

    def test_discovery_is_idempotent(self, store, audit_db, audit_log):
        ken = store.create_principal("person", "Ken")
        store.bind_agent("ag1", ken.id)
        for _ in range(3):
            audit_log.append(agent_id="ag1", tool="email.send", decision="allowed")
        first = discover_from_audit(store, audit_db, min_occurrences=3)
        second = discover_from_audit(store, audit_db, min_occurrences=3)
        assert len(first) > 0
        assert second == []  # dedupe: nothing proposed twice

    def test_confirm_promotes_with_provenance_chain(self, store):
        created = discover_from_accounts(
            store,
            [{"source": "gmail", "display_name": "Ken", "kind": "mailbox"}],
        )
        principal_cand = next(c for c in created if c.kind == "principal")
        entity = store.confirm_candidate(principal_cand.id)
        assert entity.display_name == "Ken"
        assert entity.provenance.startswith("inferred:gmail")
        assert "explicit:confirmed" in entity.provenance
        assert store.get_candidate(principal_cand.id).status == "confirmed"
        # Confirming twice is an error.
        with pytest.raises(OntologyError):
            store.confirm_candidate(principal_cand.id)

    def test_confirm_with_corrections(self, store):
        created = discover_from_accounts(
            store,
            [{"source": "gmail", "display_name": "Ken", "kind": "mailbox"}],
        )
        store.confirm_candidate(
            next(c for c in created if c.kind == "principal").id
        )
        resource_cand = next(c for c in created if c.kind == "resource")
        resource = store.confirm_candidate(
            resource_cand.id, corrections={"label_class": "work"}
        )
        assert resource.label_class == "work"
        assert "corrections" in (resource.provenance or "")

    def test_reject_candidate(self, store):
        created = discover_from_accounts(
            store, [{"source": "gmail", "display_name": "Ken", "kind": "mailbox"}]
        )
        cand = created[0]
        store.reject_candidate(cand.id)
        assert store.get_candidate(cand.id).status == "rejected"
        with pytest.raises(OntologyError):
            store.confirm_candidate(cand.id)
        # Rejected inferences stay visible for auditability.
        assert store.list_candidates(status="rejected")

    def test_time_pattern_is_cautious(self, store, audit_db, audit_log):
        store.upsert_dimension(
            "time_of_day", ["morning", "afternoon", "evening", "night"]
        )
        ken = store.create_principal("person", "Ken")
        store.bind_agent("ag1", ken.id)
        morning = dt.datetime(2026, 10, 12, 9, 30, tzinfo=dt.timezone.utc)
        for i in range(3):
            audit_log.append(
                agent_id="ag1", tool="email.send", decision="allowed",
                timestamp=morning + dt.timedelta(minutes=i),
            )
        created = discover_from_audit(store, audit_db, min_occurrences=3)
        groups = [c for c in created if c.kind == "dimension_group"]
        assert len(groups) == 1
        assert groups[0].payload["dimensions"]["time_of_day"] == "morning"
        assert groups[0].confidence == 0.4  # low: usage pattern, not a rule

    def test_no_time_dimension_no_time_inference(self, store, audit_db, audit_log):
        ken = store.create_principal("person", "Ken")
        store.bind_agent("ag1", ken.id)
        morning = dt.datetime(2026, 10, 12, 9, 30, tzinfo=dt.timezone.utc)
        for i in range(3):
            audit_log.append(
                agent_id="ag1", tool="email.send", decision="allowed",
                timestamp=morning + dt.timedelta(minutes=i),
            )
        created = discover_from_audit(store, audit_db, min_occurrences=3)
        assert not [c for c in created if c.kind == "dimension_group"]
        # ... but the purpose fallback from the tool class still fires.
        dims = [c for c in created if c.kind == "dimension"]
        assert dims and "communication" in dims[0].payload["allowed_values"]

    def test_candidate_provenance_must_be_inferred(self, store):
        with pytest.raises(OntologyError):
            store.propose_candidates(
                [
                    {
                        "kind": "principal",
                        "payload": {"kind": "person", "display_name": "X"},
                        "provenance": "explicit:manual",
                        "confidence": 0.9,
                    }
                ]
            )


# ---------------------------------------------------------------------------
# 2. Per-agent scoped views
# ---------------------------------------------------------------------------

class TestScopedViews:
    def _two_households(self, store):
        store.upsert_dimension("purpose", ["work", "personal", "family"])
        a = store.create_principal("person", "A")
        b = store.create_principal("person", "B")
        c = store.create_principal("person", "C")
        outsider = store.create_principal("person", "Outsider")
        store.add_relationship(a.id, "acts_for", b.id)
        store.add_relationship(b.id, "acts_for", c.id)
        store.bind_agent("ag_a", a.id)
        store.bind_agent("ag_b", b.id)
        return a, b, c, outsider

    def test_acts_for_closure(self, store, config_db):
        a, b, c, _ = self._two_households(store)
        view = scoped_view(config_db, "ag_a")
        assert view.bound_principal_id == a.id
        assert {a.id, b.id, c.id} <= view.principal_ids

    def test_delegates_to_grants_reverse(self, store, config_db):
        p = store.create_principal("person", "P")
        q = store.create_principal("person", "Q")
        store.add_relationship(q.id, "delegates_to", p.id)
        store.bind_agent("ag_p", p.id)
        view = scoped_view(config_db, "ag_p")
        assert q.id in view.principal_ids

    def test_household_views_are_separate(self, store, config_db):
        store.upsert_dimension("purpose", ["work", "personal", "family"])
        household = store.seed_household("Ken", ["Spouse"])
        owner, spouse = household["owner"], household["Spouse"]
        store.bind_agent("ag_spouse", spouse.id)
        store.bind_agent("ag_ken", owner.id)
        spouse_view = scoped_view(config_db, "ag_spouse")
        owner_view = scoped_view(config_db, "ag_ken")
        # A member's agent may reference the owner (owner_approval routing).
        assert owner.id in spouse_view.principal_ids
        # PAA08: the owner's agent does NOT get the member's view.
        assert spouse.id not in owner_view.principal_ids

    def test_scope_denies_outside_principal(self, engine, store, config_db):
        a, b, c, outsider = self._two_households(store)
        engine.save_version(
            [{"name": "read", "effect": "allow", "tool": "email.read"}]
        )
        # Inside the view: fine.
        ok = engine.evaluate_call(
            _agent("ag_a"), "email.read", {},
            ontology_ctx={"principal_id": b.id, "dimensions": {}},
        )
        assert ok.decision == "allow"
        # Outside the view: fail closed, citing the binding entry.
        denied = engine.evaluate_call(
            _agent("ag_a"), "email.read", {},
            ontology_ctx={"principal_id": outsider.id, "dimensions": {}},
        )
        assert denied.decision == "deny"
        assert denied.matched_rule_id is None
        ref = denied.ontology_ref
        assert ref["entry_kind"] == "agent_binding"
        assert ref["entry_id"] == "ag_a"
        assert ref["snapshot_ref"].startswith("k1:")

    def test_scope_denies_private_dimension_values(self, config_db, store):
        a, b, c, _ = self._two_households(store)
        # Agent A's mandates are work-only: purpose=personal is outside
        # the agent's scoped view.
        _, invalid, ref = resolve_ctx_for_agent(
            config_db,
            {"dimensions": {"purpose": "personal"}},
            "ag_a",
            mandate_purpose_keys=["work"],
        )
        assert invalid is True
        assert ref["entry_kind"] == "dimension"
        assert ref["entry_id"] == "purpose"
        # ... while purpose=work resolves.
        state, invalid, _ = resolve_ctx_for_agent(
            config_db,
            {"dimensions": {"purpose": "work"}},
            "ag_a",
            mandate_purpose_keys=["work"],
        )
        assert invalid is False and state.dimensions == {"purpose": "work"}

    def test_scope_denies_outside_resource(self, config_db, store):
        a, b, c, outsider = self._two_households(store)
        res = store.create_resource("mailbox", "Outsider Inbox", "private", outsider.id)
        _, invalid, ref = resolve_ctx_for_agent(
            config_db, {"dimensions": {}, "resource_id": res.id}, "ag_a"
        )
        assert invalid is True
        assert ref == {"entry_id": res.id, "entry_kind": "resource"}
        # A resource owned by an in-scope principal resolves.
        own = store.create_resource("mailbox", "A Inbox", "private", a.id)
        _, invalid, _ = resolve_ctx_for_agent(
            config_db, {"dimensions": {}, "resource_id": own.id}, "ag_a"
        )
        assert invalid is False

    def test_unbound_agent_keeps_legacy_path(self, config_db, store):
        a, _, _, _ = self._two_households(store)
        state, invalid, ref = resolve_ctx_for_agent(
            config_db, {"principal_id": a.id, "dimensions": {}}, "ag_nobody"
        )
        assert invalid is False and ref is None

    def test_agent_a_cannot_act_for_b_end_to_end(self, engine, store):
        store.upsert_dimension("purpose", ["work", "personal"])
        a = store.create_principal("person", "Alice")
        b = store.create_principal("person", "Bob")
        store.bind_agent("ag_alice", a.id)
        store.bind_agent("ag_bob", b.id)
        engine.save_version(
            [{"name": "read", "effect": "allow", "tool": "email.read"}]
        )
        # Alice's agent asking to act for Bob: denied, citing the scope.
        denied = engine.evaluate_call(
            _agent("ag_alice"), "email.read", {},
            ontology_ctx={"principal_id": b.id, "dimensions": {}},
        )
        assert denied.decision == "deny"
        assert denied.ontology_ref["entry_kind"] == "agent_binding"
        # Bob's own agent is unaffected.
        ok = engine.evaluate_call(
            _agent("ag_bob"), "email.read", {},
            ontology_ctx={"principal_id": b.id, "dimensions": {}},
        )
        assert ok.decision == "allow"


# ---------------------------------------------------------------------------
# 3. Living ontology (feedback loop -> review queue, never silent mutation)
# ---------------------------------------------------------------------------

class TestLivingOntology:
    def _work_slice(self, store):
        store.upsert_dimension("purpose", ["work", "personal"])
        group = store.create_dimension_group("work_slice", {"purpose": "work"})
        pref = store.create_preference_group(
            "work_prefs", group.id, {"require_approval": ["email.send"]}
        )
        return group, pref

    def test_mandate_withdrawal_flags_dependents(self, store):
        group, pref = self._work_slice(store)
        flagged = record_mandate_event(
            store, mandate_id="mnd_x", event="withdraw", purpose_key="work"
        )
        flagged_ids = {i.entry_id for i in flagged}
        assert pref.id in flagged_ids and group.id in flagged_ids
        reasons = {i.reason for i in flagged}
        assert any("mnd_x withdraw" in r for r in reasons)
        # Nothing was mutated: the entries still exist, unchanged.
        assert store.get_dimension_group(group.id) is not None
        assert any(p.id == pref.id for p in store.list_preference_groups())
        # And the queue holds them for the console.
        open_items = store.list_review_items(status="open")
        assert {i.entry_id for i in open_items} >= flagged_ids

    def test_mandate_event_without_purpose_flags_mandate(self, store):
        flagged = record_mandate_event(
            store, mandate_id="mnd_y", event="end"
        )
        assert len(flagged) == 1
        assert flagged[0].entry_kind == "mandate"
        assert flagged[0].entry_id == "mnd_y"

    def test_denied_vs_allow_documents_conflict(self, store):
        store.upsert_dimension("purpose", ["work", "personal"])
        group = store.create_dimension_group("slice2", {"purpose": "work"})
        pref = store.create_preference_group(
            "docs", group.id, {"allow": ["email.send"]}
        )
        flagged = record_decision_outcome(
            store,
            decision="denied",
            agent_id="ag1",
            tool="email.send",
            dimensions={"purpose": "work"},
        )
        assert any(
            i.entry_kind == "preference_group" and i.entry_id == pref.id
            for i in flagged
        )

    def test_repeated_denials_flag_staleness(self, store):
        store.upsert_dimension("purpose", ["work"])
        for _ in range(5):
            record_decision_outcome(
                store, decision="denied", agent_id="ag1",
                tool="email.send", dimensions={"purpose": "work"},
            )
        items = store.list_review_items(status="open")
        assert any(
            i.entry_kind == "tool" and i.entry_id == "email.send"
            for i in items
        )

    def test_correction_records_event_and_flag(self, store):
        event, item = record_correction(
            store,
            correction_kind="counterparty",
            target_kind="principal",
            target_id="ont_x",
            note="payee name fixed",
        )
        assert event.kind == "correction"
        assert event.provenance == "explicit:console"
        assert item.status == "open"
        assert "counterparty correction recorded" in item.reason

    def test_detect_conflicts(self, store):
        store.upsert_dimension("purpose", ["work"])
        group = store.create_dimension_group("slice3", {"purpose": "work"})
        a = store.create_preference_group(
            "deny_side", group.id, {"deny": ["email.send"]}
        )
        b = store.create_preference_group(
            "allow_side", group.id, {"allow": ["email.send"]}
        )
        flagged = detect_conflicts(store)
        assert any(i.entry_id == b.id for i in flagged)
        # The deny side is the enforced one; the allow-doc side is flagged.
        assert not any(i.entry_id == a.id for i in flagged)

    def test_sweep_stale(self, store, config_db):
        created = discover_from_accounts(
            store, [{"source": "gmail", "display_name": "Old", "kind": "mailbox"}]
        )
        old = created[0]
        old.created_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=100)
        config_db.commit()
        fresh = discover_from_accounts(
            store, [{"source": "gmail", "display_name": "New", "kind": "mailbox"}]
        )[0]
        flagged = sweep_stale(store, older_than_days=90)
        flagged_ids = {i.entry_id for i in flagged}
        assert old.id in flagged_ids
        assert fresh.id not in flagged_ids

    def test_review_resolve_and_dismiss(self, store):
        item = store.flag_for_review(
            "principal", "ont_x", "needs eyes", "inferred:pipeline"
        )
        resolved = store.resolve_review_item(item.id, resolution="checked ok")
        assert resolved.status == "resolved"
        assert resolved.context["resolution"] == "checked ok"
        with pytest.raises(OntologyError):
            store.resolve_review_item(item.id)
        item2 = store.flag_for_review(
            "principal", "ont_y", "needs eyes", "inferred:pipeline"
        )
        assert store.dismiss_review_item(item2.id).status == "dismissed"
        assert store.list_review_items(status="open") == []

    def test_feedback_events_are_immutable_log(self, store):
        store.record_feedback_event(
            "decision", {"decision": "allowed"}, "inferred:pipeline"
        )
        events = store.list_feedback_events(kind="decision")
        assert len(events) == 1
        # No update/delete API exists on the store for feedback events.
        assert not hasattr(store, "update_feedback_event")
        assert not hasattr(store, "delete_feedback_event")


# ---------------------------------------------------------------------------
# 4. Presets / templates
# ---------------------------------------------------------------------------

class TestPresets:
    def test_list_presets(self):
        assert set(list_presets()) == {
            "work_personal_separation",
            "spending_thresholds",
            "social_send_approval",
            "household_boundaries",
        }

    def test_unknown_preset(self, store, engine, config_db):
        with pytest.raises(OntologyError):
            apply_preset(
                "nope", db=config_db, store=store, engine=engine
            )

    def test_work_personal_separation_behavior(self, store, engine, config_db):
        summary = apply_preset(
            "work_personal_separation", db=config_db, store=store, engine=engine
        )
        agent = _agent("ag1")
        work = {"dimensions": {"purpose": "work"}}
        personal = {"dimensions": {"purpose": "personal"}}
        # Documented: work email allowed outright...
        r = engine.evaluate_call(agent, "email.send", {}, ontology_ctx=work)
        assert r.decision == "allow"
        # ... personal-time email escalates via the guard ...
        r = engine.evaluate_call(agent, "email.send", {}, ontology_ctx=personal)
        assert r.decision == "require_approval"
        assert r.ontology_ref["entry_kind"] == "preference_group"
        # ... and code work is denied in personal time (no allow rule
        # matches, so the pinned default-deny decides — same outcome the
        # guard's deny selector would produce).
        r = engine.evaluate_call(agent, "code.pr.open", {}, ontology_ctx=personal)
        assert r.decision == "deny" and r.matched_rule_id is None
        assert summary["policy_version"] >= 1

    def test_spending_thresholds_behavior(self, store, engine, config_db):
        apply_preset(
            "spending_thresholds", db=config_db, store=store, engine=engine
        )
        agent = _agent("ag1")
        ctx = {"dimensions": {"purpose": "personal"}}
        r = engine.evaluate_call(agent, "payment.send", {}, ontology_ctx=ctx)
        assert r.decision == "require_approval"
        r = engine.evaluate_call(agent, "shopping.buy", {}, ontology_ctx=ctx)
        assert r.decision == "require_approval"
        # The spend guard preference group exists and restricts.
        guards = [
            p for p in store.list_preference_groups()
            if p.name == "preset_spend_guard"
        ]
        assert guards and "payment.*" in guards[0].constraints["require_approval"]

    def test_social_send_approval_behavior(self, store, engine, config_db):
        apply_preset(
            "social_send_approval", db=config_db, store=store, engine=engine
        )
        agent = _agent("ag1")
        ctx = {"dimensions": {"purpose": "personal"}}
        for tool in ("social.post", "email.send"):
            r = engine.evaluate_call(agent, tool, {}, ontology_ctx=ctx)
            assert r.decision == "require_approval", tool

    def test_household_boundaries_behavior(self, store, engine, config_db):
        apply_preset(
            "household_boundaries", db=config_db, store=store, engine=engine,
            owner_display_name="Ken", member_display_names=["Spouse"],
        )
        spouse = next(
            p for p in store.list_principals(kind="person")
            if p.display_name == "Spouse"
        )
        owner = next(
            p for p in store.list_principals(kind="person")
            if p.display_name == "Ken"
        )
        store.bind_agent("ag_spouse", spouse.id)
        family = {"dimensions": {"purpose": "family"}}
        # Household member in family purpose: the rule allows, the
        # family-slice guard escalates to require_approval (cited), and
        # the rule's requires:owner_approval routes it to the owner.
        r = engine.evaluate_call(
            _agent("ag_spouse"), "photos.read", {}, ontology_ctx=family
        )
        assert r.decision == "require_approval"
        assert r.ontology_ref["entry_kind"] == "preference_group"
        guard = next(
            p for p in store.list_preference_groups()
            if p.name == "preset_household_guard"
        )
        assert r.ontology_ref["entry_id"] == guard.id
        rule = next(
            r_ for r_ in engine.version_rules_as_dicts()
            if r_["name"] == "preset:household_boundaries:family_data"
        )
        assert rule["conditions"]["ontology"]["requires"] == "owner_approval"
        assert (
            rule["conditions"]["ontology"]["relationship"]["target"] == owner.id
        )
        # A non-member's agent: default-deny (no relationship).
        stranger = store.create_principal("person", "Stranger")
        store.bind_agent("ag_stranger", stranger.id)
        r = engine.evaluate_call(
            _agent("ag_stranger"), "photos.read", {}, ontology_ctx=family
        )
        assert r.decision == "deny" and r.matched_rule_id is None

    def test_preset_is_idempotent(self, store, engine, config_db):
        apply_preset(
            "work_personal_separation", db=config_db, store=store, engine=engine
        )
        counts_before = (
            len(store.list_principals()),
            len(store.list_dimensions()),
            len(store.list_dimension_groups()),
            len(store.list_preference_groups()),
        )
        apply_preset(
            "work_personal_separation", db=config_db, store=store, engine=engine
        )
        counts_after = (
            len(store.list_principals()),
            len(store.list_dimensions()),
            len(store.list_dimension_groups()),
            len(store.list_preference_groups()),
        )
        assert counts_before == counts_after
        # The preset's rules appear exactly once in the latest version.
        names = [
            r["name"] for r in engine.version_rules_as_dicts()
            if r["name"].startswith("preset:work_personal_separation:")
        ]
        assert len(names) == 3 and len(set(names)) == 3

    def test_preset_rules_are_material(self, store, engine, config_db):
        apply_preset(
            "spending_thresholds", db=config_db, store=store, engine=engine
        )
        row = config_db.execute(
            select(PolicyVersion).where(PolicyVersion.is_current.is_(True))
        ).scalar_one()
        assert row.material_change is True
        assert "spending_thresholds" in (row.change_note or "")

    def test_preset_preserves_existing_rules(self, store, engine, config_db):
        engine.save_version(
            [{"name": "mine", "effect": "allow", "tool": "calendar.read"}]
        )
        apply_preset(
            "social_send_approval", db=config_db, store=store, engine=engine
        )
        names = [r["name"] for r in engine.version_rules_as_dicts()]
        assert "mine" in names
        assert any(n.startswith("preset:social_send_approval:") for n in names)


# ---------------------------------------------------------------------------
# 5. Enforcement-first citations
# ---------------------------------------------------------------------------

class TestEnforcementCitations:
    def test_policy_denied_carries_ontology_ref(self):
        err = policy_denied(
            "req_1", "no_allow_rule", "denied",
            ontology_ref={
                "entry_id": "ont_abc",
                "entry_kind": "preference_group",
                "snapshot_ref": "k1:deadbeef",
            },
        )
        details = err.to_envelope()["error"]["details"]
        assert details["ontology_ref"] == {
            "entry_id": "ont_abc",
            "entry_kind": "preference_group",
            "snapshot_ref": "k1:deadbeef",
        }
        # The safe vocabulary still guards the reason.
        assert details["reason"] in SAFE_REASONS

    def test_policy_denied_still_rejects_bad_reasons(self):
        with pytest.raises(ValueError):
            policy_denied("req_1", "because_i_said_so", "denied")
        with pytest.raises(ValueError):
            policy_denied(
                "req_1", "no_allow_rule", "denied",
                ontology_ref={"no_entry_id": True},
            )

    def test_preference_deny_cites_the_group(self, engine, store):
        store.upsert_dimension("purpose", ["work", "personal"])
        store.upsert_dimension("location", ["home", "office"])
        group = store.create_dimension_group(
            "home_personal", {"purpose": "personal", "location": "home"}
        )
        pref = store.create_preference_group(
            "guard", group.id, {"deny": ["code.*"]}
        )
        engine.save_version(
            [
                {
                    "name": "pr",
                    "effect": "allow",
                    "tool": "code.pr.open",
                    "conditions": {"ontology": {"dimension": {"purpose": "personal"}}},
                }
            ]
        )
        r = engine.evaluate_call(
            _agent("ag1"), "code.pr.open", {},
            ontology_ctx={"dimensions": {"purpose": "personal", "location": "home"}},
        )
        assert r.decision == "deny"
        assert r.ontology_ref["entry_kind"] == "preference_group"
        assert r.ontology_ref["entry_id"] == pref.id
        assert r.ontology_ref["snapshot_ref"] == r.ontology_snapshot_ref
        assert r.ontology_snapshot_ref.startswith("k1:")

    def test_owner_approval_cites_the_owner(self, engine, store):
        store.upsert_dimension("purpose", ["work", "personal", "family"])
        household = store.seed_household("Ken", ["Spouse"])
        owner, spouse = household["owner"], household["Spouse"]
        store.bind_agent("ag_spouse", spouse.id)
        engine.save_version(
            [
                {
                    "name": "family read",
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
        r = engine.evaluate_call(
            _agent("ag_spouse"), "email.read", {},
            ontology_ctx={"dimensions": {}},
        )
        assert r.decision == "require_approval"
        assert r.ontology_ref["entry_kind"] == "principal"
        assert r.ontology_ref["entry_id"] == owner.id

    def test_plain_rule_decisions_carry_no_ontology_ref(self, engine):
        engine.save_version(
            [{"name": "plain", "effect": "allow", "tool": "calendar.read"}]
        )
        r = engine.evaluate_call(_agent("ag1"), "calendar.read", {})
        assert r.decision == "allow"
        assert r.ontology_ref is None
        assert r.ontology_snapshot_ref is None

    def test_gateway_error_envelope_shape_unchanged(self):
        err = policy_denied("req_9", "explicit_deny", "no", tool="email.send")
        env = err.to_envelope()["error"]
        assert set(env) == {"code", "message", "request_id", "retryable", "details"}
        assert "ontology_ref" not in env["details"]
