"""Intent-layer tests — Personal Agent Security Gateway (OPA pivot).

Covers normalize_intent / intent_from_parts:
- normalization of agent, action, resource_type, params, purpose
- principal fallback: explicit -> agent->principal binding -> None
- ontology_context built only when there is something to resolve
  (binding or explicit principal); None otherwise (legacy path)
- mandate_refs attached; grant_refs empty at normalization time
- resource_id None (no tool->resource mapping in MVP)
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from gateway.config import Settings
from gateway.db import Databases
from gateway.intent import Intent, intent_from_parts, normalize_intent
from gateway.ontology.store import OntologyStore


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


def _ctx(**kw):
    base = {
        "agent_id": "ag_ken",
        "tool": "email.send",
        "args": {"to": ["a@b.com"], "subject": "hi"},
        "agent": SimpleNamespace(id="ag_ken", household_role="ken"),
        "mandate": SimpleNamespace(id="mnd_1", purpose_key="work"),
    }
    base.update(kw)
    return SimpleNamespace(**base)


class TestNormalizeIntent:
    def test_basic_fields(self, config_db):
        intent = normalize_intent(_ctx(), config_db)
        assert isinstance(intent, Intent)
        assert intent.agent_id == "ag_ken"
        assert intent.action == "email.send"
        assert intent.resource_type == "email"
        assert intent.params == {"to": ["a@b.com"], "subject": "hi"}
        assert intent.purpose == "work"
        assert intent.mandate_refs == ["mnd_1"]
        assert intent.grant_refs == []

    def test_resource_type_none_without_dot(self, config_db):
        intent = normalize_intent(_ctx(tool="approval_status"), config_db)
        assert intent.resource_type is None
        assert intent.action == "approval_status"

    def test_resource_id_none_no_mapping(self, config_db):
        # No tool->resource mapping exists in MVP (M6 checklist (a)).
        assert normalize_intent(_ctx(), config_db).resource_id is None

    def test_unbound_agent_no_ontology_context(self, config_db):
        # Unbound agent: legacy path — no ontology scope is invented.
        intent = normalize_intent(_ctx(), config_db)
        assert intent.ontology_context is None
        assert intent.principal_on_whose_behalf is None

    def test_explicit_principal_wins(self, config_db):
        intent = normalize_intent(_ctx(principal_id="ont_explicit"), config_db)
        assert intent.principal_on_whose_behalf == "ont_explicit"
        assert intent.ontology_context["principal_id"] == "ont_explicit"
        assert intent.ontology_context["dimensions"] == {"purpose": "work"}

    def test_principal_falls_back_to_binding(self, config_db):
        store = OntologyStore(config_db)
        owner = store.create_principal("person", "Ken")
        store.bind_agent("ag_ken", owner.id)
        intent = normalize_intent(_ctx(), config_db)
        assert intent.principal_on_whose_behalf == owner.id
        assert intent.ontology_context["principal_id"] == owner.id
        assert intent.ontology_context["dimensions"] == {"purpose": "work"}

    def test_binding_without_purpose(self, config_db):
        store = OntologyStore(config_db)
        owner = store.create_principal("person", "Ken")
        store.bind_agent("ag_ken", owner.id)
        ctx = _ctx(mandate=SimpleNamespace(id="mnd_1", purpose_key=None))
        intent = normalize_intent(ctx, config_db)
        assert intent.principal_on_whose_behalf == owner.id
        assert intent.ontology_context["dimensions"] == {}
        assert intent.purpose is None

    def test_no_db_no_binding(self):
        # Without a db the binding fallback is unavailable (documented).
        intent = normalize_intent(_ctx(), None)
        assert intent.principal_on_whose_behalf is None
        assert intent.ontology_context is None

    def test_no_mandate(self, config_db):
        intent = normalize_intent(_ctx(mandate=None), config_db)
        assert intent.purpose is None
        assert intent.mandate_refs == []
        assert intent.ontology_context is None


class TestIntentFromParts:
    def test_ontology_ctx_used_as_given(self, config_db):
        intent = intent_from_parts(
            agent_id="ag_ken",
            tool="email.send",
            args={},
            purpose="work",
            ontology_ctx={"principal_id": "ont_x", "dimensions": {"purpose": "work"}},
            db=config_db,
        )
        assert intent.ontology_context == {
            "principal_id": "ont_x",
            "dimensions": {"purpose": "work"},
        }
        assert intent.principal_on_whose_behalf == "ont_x"

    def test_omitted_ctx_stays_none(self, config_db):
        # Legacy path: no ontology scope is invented from purpose alone
        # (matches pre-pivot evaluate_call with ontology_ctx=None).
        intent = intent_from_parts(
            agent_id="ag_ken", tool="email.send", args={},
            purpose="work", ontology_ctx=None, db=config_db,
        )
        assert intent.ontology_context is None
        assert intent.principal_on_whose_behalf is None
        assert intent.purpose == "work"

    def test_empty_ctx_dict_resolves(self, config_db):
        intent = intent_from_parts(
            agent_id="ag_ken", tool="email.send", args={},
            ontology_ctx={}, db=config_db,
        )
        assert intent.ontology_context == {
            "principal_id": None, "dimensions": {},
        }

    def test_resource_id_passthrough(self, config_db):
        intent = intent_from_parts(
            agent_id="ag_ken", tool="photos.read", args={},
            ontology_ctx={"dimensions": {}, "resource_id": "ont_res_1"},
            db=config_db,
        )
        assert intent.resource_id == "ont_res_1"
        assert intent.ontology_context["resource_id"] == "ont_res_1"
