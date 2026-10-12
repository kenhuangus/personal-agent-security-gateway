"""Working ontology presets: one call seeds a coherent ontology plus the
policy rules that wire it, as a new material-classified policy version.

Presets (``apply_preset(name, ...)``):
- ``work_personal_separation`` — purpose/location dimensions, work vs
  personal slices, personal-time restrictions on work tools;
- ``spending_thresholds`` — payment.* always requires approval, extra
  restrictions on personal-purpose spend;
- ``social_send_approval`` — social.* and email.send require approval;
- ``household_boundaries`` — household roles (PAA08), family-purpose
  slice, family data access escalates to owner approval.

Idempotent: re-applying updates the preset's named entities in place
and replaces the preset's rules in the new policy version — never
duplicates. Policy rules remain the sole authority for allows;
preference groups only restrict (documented per preset).
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from sqlalchemy.orm import Session

from .store import OntologyError, OntologyStore

PRESET_NAMES: tuple[str, ...] = (
    "work_personal_separation",
    "spending_thresholds",
    "social_send_approval",
    "household_boundaries",
)

RULE_PREFIX = "preset"


def _rule_name(preset: str, slug: str) -> str:
    return f"{RULE_PREFIX}:{preset}:{slug}"


# ---------------------------------------------------------------------
# Idempotent entity helpers (update-in-place, never duplicate)
# ---------------------------------------------------------------------

def _ensure_dimension_values(
    store: OntologyStore, name: str, values: list[str]
) -> None:
    existing = store.get_dimension(name)
    if existing is None:
        store.upsert_dimension(name, values, provenance="explicit:preset")
    else:
        merged = list(dict.fromkeys(list(existing.allowed_values or []) + values))
        if merged != list(existing.allowed_values or []):
            store.upsert_dimension(name, merged, provenance="explicit:preset")


def _upsert_dimension_group(
    store: OntologyStore, name: str, dimensions: dict[str, str]
):
    existing = store.get_dimension_group_by_name(name)
    if existing is None:
        return store.create_dimension_group(
            name, dimensions, provenance="explicit:preset"
        )
    if dict(existing.dimensions or {}) != dict(dimensions):
        existing.dimensions = dict(dimensions)
        existing.provenance = "explicit:preset"
        store.db.commit()
        store._log("dimension_group.update", {"name": name})
    return existing


def _upsert_preference_group(
    store: OntologyStore,
    name: str,
    dimension_group_id: str,
    constraints: dict[str, list[str]],
):
    existing = next(
        (p for p in store.list_preference_groups() if p.name == name), None
    )
    if existing is None:
        return store.create_preference_group(
            name, dimension_group_id, constraints, provenance="explicit:preset"
        )
    if (
        existing.dimension_group_id != dimension_group_id
        or dict(existing.constraints or {}) != dict(constraints)
    ):
        existing.dimension_group_id = dimension_group_id
        existing.constraints = {k: list(v) for k, v in constraints.items()}
        existing.provenance = "explicit:preset"
        store.db.commit()
        store._log("preference_group.update", {"name": name})
    return existing


def _ensure_principal(
    store: OntologyStore, kind: str, display_name: str
):
    existing = next(
        (
            p
            for p in store.list_principals(kind=kind)
            if p.display_name == display_name
        ),
        None,
    )
    if existing is not None:
        return existing
    return store.create_principal(kind, display_name, provenance="explicit:preset")


def _ensure_resource(
    store: OntologyStore,
    kind: str,
    display_name: str,
    label_class: str,
    owner_principal_id: str,
):
    existing = next(
        (
            r
            for r in store.list_resources(owner_principal_id=owner_principal_id)
            if r.display_name == display_name
        ),
        None,
    )
    if existing is not None:
        return existing
    return store.create_resource(
        kind, display_name, label_class, owner_principal_id,
        provenance="explicit:preset",
    )


def _ensure_action(store: OntologyStore, name: str, sensitivity: str):
    existing = next(
        (a for a in store.list_actions() if a.name == name), None
    )
    if existing is not None:
        return existing
    return store.create_action(
        name, sensitivity, provenance="explicit:preset"
    )


def _replace_preset_rules(
    engine, preset: str, new_rules: list[dict[str, Any]], change_note: str
) -> int:
    """New policy version: keep every non-preset rule, replace this
    preset's rules. Material-classified (a preset changes enforcement)."""
    prefix = f"{RULE_PREFIX}:{preset}:"
    kept = [
        r
        for r in engine.version_rules_as_dicts()
        if not r.get("name", "").startswith(prefix)
    ]
    return engine.save_version(
        [*kept, *new_rules],
        change_note=change_note,
        created_by="ontology.preset",
        material_change=True,
    )


# ---------------------------------------------------------------------
# Presets
# ---------------------------------------------------------------------

def _preset_work_personal_separation(
    store: OntologyStore, owner_name: str, members: list[str], engine
) -> dict[str, Any]:
    owner = _ensure_principal(store, "person", owner_name)
    _ensure_dimension_values(store, "purpose", ["work", "personal"])
    _ensure_dimension_values(store, "location", ["office", "home"])
    work_hours = _upsert_dimension_group(
        store, "preset_work_hours", {"purpose": "work"}
    )
    personal_time = _upsert_dimension_group(
        store, "preset_personal_time", {"purpose": "personal"}
    )
    _upsert_preference_group(
        store,
        "preset_personal_guard",
        personal_time.id,
        {"require_approval": ["email.send"], "deny": ["code.*"]},
    )
    rules = [
        {
            "name": _rule_name("work_personal_separation", "work_email"),
            "effect": "allow",
            "tool": "email.send",
            "conditions": {"ontology": {"dimension": {"purpose": "work"}}},
            "description": "Preset: email.send allowed in work purpose.",
        },
        {
            "name": _rule_name("work_personal_separation", "personal_email"),
            "effect": "allow",
            "tool": "email.send",
            "conditions": {"ontology": {"dimension": {"purpose": "personal"}}},
            "description": (
                "Preset: email.send allowed in personal purpose — the "
                "personal-time guard escalates it to require_approval."
            ),
        },
        {
            "name": _rule_name("work_personal_separation", "personal_calendar"),
            "effect": "allow",
            "tool": "calendar.read",
            "conditions": {"ontology": {"dimension": {"purpose": "personal"}}},
            "description": "Preset: calendar.read allowed in personal purpose.",
        },
    ]
    version = _replace_preset_rules(
        engine, "work_personal_separation", rules,
        "ontology preset 'work_personal_separation' applied",
    )
    return {
        "owner_id": owner.id,
        "dimension_groups": [work_hours.name, personal_time.name],
        "policy_version": version,
    }


def _preset_spending_thresholds(
    store: OntologyStore, owner_name: str, members: list[str], engine
) -> dict[str, Any]:
    _ensure_principal(store, "person", owner_name)
    _ensure_dimension_values(store, "purpose", ["work", "personal"])
    personal_spend = _upsert_dimension_group(
        store, "preset_personal_spend", {"purpose": "personal"}
    )
    _upsert_preference_group(
        store,
        "preset_spend_guard",
        personal_spend.id,
        {"require_approval": ["payment.*", "shopping.*"]},
    )
    # The action registry records the sensitivity; the rule below is
    # the enforcement (policy remains the sole authority).
    _ensure_action(store, "payment.initiate", "sensitive")
    rules = [
        {
            "name": _rule_name("spending_thresholds", "payments"),
            "effect": "require_approval",
            "tool": "payment.*",
            "description": "Preset: any payment.* call requires approval.",
        },
        {
            "name": _rule_name("spending_thresholds", "personal_shopping"),
            "effect": "allow",
            "tool": "shopping.*",
            "conditions": {"ontology": {"dimension": {"purpose": "personal"}}},
            "description": (
                "Preset: personal-purpose shopping is allowed but the "
                "spend guard escalates it to require_approval."
            ),
        },
    ]
    version = _replace_preset_rules(
        engine, "spending_thresholds", rules,
        "ontology preset 'spending_thresholds' applied",
    )
    return {"dimension_groups": [personal_spend.name], "policy_version": version}


def _preset_social_send_approval(
    store: OntologyStore, owner_name: str, members: list[str], engine
) -> dict[str, Any]:
    _ensure_principal(store, "person", owner_name)
    _ensure_dimension_values(store, "purpose", ["work", "personal"])
    public_voice = _upsert_dimension_group(
        store, "preset_public_voice", {"purpose": "personal"}
    )
    _upsert_preference_group(
        store,
        "preset_social_guard",
        public_voice.id,
        {"require_approval": ["social.*", "email.send"]},
    )
    _ensure_action(store, "social.post", "sensitive")
    _ensure_action(store, "email.send", "sensitive")
    rules = [
        {
            "name": _rule_name("social_send_approval", "social_post"),
            "effect": "require_approval",
            "tool": "social.*",
            "description": "Preset: social.* posts require approval.",
        },
        {
            "name": _rule_name("social_send_approval", "external_email"),
            "effect": "require_approval",
            "tool": "email.send",
            "description": "Preset: email.send requires approval.",
        },
    ]
    version = _replace_preset_rules(
        engine, "social_send_approval", rules,
        "ontology preset 'social_send_approval' applied",
    )
    return {"dimension_groups": [public_voice.name], "policy_version": version}


def _preset_household_boundaries(
    store: OntologyStore, owner_name: str, members: list[str], engine
) -> dict[str, Any]:
    household = store.seed_household(
        owner_name, members, provenance="explicit:preset"
    )
    owner = household["owner"]
    _ensure_dimension_values(store, "purpose", ["work", "personal", "family"])
    family_context = _upsert_dimension_group(
        store, "preset_family_context", {"purpose": "family"}
    )
    _ensure_resource(
        store, "photos", f"{owner_name}'s Family Photos", "family", owner.id
    )
    _upsert_preference_group(
        store,
        "preset_household_guard",
        family_context.id,
        {"require_approval": ["photos.*", "files.read"]},
    )
    rules = [
        {
            "name": _rule_name("household_boundaries", "family_data"),
            "effect": "allow",
            "tool": "photos.*",
            "conditions": {
                "ontology": {
                    "dimension_group": "preset_family_context",
                    "relationship": {
                        "type": "household_member_of",
                        "target": owner.id,
                    },
                    "requires": "owner_approval",
                }
            },
            "description": (
                "Preset: household members may read family photos in the "
                "family purpose, but only with owner approval."
            ),
        },
    ]
    version = _replace_preset_rules(
        engine, "household_boundaries", rules,
        "ontology preset 'household_boundaries' applied",
    )
    return {
        "owner_id": owner.id,
        "members": [m for m in members],
        "dimension_groups": [family_context.name],
        "policy_version": version,
    }


_PRESET_BUILDERS: dict[str, Callable] = {
    "work_personal_separation": _preset_work_personal_separation,
    "spending_thresholds": _preset_spending_thresholds,
    "social_send_approval": _preset_social_send_approval,
    "household_boundaries": _preset_household_boundaries,
}


def apply_preset(
    name: str,
    *,
    db: Session,
    store: Optional[OntologyStore] = None,
    engine=None,
    owner_display_name: str = "Owner",
    member_display_names: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Apply an ontology preset (idempotent).

    Seeds/updates the preset's principals, dimensions, dimension
    groups, preference groups, and sensitive-action registry entries,
    then saves a NEW policy version carrying the preset's rules
    (material-classified; existing non-preset rules are carried over,
    the preset's own previous rules are replaced — never duplicated).

    Returns a summary dict: preset name, policy version, and the ids /
    names created or reused.
    """
    if name not in _PRESET_BUILDERS:
        raise OntologyError(
            f"unknown preset {name!r}; want one of {PRESET_NAMES}"
        )
    if engine is None:
        raise OntologyError("apply_preset requires a policy engine")
    store = store or OntologyStore(db)
    members = list(member_display_names or [])
    summary = _PRESET_BUILDERS[name](
        store, owner_display_name, members, engine
    )
    store._log("preset.apply", {"preset": name})
    return {"preset": name, **summary}


def list_presets() -> tuple[str, ...]:
    return PRESET_NAMES
