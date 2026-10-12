"""Policy-engine integration for the personal ontology.

Rule conditions gain an ``ontology`` clause::

    "conditions": {
        "ontology": {
            "dimension": {"purpose": "work", "location": "office"},
            "dimension_group": "at_office",
            "relationship": {"type": "household_member_of",
                             "target": "<principal_id>"},
            "requires": "owner_approval"
        }
    }

Semantics (all sub-keys AND together):
- ``dimension``: the call's declared dimensions must contain every pair.
- ``dimension_group``: a named DimensionGroup whose pairs must all be
  satisfied by the declared dimensions.
- ``relationship``: the calling principal must hold that directed
  relationship to the target principal.
- ``requires: "owner_approval"``: not a match predicate — on match it
  upgrades an ``allow`` effect to ``require_approval`` (the request then
  feeds M3's pending-approval queue; the gateway never approves itself).

``ontology_ctx`` (passed to ``PolicyEngine.evaluate_call``)::

    {"principal_id": "<principal_id>",        # optional
     "dimensions": {"purpose": "work", ...}}   # optional

The principal falls back to the agent→principal binding when omitted.
Declared dimensions are validated against the registered
ContextDimensions; an unknown dimension name or out-of-set value fails
CLOSED to the pinned default-deny — never a silent pass.

Preference groups ("scenario slices") apply on top of policy rules and
can only restrict: an applicable group whose ``deny`` selectors match
the tool denies the call; a matching ``require_approval`` selector
escalates it. They never widen a decision.

The engine judges authorization; it never executes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import (
    RELATIONSHIP_TYPES,
    REQUIRES_OWNER_APPROVAL,
    OntologyAgentBinding,
    OntologyDimension,
    OntologyDimensionGroup,
    OntologyPreferenceGroup,
    OntologyPrincipal,
    OntologyRelationship,
    OntologyResource,
)
from .store import OntologyError


#: Allowed keys in a rule's ``conditions.ontology`` clause.
ONTOLOGY_CLAUSE_KEYS: tuple[str, ...] = (
    "dimension",
    "dimension_group",
    "relationship",
    "requires",
)


@dataclass
class OntologyCallState:
    """Resolved ontology context for one call evaluation."""

    principal_id: Optional[str]
    dimensions: dict[str, str]


@dataclass
class ScopedView:
    """The ontology slice visible to one agent (PAA08).

    - ``principal_ids``: principals the agent may act for — its bound
      principal, the transitive ``acts_for`` closure, principals that
      delegated to it (``delegates_to`` in-edges), and the household
      owner when the bound principal is a member. Deliberately NOT the
      reverse household direction: members get separate views
      (FR-PAA08-003).
    - ``resource_ids``: resources owned by in-scope principals — the
      agent's label clearance.
    - ``dimension_group_ids``/``dimension_group_names``: groups
      applicable to the agent's mandates (by purpose key).
    - ``dimension_values``: restricted dimension value sets (currently
      ``purpose`` ← the agent's mandate purpose keys). Other dimensions
      are unrestricted vocabulary.
    """

    agent_id: str
    bound_principal_id: Optional[str]
    principal_ids: set[str]
    resource_ids: set[str]
    dimension_group_ids: set[str]
    dimension_group_names: set[str]
    dimension_values: dict[str, set[str]]


def scoped_view(
    db: Session,
    agent_id: str,
    mandate_purpose_keys: Optional[list[str]] = None,
) -> ScopedView:
    """Compute the ontology slice visible to an agent."""
    binding = db.get(OntologyAgentBinding, agent_id)
    bound = binding.principal_id if binding else None
    principal_ids: set[str] = set()
    if bound is not None:
        principal_ids.add(bound)
        # acts_for closure (out-edges, transitive): P acts for Q.
        seen = {bound}
        frontier = [bound]
        while frontier:
            cur = frontier.pop()
            for rel in db.execute(
                select(OntologyRelationship).where(
                    OntologyRelationship.source_principal_id == cur,
                    OntologyRelationship.relation_type == "acts_for",
                )
            ).scalars().all():
                target = rel.target_principal_id
                if target not in seen:
                    seen.add(target)
                    principal_ids.add(target)
                    frontier.append(target)
        # delegates_to in-edges: Q delegates to P, so P may act for Q.
        for rel in db.execute(
            select(OntologyRelationship).where(
                OntologyRelationship.target_principal_id == bound,
                OntologyRelationship.relation_type == "delegates_to",
            )
        ).scalars().all():
            principal_ids.add(rel.source_principal_id)
        # Household member -> owner (one direction only, PAA08).
        for rel in db.execute(
            select(OntologyRelationship).where(
                OntologyRelationship.source_principal_id == bound,
                OntologyRelationship.relation_type == "household_member_of",
            )
        ).scalars().all():
            principal_ids.add(rel.target_principal_id)

    resource_ids: set[str] = set()
    if principal_ids:
        resource_ids = {
            r.id
            for r in db.execute(
                select(OntologyResource).where(
                    OntologyResource.owner_principal_id.in_(principal_ids)
                )
            ).scalars().all()
        }

    group_ids: set[str] = set()
    group_names: set[str] = set()
    for group in db.execute(select(OntologyDimensionGroup)).scalars().all():
        purpose = (group.dimensions or {}).get("purpose")
        if (
            mandate_purpose_keys is not None
            and purpose is not None
            and purpose not in mandate_purpose_keys
        ):
            continue
        group_ids.add(group.id)
        group_names.add(group.name)

    dimension_values: dict[str, set[str]] = {}
    if mandate_purpose_keys is not None:
        dimension_values["purpose"] = set(mandate_purpose_keys)

    return ScopedView(
        agent_id=agent_id,
        bound_principal_id=bound,
        principal_ids=principal_ids,
        resource_ids=resource_ids,
        dimension_group_ids=group_ids,
        dimension_group_names=group_names,
        dimension_values=dimension_values,
    )


def resolve_ctx_for_agent(
    db: Session,
    ontology_ctx: Any,
    agent_id: str,
    mandate_purpose_keys: Optional[list[str]] = None,
) -> tuple[Optional[OntologyCallState], bool, Optional[dict[str, Any]]]:
    """Scoped context resolution: ``resolve_ctx`` + the agent's view.

    Returns ``(state, invalid, ontology_ref)``. ``invalid`` is True when
    the requested principal, dimension value, or resource is outside
    the agent's scoped view — the caller must deny (fail closed).
    ``ontology_ref`` cites the ontology entry that defines the
    violated boundary (``{"entry_id", "entry_kind"}``; the caller
    attaches the decision snapshot ref).

    Agents with NO ontology binding are not scoped (legacy path):
    ``resolve_ctx`` validation still applies, but there is no view to
    enforce. The M6 pipeline wiring should bind every agent.
    """
    state, invalid = resolve_ctx(db, ontology_ctx)
    if invalid or not isinstance(ontology_ctx, dict):
        return None, True, None
    binding = db.get(OntologyAgentBinding, agent_id)
    if binding is None:
        return state, False, None
    view = scoped_view(db, agent_id, mandate_purpose_keys)

    effective_principal = state.principal_id or binding.principal_id
    if effective_principal not in view.principal_ids:
        return None, True, {
            "entry_id": binding.agent_id,
            "entry_kind": "agent_binding",
            "requested_principal_id": state.principal_id,
        }
    for name, value in state.dimensions.items():
        allowed = view.dimension_values.get(name)
        if allowed is not None and value not in allowed:
            return None, True, {
                "entry_id": name,
                "entry_kind": "dimension",
                "requested_value": value,
            }
    resource_id = ontology_ctx.get("resource_id")
    if resource_id is not None:
        resource = db.get(OntologyResource, resource_id)
        if resource is None or resource.id not in view.resource_ids:
            return None, True, {
                "entry_id": str(resource_id),
                "entry_kind": "resource",
            }
    return state, False, None


# ---------------------------------------------------------------------
# Clause validation
# ---------------------------------------------------------------------

def validate_ontology_clause(clause: Any) -> None:
    """Structural validation of a rule's ``conditions.ontology`` clause.

    Raises ValueError on any problem — invalid clauses never reach
    storage (FR-PAA04-002: no untrusted content becomes authority).
    Store-aware checks (dimension names, group names, principal ids)
    live in ``validate_ontology_conditions`` below.
    """
    if not isinstance(clause, dict):
        raise ValueError("conditions.ontology must be an object")
    for key in clause:
        if key not in ONTOLOGY_CLAUSE_KEYS:
            raise ValueError(
                f"unknown ontology clause key {key!r}; "
                f"want one of {ONTOLOGY_CLAUSE_KEYS}"
            )
    dimension = clause.get("dimension")
    if dimension is not None:
        if not isinstance(dimension, dict) or not all(
            isinstance(k, str) and isinstance(v, str)
            for k, v in dimension.items()
        ):
            raise ValueError(
                "ontology clause 'dimension' must be an object of "
                "string->string pairs"
            )
    group = clause.get("dimension_group")
    if group is not None and not isinstance(group, str):
        raise ValueError("ontology clause 'dimension_group' must be a string")
    relationship = clause.get("relationship")
    if relationship is not None:
        if not isinstance(relationship, dict):
            raise ValueError("ontology clause 'relationship' must be an object")
        rel_type = relationship.get("type")
        if rel_type not in RELATIONSHIP_TYPES:
            raise ValueError(
                f"unknown relationship type {rel_type!r}; "
                f"want one of {RELATIONSHIP_TYPES}"
            )
        if not isinstance(relationship.get("target"), str):
            raise ValueError("ontology clause 'relationship.target' must be a string")
    requires = clause.get("requires")
    if requires is not None and requires != REQUIRES_OWNER_APPROVAL:
        raise ValueError(
            f"unknown ontology 'requires' value {requires!r}; "
            f"want {REQUIRES_OWNER_APPROVAL!r}"
        )


def validate_ontology_conditions(db: Session, conditions: dict[str, Any]) -> None:
    """Store-aware validation of a rule's ontology clause.

    The M6 console calls this before ``save_version``: dimension names
    and values must be registered, dimension groups must exist, and
    relationship targets must be known principals. Raises OntologyError.
    (Evaluation itself stays fail-closed regardless.)
    """
    clause = (conditions or {}).get("ontology")
    if clause is None:
        return
    validate_ontology_clause(clause)
    dimension = clause.get("dimension") or {}
    for name, value in dimension.items():
        dim = db.get(OntologyDimension, name)
        if dim is None:
            raise OntologyError(f"ontology clause: unknown dimension {name!r}")
        if value not in (dim.allowed_values or []):
            raise OntologyError(
                f"ontology clause: value {value!r} not allowed for "
                f"dimension {name!r}"
            )
    group_name = clause.get("dimension_group")
    if group_name is not None:
        group = db.execute(
            select(OntologyDimensionGroup).where(
                OntologyDimensionGroup.name == group_name
            )
        ).scalar_one_or_none()
        if group is None:
            raise OntologyError(
                f"ontology clause: unknown dimension group {group_name!r}"
            )
    relationship = clause.get("relationship")
    if relationship is not None:
        if db.get(OntologyPrincipal, relationship["target"]) is None:
            raise OntologyError(
                f"ontology clause: unknown relationship target "
                f"{relationship['target']!r}"
            )


# ---------------------------------------------------------------------
# Context resolution (fail-closed)
# ---------------------------------------------------------------------

def resolve_ctx(
    db: Session,
    ontology_ctx: Any,
    agent: Any = None,
) -> tuple[Optional[OntologyCallState], bool]:
    """Resolve the ontology call state.

    Returns ``(state, invalid)``. ``invalid`` is True when the declared
    dimensions reference an unknown dimension name, an out-of-set value,
    or an unknown principal — the caller must deny (default-deny), never
    pass silently.
    """
    if not isinstance(ontology_ctx, dict):
        return None, True
    dimensions = ontology_ctx.get("dimensions") or {}
    if not isinstance(dimensions, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in dimensions.items()
    ):
        return None, True
    for name, value in dimensions.items():
        dim = db.get(OntologyDimension, name)
        if dim is None or value not in (dim.allowed_values or []):
            return None, True  # unknown dimension scope → deny
    principal_id = ontology_ctx.get("principal_id")
    if principal_id is not None:
        if not isinstance(principal_id, str) or (
            db.get(OntologyPrincipal, principal_id) is None
        ):
            return None, True
    elif agent is not None:
        binding = db.get(OntologyAgentBinding, getattr(agent, "id", None))
        principal_id = binding.principal_id if binding else None
    return OntologyCallState(principal_id=principal_id, dimensions=dict(dimensions)), False


def clause_holds(
    db: Session, clause: dict[str, Any], state: OntologyCallState
) -> bool:
    """True iff every sub-key of the ontology clause holds.

    Unknown references (dimension group, relationship type) never match
    — the rule is skipped and evaluation falls through to default-deny.
    """
    dimension = clause.get("dimension") or {}
    for name, value in dimension.items():
        if state.dimensions.get(name) != value:
            return False
    group_name = clause.get("dimension_group")
    if group_name is not None:
        group = db.execute(
            select(OntologyDimensionGroup).where(
                OntologyDimensionGroup.name == group_name
            )
        ).scalar_one_or_none()
        if group is None:
            return False
        for name, value in (group.dimensions or {}).items():
            if state.dimensions.get(name) != value:
                return False
    relationship = clause.get("relationship")
    if relationship is not None:
        if state.principal_id is None:
            return False
        if relationship.get("type") not in RELATIONSHIP_TYPES:
            return False
        rel = db.execute(
            select(OntologyRelationship).where(
                OntologyRelationship.source_principal_id == state.principal_id,
                OntologyRelationship.relation_type == relationship["type"],
                OntologyRelationship.target_principal_id == relationship["target"],
            ).limit(1)
        ).scalar_one_or_none()
        if rel is None:
            return False
    return True


# ---------------------------------------------------------------------
# Preference groups ("scenario slices"): restrict-only enforcement
# ---------------------------------------------------------------------

def _tool_selector_matches(selector: str, tool: str) -> bool:
    if selector.endswith(".*"):
        return tool.startswith(selector[:-1])
    return selector == tool


def applicable_dimension_groups(
    db: Session, dimensions: dict[str, str]
) -> list[OntologyDimensionGroup]:
    """Dimension groups ("scenario slices") whose pairs are all satisfied
    by the declared dimensions."""
    out: list[OntologyDimensionGroup] = []
    groups = db.execute(select(OntologyDimensionGroup)).scalars().all()
    for group in groups:
        if all(
            dimensions.get(name) == value
            for name, value in (group.dimensions or {}).items()
        ):
            out.append(group)
    return out


def applicable_preference_groups(
    db: Session, dimensions: dict[str, str]
) -> list[OntologyPreferenceGroup]:
    """Preference groups whose dimension combo is fully satisfied by the
    declared dimensions (the group's pairs ⊆ declared pairs)."""
    out: list[OntologyPreferenceGroup] = []
    prefs = db.execute(select(OntologyPreferenceGroup)).scalars().all()
    for pref in prefs:
        group = db.get(OntologyDimensionGroup, pref.dimension_group_id)
        if group is None:
            continue
        if all(
            dimensions.get(name) == value
            for name, value in (group.dimensions or {}).items()
        ):
            out.append(pref)
    return out


def preference_upgrade(
    db: Session, dimensions: dict[str, str], tool: str
) -> tuple[Optional[str], list[str]]:
    """Most restrictive applicable preference-group constraint for the
    tool: ``("deny" | "require_approval" | None, [group ids])``.

    Deny wins over require_approval. Returns None when no applicable
    group constrains the tool.
    """
    groups = applicable_preference_groups(db, dimensions)
    matched_ids = [g.id for g in groups]
    decision: Optional[str] = None
    for pref in groups:
        constraints = pref.constraints or {}
        for selector in constraints.get("deny", []):
            if _tool_selector_matches(selector, tool):
                return "deny", matched_ids
        for selector in constraints.get("require_approval", []):
            if _tool_selector_matches(selector, tool):
                decision = "require_approval"
    return decision, matched_ids


def deciding_preference_group(
    db: Session, dimensions: dict[str, str], tool: str
) -> Optional[OntologyPreferenceGroup]:
    """The applicable preference group whose selector actually matched
    the tool (deny wins over require_approval), or None.

    Used to cite the specific ontology entry in deny/ask reasons
    (``ontology_ref``): the reason names the entry that decided.
    """
    for pref in applicable_preference_groups(db, dimensions):
        constraints = pref.constraints or {}
        for selector in constraints.get("deny", []):
            if _tool_selector_matches(selector, tool):
                return pref
    for pref in applicable_preference_groups(db, dimensions):
        constraints = pref.constraints or {}
        for selector in constraints.get("require_approval", []):
            if _tool_selector_matches(selector, tool):
                return pref
    return None
