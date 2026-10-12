"""The Intent layer: ontology -> INTENT -> open policy.

Every tool-call request is normalized into a structured ``Intent``
BEFORE policy evaluation. The intent — not the raw tool call — is the
unit of authorization: policies judge intents.

``normalize_intent(call_ctx, db=None)`` is the primary entry point for
the pipeline (it sees the full ``CallContext``); ``intent_from_parts``
is the lower-level builder used by ``PolicyEngine.evaluate_call``,
which keeps its historical signature.

Principal fallback chain (tested): explicit principal on the call
context -> the agent->principal ontology binding -> None.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass(frozen=True)
class Intent:
    """The normalized unit of authorization for one tool call."""

    # The calling agent's gateway id (ag_...).
    agent_id: str
    # The ontology principal on whose behalf the agent acts: explicit
    # principal_id, else the agent->principal binding, else None.
    principal_on_whose_behalf: Optional[str]
    # The action being authorized: the tool name, e.g. "email.send".
    action: str
    # Connector prefix of the tool ("email" for "email.send"); None
    # when the tool name has no dotted prefix.
    resource_type: Optional[str]
    # Ontology resource id, when a tool->resource mapping exists. No
    # mapping exists in MVP, so this is None (M6 checklist (a)).
    resource_id: Optional[str]
    # The call arguments (the policy-relevant parameters).
    params: dict[str, Any] = field(default_factory=dict)
    # Declared purpose (mandate purpose_key); None = undeclared.
    purpose: Optional[str] = None
    # The ontology context for policy evaluation:
    # {"principal_id": ..., "dimensions": {...}} — None when the call
    # carries no ontology scope (unbound agent, no declared purpose):
    # the legacy path, behavior-identical to pre-ontology evaluation.
    ontology_context: Optional[dict[str, Any]] = None
    # Mandate ids authorizing the call (usually the one live mandate).
    mandate_refs: list[str] = field(default_factory=list)
    # Grant refs authorizing the call. Empty at normalization time:
    # grants are consulted during evaluation (Fix B, MF-7) and recorded
    # on the input document's ``grants`` array then.
    grant_refs: list[str] = field(default_factory=list)


def _binding_principal(db: Any, agent_id: str) -> Optional[str]:
    """The agent->principal binding, or None (no db, no binding)."""
    if db is None or not agent_id:
        return None
    try:
        from .ontology.models import OntologyAgentBinding
    except Exception:  # noqa: BLE001 — ontology package unavailable
        return None
    binding = db.get(OntologyAgentBinding, agent_id)
    return binding.principal_id if binding is not None else None


def intent_from_parts(
    *,
    agent_id: str,
    tool: str,
    args: Optional[dict[str, Any]] = None,
    purpose: Optional[str] = None,
    ontology_ctx: Optional[dict[str, Any]] = None,
    resource_id: Optional[str] = None,
    mandate_id: Optional[str] = None,
    db: Any = None,
    agent: Any = None,
) -> Intent:
    """Build an Intent from explicit parts.

    ``ontology_ctx`` ({"principal_id": ..., "dimensions": {...},
    "resource_id": ...}) is used as given when provided (explicit
    callers, e.g. tests and the console). Otherwise it is derived:
    principal falls back to the agent->principal binding, dimensions
    carry the declared purpose — but only when there is something to
    resolve (a binding, an explicit principal, or a purpose); with none
    of those the ontology context is None (legacy path).
    """
    action = tool or ""
    resource_type = tool.split(".", 1)[0] if tool and "." in tool else None

    # The ontology context is used AS GIVEN when provided (explicit
    # callers: tests, console). When omitted it stays None — the
    # legacy path, exactly like the pre-pivot evaluate_call: no
    # ontology scope is invented from the purpose alone. The
    # agent->principal binding fallback lives in normalize_intent
    # (pipeline path) and in ontology.resolve_ctx (explicit ctx
    # without a principal_id).
    principal: Optional[str] = None
    ontology_context: Optional[dict[str, Any]] = None
    resolved_resource_id: Optional[str] = resource_id
    if ontology_ctx is not None and isinstance(ontology_ctx, dict):
        raw_principal = ontology_ctx.get("principal_id")
        principal = raw_principal if isinstance(raw_principal, str) else None
        raw_dims = ontology_ctx.get("dimensions") or {}
        dimensions = {
            str(k): str(v)
            for k, v in raw_dims.items()
            if isinstance(k, str) and isinstance(v, str)
        }
        raw_res = ontology_ctx.get("resource_id")
        if isinstance(raw_res, str):
            resolved_resource_id = raw_res
        ontology_context = {
            "principal_id": principal,
            "dimensions": dimensions,
        }
        if resolved_resource_id is not None:
            ontology_context["resource_id"] = resolved_resource_id

    mandate_refs = [mandate_id] if mandate_id else []
    return Intent(
        agent_id=agent_id,
        principal_on_whose_behalf=principal,
        action=action,
        resource_type=resource_type,
        resource_id=resolved_resource_id,
        params=dict(args or {}),
        purpose=purpose,
        ontology_context=ontology_context,
        mandate_refs=mandate_refs,
        grant_refs=[],
    )


def normalize_intent(call_ctx: Any, db: Any = None) -> Intent:
    """Normalize a pipeline ``CallContext`` into an ``Intent``.

    Reads agent_id, tool, args, the mandate (purpose_key + id), and an
    optional explicit principal (``call_ctx.principal_id`` when set).
    ``db`` enables the agent->principal binding fallback; without it
    the principal falls back to None (documented, tested).
    """
    mandate = getattr(call_ctx, "mandate", None)
    purpose = getattr(mandate, "purpose_key", None) if mandate is not None else None
    mandate_id = getattr(mandate, "id", None) if mandate is not None else None

    explicit_principal = getattr(call_ctx, "principal_id", None)
    agent_id = getattr(call_ctx, "agent_id", "") or ""
    if explicit_principal:
        ontology_ctx: Optional[dict[str, Any]] = {
            "principal_id": explicit_principal,
            "dimensions": {"purpose": purpose} if purpose else {},
        }
    elif _binding_principal(db, agent_id) is not None:
        ontology_ctx = {
            "principal_id": _binding_principal(db, agent_id),
            "dimensions": {"purpose": purpose} if purpose else {},
        }
    else:
        # Unbound agent, no explicit principal: legacy path — the
        # engine evaluates exactly as before the ontology integration
        # (ontology deviation 1).
        ontology_ctx = None

    return intent_from_parts(
        agent_id=agent_id,
        tool=getattr(call_ctx, "tool", "") or "",
        args=getattr(call_ctx, "args", None) or {},
        purpose=purpose,
        ontology_ctx=ontology_ctx,
        mandate_id=mandate_id,
        db=db,
    )
