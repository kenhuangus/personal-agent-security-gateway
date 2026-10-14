"""Gateway-side tools for the security agents (Pillar 2 §2.1).

Registered on the MCP surface like the existing
``gateway.approval_status`` meta tool when ``GATEWAY_AGENTS_ENABLED=1``
— invisible otherwise. All are default-deny for non-security agents
(allowed only via per-agent seed policy rules for the security
agents); all are read-only.

- ``audit.search`` — thin wrapper over ``AuditLog.search`` (filters:
  agent_id, tool, decision, since, until, limit≤200). Returns redacted
  rows only. The handler additionally constrains non-security callers
  to their own ``agent_id`` (defense-in-depth; default-deny makes this
  moot for others).
- ``policy.inspect`` — returns ``{policy_version, rules[]}`` (the same
  data the Policies page renders). Read-only.
"""

from __future__ import annotations

import datetime as dt
from typing import Any, Callable, Optional

from sqlalchemy.orm import Session

from .audit import AuditLog
from .pipeline import ToolDescriptor

AUDIT_SEARCH_SCHEMA = {
    "type": "object",
    "properties": {
        "agent_id": {"type": "string", "maxLength": 64},
        "tool": {"type": "string", "maxLength": 64},
        "decision": {"type": "string", "maxLength": 32},
        "since": {"type": "string", "description": "ISO-8601 UTC"},
        "until": {"type": "string", "description": "ISO-8601 UTC"},
        "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 50},
    },
    "additionalProperties": False,
}

POLICY_INSPECT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {},
    "additionalProperties": False,
}


def _parse_ts(value: Any) -> Optional[dt.datetime]:
    if not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(str(value))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed


def _row_to_dict(row: Any) -> dict[str, Any]:
    # Redacted rows only — the audit log never holds plaintext
    # (NFR-DATA-001), so the row's redacted_args are safe to return.
    return {
        "request_id": row.request_id,
        "agent_id": row.agent_id,
        "tool": row.tool,
        "action": row.action,
        "timestamp": row.timestamp.isoformat() if row.timestamp else None,
        "decision": row.decision,
        "reason": row.reason,
        "redacted_args": row.redacted_args or {},
        "mandate_id": row.mandate_id,
        "approval_request_id": row.approval_request_id,
        "scope_rule": row.scope_rule,
    }


def make_audit_search_tool(
    audit_session_factory: Callable[[], Session],
) -> ToolDescriptor:
    def handler(ctx: Any, args: dict[str, Any]) -> dict[str, Any]:
        agent_id = args.get("agent_id")
        # Defense in depth: non-security callers see only their own rows.
        if getattr(ctx.agent, "household_role", "") != "security":
            agent_id = ctx.agent_id
        limit = min(int(args.get("limit") or 50), 200)
        with audit_session_factory() as audit_db:
            rows = AuditLog(audit_db).search(
                agent_id=agent_id,
                tool=args.get("tool"),
                decision=args.get("decision"),
                since=_parse_ts(args.get("since")),
                until=_parse_ts(args.get("until")),
                limit=limit,
            )
        return {"rows": [_row_to_dict(r) for r in rows], "count": len(rows)}

    return ToolDescriptor(
        name="audit.search",
        description=(
            "Search the append-only audit log (redacted rows only). "
            "Security agents only; non-security callers are constrained "
            "to their own agent_id."
        ),
        input_schema=AUDIT_SEARCH_SCHEMA,
        sensitivity="routine",
        handler=handler,
    )


def make_policy_inspect_tool(
    config_session_factory: Callable[[], Session],
) -> ToolDescriptor:
    def handler(ctx: Any, args: dict[str, Any]) -> dict[str, Any]:
        # Local import: policy imports pipeline lazily in places; keep
        # the top-level arrow one-way.
        from .policy import PolicyEngine

        with config_session_factory() as config_db:
            engine = PolicyEngine(config_db)
            version = engine.current_version_number()
            rules = engine.list_rules_with_default_deny(version)
        # Read-only: no state change across calls (asserted in tests).
        return {"policy_version": version, "rules": rules}

    return ToolDescriptor(
        name="policy.inspect",
        description=(
            "Read the current policy version and its rules (the same "
            "data the Policies page renders). Read-only."
        ),
        input_schema=POLICY_INSPECT_SCHEMA,
        sensitivity="routine",
        handler=handler,
    )


def make_agent_tools(
    config_session_factory: Callable[[], Session],
    audit_session_factory: Callable[[], Session],
) -> list[ToolDescriptor]:
    """Build the gateway-side security-agent tools (MVP: the two reads)."""
    return [
        make_audit_search_tool(audit_session_factory),
        make_policy_inspect_tool(config_session_factory),
    ]
