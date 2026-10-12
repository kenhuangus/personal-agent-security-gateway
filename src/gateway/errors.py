"""Agent-visible error envelope (02 §2.7).

All tool-call failures return MCP ``isError: true`` with a single JSON
payload in ``content[0].text``::

    {"error": {"code", "message", "request_id", "retryable", "details"}}

Rules from the spec:
- ``policy_denied`` reasons come only from the SAFE_REASONS vocabulary:
  no rule text, no rule ids, no time windows, no domain lists (02 §2.7).
- ``invalid_input`` names the offending FIELD, never its value (04 NH-2).
- Nothing in any error leaks vault contents, policy rule text, or
  other agents' data (FR-022, NFR-SEC-003).
- ``budget_exceeded`` is reserved, never emitted in MVP (FR-029/MF-13).
- ``request_id`` is present on every error and matches the audit row.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

# Every code named in 02 §2.7, including the reserved one.
ERROR_CODES: tuple[str, ...] = (
    "policy_denied",
    "approval_required",
    "approval_denied",
    "approval_expired",
    "approval_queue_full",
    "cooldown_active",
    "already_executed",
    "agent_paused",
    "agent_canceled",
    "invalid_input",
    "rate_limited",
    "budget_exceeded",  # reserved; never emitted in MVP (FR-029 moved post-MVP)
    "injected_output_blocked",
    "upstream_failure",
    "auth_failed",
    "agent_revoked",
)

# Safe reason vocabulary for policy_denied (02 §2.7): fixed set, no rule
# text/ids, no time windows, no domain lists.
SAFE_REASONS: tuple[str, ...] = (
    "no_allow_rule",
    "explicit_deny",
    "mandate_scope_exceeded",
    "mandate_expired",
    "mandate_paused",
    "mandate_withdrawn",
    "policy_superseded",
    "approval_denied",
    "approval_expired",
    "approval_queue_full",
    "cooldown_active",
    "rate_limited",
    "invalid_input",
    "agent_paused",
    "agent_canceled",
    "agent_revoked",
)

# Retry guidance per code. approval_required is a poll-then-re-invoke
# cycle (not plain retry); approval_expired wants a fresh request.
_RETRYABLE: dict[str, Any] = {
    "policy_denied": False,
    "approval_required": "poll_then_reinvoke",
    "approval_denied": False,
    "approval_expired": "rerequest",
    "approval_queue_full": "after_request_resolves",
    "cooldown_active": "after_cooldown",
    "already_executed": False,
    "agent_paused": False,
    "agent_canceled": False,
    "invalid_input": "fix_args",
    "rate_limited": "after_retry_after",
    "budget_exceeded": False,
    "injected_output_blocked": False,
    "upstream_failure": "see_details",
    "auth_failed": False,
    "agent_revoked": False,
}


@dataclass
class GatewayError:
    code: str
    message: str
    request_id: str
    retryable: Any = False
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.code not in ERROR_CODES:
            raise ValueError(f"unknown error code {self.code!r}")
        if self.code == "budget_exceeded":
            # FR-029 is post-MVP; the code is reserved, never emitted.
            raise ValueError("budget_exceeded is reserved for post-MVP (FR-029); never emit it")
        if self.code == "policy_denied":
            reason = self.details.get("reason")
            if reason is not None and reason not in SAFE_REASONS:
                raise ValueError(
                    f"policy_denied reason {reason!r} is not in the safe vocabulary; "
                    "rule text/ids must never leak"
                )

    def to_envelope(self) -> dict[str, Any]:
        return {
            "error": {
                "code": self.code,
                "message": self.message,
                "request_id": self.request_id,
                "retryable": self.retryable,
                "details": self.details,
            }
        }

    def to_text(self) -> str:
        """The payload string that goes in content[0].text with isError=True."""
        return json.dumps(self.to_envelope())


def make_error(
    code: str,
    message: str,
    request_id: str,
    details: dict[str, Any] | None = None,
    retryable: Any | None = None,
) -> GatewayError:
    if code not in ERROR_CODES:
        raise ValueError(f"unknown error code {code!r}")
    if retryable is None:
        retryable = _RETRYABLE[code]
    return GatewayError(
        code=code,
        message=message,
        request_id=request_id,
        retryable=retryable,
        details=details or {},
    )


def policy_denied(
    request_id: str,
    reason: str,
    message: str,
    tool: str | None = None,
    ontology_ref: dict[str, Any] | None = None,
) -> GatewayError:
    """policy_denied with a safe-vocabulary reason only (no rule text/ids).

    ``ontology_ref`` (additive): ``{"entry_id", "entry_kind",
    "snapshot_ref"}`` citing the specific ontology entry behind an
    ontology-shaped denial. The entry id is an opaque ``ont_`` config
    id (never rule text); the safe-vocabulary check on ``reason`` is
    unchanged.
    """
    details: dict[str, Any] = {"reason": reason}
    if tool is not None:
        details["tool"] = tool
    if ontology_ref is not None:
        if not isinstance(ontology_ref, dict) or "entry_id" not in ontology_ref:
            raise ValueError(
                "ontology_ref must be a dict with at least 'entry_id'"
            )
        details["ontology_ref"] = dict(ontology_ref)
    return make_error("policy_denied", message, request_id, details)


def invalid_input(
    request_id: str,
    field_name: str,
    tool: str | None = None,
) -> GatewayError:
    """invalid_input names the offending field, never its value (04 NH-2)."""
    details: dict[str, Any] = {"field": field_name}
    if tool is not None:
        details["tool"] = tool
    return make_error(
        "invalid_input",
        f"{tool + ': ' if tool else ''}invalid input in field {field_name!r}",
        request_id,
        details,
    )


class ToolHalt(Exception):
    """A tool handler halting the pipeline with a proper error envelope.

    Handlers receive ``(ctx, args)`` and normally return a result; when
    a handler itself must deny (e.g. the ``gateway.approval_status``
    poll budget), it raises ``ToolHalt(error)``. ``ExecuteStage``
    converts it to the GatewayError — the isError envelope, not an
    ``upstream_failure``.
    """

    def __init__(self, error: "GatewayError") -> None:
        super().__init__(error.code)
        self.error = error
