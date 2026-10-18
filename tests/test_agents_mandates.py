"""Pillar 2 §2.1: validate_security_mandate.

The security-agent allowlist is wildcard-aware (audit.*,
gateway.approval_status) and rejects any forbidden pattern
(agent-pausing, payee-blocking, credential revocation, policy
mutation, global stop, vault reads). The seed allowlists must pass.
"""

from __future__ import annotations

import pytest

from agents.mandates import (
    FORBIDDEN_SECURITY_AGENT_TOOL_PATTERNS,
    ForbiddenMandateError,
    validate_security_mandate,
)
from agents.seed import SEED_ALLOWLISTS


def test_seed_allowlists_pass():
    for agent_id, allowlist in SEED_ALLOWLISTS.items():
        validate_security_mandate(allowlist)  # must not raise


def test_seed_allowlists_are_minimal():
    redteam = SEED_ALLOWLISTS["agent_redteam"]
    # No write tools, no vault, no agent control.
    for tool in redteam:
        assert not tool.startswith("vault.")
        assert tool not in ("code.pr.open", "policy.save")


@pytest.mark.parametrize("tool", [
    "agent.pause",
    "agent.revoke",
    "mandate.withdraw",
    "mandate.narrow",
    "gateway.global_stop",
    "vault.read",
    "vault.list",
    "vault.*",
    "policy.save",
    "policy.rollback",
    "code.pr.merge",
])
def test_forbidden_patterns_rejected(tool):
    with pytest.raises(ForbiddenMandateError):
        validate_security_mandate([tool, "audit.search"])


def test_allowed_tools_pass():
    validate_security_mandate([
        "audit.search", "policy.inspect", "sandbox.echo",
        "gateway.approval_status", "codehost.issue_open",
    ])


def test_forbidden_list_is_nonempty_and_documented():
    assert len(FORBIDDEN_SECURITY_AGENT_TOOL_PATTERNS) >= 5
    for pattern in FORBIDDEN_SECURITY_AGENT_TOOL_PATTERNS:
        assert isinstance(pattern, str) and pattern
