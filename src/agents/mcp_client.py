"""Fix-A authenticated MCP client for the security agents (Pillar 2 §1.2).

The runner authenticates *as* each agent over MCP. The raw per-agent
secret reaches the runner exactly one way: environment variables /
platform secret store, one per agent (``GATEWAY_AGENT_<NAME>_CREDENTIAL``).
The client reads the env var at run start — never logs it, never
writes it to disk or DB — and sets the ``Authorization`` header per
the M1 transport contract (``Basic base64(client_id:client_secret)``
for OAuth agents, ``Bearer key_id.token`` for fallback). The public
id comes from ``GATEWAY_AGENT_<NAME>_CREDENTIAL_ID`` (safe to persist
in the schedule row for display).

If the env var is missing at run start, that agent's run is skipped
with heartbeat status ``credential_missing`` — fail-closed, never
retried with a different identity.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

#: agent key → (credential env var, credential-id env var).
AGENT_CREDENTIAL_ENV: dict[str, tuple[str, str]] = {
    "redteam": (
        "GATEWAY_AGENT_REDATEAM_CREDENTIAL",
        "GATEWAY_AGENT_REDATEAM_CREDENTIAL_ID",
    ),
    "sentinel": (
        "GATEWAY_AGENT_SENTINEL_CREDENTIAL",
        "GATEWAY_AGENT_SENTINEL_CREDENTIAL_ID",
    ),
    "policy_assistant": (
        "GATEWAY_AGENT_POLICY_ASSISTANT_CREDENTIAL",
        "GATEWAY_AGENT_POLICY_ASSISTANT_CREDENTIAL_ID",
    ),
    "incident": (
        "GATEWAY_AGENT_INCIDENT_CREDENTIAL",
        "GATEWAY_AGENT_INCIDENT_CREDENTIAL_ID",
    ),
}


class CredentialMissing(RuntimeError):
    """The agent's credential env var is unset (heartbeat: credential_missing)."""


@dataclass
class AgentCredentials:
    agent_key: str
    credential_id: str  # public part (client_id or key_id); safe to persist
    # raw_secret: the raw secret. NEVER logged, persisted, displayed,
    # or included in the repr — it only travels into the Authorization
    # header built by build_authorization_header().
    raw_secret: str = field(default="", repr=False)


def load_agent_credentials(agent_key: str) -> AgentCredentials:
    """Read the agent's credential from the environment (run start only)."""
    pair = AGENT_CREDENTIAL_ENV.get(agent_key)
    if pair is None:
        raise CredentialMissing(f"unknown security agent {agent_key!r}")
    secret_var, id_var = pair
    raw = os.environ.get(secret_var, "")
    if not raw:
        raise CredentialMissing(
            f"{secret_var} is not set — the {agent_key} agent cannot "
            "authenticate (fail-closed; heartbeat credential_missing)"
        )
    credential_id = os.environ.get(id_var, "")
    return AgentCredentials(
        agent_key=agent_key, credential_id=credential_id, raw_secret=raw
    )


def build_authorization_header(creds: AgentCredentials, transport: str) -> str:
    """Build the M1 transport Authorization header for the credential.

    ``transport`` is "oauth" (Basic client_id:client_secret) or
    "fallback_bearer" (Bearer key_id.token).
    """
    if transport == "oauth":
        token = base64.b64encode(
            f"{creds.credential_id}:{creds.raw_secret}".encode("utf-8")
        ).decode("ascii")
        return f"Basic {token}"
    if transport == "fallback_bearer":
        return f"Bearer {creds.credential_id}.{creds.raw_secret}"
    raise ValueError(f"unknown agent credential transport {transport!r}")


class AgentMCPClient:
    """Thin async wrapper around a FastMCP client for one agent.

    The real transport is constructed lazily (``connect()``) so unit
    tests can substitute a fake ``call_tool``. ``call_tool`` returns
    the decoded result dict on success and raises ``ToolCallDenied``
    / ``ToolCallError`` on error envelopes — the scenario engine
    works with observations, not exceptions, so it catches these.
    """

    def __init__(
        self,
        agent_id: str,
        gateway_url: str,
        authorization_header: str,
        call_tool: Optional[Callable[[str, dict[str, Any]], Any]] = None,
    ) -> None:
        self.agent_id = agent_id
        self.gateway_url = gateway_url.rstrip("/")
        self.authorization_header = authorization_header
        self._call_tool = call_tool
        self._client: Any = None

    async def connect(self) -> None:
        if self._call_tool is not None:
            return  # test double
        from fastmcp import Client as FastMCPClient

        self._client = FastMCPClient(
            f"{self.gateway_url}/mcp",
            headers={"Authorization": self.authorization_header},
        )
        await self._client.__aenter__()

    async def close(self) -> None:
        if self._client is not None:
            await self._client.__aexit__(None, None, None)
            self._client = None

    async def call_tool(self, tool: str, args: dict[str, Any]) -> Any:
        if self._call_tool is not None:
            result = self._call_tool(tool, args)
            if hasattr(result, "__await__"):
                result = await result
            return result
        assert self._client is not None, "connect() first"
        return await self._client.call_tool(tool, args or {})
