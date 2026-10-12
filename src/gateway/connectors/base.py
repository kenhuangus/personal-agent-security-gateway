"""Connector plugin interface (FR-009).

A connector declares its tools (ToolDescriptor: name, description,
input schema, sensitivity, handler), its upstream OAuth scopes
(FR-013b least privilege), and a health check (FR-010: credential-valid
+ API-reachable). New connectors register via ``Connector.register``
without touching the MCP endpoint or the policy engine.

SSRF checklist (FR-009 acceptance): every adapter implements
``ssrf_checklist()`` returning named checks. The M2 adapters are
mock-only (in-memory upstreams, no network), so each check passes by
construction; the checklist is recorded per adapter in
docs/build-log.md.
"""

from __future__ import annotations

import datetime as dt
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..pipeline import ConnectorRegistry, ToolDescriptor


@dataclass(frozen=True)
class HealthStatus:
    """Result of a connector health check (FR-010)."""

    connector: str
    credential_valid: bool
    api_reachable: bool
    detail: str = ""
    checked_at: str = field(
        default_factory=lambda: dt.datetime.now(dt.timezone.utc).isoformat()
    )

    @property
    def healthy(self) -> bool:
        return self.credential_valid and self.api_reachable


class Connector(ABC):
    """Plugin interface (FR-009)."""

    #: Connector namespace, e.g. "email". Tool names are "<name>.<action>".
    name: str = ""

    @property
    @abstractmethod
    def tools(self) -> list[ToolDescriptor]:
        """ToolDescriptors this connector exposes (FR-008)."""

    @property
    @abstractmethod
    def upstream_scopes(self) -> list[str]:
        """Least-privilege upstream OAuth scopes (FR-013b)."""

    @abstractmethod
    def health_check(self) -> HealthStatus:
        """Credential-valid + API-reachable (FR-010)."""

    @abstractmethod
    def ssrf_checklist(self) -> dict[str, Any]:
        """Named SSRF review checks (FR-009 acceptance).

        Each value is True when the check passes, with an optional
        "notes" string entry. All checks must pass for acceptance.
        """

    def register(self, registry: ConnectorRegistry) -> None:
        """Register this connector's tools on the pipeline registry."""
        registry.register(self.name, self.tools)


def all_ssrf_checks_pass(checklist: dict[str, Any]) -> bool:
    """True when every named check in the checklist passes."""
    return all(
        value is True for key, value in checklist.items() if key != "notes"
    )
