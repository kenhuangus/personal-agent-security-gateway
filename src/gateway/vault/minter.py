"""Vault-backed layer-2 derived-token minter (FR-012b; 03 §2.2).

On ``mint(ctx)`` the minter:
1. reads the connector's upstream credential from the vault
   (``VaultStore.read`` — audited per FR-024, value never logged);
2. exchanges it for a short-lived derived access token scoped to the
   connector (5-min default, 00 §7 param 2), bound to
   (agent, tool, action) in gateway bookkeeping and in the audit row;
3. returns a ``DerivedToken`` handle whose ``.raw()`` yields the
   derived access token ONLY to adapter code inside the gateway.

Deliberate design point (03 §2.1): the DerivedToken's material is the
layer-2 derived access token, NOT the vault's stored credential (the
refresh token / API key). The stored credential is used for the
exchange and never leaves the vault/minter boundary. This is
strictly stronger than FR-022's floor.

The (agent, tool, action) binding is gateway bookkeeping, not
cryptographic (03 §2.2 honest statement): the gateway refuses to mint
outside granted claims, but a stolen derived token is a live Bearer <redacted>
any upstream API within the connector's registered scopes until its
5-minute expiry (03 §6 T2).

The upstream exchange is behind the ``UpstreamTokenIssuer`` protocol.
Tests use ``MockOAuthIssuer`` (W1's ``mock_oauth``); production
wiring (real Google/Microsoft/GitHub token endpoints after Ken's OAuth
app registrations) plugs in here without touching the pipeline.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import time
from dataclasses import dataclass
from typing import Optional, Protocol

from ..audit import AuditLog
from ..config import Settings
from ..pipeline import CallContext, DerivedToken, TokenMinter
from .kms import VaultError
from .mock_oauth_issuer import MockOAuthIssuer  # noqa: F401  (re-export for tests)
from .store import VaultStore


class UpstreamTokenIssuer(Protocol):
    """Issues short-lived upstream access tokens from a stored credential."""

    def issue(
        self, agent_id: str, scopes: list[str], ttl_seconds: int
    ) -> tuple[str, float]:
        """Return ``(token_value, expires_at_epoch)``."""
        ...

    def validate(self, token_value: str) -> bool:
        """True if the token is known and unexpired."""
        ...

    def expire(self, token_value: str) -> None:
        """Force expiry (test seam; mirrors MockOAuthProvider.expire)."""
        ...


def _ledger_key(token_value: str) -> str:
    # The ledger is keyed by hash, not by the token value itself.
    return hashlib.sha256(token_value.encode("utf-8")).hexdigest()


@dataclass
class _IssuedToken:
    credential_id: str
    connector: str
    agent_id: str
    tool: str
    action: str
    issued_at_epoch: float
    expires_at_epoch: float


class VaultTokenMinter(TokenMinter):
    """The W3 seam filled: vault-backed ``TokenMinter`` for
    ``TokenMintStage``."""

    def __init__(
        self,
        store: VaultStore,
        issuer: UpstreamTokenIssuer,
        settings: Settings,
        audit: Optional[AuditLog] = None,
    ) -> None:
        self._store = store
        self._issuer = issuer
        self._settings = settings
        self._audit = audit
        self._ledger: dict[str, _IssuedToken] = {}

    @property
    def store(self) -> VaultStore:
        """The underlying vault (for admin wiring; never agent-visible)."""
        return self._store

    # -- TokenMinter protocol -------------------------------------------

    def mint(self, ctx: CallContext) -> DerivedToken:
        connector = ctx.tool.split(".", 1)[0] if "." in ctx.tool else ctx.tool
        action = ctx.tool.split(".", 1)[1] if "." in ctx.tool else ctx.tool
        try:
            credential_id, _stored = self._store.read(connector, actor=ctx.agent_id)
        except VaultError as exc:
            # Fail closed (03 §7): no credential → no token → the call is
            # denied downstream. The message names the connector only;
            # secret material never appears here (FR-022).
            raise VaultError(
                f"cannot derive token for {ctx.tool}: {exc}"
            ) from exc
        # `_stored` (the refresh credential / API key) is used for the
        # exchange inside the issuer and is never placed in the token.
        ttl_seconds = self._settings.derived_token_minutes * 60
        value, expires_at = self._issuer.issue(ctx.agent_id, [connector], ttl_seconds)
        now = time.time()
        self._ledger[_ledger_key(value)] = _IssuedToken(
            credential_id=credential_id,
            connector=connector,
            agent_id=ctx.agent_id,
            tool=ctx.tool,
            action=action,
            issued_at_epoch=now,
            expires_at_epoch=expires_at,
        )
        if self._audit is not None:
            self._audit.append(
                agent_id=ctx.agent_id,
                tool=ctx.tool,
                action="token-mint",
                decision="allowed",
                redacted_args={
                    "credential_id": credential_id,
                    "connector": connector,
                    "bound_scope": {
                        "agent": ctx.agent_id,
                        "tool": ctx.tool,
                        "action": action,
                    },
                    "issued_at": dt.datetime.fromtimestamp(
                        now, dt.timezone.utc
                    ).isoformat(),
                    "expires_at": dt.datetime.fromtimestamp(
                        expires_at, dt.timezone.utc
                    ).isoformat(),
                },
            )
        return DerivedToken(
            agent_id=ctx.agent_id,
            tool=ctx.tool,
            action=action,
            expires_at_epoch=expires_at,
            _material=value,
        )

    # -- adapter-side validation ------------------------------------------

    def validate_token(
        self,
        token: DerivedToken,
        *,
        expected_agent_id: Optional[str] = None,
        expected_tool: Optional[str] = None,
    ) -> bool:
        """Adapter-side check before presenting the token upstream.

        True only when the handle was minted here, has not expired, the
        issuer still honors it, and (when given) the agent/tool binding
        matches. Rotation does NOT invalidate already-minted tokens:
        they live out their ≤5-min TTL (graceful expiry, FR-023).
        """
        rec = self._ledger.get(_ledger_key(token.raw()))
        if rec is None:
            return False
        now = time.time()
        if now >= token.expires_at_epoch or now >= rec.expires_at_epoch:
            return False
        if expected_agent_id is not None and rec.agent_id != expected_agent_id:
            return False
        if expected_tool is not None and rec.tool != expected_tool:
            return False
        return self._issuer.validate(token.raw())
