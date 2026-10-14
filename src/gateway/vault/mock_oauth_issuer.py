"""Test issuer: adapts W1's ``MockOAuthProvider`` to the minter's
``UpstreamTokenIssuer`` protocol.

The mock plays the upstream token endpoint: given the vault's stored
(mock refresh) credential, it issues a short-lived derived access
token (5-min default). In-process only; never touches the network.
Real OAuth app registrations (Google/Microsoft/GitHub) are Ken's
action — a production issuer plugs into the same protocol without
touching the pipeline or the minter.
"""

from __future__ import annotations

import datetime as dt
import time
from typing import Optional

from ..mock_oauth import MockOAuthProvider


class MockOAuthIssuer:
    """``UpstreamTokenIssuer`` backed by ``MockOAuthProvider``."""

    # The mock's local dict IS an introspection endpoint: it models a
    # provider where "is this token still honored?" is answerable (GH #22).
    supports_introspection: bool = True

    def __init__(self, provider: Optional[MockOAuthProvider] = None) -> None:
        self.provider = provider or MockOAuthProvider()
        # Test seam (issue #2): the credential the minter forwarded on
        # the last issue() call. The mock mints fake tokens and needs
        # no credential to do so, but recording it proves the plumbing
        # forwards the vault's stored credential. In-memory only —
        # never logged or persisted.
        self.last_credential: Optional[str] = None

    def issue(
        self, credential: str, agent_id: str, scopes: list[str], ttl_seconds: int
    ) -> tuple[str, float]:
        self.last_credential = credential
        tok = self.provider.issue_token(agent_id, scopes)
        expires_at = time.time() + ttl_seconds
        # Pin the mock record to the requested TTL (the mock's own
        # constructor TTL is the layer-1 60-min default).
        tok.expires_at = dt.datetime.fromtimestamp(expires_at, dt.timezone.utc)
        return tok.token, expires_at

    def validate(self, token_value: str) -> bool:
        return self.provider.validate(token_value) is not None

    def expire(self, token_value: str) -> None:
        self.provider.expire(token_value)
