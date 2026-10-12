"""Mock upstream OAuth provider for tests (Fix A, M1).

Real OAuth app registrations (Google/Microsoft/GitHub) are Ken's
action and NOT done — never block on them, never invent real
credentials. This mock plays the gateway's authorization-server role
in tests: it issues fake access tokens (60-min session credentials,
FR-012a), validates them, and simulates expiry.

The mock lives entirely in-process; it never touches the network.
"""

from __future__ import annotations

import datetime as dt
import secrets
from dataclasses import dataclass, field


@dataclass
class MockToken:
    token: str
    agent_id: str
    issued_at: dt.datetime
    expires_at: dt.datetime
    scopes: list[str] = field(default_factory=list)


class MockOAuthProvider:
    """In-process fake OAuth 2.1 authorization server."""

    def __init__(self, token_ttl_minutes: int = 60) -> None:
        self.token_ttl_minutes = token_ttl_minutes
        self._tokens: dict[str, MockToken] = {}

    def issue_token(self, agent_id: str, scopes: list[str] | None = None) -> MockToken:
        now = dt.datetime.now(dt.timezone.utc)
        tok = MockToken(
            token=f"mockat_{secrets.token_hex(24)}",
            agent_id=agent_id,
            issued_at=now,
            expires_at=now + dt.timedelta(minutes=self.token_ttl_minutes),
            scopes=scopes or [],
        )
        self._tokens[tok.token] = tok
        return tok

    def validate(self, token: str) -> MockToken | None:
        """Return the token record if it is valid and unexpired, else None."""
        rec = self._tokens.get(token)
        if rec is None:
            return None
        if rec.expires_at <= dt.datetime.now(dt.timezone.utc):
            return None
        return rec

    def expire(self, token: str) -> None:
        """Simulate expiry (e.g. the 5-minute derived-token window)."""
        rec = self._tokens.get(token)
        if rec is not None:
            rec.expires_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1)

    def revoke(self, token: str) -> None:
        self._tokens.pop(token, None)

    def discovery_document(self) -> dict:
        """The public OAuth discovery surface (02 §2.1 public exception)."""
        return {
            "issuer": "https://gateway.local/mock-oauth",
            "authorization_endpoint": "https://gateway.local/mock-oauth/authorize",
            "token_endpoint": "https://gateway.local/mock-oauth/token",
            "jwks_uri": "https://gateway.local/mock-oauth/.well-known/jwks.json",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
        }
