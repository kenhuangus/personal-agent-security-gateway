"""CSRF protection for the admin console (FR-042; Fix B, MF-8).

- Every state-changing console route requires an anti-CSRF token:
  issued per page/API-token fetch, carried in a ``SameSite=Strict``
  cookie, and submitted back via the ``X-CSRF-Token`` custom header
  (JSON APIs) or a hidden form field (server-rendered forms). The
  token must match the cookie AND be present in the server-side
  issuance registry (double-submit + server check).
- Destructive-scope approval decisions additionally require a
  per-decision confirmation token (FR-042): minted when the approval
  card is rendered, bound to the ``apr_`` id, single-use, 10-minute
  TTL. Full admin re-authentication (password + TOTP) arrives with
  M6's admin auth (FR-036); the single-use token is the M3 bar.

Tokens are process-local (MVP is a single stateful process,
NFR-REL-001).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import secrets
import threading

COOKIE_NAME = "gw_csrf"
HEADER_NAME = "x-csrf-token"
FORM_FIELD = "csrf_token"


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class ConfirmationTokenIssuer:
    """Per-decision confirmation tokens for destructive scopes (FR-042).

    ``mint(apr_id)`` at card render; ``redeem(token, apr_id)`` at
    decision time. Single-use, 10-minute TTL, bound to the apr_ id.
    """

    TTL = dt.timedelta(minutes=10)

    def __init__(self) -> None:
        self._tokens: dict[str, tuple[str, dt.datetime]] = {}
        self._lock = threading.Lock()

    def mint(self, apr_id: str) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._tokens[token] = (apr_id, _utcnow() + self.TTL)
        return token

    def redeem(self, token: str, apr_id: str) -> bool:
        """Single-use: a successful redeem deletes the token."""
        with self._lock:
            entry = self._tokens.pop(token, None)
        if entry is None:
            return False
        bound_id, expires_at = entry
        if _utcnow() > expires_at:
            return False
        return hmac.compare_digest(bound_id, apr_id)


class CsrfProtector:
    """Issues and validates anti-CSRF tokens."""

    def __init__(
        self,
        secret: bytes | None = None,
        token_ttl_minutes: int = 60,
    ) -> None:
        # The secret signs nothing here — tokens are opaque and checked
        # against the issuance registry. Kept for a future signed
        # stateless variant; generation uses secrets.token_urlsafe.
        self._secret = secret or secrets.token_bytes(32)
        self._ttl = dt.timedelta(minutes=token_ttl_minutes)
        self._tokens: dict[str, dt.datetime] = {}
        self._lock = threading.Lock()
        self.confirmations = ConfirmationTokenIssuer()

    def issue(self) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._tokens[token] = _utcnow() + self._ttl
        return token

    def validate(self, cookie_token: str | None, submitted: str | None) -> bool:
        """True only when the submitted token matches the cookie AND is
        a live issued token (double-submit + server check)."""
        if not cookie_token or not submitted:
            return False
        if not hmac.compare_digest(cookie_token, submitted):
            return False
        with self._lock:
            expires_at = self._tokens.get(submitted)
        if expires_at is None or _utcnow() > expires_at:
            return False
        return True

    def set_cookie(self, response: object, token: str) -> None:
        """Set the SameSite=Strict CSRF cookie on a FastAPI response."""
        response.set_cookie(  # type: ignore[union-attr]
            COOKIE_NAME,
            token,
            samesite="strict",
            httponly=False,  # JS needs it for the X-CSRF-Token header
            path="/",
        )

    def check_request(
        self,
        cookies: dict,
        headers: dict,
        form_token: str | None = None,
    ) -> bool:
        """Validate a request: header first, then form-field fallback."""
        cookie_token = cookies.get(COOKIE_NAME)
        submitted = headers.get(HEADER_NAME) or headers.get(HEADER_NAME.upper())
        if submitted is None:
            submitted = form_token
        return self.validate(cookie_token, submitted)

    def __repr__(self) -> str:
        return "CsrfProtector(<redacted>)"
