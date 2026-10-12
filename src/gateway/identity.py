"""Agent identity service (Fix A — the auth wall).

Rules (00 §2 Fix A; 01 FR-011/012a/015; 03 §2.3):
- Exactly one credential per agent. OAuth 2.1 is primary.
- The long-lived fallback bearer is issued ONLY for an agent whose
  platform has demonstrably failed OAuth verification, recorded with
  the test date (``verified_test_date``). It is never the default and
  never issued alongside OAuth credentials.
- The gateway refuses connections that cannot present at least a
  per-agent secret over TLS. There is no third rung (no IP-allowlist
  downgrade — 03 AOQ-1 REJECTED).
- The agent-facing session credential is validated on EVERY request —
  the session ID alone is never sufficient authentication (03 §3.1).
- Revocation is immediate: kills sessions, tokens, grants (FR-015).

Credential storage: the secret is stored as a bcrypt hash only; the
raw secret is returned to the caller exactly once at issuance and is
never persisted (FR-022).

OAuth 2.1 note: the gateway acts as authorization server in the full
build (``mcp.server.auth`` helpers exist per the M0 spike). M1 issues
the credential and records the auth method; the live OAuth
code-exchange flow and per-platform spikes (OQ-1/OQ-3) are Ken's
actions (M0 S4: not verifiable here). The fallback path is built now
so both outcomes are covered without rework.
"""

from __future__ import annotations

import datetime as dt
import secrets
from dataclasses import dataclass
from typing import Optional

import bcrypt
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Agent, AgentCredential, as_utc


@dataclass(frozen=True)
class AuthResult:
    agent: Agent
    credential_kind: str  # "oauth" | "fallback_bearer"


def _hash_secret(secret: str) -> str:
    return bcrypt.hashpw(secret.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def _check_secret(secret: str, secret_hash: str) -> bool:
    try:
        return bcrypt.checkpw(secret.encode("utf-8"), secret_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


class IdentityService:
    def __init__(self, db: Session) -> None:
        self.db = db

    # -- registration ---------------------------------------------------

    def register_agent(
        self,
        agent_id: str,
        platform: str,
        display_name: str,
        household_role: str,
    ) -> tuple[Agent, str, str]:
        """Register an agent and issue its ONE credential (OAuth primary).

        Returns (agent, client_id, client_secret). The client_secret is
        the raw value — shown once, never stored.
        """
        existing = self.db.get(Agent, agent_id)
        if existing is not None:
            raise ValueError(f"agent {agent_id!r} is already registered")
        agent = Agent(
            id=agent_id,
            platform=platform,
            display_name=display_name,
            household_role=household_role,
            status="active",
            auth_method="oauth",
        )
        self.db.add(agent)
        client_id = f"gw_{secrets.token_hex(8)}"
        client_secret = secrets.token_urlsafe(48)
        self.db.add(
            AgentCredential(
                agent_id=agent_id,
                kind="oauth",
                identifier=client_id,
                secret_hash=_hash_secret(client_secret),
                active=True,
                issued_at=dt.datetime.now(dt.timezone.utc),
            )
        )
        self.db.commit()
        return agent, client_id, client_secret

    def issue_fallback_bearer(
        self, agent_id: str, oauth_test_failed_date: str
    ) -> tuple[str, str]:
        """Gated fallback issuance (Fix A).

        Issues the long-lived per-agent bearer ONLY when:
        - the agent's platform demonstrably failed OAuth verification
          (``oauth_test_failed_date`` records the test date — FR-011);
        - the agent has no active credential already (never alongside
          OAuth credentials; the OAuth credential is deactivated).

        Returns (bearer_key_id, raw_bearer_token). The raw bearer is
        shown once, never stored (only its bcrypt hash).
        """
        agent = self.db.get(Agent, agent_id)
        if agent is None:
            raise ValueError(f"unknown agent {agent_id!r}")
        if agent.status == "revoked":
            raise ValueError(f"agent {agent_id!r} is revoked; cannot issue credentials")
        if not oauth_test_failed_date:
            raise ValueError(
                "fallback bearer requires the OAuth verification test-failure date "
                "(Fix A: gated conditional fallback, never the default)"
            )
        # Deactivate any existing active credential: never two credentials.
        active = (
            self.db.execute(
                select(AgentCredential).where(
                    AgentCredential.agent_id == agent_id, AgentCredential.active.is_(True)
                )
            )
            .scalars()
            .all()
        )
        for cred in active:
            cred.active = False
        bearer = secrets.token_urlsafe(48)
        key_id = f"fb_{secrets.token_hex(8)}"
        self.db.add(
            AgentCredential(
                agent_id=agent_id,
                kind="fallback_bearer",
                identifier=key_id,
                secret_hash=_hash_secret(bearer),
                active=True,
                issued_at=dt.datetime.now(dt.timezone.utc),
                last_rotated_at=dt.datetime.now(dt.timezone.utc),
            )
        )
        agent.auth_method = "fallback_bearer"
        agent.verified_test_date = oauth_test_failed_date
        self.db.commit()
        return key_id, bearer

    # -- per-request authentication ------------------------------------

    def find_agent_id_by_credential_identifier(self, identifier: str) -> Optional[str]:
        """Map a credential's public identifier (OAuth client_id or
        fallback key id) to its agent. Used by the MCP transport layer
        to resolve the agent before secret validation.

        Inactive credentials resolve too (latest first): a revoked agent
        presenting its old credential must get ``agent_revoked`` — the
        distinct lifecycle state (FR-PAA10-004) — not a generic
        ``auth_failed``.
        """
        cred = (
            self.db.execute(
                select(AgentCredential)
                .where(AgentCredential.identifier == identifier)
                .order_by(AgentCredential.id.desc())
            )
            .scalars()
            .first()
        )
        return cred.agent_id if cred is not None else None

    def active_credential_count(self, agent_id: str) -> int:
        """Exactly one active credential per agent (Fix A invariant)."""
        rows = (
            self.db.execute(
                select(AgentCredential).where(
                    AgentCredential.agent_id == agent_id, AgentCredential.active.is_(True)
                )
            )
            .scalars()
            .all()
        )
        return len(rows)

    def authenticate(self, agent_id: str, presented_secret: str) -> AuthResult:
        """Validate the presented per-agent secret on EVERY request.

        The session ID alone is never sufficient (03 §3.1). Raises
        ValueError on failure — the caller maps to ``auth_failed`` /
        ``agent_revoked`` / ``agent_paused`` / ``agent_canceled``
        (02 §2.8 step 1; FR-PAA10-002/004).
        """
        agent = self.db.get(Agent, agent_id)
        if agent is None:
            raise ValueError("unknown agent")  # -> auth_failed
        if agent.status == "revoked":
            raise ValueError("agent_revoked")
        if agent.status == "paused":
            raise ValueError("agent_paused")
        if agent.status == "canceled":
            raise ValueError("agent_canceled")
        if agent.status == "deleted":
            raise ValueError("agent_revoked")  # deleted identities behave as revoked
        if agent.status != "active":
            raise ValueError("unknown agent")
        cred = (
            self.db.execute(
                select(AgentCredential).where(
                    AgentCredential.agent_id == agent_id, AgentCredential.active.is_(True)
                )
            )
            .scalars()
            .one_or_none()
        )
        if cred is None:
            raise ValueError("no active credential")  # -> auth_failed
        if cred.expires_at is not None and as_utc(cred.expires_at) <= dt.datetime.now(
            dt.timezone.utc
        ):
            raise ValueError("credential expired")  # -> auth_failed
        if not _check_secret(presented_secret, cred.secret_hash):
            raise ValueError("bad credential")  # -> auth_failed
        agent.last_seen_at = dt.datetime.now(dt.timezone.utc)
        self.db.commit()
        return AuthResult(agent=agent, credential_kind=cred.kind)

    # -- lifecycle ------------------------------------------------------

    def set_status(self, agent_id: str, status: str, actor: str = "admin") -> Agent:
        """pause | cancel | revoke | delete. Distinct effects (FR-PAA10-002)."""
        if status not in ("active", "paused", "canceled", "revoked", "deleted"):
            raise ValueError(f"unknown status {status!r}")
        agent = self.db.get(Agent, agent_id)
        if agent is None:
            raise ValueError(f"unknown agent {agent_id!r}")
        agent.status = status
        self.db.commit()
        return agent

    def revoke(self, agent_id: str, actor: str = "admin") -> Agent:
        """Immediate revocation (FR-015): kills the credential (new calls
        denied now); in-flight derived tokens expire within their
        5-minute window (03 §2.2); grants are invalidated by M3's
        revocation path (they key off agent status here)."""
        agent = self.set_status(agent_id, "revoked", actor)
        creds = (
            self.db.execute(
                select(AgentCredential).where(
                    AgentCredential.agent_id == agent_id, AgentCredential.active.is_(True)
                )
            )
            .scalars()
            .all()
        )
        for cred in creds:
            cred.active = False
        self.db.commit()
        return agent

    def rotate_fallback_bearer(self, agent_id: str) -> tuple[str, str]:
        """Rotate the conditional fallback bearer (00 §7 param 1:
        max age 90 days, mandatory rotation, console-visible age)."""
        agent = self.db.get(Agent, agent_id)
        if agent is None or agent.auth_method != "fallback_bearer":
            raise ValueError(f"agent {agent_id!r} has no fallback bearer to rotate")
        key_id, bearer = self.issue_fallback_bearer(agent_id, agent.verified_test_date or "")
        return key_id, bearer

    def bearer_age_days(self, agent_id: str) -> Optional[float]:
        cred = (
            self.db.execute(
                select(AgentCredential).where(
                    AgentCredential.agent_id == agent_id,
                    AgentCredential.active.is_(True),
                    AgentCredential.kind == "fallback_bearer",
                )
            )
            .scalars()
            .one_or_none()
        )
        if cred is None or cred.last_rotated_at is None:
            return None
        rotated = as_utc(cred.last_rotated_at)
        assert rotated is not None
        delta = dt.datetime.now(dt.timezone.utc) - rotated
        return delta.total_seconds() / 86400.0
