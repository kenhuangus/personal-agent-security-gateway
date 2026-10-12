"""The NOT-vault path: M3 exempt-notification bootstrap secret.

Storage split (NFR-SEC-002 scope note; 02 §2.8 step 5; 03 §5; 03 §6 T13):

- The M4 vault holds CONNECTOR credentials only (upstream OAuth
  refresh tokens, API keys).
- The M3 email-to-Ken notifier authenticates with a bootstrap
  deploy-time secret held in the PLATFORM SECRET STORE — Fly secrets
  or GCP Secret Manager per hosting choice — never in the vault.
  ``VaultStore.store`` refuses the reserved connectors ``"system"``
  and ``"notifier"`` so the secret cannot be put in the vault by
  mistake (there is a test for this).
- The secret is encrypted at rest per NFR-SEC-002 (key managed
  outside app config), rotates via the platform secret store on a
  documented schedule (max age 90 days, 03 §5 — rotation itself is a
  platform operation, audit-logged as an admin action per FR-041),
  and every READ is audit-logged per FR-024 (below).

Local/dev: the platform secret store is simulated by the
``GATEWAY_NOTIFIER_SECRET`` environment variable (already in
``Settings``). Production: bind the real secret-manager value to
that env var — no code change.
"""

from __future__ import annotations

from ..audit import AuditLog
from ..config import Settings
from .kms import VaultError


class NotifierSecretProvider:
    """Reads the exempt-notification bootstrap secret from the platform
    secret store (env var locally). Explicitly NOT the vault."""

    ENV_VAR = "GATEWAY_NOTIFIER_SECRET"

    def __init__(self, settings: Settings, audit: AuditLog) -> None:
        self._settings = settings
        self._audit = audit

    def read(self, *, purpose: str) -> str:
        """Return the bootstrap secret, audit-logging the read (FR-024).

        The audit row records purpose + source + timestamp — NEVER the
        value. ``purpose`` is a short caller label, e.g.
        ``"approval-notify"``.
        """
        value = self._settings.notifier_secret
        if not value:
            raise VaultError(
                f"{self.ENV_VAR} is not set: the exempt-notification bootstrap "
                "secret must come from the platform secret store (Fly secrets "
                "/ GCP Secret Manager; env var for local dev). It is never "
                "stored in the vault."
            )
        self._audit.append(
            agent_id="system",
            tool="notifier.read",
            decision="allowed",
            redacted_args={
                "purpose": purpose,
                "source": "platform-secret-store",
            },
        )
        return value

    def __repr__(self) -> str:  # the secret never appears in a repr
        return "NotifierSecretProvider(<redacted>)"
