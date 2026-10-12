"""Vault storage models (01 FR-021–FR-024; 03 §5).

The vault is the THIRD SQLite file — physically separate from the
config and audit databases (03 §5). It has its own ORM Base so
``create_all`` on the config/audit databases never creates vault
tables there (and vice versa).

Conventions (shared with gateway.models):
- Timestamps: UTC, timezone-aware datetimes.
- No plaintext secrets anywhere in this schema: the payload column
  holds AES-256-GCM ciphertext; the data key that encrypts it is
  stored only in KEK-wrapped form.
"""

from __future__ import annotations

import datetime as dt
from typing import Optional

from sqlalchemy import DateTime, Index, LargeBinary, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class VaultBase(DeclarativeBase):
    pass


class VaultEntry(VaultBase):
    """One stored upstream credential (FR-021).

    Envelope encryption (see store.py): ``ciphertext`` is the secret
    encrypted under a per-entry random data key (DEK); ``wrapped_dek``
    is that DEK encrypted under the KMS key-encryption key (KEK).
    ``dek_key_id`` records which KEK version wrapped the DEK so KMS
    rotation (``VaultStore.rekey``) knows what to re-wrap.

    Lifecycle (FR-023): ``active`` → ``superseded`` (rotation, keeps
    the row readable for the graceful-expiry window) or ``revoked``
    (admin action; no new derived tokens are minted from it).
    """

    __tablename__ = "vault_entries"

    # e.g. "cred_9f2k…" — 128-bit CSPRNG, like req_/apr_/mnd_.
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    # Connector this credential belongs to: "email" | "calendar" | "codehost".
    # RESERVED names ("system", "notifier") are rejected by the store —
    # the notifier bootstrap secret lives in the platform secret store,
    # never the vault (NFR-SEC-002 scope note).
    connector: Mapped[str] = mapped_column(String(64), nullable=False)
    # Operator label, e.g. "Ken's Gmail (mock refresh)". Shown in console.
    label: Mapped[str] = mapped_column(String(256), nullable=False)
    # Envelope-encryption fields (all binary, never plaintext).
    wrapped_dek: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    dek_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    dek_key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # active | superseded | revoked
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    rotated_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    superseded_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    superseded_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    # admin_id seam for later team RBAC (02 §3.3); single admin in MVP.
    admin_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        Index("ix_vault_entries_connector_status", "connector", "status"),
    )

    def console_metadata(self) -> dict:
        """Console-safe metadata (FR-022): no ciphertext, no secrets."""
        return {
            "credential_id": self.id,
            "connector": self.connector,
            "label": self.label,
            "key_id": self.dek_key_id,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "rotated_at": self.rotated_at.isoformat() if self.rotated_at else None,
            "superseded_by": self.superseded_by,
        }
