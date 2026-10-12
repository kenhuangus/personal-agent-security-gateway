"""Encrypted credential vault (01 FR-021–FR-024; 02 §2.8 step 5; 03 §5).

Encryption choice (documented per the M4 task): envelope encryption.

- Per-credential random 256-bit data key (DEK). The DEK encrypts the
  payload with AES-256-GCM; the credential id is bound as
  additional authenticated data (AAD), so a ciphertext row cannot be
  transplanted onto another entry id.
- The DEK is wrapped (encrypted) with the KMS key-encryption key
  (KEK) via AES-256-GCM. Only the wrapped form is stored.
- Rationale over "KEK encrypts the payload directly": KMS key
  rotation becomes re-wrapping DEKs (``rekey``) instead of
  re-encrypting every payload, and KEK usage is minimized. The DEK
  never leaves the vault process in unwrapped form.

Narrow internal API (03 §2.5): the only caller is the connector-adapter
layer (via ``VaultTokenMinter``), and the only thing that leaves the
vault is a short-lived derived token — never a stored secret
(FR-022). The admin console gets ``list_entries()`` metadata only.
Every read is audit-logged (FR-024); rotation/revocation are
audit-logged as admin actions (FR-041).

The notifier bootstrap secret is REFUSED here: connectors
``"system"`` and ``"notifier"`` raise ``VaultError``. That secret
lives in the platform secret store (see notifier_secret.py).
"""

from __future__ import annotations

import datetime as dt
import secrets
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from ..audit import AuditLog
from ..db import make_engine
from .kms import KmsProvider, VaultError
from .models import VaultBase, VaultEntry, utcnow


# Connectors the vault refuses to store. The M3 exempt-notification
# bootstrap secret lives in the platform secret store (NFR-SEC-002
# scope note; 02 §2.8 step 5) — never in the vault, which holds
# connector credentials only.
RESERVED_CONNECTORS = frozenset({"system", "notifier"})

# VaultEntry.status values.
ACTIVE = "active"
SUPERSEDED = "superseded"
REVOKED = "revoked"


def new_credential_id() -> str:
    """128-bit CSPRNG credential id (cred_ prefix)."""
    return f"cred_{secrets.token_hex(16)}"


def _encrypt_dek(kek: bytes, dek: bytes) -> tuple[bytes, bytes]:
    nonce = secrets.token_bytes(12)
    return AESGCM(kek).encrypt(nonce, dek, None), nonce


def _decrypt_dek(kek: bytes, wrapped: bytes, nonce: bytes) -> bytes:
    try:
        return AESGCM(kek).decrypt(nonce, wrapped, None)
    except InvalidTag as exc:
        raise VaultError("cannot unwrap data key: KEK mismatch or corruption") from exc


def _encrypt_payload(dek: bytes, entry_id: str, plaintext: bytes) -> tuple[bytes, bytes]:
    nonce = secrets.token_bytes(12)
    ct = AESGCM(dek).encrypt(nonce, plaintext, entry_id.encode("utf-8"))
    return ct, nonce


def _decrypt_payload(dek: bytes, entry: VaultEntry) -> bytes:
    try:
        return AESGCM(dek).decrypt(
            entry.payload_nonce, entry.ciphertext, entry.id.encode("utf-8")
        )
    except InvalidTag as exc:
        raise VaultError("cannot decrypt credential payload: corruption or tampering") from exc


class VaultStore:
    """Server-side encrypted credential store (one SQLite file, 03 §5)."""

    def __init__(
        self,
        db_path: str,
        kms: KmsProvider,
        audit: Optional[AuditLog] = None,
    ) -> None:
        self.db_path = db_path
        self.kms = kms
        self.audit = audit
        self._engine = make_engine(db_path)  # WAL mode, like the other DBs
        VaultBase.metadata.create_all(self._engine)
        self._factory = sessionmaker(
            bind=self._engine, class_=Session, expire_on_commit=False
        )

    def close(self) -> None:
        self._engine.dispose()

    # -- internal helpers -------------------------------------------------

    def _log(
        self,
        tool: str,
        redacted_args: dict,
        *,
        agent_id: str = "console",
        action: str = "",
        decision: str = "allowed",
    ) -> None:
        if self.audit is not None:
            self.audit.append(
                agent_id=agent_id,
                tool=tool,
                action=action,
                decision=decision,
                redacted_args=redacted_args,
            )

    # -- CRUD ---------------------------------------------------------------

    def store(
        self,
        connector: str,
        label: str,
        secret: str,
        *,
        admin_id: Optional[str] = None,
    ) -> VaultEntry:
        """Store a new upstream credential (FR-021). Fails if an active
        entry already exists for the connector — use ``rotate``."""
        if connector in RESERVED_CONNECTORS:
            raise VaultError(
                f"connector {connector!r} is reserved: the notifier bootstrap "
                "secret lives in the platform secret store, never the vault "
                "(NFR-SEC-002 scope note)"
            )
        if not connector or not label:
            raise VaultError("connector and label are required")
        if not secret:
            raise VaultError("refusing to store an empty credential")
        with self._factory() as db:
            existing = db.execute(
                select(VaultEntry).where(
                    VaultEntry.connector == connector, VaultEntry.status == ACTIVE
                )
            ).scalar_one_or_none()
            if existing is not None:
                raise VaultError(
                    f"connector {connector!r} already has an active credential "
                    f"({existing.id}); use rotate() instead"
                )
            kek = self.kms.get_data_key()
            dek = secrets.token_bytes(32)
            wrapped_dek, dek_nonce = _encrypt_dek(kek, dek)
            entry_id = new_credential_id()
            ciphertext, payload_nonce = _encrypt_payload(
                dek, entry_id, secret.encode("utf-8")
            )
            entry = VaultEntry(
                id=entry_id,
                connector=connector,
                label=label,
                wrapped_dek=wrapped_dek,
                dek_nonce=dek_nonce,
                dek_key_id=self.kms.key_id,
                payload_nonce=payload_nonce,
                ciphertext=ciphertext,
                status=ACTIVE,
                admin_id=admin_id,
            )
            db.add(entry)
            db.commit()
            self._log(
                "vault.store",
                {
                    "credential_id": entry_id,
                    "connector": connector,
                    "label": label,
                    "key_id": self.kms.key_id,
                },
            )
            return entry

    def read(self, connector: str, *, actor: str) -> tuple[str, str]:
        """Return ``(credential_id, secret)`` for the connector's ACTIVE
        entry, and audit-log the read (FR-024).

        Narrow API: the only legitimate caller is the token minter at
        call time (03 §2.5). ``actor`` names who triggered the read
        (the calling agent id); the audit row records adapter +
        credential id + timestamp — NEVER the value.
        """
        with self._factory() as db:
            entry = db.execute(
                select(VaultEntry).where(
                    VaultEntry.connector == connector, VaultEntry.status == ACTIVE
                )
            ).scalar_one_or_none()
            if entry is None:
                raise VaultError(
                    f"no active vault credential for connector {connector!r}"
                )
            dek = _decrypt_dek(self.kms.get_data_key(), entry.wrapped_dek, entry.dek_nonce)
            secret = _decrypt_payload(dek, entry).decode("utf-8")
            self._log(
                "vault.read",
                {
                    "credential_id": entry.id,
                    "connector": connector,
                    "key_id": entry.dek_key_id,
                    "adapter": "TokenMintStage",
                    "purpose": "derived-token-mint",
                },
                agent_id=actor,
                action=connector,
            )
            return entry.id, secret

    def rotate(
        self,
        connector: str,
        new_secret: str,
        *,
        admin_id: Optional[str] = None,
    ) -> VaultEntry:
        """Rotate a credential (FR-023; admin action per FR-041).

        The old entry becomes ``superseded`` (kept encrypted at rest);
        derived tokens already minted against it live out their ≤5-min
        TTL — nothing is actively killed (graceful expiry, user
        story 12). No new derived token is minted from the old entry.
        """
        if not new_secret:
            raise VaultError("refusing to rotate to an empty credential")
        with self._factory() as db:
            old = db.execute(
                select(VaultEntry).where(
                    VaultEntry.connector == connector, VaultEntry.status == ACTIVE
                )
            ).scalar_one_or_none()
            if old is None:
                raise VaultError(
                    f"no active vault credential for connector {connector!r} to rotate"
                )
            kek = self.kms.get_data_key()
            dek = secrets.token_bytes(32)
            wrapped_dek, dek_nonce = _encrypt_dek(kek, dek)
            entry_id = new_credential_id()
            ciphertext, payload_nonce = _encrypt_payload(
                dek, entry_id, new_secret.encode("utf-8")
            )
            new_entry = VaultEntry(
                id=entry_id,
                connector=connector,
                label=old.label,
                wrapped_dek=wrapped_dek,
                dek_nonce=dek_nonce,
                dek_key_id=self.kms.key_id,
                payload_nonce=payload_nonce,
                ciphertext=ciphertext,
                status=ACTIVE,
                rotated_at=utcnow(),
                admin_id=admin_id,
            )
            old.status = SUPERSEDED
            old.superseded_at = utcnow()
            old.superseded_by = entry_id
            db.add(new_entry)
            db.commit()
            self._log(
                "vault.rotate",
                {
                    "connector": connector,
                    "old_credential_id": old.id,
                    "new_credential_id": entry_id,
                    "key_id": self.kms.key_id,
                },
            )
            return new_entry

    def revoke(self, connector: str, *, admin_id: Optional[str] = None) -> VaultEntry:
        """Revoke a connector's credential (admin action). Subsequent
        mints fail closed — calls are denied, the gateway stays up
        (03 §7)."""
        with self._factory() as db:
            entry = db.execute(
                select(VaultEntry).where(
                    VaultEntry.connector == connector, VaultEntry.status == ACTIVE
                )
            ).scalar_one_or_none()
            if entry is None:
                raise VaultError(
                    f"no active vault credential for connector {connector!r} to revoke"
                )
            entry.status = REVOKED
            db.commit()
            self._log(
                "vault.revoke",
                {"credential_id": entry.id, "connector": connector},
            )
            return entry

    def rekey(self, new_kms: KmsProvider) -> int:
        """Re-wrap every entry's DEK under a new KEK (KMS rotation).

        Payloads are NOT re-encrypted — only the wrapped DEKs change.
        Audit-logged as an admin action (FR-041).
        """
        old_kek = self.kms.get_data_key()
        new_kek = new_kms.get_data_key()
        count = 0
        with self._factory() as db:
            entries = db.execute(select(VaultEntry)).scalars().all()
            for entry in entries:
                dek = _decrypt_dek(old_kek, entry.wrapped_dek, entry.dek_nonce)
                wrapped, nonce = _encrypt_dek(new_kek, dek)
                entry.wrapped_dek = wrapped
                entry.dek_nonce = nonce
                entry.dek_key_id = new_kms.key_id
                count += 1
            db.commit()
        self.kms = new_kms
        self._log(
            "vault.rekey",
            {"entries_rewrapped": count, "new_key_id": new_kms.key_id},
        )
        return count

    def list_entries(self) -> list[dict]:
        """Console-safe listing (FR-022): metadata only, no ciphertext."""
        with self._factory() as db:
            entries = db.execute(
                select(VaultEntry).order_by(VaultEntry.created_at)
            ).scalars().all()
            return [e.console_metadata() for e in entries]
