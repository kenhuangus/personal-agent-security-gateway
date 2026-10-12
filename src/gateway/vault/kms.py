"""KMS provider abstraction for the vault (NFR-SEC-002; 03 §5).

The vault's key-encryption key (KEK) is managed OUTSIDE application
config. This module defines the narrow interface the vault needs and
the local/dev provider. Production bindings are documented below —
this module makes no cloud calls.

Local/dev provider
------------------
``EnvKmsProvider`` reads a base64-encoded 32-byte key from the
``GATEWAY_KMS_KEY`` environment variable. Generate one with::

    python -m gateway.vault.kms --generate

then export it (dev) or store it in the platform secret store (prod).
Never hardcode a key. Never commit one. Test keys are generated at
test time only.

Production bindings (interface only)
------------------------------------
- Fly.io: ``fly secrets set GATEWAY_KMS_KEY="$(python -m gateway.vault.kms --generate-key)"``.
  The value lands as an encrypted env var on the machine; the gateway
  reads it through ``EnvKmsProvider`` unchanged.
- GCP (Cloud Run): create the same base64 value as a Secret Manager
  secret and expose it to the service as the ``GATEWAY_KMS_KEY``
  environment variable (or mount it as a volume and point a small
  ``GcpSecretManagerKmsProvider`` at it — the seam is the
  ``KmsProvider`` protocol below).
- Plain VPS: keep the base64 value in a root-only file (0600) and
  export it in the service's environment file.

``GATEWAY_KMS_KEY_ID`` (optional, default ``"local-dev-1"``) names the
key version so entries record which KEK wrapped their data key
(needed for KMS rotation via ``VaultStore.rekey``).
"""

from __future__ import annotations

import argparse
import base64
import binascii
import os
import secrets
import sys
from typing import Mapping, Protocol, runtime_checkable


class VaultError(RuntimeError):
    """Vault/KMS failure. Never carries secret material in its message."""


@runtime_checkable
class KmsProvider(Protocol):
    """The narrow KMS interface the vault needs (03 §5)."""

    @property
    def key_id(self) -> str:
        """Operator-visible key version, e.g. ``"fly-kms-2026-10"``."""
        ...

    def get_data_key(self) -> bytes:
        """Return the 32-byte key-encryption key (KEK)."""
        ...


def generate_kms_key() -> str:
    """Generate a fresh 256-bit KEK, base64-encoded. Test/dev only —
    production keys are created by the operator at deploy time."""
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


class EnvKmsProvider:
    """Local/dev KMS: KEK from the ``GATEWAY_KMS_KEY`` env var.

    Production use is the same class: on Fly.io / Cloud Run the
    platform secret store injects ``GATEWAY_KMS_KEY`` as an encrypted
    env var, so no code change is needed between dev and prod
    (03 §4).
    """

    ENV_VAR = "GATEWAY_KMS_KEY"
    KEY_ID_ENV_VAR = "GATEWAY_KMS_KEY_ID"

    def __init__(self, env: Mapping[str, str] | None = None) -> None:
        env = os.environ if env is None else env
        raw = env.get(self.ENV_VAR)
        if not raw:
            raise VaultError(
                f"{self.ENV_VAR} is not set: the vault KEK must come from the "
                "environment or the platform secret store (NFR-SEC-002). "
                "Generate one with: python -m gateway.vault.kms --generate"
            )
        try:
            key = base64.b64decode(raw.strip(), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise VaultError(
                f"{self.ENV_VAR} is not valid base64: {exc}"
            ) from exc
        if len(key) != 32:
            raise VaultError(
                f"{self.ENV_VAR} must decode to exactly 32 bytes "
                f"(AES-256); got {len(key)}"
            )
        self._key = key
        self._key_id = env.get(self.KEY_ID_ENV_VAR, "local-dev-1")

    @property
    def key_id(self) -> str:
        return self._key_id

    def get_data_key(self) -> bytes:
        return self._key

    def __repr__(self) -> str:  # never show the key
        return f"EnvKmsProvider(key_id={self._key_id!r}, key=<redacted>)"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate a base64-encoded 256-bit vault KEK (dev/test only)."
    )
    parser.add_argument(
        "--generate",
        "--generate-key",
        dest="generate",
        action="store_true",
        help="print a fresh key as a GATEWAY_KMS_KEY assignment",
    )
    args = parser.parse_args(argv)
    if not args.generate:
        parser.print_help()
        return 2
    key = generate_kms_key()
    sys.stdout.write(f"GATEWAY_KMS_KEY={key}\n")
    sys.stdout.write(
        "# Put this in the platform secret store (Fly secrets / GCP Secret "
        "Manager),\n"
        "# never in source control. Optional: GATEWAY_KMS_KEY_ID=<version>.\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
