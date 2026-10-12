"""Server-side encrypted credential vault (M4; 01 FR-021–FR-024; 03 §5).

Contents:
- ``kms`` — KMS provider interface + env-based local/dev provider +
  ``--generate`` key CLI. Production binding (Fly secrets / GCP
  Secret Manager) is documented there; no cloud calls here.
- ``store`` — ``VaultStore``: encrypted SQLite secrets file (separate
  from the config and audit DBs), envelope encryption
  (KMS KEK wraps per-credential DEKs), CRUD + rotation with graceful
  expiry + revocation + KMS rekey. Every read is audit-logged
  (FR-024); rotation/revocation/rekey are admin actions (FR-041).
- ``minter`` — ``VaultTokenMinter``: the vault-backed ``TokenMinter``
  for the pipeline's ``TokenMintStage``. Mints the layer-2 derived
  call token (5-min TTL, bound to agent/tool/action as gateway
  bookkeeping — 03 §2.2) from the vault credential via an
  ``UpstreamTokenIssuer``.
- ``mock_oauth_issuer`` — test issuer adapting W1's ``mock_oauth``.
- ``notifier_secret`` — the explicit NON-vault path for the M3
  exempt-notification bootstrap secret (platform secret store, not
  the vault; NFR-SEC-002 scope note).

Isolation (03 §2.5): the only caller is the connector-adapter layer
(via the minter); the only thing that leaves the vault is a
short-lived derived token, never a stored secret (FR-022).
"""

from .kms import EnvKmsProvider, KmsProvider, VaultError, generate_kms_key
from .minter import MockOAuthIssuer, UpstreamTokenIssuer, VaultTokenMinter
from .models import VaultBase, VaultEntry
from .notifier_secret import NotifierSecretProvider
from .store import RESERVED_CONNECTORS, VaultStore, new_credential_id

__all__ = [
    "EnvKmsProvider",
    "KmsProvider",
    "MockOAuthIssuer",
    "NotifierSecretProvider",
    "RESERVED_CONNECTORS",
    "UpstreamTokenIssuer",
    "VaultBase",
    "VaultEntry",
    "VaultError",
    "VaultStore",
    "generate_kms_key",
    "new_credential_id",
]
