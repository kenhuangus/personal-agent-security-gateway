"""HMAC-SHA256 of canonical JSON arguments with the gateway-held key.

Used for:
- the idempotent approval lookup chain (02 §2.8 step 3): dedupe on
  (agent, tool, argument-hash), already-executed check, refusal-cooldown
  check, denial-streak escalation;
- the evidence-subset record (02 §2.8 step 4): HMAC of the canonical
  full arguments (never plaintext in the approvals table; never plain
  SHA-256 — offline brute-forceable by anyone with config-DB read
  access, per Round-3 MINOR-8).

Key lifecycle (03 §5): the key lives in the platform secret store
(Fly secrets / GCP Secret Manager per hosting choice) — NOT in the
config SQLite that gets backed up. Stored hashes are tagged with the
key id; a retired key is kept for verifying in-flight lookups until no
pending request references it. Rotation support is a stub seam here
(the key holder registers multiple keys); M1 uses one key.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from typing import Any


def canonical_json(value: Any) -> str:
    """Canonical JSON serialization per FR-PAA06-002.

    Key order and insignificant whitespace are normalized so immaterial
    diffs do not change the argument hash (and do not force re-approval).
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


@dataclass
class HmacKeyRing:
    """Holds the active HMAC key and retired keys for lookup.

    The key id is tagged on stored hashes (``key_id:hexdigest``), so
    rotation keeps in-flight lookups verifiable (03 §5).
    """

    active_key_id: str = "k1"
    _keys: dict[str, bytes] = field(default_factory=dict, repr=False)

    @classmethod
    def from_env_string(cls, key_id: str, key_material: str) -> "HmacKeyRing":
        ring = cls(active_key_id=key_id)
        ring.add_key(key_id, key_material)
        return ring

    def add_key(self, key_id: str, key_material: str) -> None:
        """Add a key. Supports the rotation seam: new keys go active,
        retired keys stay for verifying in-flight hashes (03 §5)."""
        material = key_material.encode("utf-8")
        if len(material) < 16:
            raise ValueError("HMAC key material must be at least 16 bytes (128 bits)")
        self._keys[key_id] = material

    def retire_key(self, key_id: str) -> None:
        """Stop using a key for NEW hashes while keeping it for verification."""
        if key_id == self.active_key_id:
            raise ValueError("cannot retire the active key; add the replacement first")

    def _key(self, key_id: str) -> bytes:
        try:
            return self._keys[key_id]
        except KeyError:
            raise ValueError(f"unknown HMAC key id {key_id!r}") from None

    def digest(self, value: Any, key_id: str | None = None) -> str:
        """``key_id:hexdigest`` over the canonical JSON of *value*.

        Plain SHA-256 is never used (Round-3 MINOR-8): anyone with
        config-DB read access could brute-force argument space offline.
        """
        kid = key_id or self.active_key_id
        mac = hmac.new(self._key(kid), canonical_json(value).encode("utf-8"), hashlib.sha256)
        return f"{kid}:{mac.hexdigest()}"

    def matches(self, value: Any, tagged_digest: str) -> bool:
        """Verify *value* against a stored ``key_id:hexdigest`` tag."""
        try:
            kid, hexpart = tagged_digest.split(":", 1)
        except ValueError:
            return False
        expected = hmac.new(
            self._key(kid), canonical_json(value).encode("utf-8"), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, hexpart)


def argument_hash(args: dict[str, Any], ring: HmacKeyRing) -> str:
    """The (agent, tool, argument-hash) dedupe/grant hash (02 §2.8 step 3)."""
    return ring.digest(args or {})
