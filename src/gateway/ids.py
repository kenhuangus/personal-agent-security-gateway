"""Request / approval / mandate identifiers.

- 128-bit CSPRNG values (00 §7 param 12; 02 §2.8).
- ``req_`` — tool-call request ids (error envelope request_id, audit correlation).
- ``apr_`` — approval request ids.
- ``mnd_`` — mandate ids.

Encoding: 32 lowercase hex chars (16 raw bytes). No grant ids cross the
agent boundary (internal grant ids never leave the gateway).
"""

from __future__ import annotations

import re
import secrets

_RAW_HEX_LEN = 32  # 128 bits

_ID_RE = re.compile(r"^[a-z]+_[0-9a-f]{32}$")

_PREFIXES = ("req_", "apr_", "mnd_")


def new_id(prefix: str) -> str:
    """Mint a fresh 128-bit id with the given prefix."""
    if prefix not in _PREFIXES:
        raise ValueError(f"unknown id prefix {prefix!r}; expected one of {_PREFIXES}")
    return f"{prefix}{secrets.token_hex(16)}"


def is_valid_id(value: str, prefix: str | None = None) -> bool:
    """True if *value* has the expected shape (and prefix, when given)."""
    if not isinstance(value, str) or not _ID_RE.match(value):
        return False
    if prefix is not None:
        return value.startswith(prefix)
    return True


def new_request_id() -> str:
    return new_id("req_")


def new_approval_id() -> str:
    return new_id("apr_")


def new_mandate_id() -> str:
    return new_id("mnd_")
