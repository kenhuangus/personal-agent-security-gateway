"""m001 (MVP): quorum columns on ``approval_requests``.

Adds:
- ``quorum_required`` INTEGER, default 1 (1 = existing single-approver path)
- ``approvals`` JSON, default list — per-approver slots, append-only
- ``evidence_hash`` VARCHAR(128), nullable — HMAC of the frozen evidence subset
- ``context_fingerprint`` JSON, nullable — {mandate_status, policy_version,
  counterparty_record_version} at creation
- ``request_type`` VARCHAR(16), default "tool_call" ("tool_call" | "event_release")

Idempotent: each ADD COLUMN is skipped when the column already exists.
"""

from __future__ import annotations

from sqlalchemy import inspect
from sqlalchemy.engine import Engine

VERSION = "m001_quorum"

_COLUMNS: tuple[tuple[str, str], ...] = (
    ("quorum_required", "INTEGER NOT NULL DEFAULT 1"),
    ("approvals", "JSON"),
    ("evidence_hash", "VARCHAR(128)"),
    ("context_fingerprint", "JSON"),
    ("request_type", "VARCHAR(16) NOT NULL DEFAULT 'tool_call'"),
)


def upgrade(engine: Engine) -> None:
    insp = inspect(engine)
    existing = {c["name"] for c in insp.get_columns("approval_requests")}
    with engine.begin() as conn:
        for name, ddl in _COLUMNS:
            if name in existing:
                continue
            conn.exec_driver_sql(
                f"ALTER TABLE approval_requests ADD COLUMN {name} {ddl}"
            )
