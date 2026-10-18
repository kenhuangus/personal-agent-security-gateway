"""m002 (MVP): money-pack tables.

- ``money_ledger``: one row per moved payment (post-execute; dry_run=1
  rows exercise the pipeline but are excluded from budget sums).
- ``counterparty_allowlist``: operator-curated payee allowlist,
  distinct from the auto-built ``counterparty_records``. Unique on
  (namespace_id, payee_key) — NULL namespaces handled via a partial
  unique index in SQLite; the service layer coalesces NULL for lookup.
- ``money_pair_cooldowns``: (agent_id, counterparty_key) → expiry;
  separate from ``refusal_cooldowns`` because the key is the payee,
  not the argument hash.

New tables are created via the ORM metadata (idempotent:
``checkfirst=True``). Rollback = restore from the nightly backup;
migrations are forward-only.
"""

from __future__ import annotations

from sqlalchemy.engine import Engine

VERSION = "m002_money"


def upgrade(engine: Engine) -> None:
    # Import here (not top-level): migrations must not import the full
    # gateway package at module import time — models is standalone.
    from ..models import Base

    Base.metadata.tables["money_ledger"].create(engine, checkfirst=True)
    Base.metadata.tables["counterparty_allowlist"].create(engine, checkfirst=True)
    Base.metadata.tables["money_pair_cooldowns"].create(engine, checkfirst=True)
