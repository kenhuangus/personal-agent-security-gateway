"""Pillar 1 §9: hand-rolled versioned migrations m001 (quorum) + m002 (money).

The migrations are idempotent and applied at boot after ``create_all()``.
These tests exercise the upgrade logic against legacy schemas (a
``approval_requests`` table from before the quorum columns existed, and
a DB missing the money tables), plus the ``migrate()`` runner's
idempotency and version bookkeeping.
"""

from __future__ import annotations

from sqlalchemy import create_engine, inspect
from sqlalchemy.engine import Engine

from gateway.db import Database
from gateway.migrations import MIGRATIONS, migrate
from gateway.migrations import m001_quorum, m002_money
_QUORUM_COLUMNS = {
    "quorum_required",
    "approvals",
    "evidence_hash",
    "context_fingerprint",
    "request_type",
}

_LEGACY_APPROVAL_DDL = (
    "CREATE TABLE approval_requests ("
    "id VARCHAR(64) PRIMARY KEY, "
    "agent_id VARCHAR(128) NOT NULL)"
)


def _engine(tmp_path) -> Engine:
    return create_engine(f"sqlite:///{tmp_path}/mig.db")


def test_migrations_registry_lists_mvp_slice():
    versions = [v for v, _db, _fn in MIGRATIONS]
    assert versions == ["m001_quorum", "m002_money"]


def test_m001_adds_quorum_columns_to_legacy_table(tmp_path):
    engine = _engine(tmp_path)
    with engine.begin() as conn:
        conn.exec_driver_sql(_LEGACY_APPROVAL_DDL)

    before = {c["name"] for c in inspect(engine).get_columns("approval_requests")}
    assert not (_QUORUM_COLUMNS & before)

    m001_quorum.upgrade(engine)

    after = {c["name"] for c in inspect(engine).get_columns("approval_requests")}
    assert _QUORUM_COLUMNS <= after
    # Legacy columns survive.
    assert "agent_id" in after


def test_m001_is_idempotent(tmp_path):
    engine = _engine(tmp_path)
    with engine.begin() as conn:
        conn.exec_driver_sql(_LEGACY_APPROVAL_DDL)
    m001_quorum.upgrade(engine)
    m001_quorum.upgrade(engine)  # must not raise on re-run
    after = {c["name"] for c in inspect(engine).get_columns("approval_requests")}
    assert _QUORUM_COLUMNS <= after


def test_m002_creates_money_tables(tmp_path):
    engine = _engine(tmp_path)
    m002_money.upgrade(engine)
    tables = set(inspect(engine).get_table_names())
    assert {"money_ledger", "counterparty_allowlist", "money_pair_cooldowns"} <= tables


def test_m002_is_idempotent(tmp_path):
    engine = _engine(tmp_path)
    m002_money.upgrade(engine)
    m002_money.upgrade(engine)  # checkfirst=True: no failing DDL


def test_migrate_records_versions_and_is_idempotent(tmp_path):
    # Boot flow: create_all() already runs the idempotent migrations,
    # so a second migrate() is a no-op — but the versions were recorded.
    path = str(tmp_path / "config.db")
    db = Database(path, name="config")
    db.create_all()
    assert migrate(db.engine, "config") == []

    with db.engine.connect() as conn:
        rows = conn.exec_driver_sql("SELECT version FROM schema_version").fetchall()
    assert {r[0] for r in rows} == {"m001_quorum", "m002_money"}


def test_migrate_converges_legacy_schema(tmp_path):
    # An operator DB from before the money pack: approval_requests
    # without quorum columns, no money tables.
    engine = _engine(tmp_path)
    with engine.begin() as conn:
        conn.exec_driver_sql(_LEGACY_APPROVAL_DDL)
    applied = migrate(engine, "config")
    assert applied == ["m001_quorum", "m002_money"]
    after = {c["name"] for c in inspect(engine).get_columns("approval_requests")}
    assert _QUORUM_COLUMNS <= after
    tables = set(inspect(engine).get_table_names())
    assert "money_ledger" in tables
