"""Hand-rolled versioned migrations (Pillar 1 §9).

Decision: hand-rolled versioned migrations, NOT Alembic. The codebase
has no migration infrastructure today (``Database.create_all()``
only); the deploy target is a single stateful process with three
SQLite files; Alembic would add a dependency and autogenerate churn
for a schema that changes in small, reviewable steps. A
``schema_version`` table + numbered, idempotent, forward-only
migration modules keeps every schema change visible in review — which
matters for a security gateway. Migrations are written with
SQLAlchemy DDL constructs (portable); ``models.py`` remains the ORM
source of truth. Rollback = restore from the nightly backup;
migrations themselves are forward-only.

``migrate(engine, db_name)`` is applied at process boot by the
launcher (MCP server, console, scripts) after ``create_all()`` — on a
fresh DB every upgrade is a no-op (schema converges); on an existing
DB only the missing pieces are applied. Each upgrade is idempotent:
it inspects the live schema before issuing DDL, so a crashed or
partially-applied run can be re-run safely.

``db_name`` selects which migrations apply: "config" (m001–m004),
"audit" (m006), "vault" (m005).
"""

from __future__ import annotations

from typing import Callable

from sqlalchemy import inspect
from sqlalchemy.engine import Engine

from . import m001_quorum, m002_money

# Registry: (version, db_name, upgrade_fn). Numbered sequentially
# (m001–m006); m001–m002 are the MVP slice, m003–m006 extensions.
MIGRATIONS: tuple[tuple[str, str, Callable[[Engine], None]], ...] = (
    ("m001_quorum", "config", m001_quorum.upgrade),
    ("m002_money", "config", m002_money.upgrade),
)

def _applied_versions(engine: Engine) -> set[str]:
    insp = inspect(engine)
    if "schema_version" not in insp.get_table_names():
        return set()
    with engine.connect() as conn:
        rows = conn.exec_driver_sql("SELECT version FROM schema_version").fetchall()
    return {str(r[0]) for r in rows}


def _record_applied(engine: Engine, version: str) -> None:
    with engine.begin() as conn:
        conn.exec_driver_sql(
            "INSERT INTO schema_version (version) VALUES (?)", (version,)
        )


def migrate(engine: Engine, db_name: str = "config") -> list[str]:
    """Apply pending migrations for *db_name*. Returns applied versions.

    Idempotent: already-recorded versions are skipped; each upgrade
    module also inspects the live schema, so re-runs never emit
    failing DDL (SQLite has no ADD COLUMN IF NOT EXISTS).
    """
    insp = inspect(engine)
    if "schema_version" not in insp.get_table_names():
        with engine.begin() as conn:
            conn.exec_driver_sql(
                "CREATE TABLE IF NOT EXISTS schema_version ("
                "version VARCHAR(32) PRIMARY KEY, "
                "applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
            )
    applied = _applied_versions(engine)
    newly: list[str] = []
    for version, target_db, upgrade in MIGRATIONS:
        if target_db != db_name:
            continue
        if version in applied:
            continue
        upgrade(engine)
        _record_applied(engine, version)
        newly.append(version)
    return newly
