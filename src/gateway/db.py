"""Database access: TWO SQLite files (03 §5), WAL mode, ORM seam.

- ``config`` DB: agent registrations, credentials, mandates, policies,
  approvals, grants, counterparties, decision criteria, rate counters,
  admin users. Mutable config.
- ``audit`` DB: append-only audit entries. Physically separate file
  (03 §5); append-only enforced at the application layer (audit.py).

WAL mode on both (03 §5). Postgres migration seam: everything goes
through the SQLAlchemy ORM, so a later phase can swap the engine URL
without touching model code.

In-process session management: MVP is a single stateful process
(NFR-REL-001); no connection pooling tricks, no cross-process locks.
"""

from __future__ import annotations

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from .models import Base


def _apply_sqlite_pragmas(dbapi_conn, _connection_record) -> None:  # noqa: ANN001
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL;")
    cursor.execute("PRAGMA foreign_keys=ON;")
    # GH #7: WAL allows concurrent readers, but writers still serialize
    # and the default busy timeout is 0. The hot path writes on every
    # call (last_seen_at, the terminal audit append, rate counters), so
    # wait up to 5s on a locked database instead of raising SQLITE_BUSY.
    cursor.execute("PRAGMA busy_timeout=5000;")
    cursor.close()


def make_engine(db_path: str) -> Engine:
    engine = create_engine(f"sqlite:///{db_path}", future=True)
    event.listen(engine, "connect", _apply_sqlite_pragmas)
    return engine


def journal_mode(engine: Engine) -> str:
    with engine.connect() as conn:
        row = conn.exec_driver_sql("PRAGMA journal_mode;").first()
    return (row[0] if row else "").upper()


class Database:
    """One engine + session factory. Create two: config and audit."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.engine: Engine = make_engine(path)
        self._factory = sessionmaker(bind=self.engine, class_=Session, expire_on_commit=False)

    def create_all(self) -> None:
        Base.metadata.create_all(self.engine)

    def session(self) -> Session:
        return self._factory()


class Databases:
    """The gateway's two databases."""

    def __init__(self, config_path: str, audit_path: str) -> None:
        self.config = Database(config_path)
        self.audit = Database(audit_path)

    def create_all(self) -> None:
        self.config.create_all()
        self.audit.create_all()
