#!/usr/bin/env python3
"""Replay the audit dead-letter file (GH #18).

Reads ``data/audit-dead-letter.jsonl`` (or the path in
``GATEWAY_AUDIT_DEAD_LETTER``) and re-inserts each spilled row into the
audit DB. Rows are matched by ``request_id`` so a replay is idempotent:
already-present rows are skipped, not duplicated.

Usage:
    python3 scripts/replay_audit_dead_letter.py [--dry-run] [--path PATH]

Exit codes: 0 = all replayed (or nothing to replay), 1 = errors remain.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sqlalchemy import select  # noqa: E402

from gateway.audit import DEFAULT_DEAD_LETTER_PATH  # noqa: E402
from gateway.db import Database  # noqa: E402
from gateway.models import AuditEntry  # noqa: E402


def _parse_ts(raw: str | None) -> dt.datetime | None:
    if not raw:
        return None
    try:
        parsed = dt.datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed


def replay(dead_letter: Path, audit_db_path: str, dry_run: bool = False) -> tuple[int, int, int]:
    """Return (replayed, skipped, errors)."""
    db = Database(audit_db_path)
    replayed = skipped = errors = 0
    with db.session() as session:
        for line_no, line in enumerate(dead_letter.read_text(encoding="utf-8").splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                row = record["row"]
            except (ValueError, KeyError) as exc:
                print(f"line {line_no}: unparseable, skipping ({exc})")
                errors += 1
                continue
            exists = session.execute(
                select(AuditEntry).where(AuditEntry.request_id == row.get("request_id"))
            ).scalars().first()
            if exists is not None:
                skipped += 1
                continue
            if dry_run:
                replayed += 1
                continue
            try:
                session.add(AuditEntry(
                    request_id=row.get("request_id"),
                    approval_request_id=row.get("approval_request_id"),
                    agent_id=row.get("agent_id"),
                    tool=row.get("tool"),
                    action=row.get("action") or "",
                    timestamp=_parse_ts(row.get("timestamp")) or dt.datetime.now(dt.timezone.utc),
                    decision=row.get("decision"),
                    reason=row.get("reason"),
                    redacted_args=row.get("redacted_args") or {},
                    mandate_id=row.get("mandate_id"),
                    scope_rule=row.get("scope_rule"),
                    irreversible=bool(row.get("irreversible")),
                    irreversible_note=row.get("irreversible_note"),
                    ontology_snapshot_ref=row.get("ontology_snapshot_ref"),
                    data_snapshot_id=row.get("data_snapshot_id"),
                ))
                session.commit()
                replayed += 1
            except Exception as exc:  # noqa: BLE001 — keep replaying the rest
                session.rollback()
                print(f"line {line_no}: replay failed ({exc})")
                errors += 1
    return replayed, skipped, errors


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dry-run", action="store_true",
                    help="count what would be replayed without writing")
    ap.add_argument("--path", default=os.environ.get(
        "GATEWAY_AUDIT_DEAD_LETTER", DEFAULT_DEAD_LETTER_PATH),
        help="dead-letter JSONL path")
    ap.add_argument("--audit-db", default=os.environ.get(
        "GATEWAY_AUDIT_DB", "data/audit.db"),
        help="audit SQLite path")
    args = ap.parse_args()
    dead_letter = Path(args.path)
    if not dead_letter.exists():
        print(f"no dead-letter file at {dead_letter}; nothing to replay")
        return 0
    replayed, skipped, errors = replay(dead_letter, args.audit_db, args.dry_run)
    print(f"replayed={replayed} skipped={skipped} errors={errors}"
          f"{' (dry run)' if args.dry_run else ''}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
