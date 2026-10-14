"""Append-only audit log (FR-030–FR-034; FR-031; FR-032).

- Append-only: this module exposes NO update/delete path (FR-032).
- Every row carries: agent, tool, action, timestamp, decision,
  redacted args, mandate_id, request_id, irreversible marker
  (FR-PAA10-005), and the scope rule that authorized the call
  (FR-PAA01-007).
- PII redaction applies BEFORE the audit write (NFR-DATA-001). M1
  stores caller-supplied redacted args; the M5 inspection pipeline
  performs the redaction. The audit row never carries plaintext PII.
- Search/filter by agent, tool, time range, decision (FR-034).
- JSON/CSV export for a time range; the export itself is audit-logged
  (FR-033). Exports are staged to local disk for manual download in
  MVP (00 §7 param 19).
- approval_status routine polls are exempt from per-call rows
  (Round-1 m-3); polls returning denied/expired/not-found ARE logged.
"""

from __future__ import annotations

import csv
import datetime as dt
import io
import json
import logging
import time
from pathlib import Path
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from .ids import new_request_id
from .models import AuditEntry

log = logging.getLogger(__name__)

#: Default dead-letter file for audit rows that could not be committed
#: (GH #18). Overridable per AuditLog and via
#: Settings.audit_dead_letter_path.
DEFAULT_DEAD_LETTER_PATH = "data/audit-dead-letter.jsonl"

#: Commit retry schedule (seconds) before the dead-letter spill.
_AUDIT_RETRY_BACKOFF = (0.05, 0.2, 0.5)


# Decisions recorded in the audit log (02 §2.8; 02 §7 filters).
DECISIONS: tuple[str, ...] = (
    "allowed",
    "denied",
    "approval_required",
    "approved",
    "denied_decision",  # the approval DECISION record (FR-031), distinct from a denied call
    "expired",
    "allowed_via_approval",
    "error",
)


class AuditLog:
    """Append-only audit log.

    GH #18: the terminal audit write is retried with backoff; on
    persistent commit failure the row spills to a local dead-letter
    JSONL file (replayable with scripts/replay_audit_dead_letter.py)
    instead of being silently lost. ``dead_lettered`` counts rows that
    took the spill path.
    """

    def __init__(self, db: Session, dead_letter_path: Optional[str] = None) -> None:
        self.db = db
        self.dead_letter_path = dead_letter_path or DEFAULT_DEAD_LETTER_PATH
        self.dead_lettered = 0

    def append(
        self,
        agent_id: str,
        tool: str,
        decision: str,
        request_id: Optional[str] = None,
        action: str = "",
        redacted_args: Optional[dict[str, Any]] = None,
        mandate_id: Optional[str] = None,
        scope_rule: Optional[str] = None,
        reason: Optional[str] = None,
        approval_request_id: Optional[str] = None,
        irreversible: bool = False,
        irreversible_note: Optional[str] = None,
        timestamp: Optional[dt.datetime] = None,
        ontology_snapshot_ref: Optional[str] = None,
        data_snapshot_id: Optional[str] = None,
    ) -> AuditEntry:
        """Append one row. Redacted args ONLY — never plaintext PII.

        ``ontology_snapshot_ref`` (additive): the content-addressed ref of
        the ontology decision snapshot (PAA04 traceability); None when
        the ontology module did not shape the decision.
        ``data_snapshot_id`` (additive): the fingerprint of the policy
        data behind the decision (input-document versioning).
        """
        if decision not in DECISIONS:
            raise ValueError(f"unknown decision {decision!r}")
        entry = AuditEntry(
            request_id=request_id or new_request_id(),
            approval_request_id=approval_request_id,
            agent_id=agent_id,
            tool=tool,
            action=action,
            timestamp=timestamp or dt.datetime.now(dt.timezone.utc),
            decision=decision,
            reason=reason,
            redacted_args=redacted_args or {},
            mandate_id=mandate_id,
            scope_rule=scope_rule,
            irreversible=irreversible,
            irreversible_note=irreversible_note,
            ontology_snapshot_ref=ontology_snapshot_ref,
            data_snapshot_id=data_snapshot_id,
        )
        self.db.add(entry)
        self._commit_with_retry(entry)
        return entry

    def _commit_with_retry(self, entry: AuditEntry) -> None:
        """Commit with backoff; spill to the dead-letter file on failure.

        GH #18: if the commit fails (lock contention, disk full,
        corruption) AFTER ExecuteStage ran, the upstream action executed
        but no audit row would exist (an FR-030 gap) — and the agent
        would get a 500 instead of its result, inviting a retry that
        double-executes non-idempotent actions. Retrying first, then
        spilling the row to the dead-letter file, preserves the trail.
        Never raises for DB errors: losing the row silently is worse
        than a loud log, and crashing the gateway on an audit write
        turns a logging failure into a full outage.
        """
        last_exc: Optional[BaseException] = None
        for attempt, backoff in enumerate((0.0,) + _AUDIT_RETRY_BACKOFF):
            if backoff:
                time.sleep(backoff)
            try:
                # Re-add: a rollback() after a failed flush can detach
                # the pending row; add() on an attached object is a
                # no-op, so this is safe on every attempt.
                self.db.add(entry)
                self.db.commit()
                if attempt:
                    log.warning(
                        "audit commit succeeded on retry %d (request_id=%s)",
                        attempt, entry.request_id,
                    )
                return
            except SQLAlchemyError as exc:
                last_exc = exc
                try:
                    self.db.rollback()
                except Exception:  # noqa: BLE001 — rollback is best-effort
                    pass
                log.warning(
                    "audit commit failed (attempt %d, request_id=%s): %s",
                    attempt + 1, entry.request_id, exc,
                )
        self._dead_letter(entry, last_exc)

    def _dead_letter(self, entry: AuditEntry, exc: Optional[BaseException]) -> None:
        """Spill one audit row to the dead-letter JSONL file (GH #18)."""
        row = {
            "dead_lettered_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "commit_error": f"{type(exc).__name__}: {exc}" if exc else "unknown",
            "row": {
                "request_id": entry.request_id,
                "approval_request_id": entry.approval_request_id,
                "agent_id": entry.agent_id,
                "tool": entry.tool,
                "action": entry.action,
                "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
                "decision": entry.decision,
                "reason": entry.reason,
                "redacted_args": entry.redacted_args,
                "mandate_id": entry.mandate_id,
                "scope_rule": entry.scope_rule,
                "irreversible": entry.irreversible,
                "irreversible_note": entry.irreversible_note,
                "ontology_snapshot_ref": entry.ontology_snapshot_ref,
                "data_snapshot_id": entry.data_snapshot_id,
            },
        }
        try:
            path = Path(self.dead_letter_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(row, ensure_ascii=True, default=str) + "\n")
            self.dead_lettered += 1
        except Exception:  # noqa: BLE001 — the disk itself is failing
            log.critical(
                "AUDIT ROW LOST: dead-letter write failed (request_id=%s "
                "path=%s): %s",
                entry.request_id, self.dead_letter_path, exc,
                exc_info=True,
            )
            return
        log.critical(
            "audit commit failed persistently (request_id=%s tool=%s); row "
            "spilled to dead-letter file %s — replay with "
            "scripts/replay_audit_dead_letter.py",
            entry.request_id, entry.tool, self.dead_letter_path,
        )

    # Intentionally no update() / delete() / clear() methods (FR-032).

    def search(
        self,
        agent_id: Optional[str] = None,
        tool: Optional[str] = None,
        decision: Optional[str] = None,
        since: Optional[dt.datetime] = None,
        until: Optional[dt.datetime] = None,
        approval_request_id: Optional[str] = None,
        limit: int = 200,
    ) -> list[AuditEntry]:
        """Search/filter the audit log (FR-034)."""
        stmt = select(AuditEntry)
        if agent_id is not None:
            stmt = stmt.where(AuditEntry.agent_id == agent_id)
        if tool is not None:
            stmt = stmt.where(AuditEntry.tool == tool)
        if decision is not None:
            stmt = stmt.where(AuditEntry.decision == decision)
        if since is not None:
            stmt = stmt.where(AuditEntry.timestamp >= since)
        if until is not None:
            stmt = stmt.where(AuditEntry.timestamp <= until)
        if approval_request_id is not None:
            stmt = stmt.where(AuditEntry.approval_request_id == approval_request_id)
        stmt = stmt.order_by(AuditEntry.timestamp.desc()).limit(limit)
        return list(self.db.execute(stmt).scalars().all())

    def _row(self, e: AuditEntry) -> dict[str, Any]:
        return {
            "request_id": e.request_id,
            "approval_request_id": e.approval_request_id,
            "agent_id": e.agent_id,
            "tool": e.tool,
            "action": e.action,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "decision": e.decision,
            "reason": e.reason,
            "redacted_args": e.redacted_args,
            "mandate_id": e.mandate_id,
            "scope_rule": e.scope_rule,
            "ontology_snapshot_ref": e.ontology_snapshot_ref,
            "data_snapshot_id": e.data_snapshot_id,
            "irreversible": e.irreversible,
            "irreversible_note": e.irreversible_note,
        }

    def export_json(
        self,
        since: Optional[dt.datetime] = None,
        until: Optional[dt.datetime] = None,
    ) -> str:
        rows = self.search(since=since, until=until, limit=100000)
        return json.dumps([self._row(e) for e in rows], indent=2, ensure_ascii=True)

    def export_csv(
        self,
        since: Optional[dt.datetime] = None,
        until: Optional[dt.datetime] = None,
    ) -> str:
        rows = self.search(since=since, until=until, limit=100000)
        buf = io.StringIO()
        fieldnames = [
            "request_id",
            "approval_request_id",
            "agent_id",
            "tool",
            "action",
            "timestamp",
            "decision",
            "reason",
            "mandate_id",
            "scope_rule",
            "ontology_snapshot_ref",
            "data_snapshot_id",
            "irreversible",
            "irreversible_note",
            "redacted_args",
        ]
        writer = csv.DictWriter(buf, fieldnames=fieldnames)
        writer.writeheader()
        for e in rows:
            row = self._row(e)
            row["redacted_args"] = json.dumps(row["redacted_args"], ensure_ascii=True)
            writer.writerow(row)
        return buf.getvalue()

    def export_to_file(
        self,
        path: str,
        fmt: str = "json",
        since: Optional[dt.datetime] = None,
        until: Optional[dt.datetime] = None,
        exporting_agent_id: str = "console",
    ) -> str:
        """Export to a local-disk file (MVP staging, 00 §7 param 19) and
        audit-log the export itself (FR-033)."""
        if fmt == "json":
            payload = self.export_json(since=since, until=until)
        elif fmt == "csv":
            payload = self.export_csv(since=since, until=until)
        else:
            raise ValueError(f"unknown export format {fmt!r}")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(payload)
        # The export itself is audit-logged (FR-033).
        self.append(
            agent_id=exporting_agent_id,
            tool="audit.export",
            decision="allowed",
            redacted_args={"format": fmt, "path": path},
            reason=None,
        )
        return path
