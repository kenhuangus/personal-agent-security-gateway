"""In-memory mock upstreams (M2): fake Gmail / Calendar / GitHub.

NO network, NO credentials, NO real data. Every adapter talks only to
these mocks, which is what makes the SSRF checklist trivially
satisfiable (recorded per adapter in docs/build-log.md):

- egress allowlist: nothing — the mocks are in-process objects;
- no open-ended URL fetch: no tool accepts a URL parameter;
- cloud-metadata endpoints: unreachable — there is no HTTP client here.

Synthetic datasets include TRACEABLE synthetic facts (markers like
``SYNTHETIC-TRACE-FACT-PAA03-01``) so the PAA03 leakage tests in later
milestones can assert that private-labeled facts are filtered or
redacted, never delivered.

FR-PAA06-003 (conditional): ``MockGmail.transaction_status`` is the
transaction-status stub connectors use to confirm non-execution before
a retry after an unknown outcome.
"""

from __future__ import annotations

import copy
import datetime as dt
import itertools
from typing import Any, Optional


def _utcnow_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


# ---------------------------------------------------------------------
# Mock Gmail
# ---------------------------------------------------------------------

class MockGmail:
    """In-memory fake Gmail API surface (FR-007 email connector)."""

    def __init__(self) -> None:
        self._ids = itertools.count(1)
        self._sent_log: list[dict[str, Any]] = []
        self.reset()

    def reset(self) -> None:
        self._ids = itertools.count(1)
        self._sent_log = []
        self.messages: list[dict[str, Any]] = [
            {
                "message_id": "msg_001",
                "thread_id": "thr_001",
                "from": "alice@example.com",
                "to": ["ken@example.com"],
                "subject": "Q3 planning notes",
                "snippet": "Here are the Q3 planning notes for the work review…",
                "body": (
                    "Hi Ken,\n\nHere are the Q3 planning notes for the work "
                    "review. The roadmap draft is attached to the shared doc."
                    "\n\n— Alice"
                ),
                "labels": ["work"],
                "date": "2026-10-10T09:00:00Z",
            },
            {
                "message_id": "msg_002",
                "thread_id": "thr_002",
                "from": "family@example.com",
                "to": ["ken@example.com"],
                "subject": "Weekend plans",
                "snippet": "Are we still on for Saturday? Also…",
                "body": (
                    "Are we still on for Saturday? Also, a reminder about the "
                    "family matter we discussed: SYNTHETIC-TRACE-FACT-PAA03-01 "
                    "(private family note — must never leak into work context)."
                ),
                "labels": ["private", "family"],
                "date": "2026-10-11T18:30:00Z",
            },
            {
                "message_id": "msg_003",
                "thread_id": "thr_003",
                "from": "bank-alerts@example.com",
                "to": ["ken@example.com"],
                "subject": "Statement ready",
                "snippet": "Your monthly statement is ready…",
                "body": (
                    "Your monthly statement is ready. Reference "
                    "SYNTHETIC-TRACE-FACT-PAA03-02 (private account ref — "
                    "must never leak into work context)."
                ),
                "labels": ["private"],
                "date": "2026-10-09T12:00:00Z",
            },
        ]
        self.drafts: list[dict[str, Any]] = []
        self.settings: dict[str, Any] = {
            "forwarding": {"enabled": False, "forward_to": None},
            "filters": [
                {
                    "id": "flt_001",
                    "criteria": {"from": "newsletter@example.com"},
                    "action": {"label": "news"},
                }
            ],
            "recovery_address": None,
        }

    # -- read ---------------------------------------------------------

    def search(
        self,
        query: str,
        mailbox: str = "inbox",
        since: Optional[str] = None,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        q = (query or "").lower()
        hits = [
            m
            for m in self.messages
            if q in m["subject"].lower() or q in m["snippet"].lower()
        ]
        if since:
            hits = [m for m in hits if m["date"] >= since]
        return [
            {k: m[k] for k in ("message_id", "thread_id", "from", "subject", "snippet", "date", "labels")}
            for m in hits[: max(1, min(limit, 50))]
        ]

    def read(self, message_id: str) -> dict[str, Any]:
        for m in self.messages:
            if m["message_id"] == message_id:
                return copy.deepcopy(m)
        raise KeyError(f"unknown message {message_id!r}")

    # -- write --------------------------------------------------------

    def send(
        self, to: list[str], subject: str, body: str,
        cc: Optional[list[str]] = None, bcc: Optional[list[str]] = None,
        token: str = "",
    ) -> dict[str, Any]:
        # ``token`` is the derived call token handed down by the adapter;
        # the mock ignores it (no real upstream to authorize against).
        _ = token
        message_id = f"msg_sent_{next(self._ids):04d}"
        record = {
            "message_id": message_id,
            "to": list(to),
            "cc": list(cc or []),
            "bcc": list(bcc or []),
            "subject": subject,
            "body": body,
            "status": "sent",
            "sent_at": _utcnow_iso(),
        }
        self._sent_log.append(record)
        return {"message_id": message_id, "status": "sent"}

    def transaction_status(self, message_id: str) -> dict[str, Any]:
        """FR-PAA06-003 stub: confirm whether a send executed.

        After an unknown outcome (timeout/ambiguous response), retry is
        permitted only after this status check confirms non-execution.
        """
        for record in self._sent_log:
            if record["message_id"] == message_id:
                return {
                    "message_id": message_id,
                    "status": record["status"],
                    "sent_at": record["sent_at"],
                }
        return {"message_id": message_id, "status": "not_found"}

    def draft(
        self, to: list[str], subject: str, body: str, token: str = ""
    ) -> dict[str, Any]:
        _ = token
        draft_id = f"drf_{next(self._ids):04d}"
        self.drafts.append(
            {"draft_id": draft_id, "to": list(to), "subject": subject, "body": body}
        )
        return {"draft_id": draft_id, "status": "drafted"}

    # -- settings (FR-PAA02-005 read visibility) -----------------------

    def settings_read(self, section: str = "all") -> dict[str, Any]:
        if section == "all":
            return copy.deepcopy(self.settings)
        if section not in self.settings:
            raise KeyError(f"unknown settings section {section!r}")
        return copy.deepcopy({section: self.settings[section]})

    def settings_write(self, section: str, settings: dict[str, Any], token: str = "") -> dict[str, Any]:
        _ = token
        if section not in self.settings:
            raise KeyError(f"unknown settings section {section!r}")
        if not isinstance(settings, dict):
            raise ValueError("settings must be an object")
        self.settings[section] = copy.deepcopy(settings)
        return {"section": section, "status": "updated"}


# ---------------------------------------------------------------------
# Mock Calendar
# ---------------------------------------------------------------------

class MockCalendar:
    """In-memory fake Calendar API surface (FR-007 calendar connector)."""

    def __init__(self) -> None:
        self._ids = itertools.count(1)
        self.reset()

    def reset(self) -> None:
        self._ids = itertools.count(100)
        self.events: list[dict[str, Any]] = [
            {
                "event_id": "evt_001",
                "calendar_id": "primary",
                "title": "Work sync",
                "start": "2026-10-13T10:00:00Z",
                "end": "2026-10-13T10:30:00Z",
                "attendees": ["alice@example.com"],
                "description": "Weekly work sync.",
                "location": "virtual",
                "visibility": "public",
            },
            {
                "event_id": "evt_002",
                "calendar_id": "primary",
                "title": "Family dinner",
                "start": "2026-10-13T19:00:00Z",
                "end": "2026-10-13T21:00:00Z",
                "attendees": ["family@example.com"],
                "description": (
                    "Family dinner. Private note: SYNTHETIC-TRACE-FACT-PAA03-03 "
                    "(must never leak into work context)."
                ),
                "location": "home",
                "visibility": "private",
            },
        ]

    def list(
        self, start: str, end: str, calendar_id: str = "primary", limit: int = 25
    ) -> list[dict[str, Any]]:
        hits = [
            e
            for e in self.events
            if e["calendar_id"] == calendar_id and e["start"] >= start and e["end"] <= end
        ]
        return [copy.deepcopy(e) for e in hits[: max(1, min(limit, 100))]]

    def create(self, token: str = "", **fields: Any) -> dict[str, Any]:
        _ = token
        event_id = f"evt_{next(self._ids):04d}"
        event = {
            "event_id": event_id,
            "calendar_id": fields.get("calendar_id", "primary"),
            "title": fields.get("title", ""),
            "start": fields.get("start", ""),
            "end": fields.get("end", ""),
            "attendees": list(fields.get("attendees") or []),
            "description": fields.get("description", ""),
            "location": fields.get("location", ""),
            "visibility": "public",
        }
        self.events.append(event)
        return copy.deepcopy(event)

    def update(self, event_id: str, token: str = "", **fields: Any) -> dict[str, Any]:
        _ = token
        for e in self.events:
            if e["event_id"] == event_id:
                for key in ("title", "start", "end", "attendees", "description", "location"):
                    if key in fields and fields[key] is not None:
                        e[key] = copy.deepcopy(fields[key])
                return copy.deepcopy(e)
        raise KeyError(f"unknown event {event_id!r}")

    def delete(self, event_id: str, token: str = "") -> dict[str, Any]:
        _ = token
        for i, e in enumerate(self.events):
            if e["event_id"] == event_id:
                del self.events[i]
                return {"event_id": event_id, "status": "deleted"}
        raise KeyError(f"unknown event {event_id!r}")


# ---------------------------------------------------------------------
# Mock GitHub (code host)
# ---------------------------------------------------------------------

class MockGitHub:
    """In-memory fake GitHub API surface (FR-007 code-host connector).

    Read-first: file reads + PR open only. NO merge — ``code.pr.merge``
    is deferred out of MVP until the approval loop proves itself on
    email.send (00 §3).
    """

    def __init__(self) -> None:
        self._prs = itertools.count(1)
        self.reset()

    def reset(self) -> None:
        self._prs = itertools.count(1)
        self.repos: dict[str, dict[str, str]] = {
            "kenhuangus/example": {
                "README.md": "# example\n\nSynthetic repo for gateway tests.\n",
                "src/main.py": 'print("hello from the synthetic repo")\n',
            }
        }
        self.pull_requests: list[dict[str, Any]] = []

    def file_read(self, repo: str, path: str, ref: str = "HEAD") -> dict[str, Any]:
        _ = ref  # mock has no branches; ref accepted for schema compat
        files = self.repos.get(repo)
        if files is None:
            raise KeyError(f"unknown repo {repo!r}")
        content = files.get(path.lstrip("/"))
        if content is None:
            raise KeyError(f"unknown path {path!r} in repo {repo!r}")
        return {"repo": repo, "path": path, "ref": ref, "content": content}

    def pr_open(
        self, repo: str, title: str, head: str, base: str, body: str, token: str = ""
    ) -> dict[str, Any]:
        _ = token
        if repo not in self.repos:
            raise KeyError(f"unknown repo {repo!r}")
        number = next(self._prs)
        pr = {
            "repo": repo,
            "number": number,
            "title": title,
            "head": head,
            "base": base,
            "body": body,
            "state": "open",
            "url": f"https://example.invalid/{repo}/pull/{number}",
        }
        self.pull_requests.append(pr)
        return copy.deepcopy(pr)
