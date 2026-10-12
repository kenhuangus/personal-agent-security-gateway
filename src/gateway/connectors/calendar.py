"""Calendar connector (FR-007): Calendar adapter over the in-memory mock.

Tools (02 §2.2): calendar.list (routine), calendar.create
(conditional — routine unless external attendees are included),
calendar.update (routine), calendar.delete (sensitive, destructive).

Conditional sensitivity is expressed through policy rules (argument
constraints on attendees), not in the adapter: the descriptor carries
"conditional" and the policy engine decides per call.

Derived-token handling follows the email connector: ``raw()`` is
called only inside this adapter (FR-012b).
"""

from __future__ import annotations

from typing import Any, Callable

from ..pipeline import ToolDescriptor
from .base import Connector, HealthStatus
from .mock_upstream import MockCalendar

CALENDAR_LIST_SCHEMA = {
    "type": "object",
    "properties": {
        "start": {"type": "string", "format": "date-time"},
        "end": {"type": "string", "format": "date-time"},
        "calendar_id": {"type": "string"},
        "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 25},
    },
    "required": ["start", "end"],
}

CALENDAR_CREATE_SCHEMA = {
    "type": "object",
    "properties": {
        "title": {"type": "string"},
        "start": {"type": "string", "format": "date-time"},
        "end": {"type": "string", "format": "date-time"},
        "attendees": {"type": "array", "items": {"type": "string", "format": "email"}},
        "description": {"type": "string"},
        "location": {"type": "string"},
        "calendar_id": {"type": "string"},
    },
    "required": ["title", "start", "end"],
}

CALENDAR_UPDATE_SCHEMA = {
    "type": "object",
    "properties": {
        "event_id": {"type": "string"},
        "title": {"type": "string"},
        "start": {"type": "string", "format": "date-time"},
        "end": {"type": "string", "format": "date-time"},
        "attendees": {"type": "array", "items": {"type": "string", "format": "email"}},
        "description": {"type": "string"},
        "location": {"type": "string"},
    },
    "required": ["event_id"],
}

CALENDAR_DELETE_SCHEMA = {
    "type": "object",
    "properties": {
        "event_id": {"type": "string"},
    },
    "required": ["event_id"],
}


class CalendarConnector(Connector):
    name = "calendar"

    def __init__(self, upstream: MockCalendar | None = None):
        self.upstream = upstream or MockCalendar()
        self.last_token_seen: str | None = None

    def _token(self, ctx: Any) -> str:
        """Read the derived token INSIDE the adapter (FR-012b)."""
        token = ctx.derived_token.raw() if ctx.derived_token is not None else ""
        self.last_token_seen = token
        return token

    # -- handlers ------------------------------------------------------

    def _list(self, ctx: Any, args: dict[str, Any]) -> Any:
        self._token(ctx)
        return {
            "events": self.upstream.list(
                start=args["start"],
                end=args["end"],
                calendar_id=args.get("calendar_id", "primary"),
                limit=args.get("limit", 25),
            )
        }

    def _create(self, ctx: Any, args: dict[str, Any]) -> Any:
        token = self._token(ctx)
        return self.upstream.create(token=token, **args)

    def _update(self, ctx: Any, args: dict[str, Any]) -> Any:
        token = self._token(ctx)
        event_id = args["event_id"]
        fields = {k: v for k, v in args.items() if k != "event_id"}
        return self.upstream.update(event_id, token=token, **fields)

    def _delete(self, ctx: Any, args: dict[str, Any]) -> Any:
        token = self._token(ctx)
        return self.upstream.delete(args["event_id"], token=token)

    # -- Connector interface --------------------------------------------

    @property
    def tools(self) -> list[ToolDescriptor]:
        def bind(fn: Callable[[Any, dict[str, Any]], Any]) -> Callable[[Any, dict[str, Any]], Any]:
            return lambda ctx, args: fn(ctx, args)

        return [
            ToolDescriptor(
                name="calendar.list",
                description="List calendar events in a time range.",
                input_schema=CALENDAR_LIST_SCHEMA,
                sensitivity="routine",
                handler=bind(self._list),
            ),
            ToolDescriptor(
                name="calendar.create",
                description=(
                    "Create a calendar event. Conditional sensitivity: routine, "
                    "but policy requires approval when attendees include "
                    "external addresses."
                ),
                input_schema=CALENDAR_CREATE_SCHEMA,
                sensitivity="conditional",
                handler=bind(self._create),
            ),
            ToolDescriptor(
                name="calendar.update",
                description="Update a calendar event.",
                input_schema=CALENDAR_UPDATE_SCHEMA,
                sensitivity="routine",
                handler=bind(self._update),
            ),
            ToolDescriptor(
                name="calendar.delete",
                description="SENSITIVE: Delete a calendar event. Destructive — no undo at the service. Execution pauses for human approval in the admin console.",
                input_schema=CALENDAR_DELETE_SCHEMA,
                sensitivity="sensitive",
                handler=bind(self._delete),
            ),
        ]

    @property
    def upstream_scopes(self) -> list[str]:
        return ["calendar.readonly", "calendar.events"]

    def health_check(self) -> HealthStatus:
        return HealthStatus(
            connector=self.name,
            credential_valid=True,
            api_reachable=True,
            detail="mock upstream: in-memory MockCalendar",
        )

    def ssrf_checklist(self) -> dict[str, Any]:
        return {
            "egress_allowlist": True,
            "no_open_url_fetch": True,
            "metadata_endpoints_blocked": True,
            "no_credentials_in_args": True,
            "notes": (
                "Mock-only adapter: in-process MockCalendar, no network egress, "
                "no tool accepts a URL parameter, no HTTP client exists to "
                "reach cloud-metadata endpoints, no tool accepts credentials "
                "(02 §2.4)."
            ),
        }
