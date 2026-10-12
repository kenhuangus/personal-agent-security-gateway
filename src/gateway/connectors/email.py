"""Email connector (FR-007): Gmail adapter over the in-memory mock.

Tools (02 §2.2): email.search / email.read / email.send / email.draft /
email.settings.read / email.settings.write. Sensitivities per the
inventory: send and settings.write are sensitive (step-up approval);
the rest are routine.

The adapter is the ONLY place that touches the derived call token:
``ctx.derived_token.raw()`` is called here, inside the gateway, and
the raw material never appears in a handler result or an error
(FR-012b). The mock upstream ignores the token value.
"""

from __future__ import annotations

from typing import Any, Callable

from ..pipeline import ToolDescriptor
from .base import Connector, HealthStatus
from .mock_upstream import MockGmail

EMAIL_SEARCH_SCHEMA = {
    "type": "object",
    "properties": {
        "query": {"type": "string", "description": "Search text."},
        "mailbox": {"type": "string", "enum": ["inbox", "sent"], "default": "inbox"},
        "since": {"type": "string", "format": "date-time"},
        "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10},
    },
    "required": ["query"],
}

EMAIL_READ_SCHEMA = {
    "type": "object",
    "properties": {
        "message_id": {"type": "string", "description": "Message id from email.search."},
    },
    "required": ["message_id"],
}

EMAIL_SEND_SCHEMA = {
    "type": "object",
    "properties": {
        "to": {"type": "array", "items": {"type": "string", "format": "email"}, "minItems": 1},
        "cc": {"type": "array", "items": {"type": "string", "format": "email"}},
        "bcc": {"type": "array", "items": {"type": "string", "format": "email"}},
        "subject": {"type": "string", "maxLength": 200},
        "body": {"type": "string", "maxLength": 100000},
    },
    "required": ["to", "subject", "body"],
}

EMAIL_DRAFT_SCHEMA = {
    "type": "object",
    "properties": {
        "to": {"type": "array", "items": {"type": "string", "format": "email"}, "minItems": 1},
        "subject": {"type": "string", "maxLength": 200},
        "body": {"type": "string", "maxLength": 100000},
    },
    "required": ["to", "subject", "body"],
}

EMAIL_SETTINGS_READ_SCHEMA = {
    "type": "object",
    "properties": {
        "section": {"type": "string", "enum": ["forwarding", "filters", "all"], "default": "all"},
    },
}

EMAIL_SETTINGS_WRITE_SCHEMA = {
    "type": "object",
    "properties": {
        "section": {"type": "string", "enum": ["forwarding", "filters", "recovery_address"]},
        "settings": {"type": "object", "description": "New settings for the section."},
    },
    "required": ["section", "settings"],
}


class EmailConnector(Connector):
    name = "email"

    def __init__(self, upstream: MockGmail | None = None):
        self.upstream = upstream or MockGmail()
        # The mock records the last derived-token material it saw so
        # tests can assert the adapter (and only the adapter) handled it.
        self.last_token_seen: str | None = None

    # -- adapter-internal token handling (FR-012b) --------------------

    def _token(self, ctx: Any) -> str:
        """Read the derived token INSIDE the adapter.

        Never called outside this module; the raw material never crosses
        the agent boundary.
        """
        token = ctx.derived_token.raw() if ctx.derived_token is not None else ""
        self.last_token_seen = token
        return token

    # -- handlers ------------------------------------------------------

    def _search(self, ctx: Any, args: dict[str, Any]) -> Any:
        self._token(ctx)
        return {
            "messages": self.upstream.search(
                query=args["query"],
                mailbox=args.get("mailbox", "inbox"),
                since=args.get("since"),
                limit=args.get("limit", 10),
            )
        }

    def _read(self, ctx: Any, args: dict[str, Any]) -> Any:
        self._token(ctx)
        return self.upstream.read(args["message_id"])

    def _send(self, ctx: Any, args: dict[str, Any]) -> Any:
        token = self._token(ctx)
        return self.upstream.send(
            to=args["to"],
            subject=args["subject"],
            body=args["body"],
            cc=args.get("cc"),
            bcc=args.get("bcc"),
            token=token,
        )

    def _draft(self, ctx: Any, args: dict[str, Any]) -> Any:
        token = self._token(ctx)
        return self.upstream.draft(
            to=args["to"], subject=args["subject"], body=args["body"], token=token
        )

    def _settings_read(self, ctx: Any, args: dict[str, Any]) -> Any:
        self._token(ctx)
        return {"settings": self.upstream.settings_read(args.get("section", "all"))}

    def _settings_write(self, ctx: Any, args: dict[str, Any]) -> Any:
        token = self._token(ctx)
        return self.upstream.settings_write(
            args["section"], args["settings"], token=token
        )

    # -- Connector interface --------------------------------------------

    @property
    def tools(self) -> list[ToolDescriptor]:
        def bind(fn: Callable[[Any, dict[str, Any]], Any]) -> Callable[[Any, dict[str, Any]], Any]:
            return lambda ctx, args: fn(ctx, args)

        return [
            ToolDescriptor(
                name="email.search",
                description="Search the mailbox. Returns message metadata and snippets, not full bodies.",
                input_schema=EMAIL_SEARCH_SCHEMA,
                sensitivity="routine",
                handler=bind(self._search),
            ),
            ToolDescriptor(
                name="email.read",
                description="Read a full message by id.",
                input_schema=EMAIL_READ_SCHEMA,
                sensitivity="routine",
                handler=bind(self._read),
            ),
            ToolDescriptor(
                name="email.send",
                description="SENSITIVE: Send an email. Execution pauses for human approval in the admin console.",
                input_schema=EMAIL_SEND_SCHEMA,
                sensitivity="sensitive",
                handler=bind(self._send),
            ),
            ToolDescriptor(
                name="email.draft",
                description="Create an email draft. Routine. Sending the draft always requires its own step-up approval (email.send).",
                input_schema=EMAIL_DRAFT_SCHEMA,
                sensitivity="routine",
                handler=bind(self._draft),
            ),
            ToolDescriptor(
                name="email.settings.read",
                description="Read mailbox recovery-relevant settings (forwarding addresses, filter rules). Read-only; for console review (FR-PAA02-005).",
                input_schema=EMAIL_SETTINGS_READ_SCHEMA,
                sensitivity="routine",
                handler=bind(self._settings_read),
            ),
            ToolDescriptor(
                name="email.settings.write",
                description="SENSITIVE: Change mailbox recovery-relevant settings (forwarding, filter rules, recovery address). Execution pauses for human approval in the admin console (protected flow, FR-PAA02-002/003).",
                input_schema=EMAIL_SETTINGS_WRITE_SCHEMA,
                sensitivity="sensitive",
                handler=bind(self._settings_write),
            ),
        ]

    @property
    def upstream_scopes(self) -> list[str]:
        return ["gmail.readonly", "gmail.send", "gmail.settings.basic"]

    def health_check(self) -> HealthStatus:
        # Mock upstream: no credential to validate, no network to reach.
        # The check shape (credential-valid + API-reachable) is fixed so
        # the real adapter later only swaps the probes.
        return HealthStatus(
            connector=self.name,
            credential_valid=True,
            api_reachable=True,
            detail="mock upstream: in-memory MockGmail",
        )

    def ssrf_checklist(self) -> dict[str, Any]:
        return {
            "egress_allowlist": True,
            "no_open_url_fetch": True,
            "metadata_endpoints_blocked": True,
            "no_credentials_in_args": True,
            "notes": (
                "Mock-only adapter: in-process MockGmail, no network egress, "
                "no tool accepts a URL parameter, no HTTP client exists to "
                "reach cloud-metadata endpoints, no tool accepts credentials "
                "(02 §2.4)."
            ),
        }
