"""Code-host connector (FR-007): GitHub adapter over the in-memory mock.

Tools (02 §2.2): code.file.read (routine), code.pr.open (sensitive —
write action, sensitive-gated from day one per OQ-7), codehost.issue_open
(sensitive — Pillar 2: red-team finding filing, approval-gated).

NO code.pr.merge: deferred out of MVP until the approval loop proves
itself on email.send (00 §3). There is deliberately no merge tool to
register.

Derived-token handling follows the email connector: ``raw()`` is
called only inside this adapter (FR-012b).
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from ..pipeline import ToolDescriptor
from .base import Connector, HealthStatus
from .issue_store import IssueOpener, LocalIssueStore
from .mock_upstream import MockGitHub

CODE_FILE_READ_SCHEMA = {
    "type": "object",
    "properties": {
        "repo": {"type": "string", "description": "owner/name"},
        "path": {"type": "string"},
        "ref": {"type": "string", "default": "HEAD"},
    },
    "required": ["repo", "path"],
}

CODE_PR_OPEN_SCHEMA = {
    "type": "object",
    "properties": {
        "repo": {"type": "string", "description": "owner/name"},
        "title": {"type": "string"},
        "head": {"type": "string"},
        "base": {"type": "string"},
        "body": {"type": "string"},
    },
    "required": ["repo", "title", "head", "base"],
}

CODEHOST_ISSUE_OPEN_SCHEMA = {
    "type": "object",
    "properties": {
        "repo": {"type": "string", "description": "owner/name"},
        "title": {"type": "string", "maxLength": 256},
        "body": {"type": "string", "maxLength": 20000},
        "labels": {"type": "array", "items": {"type": "string"}, "maxItems": 16},
    },
    "required": ["repo", "title", "body"],
    "additionalProperties": False,
}


class CodeHostConnector(Connector):
    name = "code"

    def __init__(
        self,
        upstream: MockGitHub | None = None,
        issue_opener: Optional[IssueOpener] = None,
    ):
        self.upstream = upstream or MockGitHub()
        # Pillar 2 §3.5: the issue opener backing codehost.issue_open.
        # Defaults to the safe local file store; the GitHub backend
        # raises a fail-closed config error until implemented.
        self.issue_opener: IssueOpener = issue_opener or LocalIssueStore("data/issues")
        self.last_token_seen: str | None = None

    def _token(self, ctx: Any) -> str:
        """Read the derived token INSIDE the adapter (FR-012b)."""
        token = ctx.derived_token.raw() if ctx.derived_token is not None else ""
        self.last_token_seen = token
        return token

    # -- handlers ------------------------------------------------------

    def _file_read(self, ctx: Any, args: dict[str, Any]) -> Any:
        self._token(ctx)
        return self.upstream.file_read(
            repo=args["repo"], path=args["path"], ref=args.get("ref", "HEAD")
        )

    def _pr_open(self, ctx: Any, args: dict[str, Any]) -> Any:
        token = self._token(ctx)
        return self.upstream.pr_open(
            repo=args["repo"],
            title=args["title"],
            head=args["head"],
            base=args["base"],
            body=args.get("body", ""),
            token=token,
        )

    def _issue_open(self, ctx: Any, args: dict[str, Any]) -> Any:
        self._token(ctx)
        # Pillar 2 §3.5: sensitive-gated — the pipeline pauses for
        # human approval before this handler runs (approval-per-issue,
        # the default). The pre-file redaction gate runs in the
        # agent's filing pipeline BEFORE this call, identically for
        # both backends.
        ref = self.issue_opener.open_issue(
            repo=args["repo"],
            title=args["title"],
            body=args["body"],
            labels=list(args.get("labels") or []),
        )
        return {
            "issue_id": ref.id,
            "url": ref.url,
            "dedupe_key": ref.dedupe_key,
            "state": ref.state,
        }

    # -- Connector interface --------------------------------------------

    @property
    def tools(self) -> list[ToolDescriptor]:
        def bind(fn: Callable[[Any, dict[str, Any]], Any]) -> Callable[[Any, dict[str, Any]], Any]:
            return lambda ctx, args: fn(ctx, args)

        return [
            ToolDescriptor(
                name="code.file.read",
                description="Read a file from a repository at a ref (branch, tag, or commit).",
                input_schema=CODE_FILE_READ_SCHEMA,
                sensitivity="routine",
                handler=bind(self._file_read),
            ),
            ToolDescriptor(
                name="code.pr.open",
                description="SENSITIVE: Open a pull request. Execution pauses for human approval in the admin console.",
                input_schema=CODE_PR_OPEN_SCHEMA,
                sensitivity="sensitive",
                handler=bind(self._pr_open),
            ),
        ]

    @property
    def issue_tools(self) -> list[ToolDescriptor]:
        """The ``codehost.*`` namespace (Pillar 2): filed under its own
        connector name so the ``<connector>.<action>`` naming rule
        (02 §2.1) holds — ``codehost.issue_open``, not ``code.issue_open``."""
        return [
            ToolDescriptor(
                name="codehost.issue_open",
                description=(
                    "SENSITIVE: File an issue (red-team findings). Execution "
                    "pauses for human approval in the admin console "
                    "(approval-per-issue, the default)."
                ),
                input_schema=CODEHOST_ISSUE_OPEN_SCHEMA,
                sensitivity="sensitive",
                handler=lambda ctx, args: self._issue_open(ctx, args),
            ),
        ]

    def register(self, registry: Any) -> None:
        """Register ``code.*`` tools plus the ``codehost.*`` namespace."""
        super().register(registry)
        registry.register("codehost", self.issue_tools)

    @property
    def upstream_scopes(self) -> list[str]:
        return ["repo:read", "pull_requests:write"]

    def health_check(self) -> HealthStatus:
        return HealthStatus(
            connector=self.name,
            credential_valid=True,
            api_reachable=True,
            detail="mock upstream: in-memory MockGitHub",
        )

    def ssrf_checklist(self) -> dict[str, Any]:
        return {
            "egress_allowlist": True,
            "no_open_url_fetch": True,
            "metadata_endpoints_blocked": True,
            "no_credentials_in_args": True,
            "notes": (
                "Mock-only adapter: in-process MockGitHub, no network egress. "
                "No tool accepts a repository URL — only owner/name strings "
                "resolved against the mock, so there is no open-ended fetch. "
                "No HTTP client exists to reach cloud-metadata endpoints; no "
                "tool accepts credentials (02 §2.4)."
            ),
        }
