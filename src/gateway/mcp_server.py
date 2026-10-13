"""MCP server (Streamable HTTP) for the Personal Agent Security Gateway.

M1 scope:
- FastMCP app served over Streamable HTTP at ``/mcp`` (M0-verified path).
- Auth middleware REJECTS unauthenticated ``initialize`` / ``tools/list``
  / ``tools/call`` with ``auth_failed`` (02 §2.1). Public exceptions are
  ONLY the OAuth 2.1 discovery/metadata/authorization/JWKS endpoints —
  those arrive with the gateway-as-authorization-server build (later
  milestone); M1 has no other public surface.
- Tools are registered dynamically from the ConnectorRegistry (W2's
  interface); each call runs the Fix-B pipeline.
- ``no_proxy``/``NO_PROXY`` is sanitized at startup BEFORE any FastMCP
  import touches the network stack (M0 environment quirk: FastMCP 4.x
  vendors httpx2, whose no_proxy parsing raises InvalidURL on bracketed
  IPv6 entries).

M1 credential transport contract (per-agent secret over TLS; no third
rung — Fix A):
- OAuth client credentials: ``Authorization: Basic base64(client_id:client_secret)``
- Conditional fallback bearer: ``Authorization: Bearer <key_id>.<raw_token>``

The gateway-as-OAuth-authorization-server code exchange (mock_oauth.py
covers the shape for tests) and the per-platform OAuth spikes (OQ-1/OQ-3)
are Ken's actions; M1 authenticates the per-agent secret at the transport
edge on EVERY request — the session ID alone never suffices (03 §3.1).
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# 0. Sanitize no_proxy/NO_PROXY FIRST (M0 quirk). Must run before any
# FastMCP/httpx2 import touches the network stack: bracketed IPv6 entries
# ([::1], [fd8b:...]) in this sandbox's NO_PROXY make httpx2 raise
# InvalidURL. Drop bracketed entries; keep the rest.
# ---------------------------------------------------------------------------

import os as _os


def _sanitize_no_proxy() -> None:
    for var in ("no_proxy", "NO_PROXY"):
        raw = _os.environ.get(var)
        if not raw:
            continue
        kept = [p for p in raw.split(",") if p.strip() and not p.strip().startswith("[")]
        if kept:
            _os.environ[var] = ",".join(kept)
        else:
            _os.environ.pop(var, None)


_sanitize_no_proxy()

# ---------------------------------------------------------------------------
# Normal imports (safe after the sanitize above).
# ---------------------------------------------------------------------------

import asyncio
import base64
import binascii
import json
from typing import Any, Callable, Optional

import uvicorn
from mcp.types import TextContent
from sqlalchemy.orm import Session
from starlette.responses import JSONResponse
from starlette.routing import Route

from fastmcp import FastMCP
from fastmcp.server.middleware import Middleware
from fastmcp.tools.base import ToolResult
from fastmcp.tools.function_tool import FunctionTool

from .config import Settings, load_settings
from .db import Databases
from .errors import make_error
from .hmac_util import HmacKeyRing
from .identity import IdentityService
from .pipeline import (
    ConnectorRegistry,
    _pending_credential,
    _validated_auth,
    bind_request_auth,
    build_m1_pipeline,  # kept for M1-compat; the live path uses build_pipeline
    build_pipeline,  # M2: minimal validator + real policy engine; M3: + approval flow
    clear_request_auth,
)


# ---------------------------------------------------------------------------
# Credential transport
# ---------------------------------------------------------------------------

def parse_authorization_header(value: str) -> Optional[tuple[str, str, str]]:
    """Parse the M1 credential transport contract.

    Returns (kind, identifier, secret) where kind is "oauth" or
    "fallback_bearer", or None when the header is missing/unparseable.
    """
    if not value:
        return None
    scheme, _, rest = value.partition(" ")
    scheme = scheme.strip().lower()
    rest = rest.strip()
    if scheme == "basic" and rest:
        try:
            decoded = base64.b64decode(rest, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            return None
        client_id, sep, client_secret = decoded.partition(":")
        if not sep or not client_id or not client_secret:
            return None
        return ("oauth", client_id, client_secret)
    if scheme == "bearer" and rest:
        key_id, sep, token = rest.partition(".")
        if not sep or not key_id or not token:
            return None
        return ("fallback_bearer", key_id, token)
    return None


class CredentialExtractionMiddleware:
    """Pure-ASGI layer: extracts the Authorization header per HTTP
    request and stashes the parsed credential in a contextvar for the
    FastMCP auth middleware to validate. Non-HTTP scopes pass through."""

    def __init__(self, app: Callable) -> None:
        self.app = app

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        headers = {k.lower(): v for k, v in scope.get("headers", [])}
        raw = headers.get(b"authorization", b"").decode("latin-1")
        parsed = parse_authorization_header(raw)
        token = _pending_credential.set(parsed)
        try:
            await self.app(scope, receive, send)
        finally:
            _pending_credential.reset(token)


class AuthFailedError(Exception):
    """Raised to reject initialize/tools-list without a valid credential."""

    def __init__(self, envelope_text: str) -> None:
        super().__init__(envelope_text)
        self.envelope_text = envelope_text


class GatewayAuthMiddleware(Middleware):
    """Fix-A auth at the transport edge (02 §2.1).

    Validates the presented per-agent secret on EVERY initialize /
    tools/list / tools/call request (03 §3.1 — the session ID alone
    never suffices) via IdentityService (bcrypt + lifecycle state), and
    binds the AuthResult for the pipeline's AuthenticateStage (exactly
    one credential validation per request).
    """

    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory

    def _validate_current_request(self) -> tuple[str, Any]:
        """Parse + validate. Returns (agent_id, AuthResult). Raises
        AuthFailedError carrying the auth_failed envelope."""
        from .ids import new_request_id

        req_id = new_request_id()

        def _fail(msg: str) -> AuthFailedError:
            return AuthFailedError(
                make_error("auth_failed", msg, req_id, {"tool": "(handshake)"}).to_text()
            )

        parsed = _pending_credential.get()
        if parsed is None:
            raise _fail("missing or malformed Authorization header")
        _kind, identifier, secret = parsed
        with self._session_factory() as db:
            identity = IdentityService(db)
            agent_id = identity.find_agent_id_by_credential_identifier(identifier)
            if agent_id is None:
                raise _fail("unknown credential")
            try:
                result = identity.authenticate(agent_id, secret)
            except ValueError as exc:
                code = str(exc)
                if code == "agent_revoked":
                    raise AuthFailedError(
                        make_error("agent_revoked", "agent identity revoked", req_id).to_text()
                    ) from None
                if code == "agent_paused":
                    raise AuthFailedError(
                        make_error("agent_paused", "agent is paused", req_id).to_text()
                    ) from None
                if code == "agent_canceled":
                    raise AuthFailedError(
                        make_error("agent_canceled", "agent work was canceled", req_id).to_text()
                    ) from None
                raise _fail("agent authentication failed") from None
            # Detach so the pipeline can use the identity after close.
            db.expunge(result.agent)
            return agent_id, result

    async def _guard(self, context: Any, call_next: Any) -> Any:
        try:
            agent_id, result = await asyncio.to_thread(self._validate_current_request)
        except AuthFailedError:
            raise
        except Exception as exc:  # noqa: BLE001 — fail closed on unexpected errors
            from .ids import new_request_id

            raise AuthFailedError(
                make_error(
                    "auth_failed", "authentication error", new_request_id()
                ).to_text()
            ) from exc
        bind_request_auth(agent_id, result)
        try:
            return await call_next(context)
        finally:
            clear_request_auth()

    async def on_initialize(self, context: Any, call_next: Any) -> Any:
        return await self._guard(context, call_next)

    async def on_list_tools(self, context: Any, call_next: Any) -> Any:
        return await self._guard(context, call_next)

    async def _auth_failed_tool_result(self, envelope_text: str) -> ToolResult:
        return ToolResult(
            content=[TextContent(type="text", text=envelope_text)],
            is_error=True,
        )

    async def on_call_tool(self, context: Any, call_next: Any) -> Any:
        """For tools/call the rejection uses the spec's error envelope
        (isError: true with the JSON payload in content[0].text, 02 §2.7)."""
        try:
            agent_id, result = await asyncio.to_thread(self._validate_current_request)
        except AuthFailedError as exc:
            return await self._auth_failed_tool_result(exc.envelope_text)
        except Exception:  # noqa: BLE001 — fail closed
            from .ids import new_request_id

            return await self._auth_failed_tool_result(
                make_error("auth_failed", "authentication error", new_request_id()).to_text()
            )
        bind_request_auth(agent_id, result)
        try:
            return await call_next(context)
        finally:
            clear_request_auth()


# ---------------------------------------------------------------------------
# App assembly
# ---------------------------------------------------------------------------

def _make_tool_fn(
    tool_name: str,
    registry: ConnectorRegistry,
    settings: Settings,
    hmac_ring: Optional[HmacKeyRing],
    config_session_factory: Callable[[], Session],
    audit_session_factory: Callable[[], Session],
) -> Callable:
    async def _gateway_tool(**kwargs: Any) -> ToolResult:
        bound = _validated_auth.get()
        if bound is None:
            # Unreachable: GatewayAuthMiddleware guards every tools/call.
            # Fail closed with the envelope anyway.
            from .ids import new_request_id

            err = make_error(
                "auth_failed", "missing request authentication", new_request_id()
            )
            return ToolResult(
                content=[TextContent(type="text", text=err.to_text())], is_error=True
            )
        agent_id, _ = bound
        # Per-call pipeline with fresh sessions; the shared registry
        # carries W2's tool registrations. AuthenticateStage adopts the
        # middleware's per-request validation (no second bcrypt).
        with config_session_factory() as config_db, audit_session_factory() as audit_db:
            # M3: the live path runs the full Fix-B approval flow when
            # the HMAC ring is configured (keyed argument hashing is
            # load-bearing for dedupe/grants). Without it the gateway
            # degrades to the M2 halt-at-policy shape and warns — no
            # approval request is ever created without keyed hashing.
            use_approvals = hmac_ring is not None
            if not use_approvals:
                import warnings

                warnings.warn(
                    "gateway: GATEWAY_HMAC_KEY not configured — approval "
                    "flow disabled (M2 shape); sensitive calls cannot "
                    "complete the approval loop"
                )
            pipeline, _, _ = build_pipeline(
                config_db, audit_db, settings, hmac_ring, registry=registry,
                approvals=use_approvals,
            )
            outcome = pipeline.execute(agent_id, tool_name, dict(kwargs))
        if outcome.error is not None:
            return ToolResult(
                content=[TextContent(type="text", text=outcome.error.to_text())],
                is_error=True,
            )
        return ToolResult(
            content=[
                TextContent(
                    type="text",
                    text=json.dumps(outcome.context.result, default=str, ensure_ascii=True),
                )
            ]
        )

    _gateway_tool.__name__ = f"gateway_tool_{tool_name.replace('.', '_')}"
    return _gateway_tool


class GatewayApp:
    """Assembled gateway: databases, pipeline, registry, FastMCP app."""

    def __init__(self, settings: Optional[Settings] = None) -> None:
        self.settings = settings or load_settings()
        problems = self.settings.validate()
        if problems:
            # M1: HMAC key missing is the expected local-dev gap; warn,
            # don't crash (the key is required for approval hashing in M3).
            import warnings

            for p in problems:
                warnings.warn(f"gateway config: {p}")
        self.databases = Databases(self.settings.config_db_path, self.settings.audit_db_path)
        self.databases.create_all()

        # Shared connector registry (W2's registration point). The MCP
        # server builds one pipeline per tool call with fresh DB
        # sessions, all sharing this registry.
        self.registry = ConnectorRegistry()
        self.hmac_ring: Optional[HmacKeyRing] = None
        if self.settings.hmac_key:
            self.hmac_ring = HmacKeyRing.from_env_string(
                self.settings.hmac_key_id, self.settings.hmac_key
            )

        self.mcp = FastMCP(
            "agent-security-gateway",
            middleware=[GatewayAuthMiddleware(self.databases.config.session)],
        )

        # M3: the agent-visible meta tool (02 §2.5) — registered on both
        # the pipeline registry and the MCP surface via the same path
        # as connector tools (FR-009). Caller-bound, own rate budget
        # (enforced by the pipeline's validate-stage rate limiter),
        # audit carve-out (02 §2.5).
        # Runtime import: approvals.py is imported by pipeline clients
        # in orders that forbid a top-level import here.
        from .approvals import make_approval_status_tool

        self.register_connector_tools(
            "gateway",
            [
                make_approval_status_tool(
                    config_session_factory=self.databases.config.session,
                    audit_session_factory=self.databases.audit.session,
                    settings=self.settings,
                    hmac_ring=self.hmac_ring,
                )
            ],
        )

        # Demo connector (docker-compose one-command demo only). Default
        # OFF: enabled explicitly via GATEWAY_DEMO_TOOLS=1. Registers
        # demo.read (seeded allow rule) and demo.write (default-deny)
        # so the smoke test can assert one ALLOW and one DENY through
        # the real MCP endpoint. Never enable in production.
        if _os.environ.get("GATEWAY_DEMO_TOOLS") == "1":
            from .demo_tools import make_demo_tools

            self.register_connector_tools("demo", make_demo_tools())

    def _register_tool_on_mcp(self, d: Any) -> None:
        self.mcp.add_tool(
            FunctionTool(
                name=d.name,
                description=d.description,
                parameters=d.input_schema,
                fn=_make_tool_fn(
                    d.name,
                    self.registry,
                    self.settings,
                    self.hmac_ring,
                    self.databases.config.session,
                    self.databases.audit.session,
                ),
            )
        )

    # -- W2's registration point -----------------------------------------
    def register_connector_tools(self, connector: str, tools: list) -> None:
        """Register connector tools on BOTH the pipeline registry and the
        MCP surface (FR-009). W2 calls this per connector."""
        self.registry.register(connector, tools)
        for d in tools:
            self._register_tool_on_mcp(d)

    # -- test/operator seams ------------------------------------------------
    def new_config_session(self) -> Session:
        return self.databases.config.session()

    def new_audit_session(self) -> Session:
        return self.databases.audit.session()

    # -- ASGI ---------------------------------------------------------------
    def http_app(self, path: str = "/mcp"):
        """Starlette app: Streamable HTTP at *path*, /healthz, and the
        credential-extraction ASGI layer outside FastMCP."""
        app = self.mcp.http_app(path=path)

        async def healthz(_request: Any) -> JSONResponse:
            return JSONResponse({"status": "ok", "service": "agent-security-gateway"})

        app.routes.append(Route("/healthz", healthz))
        return CredentialExtractionMiddleware(app)


def main() -> None:
    settings = load_settings()
    gateway = GatewayApp(settings)
    uvicorn.run(
        gateway.http_app(),
        host=settings.host,
        port=settings.port,
        log_level="info",
    )


if __name__ == "__main__":
    main()
