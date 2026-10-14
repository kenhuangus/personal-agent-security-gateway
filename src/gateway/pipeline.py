"""The tool-call pipeline skeleton (03 §1.2, Fix-B order).

Fix-B order (never reordered):
    authenticate → validate inputs → check mandate liveness →
    evaluate policy → approval → mint token → execute →
    inspect output → audit

Each stage is an injectable callable with a documented signature, so
later milestones replace stubs without touching the order:

- M1 wires: authenticate, mandate, audit. (This milestone.)
- M2 (policy engine): replaces the default-deny ``PolicyStage`` stub.
- M3 (approval workflow): replaces the no-op ``ApprovalStage`` stub
  with the full Fix-B flow (validate-first, dedupe, cooldowns, cap,
  evidence subset, grant-before-rule, atomic consumption).
- M5 (inspection): hardened ``ValidateInputsStage`` in place and the
  real ``InspectOutputStage`` (``gateway.inspection``) — injection
  scan + redaction + leakage flags. DONE.
- W2 (connectors): registers tools via ``ConnectorRegistry.register``;
  the ``ExecuteStage`` dispatches to them.
- W3/M4 (vault): ``VaultTokenMinter`` (gateway.vault) replaces
  ``StubTokenMinter`` via the ``minter`` parameter of
  ``build_m1_pipeline``; mint failures fail closed to
  ``upstream_failure`` (03 §7).

The pipeline also ships a gateway-internal timing-span helper for
AC-11 (gateway-internal spans; adapter upstream timer subtracted).
"""

from __future__ import annotations

import contextvars
import logging
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator, Optional, Protocol

from sqlalchemy.orm import Session

from .audit import AuditLog
from .config import Settings
from .errors import GatewayError, SAFE_REASONS, ToolHalt, invalid_input, make_error, policy_denied
from .hmac_util import HmacKeyRing, argument_hash
from .ids import new_request_id
from .identity import IdentityService
from .inspection.output import InspectOutputStage, InspectionConfig
from .latency import record
from .inspection.rate_limit import RateLimiter
from .inspection.redaction import RedactionCatalog, redact_ctx_for_audit
from .inspection.urgency_flags import scan_trigger_content
from .inspection.validation import (
    canonicalize_args,
    check_json_limits,
    find_control_chars,
    validate_against_schema,
)
from .mandates import MandateService
from .models import Agent, Mandate

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------
# Request-scoped auth binding.
#
# The MCP server's auth middleware validates the presented credential
# on EVERY request (Fix A; 03 §3.1 — the session ID alone never
# suffices) and binds the resulting AuthResult here for the duration
# of the request. AuthenticateStage adopts it instead of re-validating,
# so there is exactly one credential validation per request.
# Direct pipeline users (tests, console) present via
# AuthenticateStage.presented and get the full validation there.
# ---------------------------------------------------------------------

from contextvars import ContextVar

from .identity import AuthResult as _AuthResult  # noqa: E402  (re-export for the server)

_validated_auth: ContextVar[tuple[str, _AuthResult] | None] = ContextVar(
    "gateway_validated_auth", default=None
)

# Raw parsed credential, set by the ASGI extraction layer before the
# FastMCP middleware validates it: (scheme, identifier, secret).
_pending_credential: ContextVar[tuple[str, str, str] | None] = ContextVar(
    "gateway_pending_credential", default=None
)


def bind_request_auth(agent_id: str, result: _AuthResult) -> None:
    _validated_auth.set((agent_id, result))


def clear_request_auth() -> None:
    _validated_auth.set(None)


# ---------------------------------------------------------------------
# Timing spans (AC-11): gateway-internal overhead, isolated from
# downstream latency. The adapter's upstream-call timer is subtracted
# from end-to-end timing at measurement time.
# ---------------------------------------------------------------------

@contextmanager
def timing_span(ctx: "CallContext", name: str) -> Iterator[None]:
    """Record a gateway-internal timing span on the call context."""
    start = time.perf_counter()
    try:
        yield
    finally:
        ctx.spans[name] = (time.perf_counter() - start) * 1000.0  # ms


# ---------------------------------------------------------------------
# Call context
# ---------------------------------------------------------------------

@dataclass
class CallContext:
    request_id: str = field(default_factory=new_request_id)
    agent_id: str = ""
    tool: str = ""
    args: dict[str, Any] = field(default_factory=dict)  # raw args: NEVER stored/audited
    agent: Optional[Agent] = None
    credential_kind: Optional[str] = None
    mandate: Optional[Mandate] = None
    redacted_args: Optional[dict[str, Any]] = None
    decision: Optional[str] = None
    deny_reason: Optional[str] = None  # safe-vocabulary reason when halted by denial
    result: Any = None
    derived_token: Optional["DerivedToken"] = None
    spans: dict[str, float] = field(default_factory=dict)
    policy_version: int = 1
    # The scope rule that authorized the call (FR-PAA01-007), set by the
    # M2 PolicyStage; the audit stage writes it to the row.
    scope_rule: Optional[str] = None
    # OPA pivot: input-document versioning — the fingerprint of the
    # policy data behind the decision ("pv<N>/rules:<sha>/ont:<sha>").
    # Set by the PolicyStage; the audit row carries it additively.
    data_snapshot_id: Optional[str] = None
    # PAA04: the content-addressed ontology decision-snapshot ref,
    # set by the PolicyStage when the ontology shaped the decision.
    ontology_snapshot_ref: Optional[str] = None
    # The ontology entry that decided a deny/ask
    # ({"entry_id", "entry_kind", "snapshot_ref"}); copied into
    # policy_denied details and available for the approval record.
    ontology_ref: Optional[dict[str, Any]] = None
    # -- M3 approval flow ------------------------------------------------
    # Set by the policy stage when the call requires step-up approval;
    # the ApprovalStage (step 5) then runs the 02 §2.8 lookup chain.
    needs_approval: bool = False
    # Set when the call was authorized by a consumed one-time grant
    # (allowed_via_approval); the audit decision reflects it.
    via_grant: bool = False
    # The apr_ id: set when the approval request is created (paused
    # call row) and when a grant authorizes execution. Links the three
    # audit rows (paused call → decision → executed call).
    approval_request_id: Optional[str] = None
    # Counterparty escalation reason (new_payee / changed_details) when
    # the sensitivity escalator fired (FR-PAA05-002).
    escalation_reason: Optional[str] = None
    # HMAC-SHA256 of the canonical args (02 §2.8 step 3), computed once
    # per call when the HMAC ring is configured. The dedupe/grant/
    # cooldown key; None when no ring is configured (approval flow
    # refuses to run without it — fail closed).
    argument_hash: Optional[str] = None
    # Snapshot of the raw args taken before the M5 pre-audit redaction
    # hook rebinds ctx.args (NFR-DATA-001). The counterparty hook
    # (FR-PAA05-001) needs the plaintext payee key; the audit row
    # itself keeps the redacted args.
    raw_args: dict[str, Any] = field(default_factory=dict)
    # gateway.approval_status (02 §2.5 carve-out): the handler writes
    # its own audit rows for denied/expired/not-found outcomes and
    # sets this so the terminal audit stage writes nothing for the
    # exempt routine polls.
    skip_audit: bool = False
    # M5 inspection state.
    # Urgency flags from the trigger-content scan (FR-PAA09-002),
    # computed in validate_inputs so the approval card (step 5) can
    # surface them via urgency_flags_for_approval_record().
    urgency_flags: list[dict[str, str]] = field(default_factory=list)
    # Free-form notes from output inspection (e.g. the leakage report's
    # flagged/unlabeled counts); observability only.
    inspection_notes: dict[str, Any] = field(default_factory=dict)
    # Judge advisory state (gateway.judge; default OFF).
    # judge_risk: the RiskScore when the intent risk scorer stepped an
    # allowed call up to approval (allow→ask); rides to the approval
    # record/card via judge_risk_for_approval_record(). Never set on
    # deny/require_approval paths.
    judge_risk: Optional[Any] = None
    # judge_counterparty_signals: advisory urgency/impersonation
    # signals for the approval record's counterparty evidence
    # (judge_signals_for_approval_record()); deterministic flags and
    # the escalator are unchanged.
    judge_counterparty_signals: Optional[dict[str, Any]] = None


@dataclass(frozen=True)
class DerivedToken:
    """Layer-2 derived call token handle (FR-012b).

    Server-side only: short-lived, scoped to (agent, tool, action),
    consumed by the connector adapter inside the gateway, never exposed
    to the agent in raw form. The raw token material (if any) lives
    only here; ``repr`` never shows it. W3's vault-backed minter
    produces these.
    """

    agent_id: str
    tool: str
    action: str
    expires_at_epoch: float
    _material: str = field(default="", repr=False)

    def raw(self) -> str:
        """Adapter-internal use only. Never crosses the agent boundary."""
        return self._material


# ---------------------------------------------------------------------
# Connector registry (W2's registration point)
# ---------------------------------------------------------------------

@dataclass(frozen=True)
class ToolDescriptor:
    """One tool declared by a connector (FR-008)."""

    name: str  # "<connector>.<action>", lowercase (02 §2.1)
    description: str
    input_schema: dict[str, Any]  # JSON Schema draft 2020-12
    sensitivity: str  # "routine" | "sensitive" | "conditional"
    # The tool handler: receives (ctx, args) and returns the raw result.
    # W2 implements these per connector. Handlers run INSIDE the gateway
    # with the derived token on ctx.
    handler: Callable[["CallContext", dict[str, Any]], Any]


class ConnectorRegistry:
    """Plugin interface (FR-009): new connectors register tools here
    without touching the MCP endpoint or the policy engine.

    W2 usage:
        registry.register("email", [
            ToolDescriptor(name="email.search", description=..., input_schema=...,
                           sensitivity="routine", handler=email_search),
            ...
        ])
    """

    def __init__(self) -> None:
        self._tools: dict[str, ToolDescriptor] = {}

    def register(self, connector: str, tools: list[ToolDescriptor]) -> None:
        for t in tools:
            if not t.name.startswith(f"{connector}."):
                raise ValueError(
                    f"tool {t.name!r} does not belong to connector {connector!r} "
                    "(02 §2.1 naming)"
                )
            if t.sensitivity not in ("routine", "sensitive", "conditional"):
                raise ValueError(f"tool {t.name!r}: bad sensitivity {t.sensitivity!r}")
            if t.name in self._tools:
                raise ValueError(f"tool {t.name!r} already registered")
            self._tools[t.name] = t

    def get(self, name: str) -> Optional[ToolDescriptor]:
        return self._tools.get(name)

    def tool_names(self) -> list[str]:
        return sorted(self._tools)


# ---------------------------------------------------------------------
# Stage protocol
# ---------------------------------------------------------------------

class Stage(Protocol):
    """One pipeline stage.

    ``run`` mutates the CallContext and returns:
    - ``None`` → continue to the next stage;
    - a ``GatewayError`` → halt the pipeline; the pipeline audits the
      denial/error and returns the error envelope.
    """

    name: str

    def run(self, ctx: CallContext) -> Optional[GatewayError]: ...


# ---------------------------------------------------------------------
# M1 stages
# ---------------------------------------------------------------------

class AuthenticateStage:
    """Step 1: per-request credential validation (Fix A).

    Session ID alone never suffices (03 §3.1); the presented per-agent
    secret is validated on EVERY request. Lifecycle state is checked at
    entry with distinct codes (FR-PAA10-002/004).
    """

    name = "authenticate"

    def __init__(self, identity: IdentityService) -> None:
        self.identity = identity
        # agent_id -> presented secret. The transport delivers these;
        # M1 tests inject them directly. The MCP server (mcp_server.py)
        # extracts them from the request's Authorization header.
        self.presented: dict[str, str] = {}

    def run(self, ctx: CallContext) -> Optional[GatewayError]:
        # Adopt the middleware's per-request validation when present
        # (exactly one credential validation per request on the MCP path).
        bound = _validated_auth.get()
        if bound is not None:
            bound_agent_id, result = bound
            if bound_agent_id != ctx.agent_id:
                return make_error(
                    "auth_failed", "agent identity mismatch", ctx.request_id
                )
            ctx.agent = result.agent
            ctx.credential_kind = result.credential_kind
            return None
        secret = self.presented.get(ctx.agent_id, "")
        if not secret:
            return make_error(
                "auth_failed",
                "missing agent credential",
                ctx.request_id,
                {"tool": ctx.tool},
            )
        try:
            with timing_span(ctx, "authenticate"):
                result = self.identity.authenticate(ctx.agent_id, secret)
        except ValueError as exc:
            code = str(exc)
            if code == "agent_revoked":
                return make_error("agent_revoked", "agent identity revoked", ctx.request_id)
            if code == "agent_paused":
                return make_error("agent_paused", "agent is paused", ctx.request_id)
            if code == "agent_canceled":
                return make_error("agent_canceled", "agent work was canceled", ctx.request_id)
            if code == "fallback_bearer_expired":
                # GH #21: distinct code directing the admin to rotate the
                # fallback Bearer <redacted> (console agents page).
                return make_error(
                    "fallback_bearer_expired",
                    "fallback Bearer <redacted> exceeded max age — "
                    "rotate it in the admin console",
                    ctx.request_id,
                )
            return make_error("auth_failed", "agent authentication failed", ctx.request_id)
        ctx.agent = result.agent
        ctx.credential_kind = result.credential_kind
        return None


class ValidateInputsStage:
    """Step 2: hardened input validation (M5; was the M2 minimal hook).

    Order inside the stage: rate limit → schema validation (strict
    formats, ``additionalProperties`` honored where the schema opts
    in, per-tool ``pattern`` constraints) → control-character rejection
    → canonicalization before hashing → urgency-flag scan on the
    trigger content (FR-PAA09-002; computed HERE rather than in
    inspect_output because the approval card at step 5 needs the flags).

    Failure returns ``invalid_input`` (naming the field, never its
    value) and never creates an approval request (Fix B, MF-4).
    """

    name = "validate_inputs"

    def __init__(
        self,
        registry: ConnectorRegistry,
        rate_limiter: Optional[RateLimiter] = None,
    ) -> None:
        self.registry = registry
        self.rate_limiter = rate_limiter

    def run(self, ctx: CallContext) -> Optional[GatewayError]:
        with timing_span(ctx, "validate_inputs"):
            # Rate limit first: every attempt counts, valid or not.
            if self.rate_limiter is not None:
                with timing_span(ctx, "validate.rate_limit"):
                    limited = self.rate_limiter.check(
                        ctx.agent_id, ctx.tool, ctx.request_id
                    )
                if limited is not None:
                    return limited
            descriptor = self.registry.get(ctx.tool)
            if descriptor is None:
                # Unknown tool: no allow rule can exist → default-deny.
                return policy_denied(
                    ctx.request_id, "no_allow_rule",
                    f"{ctx.tool}: no such tool", tool=ctx.tool,
                )
            # GH #14: ingress bounds FIRST, before any recursive walk
            # over agent-supplied JSON (walk_strings, canonicalize_args,
            # the redaction/injection walkers). A bound violation is
            # invalid_input, never a RecursionError out of the pipeline.
            limit_violation = check_json_limits(ctx.args)
            if limit_violation is not None:
                log.warning(
                    "ingress bound violated (request_id=%s tool=%s): %s",
                    ctx.request_id, ctx.tool, limit_violation,
                )
                return invalid_input(ctx.request_id, "arguments", tool=ctx.tool)
            try:
                # Strict schema validation (RFC 3339 date-time, email,
                # additionalProperties, per-tool patterns).
                bad_field = validate_against_schema(
                    descriptor.input_schema, ctx.args
                )
                if bad_field is not None:
                    return invalid_input(ctx.request_id, bad_field, tool=ctx.tool)
                # Injection-oriented constraint: no control characters in
                # string fields.
                bad_field = find_control_chars(ctx.args)
                if bad_field is not None:
                    return invalid_input(ctx.request_id, bad_field, tool=ctx.tool)
                # Canonicalize in place: stable key order (+ integral-float
                # normalization) before the HMAC argument hash.
                ctx.args = canonicalize_args(ctx.args)
                # False-urgency / deceptive-relationship-claim flags for the
                # approval card (FR-PAA09-002). Stored on the context; M3's
                # approval service reads them via
                # urgency_flags_for_approval_record().
                with timing_span(ctx, "validate.urgency_scan"):
                    ctx.urgency_flags = scan_trigger_content(ctx.args)
            except Exception:  # noqa: BLE001 — GH #14: validators are total
                # Any validator failure (RecursionError on a pathological
                # payload that slipped the depth cap, a broken tool
                # schema, an urgency-scan bug) is invalid_input — never
                # an unaudited crash out of Pipeline.run.
                log.exception(
                    "validator failed (request_id=%s tool=%s); failing closed",
                    ctx.request_id, ctx.tool,
                )
                return invalid_input(ctx.request_id, "arguments", tool=ctx.tool)
        return None


class MandateStage:
    """Step 3: mandate-liveness check BEFORE any tool logic (FR-PAA01-002).

    Distinct deny reasons per mandate state (Round-3 MAJOR-1).
    """

    name = "mandate"

    def __init__(self, mandates: MandateService) -> None:
        self.mandates = mandates

    def run(self, ctx: CallContext) -> Optional[GatewayError]:
        with timing_span(ctx, "mandate"):
            check = self.mandates.check(ctx.agent_id, ctx.tool)
        if check.ok:
            ctx.mandate = check.mandate
            return None
        reason = check.reason or "mandate_withdrawn"
        return policy_denied(
            ctx.request_id, reason,
            f"{ctx.tool}: mandate not live ({reason})", tool=ctx.tool,
        )


class PolicyStage:
    """Step 4: policy evaluation hook.

    M1 STUB — visible default-deny (02 §1 design principle 1; FR-017):
    with no allow rules loaded, every call is denied with
    ``policy_denied`` / ``no_allow_rule`` and the denial is logged.
    TODO(M2): replace with the hand-rolled JSON rule evaluator —
    per-agent/per-tool/per-action allow/deny, grant-before-rule
    short-circuit to allowed_via_approval (live-mandate + supersession
    re-checks), default-deny stays a pinned visible row.
    """

    name = "policy"

    def __init__(self, policy_version: int = 1) -> None:
        self.policy_version = policy_version

    def run(self, ctx: CallContext) -> Optional[GatewayError]:
        with timing_span(ctx, "policy"):
            ctx.policy_version = self.policy_version
        return policy_denied(
            ctx.request_id, "no_allow_rule",
            f"{ctx.tool}: denied by default-deny (no allow rule)",
            tool=ctx.tool,
        )


# ApprovalStage lives in gateway.approvals (M3; replaces the M1/M2
# no-op stub). It is re-exported here lazily because approvals.py is
# imported by pipeline clients in orders that forbid a top-level
# import (vault/minter → pipeline). ``from gateway.pipeline import
# ApprovalStage`` keeps working (PEP 562).
def __getattr__(name: str) -> Any:
    if name == "ApprovalStage":
        from .approvals import ApprovalStage

        return ApprovalStage
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


class TokenMintStage:
    """Step 6: mint the layer-2 derived call token (FR-012b).

    W3's seam: the vault-backed minter replaces ``StubTokenMinter``.
    The stub mints an unusable handle so the pipeline shape is
    testable; it must never be used for real upstream calls.
    """

    name = "mint_token"

    def __init__(self, minter: "TokenMinter") -> None:
        self.minter = minter

    def run(self, ctx: CallContext) -> Optional[GatewayError]:
        with timing_span(ctx, "mint_token"):
            try:
                ctx.derived_token = self.minter.mint(ctx)
            except Exception:
                # Fail closed (03 §7: vault/KMS unavailable → no
                # credential can be derived → the call is denied; the
                # gateway stays up). The envelope names the tool only —
                # secret material never appears here (FR-022).
                return make_error(
                    "upstream_failure",
                    f"{ctx.tool}: credential mint failed",
                    ctx.request_id,
                    {"tool": ctx.tool},
                )
        return None


class TokenMinter(Protocol):
    """W3's interface: mint a layer-2 derived call token for the call.

    The implementation reads the connector's upstream credential from
    the vault (envelope-encrypted, NFR-SEC-002), derives a short-lived
    (5-min) token scoped to (agent, tool, action), and returns the
    handle. The raw vault credential never leaves the vault boundary
    (FR-022); the derived token never reaches the agent (FR-012b).
    """

    def mint(self, ctx: CallContext) -> DerivedToken: ...


class StubTokenMinter:
    """M1 placeholder. Produces an obviously-fake handle; the execute
    stage refuses to perform real upstream calls with it."""

    def mint(self, ctx: CallContext) -> DerivedToken:
        import time as _time

        return DerivedToken(
            agent_id=ctx.agent_id,
            tool=ctx.tool,
            action=ctx.tool.split(".", 1)[1] if "." in ctx.tool else ctx.tool,
            expires_at_epoch=_time.time() + 5 * 60,
            _material="STUB-NOT-FOR-UPSTREAM-USE",
        )


class ExecuteStage:
    """Step 7: dispatch to the connector's tool handler.

    W2 owns the handlers. The handler receives the context (with the
    derived token) and the validated args, and returns the raw upstream
    result. Upstream failure → ``upstream_failure`` (NFR-REL-002).
    A handler may raise ``ToolHalt`` to halt with a proper error
    envelope (e.g. ``gateway.approval_status``'s poll budget).
    ``TimeoutError`` (unknown outcome) records an
    ``UnknownOutcomeBlock`` and blocks automatic retry until the
    console resolves it (FR-PAA06-003, M3).
    """

    name = "execute"

    def __init__(self, registry: ConnectorRegistry, unknown_outcome: Any = None) -> None:
        self.registry = registry
        self.unknown_outcome = unknown_outcome

    def run(self, ctx: CallContext) -> Optional[GatewayError]:
        descriptor = self.registry.get(ctx.tool)
        if descriptor is None:  # unreachable after ValidateInputsStage; belt and braces
            return policy_denied(
                ctx.request_id, "no_allow_rule", f"{ctx.tool}: no such tool", tool=ctx.tool
            )
        with timing_span(ctx, "execute"):
            try:
                ctx.result = descriptor.handler(ctx, ctx.args)
            except ToolHalt as halt:
                return halt.error
            except TimeoutError as exc:  # unknown outcome: did it execute?
                if self.unknown_outcome is not None and ctx.argument_hash is not None:
                    self.unknown_outcome.record_block(
                        ctx.agent_id, ctx.tool, ctx.argument_hash,
                        f"TimeoutError: {exc}"[:200],
                    )
                return make_error(
                    "upstream_failure",
                    f"{ctx.tool}: outcome unknown (timeout); automatic retry "
                    "blocked pending console status check",
                    ctx.request_id,
                    {"tool": ctx.tool, "unknown_outcome": True, "retry_blocked": True},
                )
            except Exception as exc:  # noqa: BLE001 — connector failure must not crash the gateway
                # GH #8: the exception text stays server-side (upstream
                # errors routinely embed request IDs, key prefixes, or
                # PII). The agent gets the generic envelope; the detail
                # is in the server log keyed by request_id.
                log.error(
                    "connector call failed (request_id=%s tool=%s agent=%s): %s: %s",
                    ctx.request_id, ctx.tool, ctx.agent_id,
                    type(exc).__name__, exc,
                )
                return make_error(
                    "upstream_failure",
                    f"{ctx.tool}: connector call failed",
                    ctx.request_id,
                    {"tool": ctx.tool},
                )
        return None


# InspectOutputStage is the real M5 stage, defined in
# gateway.inspection.output and imported above (replaces the M1 stub):
# injection scan → PII/code-artifact redaction → context-leakage flags,
# all before agent delivery and the audit write; fail-closed per 03 §7.
# (Urgency flags are computed in ValidateInputsStage so the approval
# card at step 5 can surface them — see FR-PAA09-002.)


class AuditStage:
    """Step 9 (terminal): append the audit row (FR-030).

    Redacted args only. M1's redaction is structural: the pipeline's
    redaction hook is a documented pass-through STUB — the M5
    inspection stage performs catalog redaction. The seam (audit.py
    accepts only ``redacted_args``) is already in place, so the
    guarantee hardens without an API change.

    M3: ``counterparty`` records per-payee records from executed calls
    (FR-PAA05-001); ``ctx.skip_audit`` (the ``gateway.approval_status``
    carve-out, 02 §2.5) skips the row entirely.
    """

    name = "audit"

    def __init__(self, audit: AuditLog, counterparty: Any = None) -> None:
        self.audit = audit
        self.counterparty = counterparty

    def run(self, ctx: CallContext) -> Optional[GatewayError]:
        if ctx.skip_audit:
            # 02 §2.5 carve-out: the approval_status handler writes its
            # own rows for denied/expired/not-found outcomes; routine
            # polls leave no row.
            return None
        # M1 redaction stub: deep-copy through the redaction seam.
        # TODO(M5): apply the redaction catalog here (before this write
        # AND before agent delivery), per NFR-DATA-001/AC-07.
        import copy

        ctx.redacted_args = copy.deepcopy(ctx.args)
        self.audit.append(
            agent_id=ctx.agent_id,
            tool=ctx.tool,
            decision=ctx.decision or "allowed",
            request_id=ctx.request_id,
            redacted_args=ctx.redacted_args,
            mandate_id=ctx.mandate.id if ctx.mandate else None,
            scope_rule=ctx.scope_rule,  # M2: set by the real PolicyStage (FR-PAA01-007)
            reason=ctx.deny_reason,  # safe-vocabulary only; enforced at creation in errors.py
            approval_request_id=ctx.approval_request_id,  # M3: links the 3 approval rows
            # OPA pivot (M6 checklist (b)): traceability, additive.
            ontology_snapshot_ref=ctx.ontology_snapshot_ref,
            data_snapshot_id=ctx.data_snapshot_id,
        )
        if self.counterparty is not None and ctx.decision in ("allowed", "allowed_via_approval"):
            # FR-PAA05-001: per-payee records are written from audited
            # (executed) calls only — never from denied/paused ones.
            # The hook reads ctx.raw_args (pre-redaction): the M5
            # pre-audit hook rebinds ctx.args for the audit row
            # (NFR-DATA-001), but the payee key must stay plaintext.
            hook_args = ctx.raw_args or ctx.args
            self.counterparty.record_from_call(ctx.agent_id, ctx.tool, hook_args)
        return None


# ---------------------------------------------------------------------
# The pipeline
# ---------------------------------------------------------------------

class Pipeline:
    """Runs the Fix-B stage order. Stages are injectable for tests and
    later milestones (M2/M3/M5/W2/W3).

    The audit stage is terminal and runs exactly once per call — after
    the last non-terminal stage, whether the call succeeded or halted.
    """

    def __init__(
        self,
        stages: list[Stage],
        audit_stage: AuditStage,
        settings: Optional[Settings] = None,
        hmac_ring: Optional[HmacKeyRing] = None,
        pre_audit_hook: Optional[Callable[[CallContext], None]] = None,
    ) -> None:
        self.stages = [s for s in stages if not isinstance(s, AuditStage)]
        self.audit_stage = audit_stage
        self.settings = settings or Settings()
        self.hmac_ring = hmac_ring
        # M5: runs after the last non-terminal stage and BEFORE the
        # terminal audit write, on every path (success or halt). Used
        # for NFR-DATA-001 redaction of call arguments. Fail-closed: a
        # hook failure must never let plaintext PII reach the audit log.
        self.pre_audit_hook = pre_audit_hook

    def execute(self, agent_id: str, tool: str, args: dict[str, Any]) -> "PipelineOutcome":
        ctx = CallContext(agent_id=agent_id, tool=tool, args=dict(args))
        # M3: snapshot for the counterparty hook before the M5
        # pre-audit hook rebinds ctx.args (NFR-DATA-001 vs FR-PAA05-001).
        ctx.raw_args = dict(ctx.args)
        # M3: the (agent, tool, argument-hash) key for the approval
        # lookup chain, computed once per call. None without a ring —
        # the approval flow refuses to run then (fail closed).
        if self.hmac_ring is not None:
            ctx.argument_hash = argument_hash(ctx.args, self.hmac_ring)
        timeout = self._deadline_seconds()
        if timeout is not None:
            return self._execute_with_deadline(ctx, timeout)
        return self._execute_inner(ctx)

    def _deadline_seconds(self) -> Optional[float]:
        """The configured pipeline deadline, or None when disabled."""
        try:
            timeout = float(self.settings.pipeline_timeout_seconds)
        except (TypeError, ValueError):
            return None
        return timeout if timeout > 0 else None

    def _execute_with_deadline(
        self, ctx: CallContext, timeout: float
    ) -> "PipelineOutcome":
        """Run the stage loop on a worker thread bounded by *timeout*.

        GH #9: a hung connector handler must not tie up the caller
        forever (application-layer DoS). The worker thread is a daemon
        (one per call — no pool, so a flood of hung calls cannot
        head-of-line-block healthy ones); it keeps running after the
        deadline so its terminal audit write still lands if the handler
        ever returns. Request-scoped contextvars propagate via
        ``contextvars.copy_context`` (the MCP auth binding lives in one).
        """
        box: dict[str, Any] = {}
        parent_ctx = contextvars.copy_context()

        def _target() -> None:
            try:
                box["outcome"] = parent_ctx.run(self._execute_inner, ctx)
            except Exception:  # noqa: BLE001 — contained; the caller already failed closed
                log.exception(
                    "pipeline worker thread failed after deadline "
                    "(request_id=%s tool=%s)",
                    ctx.request_id, ctx.tool,
                )

        worker = threading.Thread(
            target=_target,
            daemon=True,
            name=f"gateway-pipeline-{ctx.request_id}",
        )
        worker.start()
        worker.join(timeout)
        if worker.is_alive():
            # Deadline exceeded: fail closed through the unknown-outcome
            # gate (FR-PAA06-003) — the same envelope shape as a handler
            # TimeoutError, so automatic retry stays blocked until the
            # console resolves the block.
            self._record_deadline_block(ctx)
            log.error(
                "pipeline deadline exceeded (request_id=%s tool=%s agent=%s "
                "timeout=%.1fs); worker thread left running, unknown-outcome "
                "block recorded",
                ctx.request_id, ctx.tool, ctx.agent_id, timeout,
            )
            error = make_error(
                "upstream_failure",
                f"{ctx.tool}: pipeline deadline exceeded; outcome unknown; "
                "automatic retry blocked pending console status check",
                ctx.request_id,
                {
                    "tool": ctx.tool,
                    "unknown_outcome": True,
                    "retry_blocked": True,
                    "deadline_exceeded": True,
                },
            )
            ctx.decision = _decision_for_error(error)
            ctx.deny_reason = error.details.get("reason")
            if ctx.deny_reason is None and error.code in SAFE_REASONS:
                ctx.deny_reason = error.code
            return PipelineOutcome(context=ctx, error=error, halted_at="deadline")
        outcome = box.get("outcome")
        if outcome is None:  # unreachable: _target always sets it or logs
            error = make_error(
                "upstream_failure",
                f"{ctx.tool}: pipeline worker lost",
                ctx.request_id,
                {"tool": ctx.tool},
            )
            return PipelineOutcome(context=ctx, error=error, halted_at="deadline")
        return outcome

    def _record_deadline_block(self, ctx: CallContext) -> None:
        """Record the unknown-outcome block synchronously (GH #9).

        Runs on the CALLER thread while its DB session is still open —
        the worker thread may outlive the session, so the block (the
        durable retry-stop trace) must not depend on it.
        """
        if ctx.argument_hash is None:
            return
        for stage in self.stages:
            gate = getattr(stage, "unknown_outcome", None)
            if gate is not None:
                try:
                    gate.record_block(
                        ctx.agent_id, ctx.tool, ctx.argument_hash,
                        f"pipeline deadline exceeded after "
                        f"{self._deadline_seconds():.1f}s; outcome unknown",
                    )
                except Exception:  # noqa: BLE001 — the block is best-effort; the envelope already fails closed
                    log.exception(
                        "failed to record unknown-outcome block "
                        "(request_id=%s)", ctx.request_id,
                    )
                return

    def _execute_inner(self, ctx: CallContext) -> "PipelineOutcome":
        error: Optional[GatewayError] = None
        halted_at: Optional[str] = None
        for stage in self.stages:
            with timing_span(ctx, f"stage:{stage.name}"):
                error = stage.run(ctx)
            if stage.name == "inspect_output":
                # AC-11: record the inspection-stage latency measured by
                # the timing_span above (no second timer), labeled with
                # the stage outcome. Advisory-only: no change to stage
                # logic, ordering, or error handling.
                ms = ctx.spans.get("stage:inspect_output")
                if ms is not None:
                    record(
                        "inspection", ms,
                        label=error.code if error is not None else "ok",
                    )
            if error is not None:
                halted_at = stage.name
                ctx.decision = _decision_for_error(error)
                # Safe-vocabulary reason for the audit row (M2: every denial
                # is logged with a reason). Prefer the error's own reason;
                # fall back to the code itself when it is safe vocabulary
                # (e.g. invalid_input carries no "reason" key in details).
                ctx.deny_reason = error.details.get("reason")
                if ctx.deny_reason is None and error.code in SAFE_REASONS:
                    ctx.deny_reason = error.code
                break
        else:
            # M3: a call authorized by a consumed one-time grant logs
            # decision allowed_via_approval on the same
            # approval_request_id (02 §2.8 step 9).
            ctx.decision = "allowed_via_approval" if ctx.via_grant else "allowed"
        # M5 pre-audit hook (NFR-DATA-001): redact arguments before the
        # terminal audit write, on every path — including calls halted
        # before output inspection. Fail closed: if redaction itself
        # fails, the args are replaced with a marker rather than written
        # as plaintext PII.
        if self.pre_audit_hook is not None:
            try:
                self.pre_audit_hook(ctx)
            except Exception:  # noqa: BLE001 — fail closed, never plaintext
                ctx.args = {"_redaction_failed": True}
        # Terminal audit: exactly one row per call (success or halt).
        self.audit_stage.run(ctx)
        return PipelineOutcome(context=ctx, error=error, halted_at=halted_at)


def _decision_for_error(error: GatewayError) -> str:
    return {
        "policy_denied": "denied",
        "approval_required": "approval_required",
        "approval_denied": "denied",
        "approval_expired": "expired",
        "approval_queue_full": "denied",
        "cooldown_active": "denied",
        "already_executed": "denied",
        "agent_paused": "denied",
        "agent_canceled": "denied",
        "invalid_input": "denied",
        "rate_limited": "denied",
        "injected_output_blocked": "denied",
        "upstream_failure": "error",
        "auth_failed": "denied",
        "agent_revoked": "denied",
    }.get(error.code, "error")


@dataclass
class PipelineOutcome:
    context: CallContext
    error: Optional[GatewayError]  # None → success; ctx.result holds the value
    halted_at: Optional[str]      # stage name that halted, None on success

    @property
    def ok(self) -> bool:
        return self.error is None


def _judge_wiring(
    settings: Settings, judge_cascade: Optional[Any]
) -> tuple[Optional[Any], Optional[Any]]:
    """Build the judge hooks for the pipeline builders.

    Returns ``(inspection_hook, risk_scorer)`` — both None unless
    ``GATEWAY_JUDGE_ENABLED=1``. When enabled without an explicit
    cascade, the cascade is built from settings
    (``GATEWAY_JUDGE_BACKEND``; ``"none"`` → DisabledBackend →
    JudgeUnavailable → deterministic fallback everywhere) with the
    escalation backend named by ``GATEWAY_JUDGE_ESCALATION``
    (``"none"`` default → no escalation). Imports are
    lazy: the judge package is untouched when the hooks are off.
    """
    if not getattr(settings, "judge_enabled", False):
        return None, None
    from .judge.cascade import JudgeCascade
    from .judge.factory import backend_from_settings, escalation_from_settings
    from .judge.inspection_hook import JudgeInspectionHook
    from .judge.risk import build_risk_scorer

    cascade = judge_cascade
    if cascade is None:
        cascade = JudgeCascade(
            primary=backend_from_settings(settings),
            escalation=escalation_from_settings(settings),
            threshold=0.75,
            timeout_s=getattr(settings, "judge_timeout_s", 2.0),
            # GH #31: readiness alert after N minutes of continuous
            # unreachability.
            alert_after_minutes=getattr(settings, "judge_alert_after_minutes", 5.0),
        )
    hook = JudgeInspectionHook(
        cascade, always_on=getattr(settings, "judge_always_on", False)
    )
    return hook, build_risk_scorer(settings, cascade)


def build_m1_pipeline(
    config_db: Session,
    audit_db: Session,
    settings: Optional[Settings] = None,
    hmac_ring: Optional[HmacKeyRing] = None,
    registry: Optional[ConnectorRegistry] = None,
    minter: Optional["TokenMinter"] = None,
    judge_cascade: Optional[Any] = None,
) -> tuple[Pipeline, ConnectorRegistry, AuthenticateStage]:
    """Assemble the M1 pipeline: auth + mandate + audit wired; every
    other stage is a documented stub naming its owning milestone —
    except M5's inspection stages, which are real here too (hardened
    ``ValidateInputsStage`` + ``InspectOutputStage`` with rate
    limiting, injection scan, redaction, and leakage flags).

    *registry* may be shared across pipeline instances (the MCP server
    builds one pipeline per call with fresh sessions but a single
    registry, so W2's registrations are visible to every call).
    *minter* replaces the ``StubTokenMinter`` (W3/M4 seam): pass the
    vault-backed ``VaultTokenMinter`` to wire the real layer-2 mint.
    *judge_cascade*: an optional ``gateway.judge.JudgeCascade``; the
    advisory inspection hook is installed only when
    ``GATEWAY_JUDGE_ENABLED=1`` (default off).
    """
    settings = settings or Settings()
    registry = registry if registry is not None else ConnectorRegistry()
    identity = IdentityService(
        config_db, settings.fallback_bearer_max_days
    )
    mandates = MandateService(config_db)
    audit = AuditLog(audit_db, dead_letter_path=settings.audit_dead_letter_path)
    # M5 inspection wiring (shared by both builders).
    catalog = RedactionCatalog(config_db)
    rate_limiter = RateLimiter(config_db, settings)
    inspection_config = InspectionConfig()
    # Judge hooks (advisory; default off — see _judge_wiring).
    judge_hook, _ = _judge_wiring(settings, judge_cascade)

    auth_stage = AuthenticateStage(identity)
    audit_stage = AuditStage(audit)
    # Lazy: approvals.py is imported by pipeline clients in orders that
    # forbid a top-level import (vault/minter → pipeline).
    from .approvals import ApprovalStage

    stages: list[Stage] = [
        auth_stage,
        ValidateInputsStage(registry, rate_limiter=rate_limiter),
        MandateStage(mandates),
        PolicyStage(),           # M1: visible default-deny; TODO(M2)
        ApprovalStage(),        # M1: no-op; TODO(M3)
        # W3/M4 seam: the vault-backed minter replaces the stub when
        # passed via the *minter* parameter (VaultTokenMinter).
        TokenMintStage(minter if minter is not None else StubTokenMinter()),
        ExecuteStage(registry),  # W2: connector handlers
        InspectOutputStage(audit=audit, catalog=catalog, config=inspection_config,
                           judge=judge_hook),
        # AuditStage is terminal: passed separately, runs exactly once.
    ]
    pipeline = Pipeline(
        stages, audit_stage, settings, hmac_ring,
        # NFR-DATA-001: redact arguments before the terminal audit
        # write, on every path (AuditStage itself is untouched).
        pre_audit_hook=lambda ctx: redact_ctx_for_audit(ctx, catalog, audit),
    )
    return pipeline, registry, auth_stage


def build_pipeline(
    config_db: Session,
    audit_db: Session,
    settings: Optional[Settings] = None,
    hmac_ring: Optional[HmacKeyRing] = None,
    registry: Optional[ConnectorRegistry] = None,
    grant_checker: Optional[Callable[..., Any]] = None,
    approval_service: Any = None,
    approvals: bool = False,
    minter: Optional["TokenMinter"] = None,
    judge_cascade: Optional[Any] = None,
) -> tuple[Pipeline, ConnectorRegistry, AuthenticateStage]:
    """Assemble the M2/M3 pipeline: hardened validator + REAL policy engine.

    Same Fix-B stage order as build_m1_pipeline; the only differences
    are (1) ``policy.PolicyStage`` replaces the default-deny stub, and
    (2) ``ValidateInputsStage`` now runs the M5 hardened validator.
    *judge_cascade*: an optional ``gateway.judge.JudgeCascade``; the
    advisory inspection hook and intent risk step-up are installed only
    when ``GATEWAY_JUDGE_ENABLED=1`` (default off).
    W2 registers connector tools; W3 replaces the token minter.

    ``grant_checker`` is the M3 grant-store seam (Fix B, MF-7); None in
    M2 (no grants exist yet).

    M3: pass ``approvals=True`` (or an explicit ``approval_service``)
    to wire the full Fix-B approval flow — grant-before-rule
    evaluation, the 02 §2.8 step-3 lookup chain at the approval stage
    (``require_approval`` passes through instead of halting at the
    policy stage), counterparty escalation (FR-PAA05-002), the
    unknown-outcome retry gate (FR-PAA06-003), and per-payee
    bookkeeping on executed calls. Requires ``hmac_ring`` (fail
    closed at build time without keyed hashing).
    """
    # Lazy import: policy.py imports timing_span from this module at its
    # top level, so this module must not import policy at top level.
    from .policy import PolicyStage as RealPolicyStage

    settings = settings or Settings()
    registry = registry if registry is not None else ConnectorRegistry()
    identity = IdentityService(
        config_db, settings.fallback_bearer_max_days
    )
    mandates = MandateService(config_db)
    audit = AuditLog(audit_db, dead_letter_path=settings.audit_dead_letter_path)
    # M5 inspection wiring (shared by both builders).
    catalog = RedactionCatalog(config_db)
    rate_limiter = RateLimiter(config_db, settings)
    inspection_config = InspectionConfig()
    # Judge hooks (advisory; default off — see _judge_wiring).
    judge_hook, risk_scorer = _judge_wiring(settings, judge_cascade)

    # -- M3 approval wiring -------------------------------------------------
    # Lazy: approvals.py is imported by pipeline clients in orders that
    # forbid a top-level import (vault/minter → pipeline).
    approval_stage_service = approval_service
    counterparty_svc: Any = None
    unknown_gate: Any = None
    escalator: Any = None
    defer_approval = False
    if approval_stage_service is not None or approvals:
        if hmac_ring is None:
            raise ValueError(
                "the M3 approval flow requires hmac_ring "
                "(HMAC-SHA256 argument hashing is load-bearing)"
            )
        from .approvals import ApprovalService as _ApprovalService
        from .approvals import ApprovalStage as _ApprovalStage
        from .counterparty import CounterpartyService, counterparty_escalator
        from .notifier import build_notifier

        if approval_stage_service is None:
            counterparty_svc = CounterpartyService(config_db)
            approval_stage_service = _ApprovalService(
                config_db, audit, settings, hmac_ring, mandates,
                notifier=build_notifier(settings, audit, transport=None),
                counterparty=counterparty_svc,
            )
        counterparty_svc = approval_stage_service.counterparty
        unknown_gate = approval_stage_service.unknown_outcome
        escalator = counterparty_escalator(counterparty_svc)
        grant_checker = approval_stage_service.grants.check
        defer_approval = True
    else:
        from .approvals import ApprovalStage as _ApprovalStage

    auth_stage = AuthenticateStage(identity)
    audit_stage = AuditStage(audit, counterparty=counterparty_svc)
    stages: list[Stage] = [
        auth_stage,
        ValidateInputsStage(registry, rate_limiter=rate_limiter),
        MandateStage(mandates),
        RealPolicyStage(
            config_db, grant_checker=grant_checker, hmac_ring=hmac_ring,
            defer_approval=defer_approval,
            sensitivity_escalator=escalator,
            unknown_outcome_gate=unknown_gate,
            risk_scorer=risk_scorer,
        ),
        _ApprovalStage(approval_stage_service),
        TokenMintStage(minter if minter is not None else StubTokenMinter()),
        ExecuteStage(registry, unknown_outcome=unknown_gate),
        InspectOutputStage(audit=audit, catalog=catalog, config=inspection_config,
                           judge=judge_hook),
    ]
    pipeline = Pipeline(
        stages, audit_stage, settings, hmac_ring,
        # NFR-DATA-001: redact arguments before the terminal audit
        # write, on every path (AuditStage itself is untouched).
        pre_audit_hook=lambda ctx: redact_ctx_for_audit(ctx, catalog, audit),
    )
    return pipeline, registry, auth_stage


# ---------------------------------------------------------------------
# Execute-on-approval (MF-11): server-side replay of an approved call.
# ---------------------------------------------------------------------

def execute_approved_call(
    *,
    config_session_factory: Callable[[], Session],
    audit_session_factory: Callable[[], Session],
    settings: Optional[Settings],
    hmac_ring: Optional[HmacKeyRing],
    registry: ConnectorRegistry,
    minter: Optional["TokenMinter"],
    agent_id: str,
    tool: str,
    args: dict[str, Any],
    approval_request_id: str,
    policy_version: int,
    mandate_id: str,
) -> dict[str, Any]:
    """Run an approved call server-side (the MF-11 fallback).

    Ken approves with ``execute_on_approval`` for a platform whose
    agent cannot poll. The grant was already consumed atomically at
    approval time, so this never double-executes. Runs validate →
    mandate → mint_token → execute → inspect_output → audit with
    FRESH sessions, independent of any agent request.

    Returns ``{"ok", "result" | "error", "request_id"}``.
    """
    # Lazy: keeps the top-level import arrow one-way (see build_pipeline).
    from .approvals import UnknownOutcomeService, policy_materially_superseded
    from .counterparty import CounterpartyService

    settings = settings or Settings()
    with config_session_factory() as config_db, audit_session_factory() as audit_db:
        audit = AuditLog(audit_db, dead_letter_path=settings.audit_dead_letter_path)
        catalog = RedactionCatalog(config_db)
        mandates = MandateService(config_db)
        counterparty = CounterpartyService(config_db)
        unknown_outcome = UnknownOutcomeService(config_db)

        ctx = CallContext(agent_id=agent_id, tool=tool, args=dict(args))
        ctx.raw_args = dict(ctx.args)
        ctx.approval_request_id = approval_request_id
        ctx.policy_version = policy_version
        ctx.scope_rule = f"grant:{approval_request_id}"
        if hmac_ring is not None:
            ctx.argument_hash = argument_hash(ctx.args, hmac_ring)

        error: Optional[GatewayError] = None
        # GH #23: policy-supersession re-check at replay start. A material
        # policy change landing between approval (grant consumed, with the
        # supersession check) and this server-side replay must not execute
        # under the old policy. Uses the same material-change semantics as
        # the grant path (approvals.policy_materially_superseded): a
        # non-material version does not block the replay.
        if policy_materially_superseded(config_db, policy_version):
            error = policy_denied(
                ctx.request_id,
                "policy_superseded",
                f"{tool}: policy changed materially since this call was "
                "approved; re-request approval",
                tool=tool,
            )
            ctx.decision = _decision_for_error(error)
            ctx.deny_reason = "policy_superseded"
        if error is None:
            stages: list[Stage] = [
                ValidateInputsStage(registry),
                MandateStage(mandates),
                TokenMintStage(minter if minter is not None else StubTokenMinter()),
                ExecuteStage(registry, unknown_outcome=unknown_outcome),
                InspectOutputStage(audit=audit, catalog=catalog, config=InspectionConfig()),
            ]
            for stage in stages:
                with timing_span(ctx, f"stage:{stage.name}"):
                    error = stage.run(ctx)
                if error is not None:
                    ctx.decision = _decision_for_error(error)
                    ctx.deny_reason = error.details.get("reason")
                    if ctx.deny_reason is None and error.code in SAFE_REASONS:
                        ctx.deny_reason = error.code
                    break
            else:
                ctx.decision = "allowed_via_approval"
        # The audit row links to the approval that authorized this
        # replay (the grant's mandate), not whatever mandate happens
        # to be live now.
        ctx.mandate = config_db.get(Mandate, mandate_id)
        try:
            redact_ctx_for_audit(ctx, catalog, audit)
        except Exception:  # noqa: BLE001 — fail closed, never plaintext
            ctx.args = {"_redaction_failed": True}
        AuditStage(audit, counterparty=counterparty).run(ctx)
        if error is not None:
            return {"ok": False, "error": error.to_envelope(), "request_id": ctx.request_id}
        return {"ok": True, "result": ctx.result, "request_id": ctx.request_id}
