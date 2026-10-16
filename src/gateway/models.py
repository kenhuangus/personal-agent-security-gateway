"""SQLAlchemy models (03 §5; 01 §4.2–§4.8, §10.1, §10.10).

Both DBs share the ORM Base (Postgres-migration seam). The two
physical files stay separate: mutable config + state in one,
append-only audit in the other.

Conventions:
- Timestamps: UTC, timezone-aware datetimes, stored as ISO text.
- Money/terms: approval records bind a term sheet (FR-PAA06-001).
- No plaintext secrets anywhere: AgentCredential stores a hash only
  (FR-022). Evidence-subset rule (02 §2.8 step 4): the approvals
  record stores the narrow cleartext evidence subset + redacted args +
  HMAC of canonical args — never plaintext full arguments.
"""

from __future__ import annotations

import datetime as dt
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def as_utc(value: dt.datetime | None) -> dt.datetime | None:
    """Normalize a stored datetime to timezone-aware UTC.

    SQLite returns naive datetimes for DateTime(timezone=True) columns;
    treat naive values as UTC so comparisons never mix naive and aware.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=dt.timezone.utc)
    return value


class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------
# Identity (Fix A): exactly one credential per agent.
# ---------------------------------------------------------------------

class Agent(Base):
    __tablename__ = "agents"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # e.g. "ag_muse_01"
    platform: Mapped[str] = mapped_column(String(32), nullable=False)  # muse | grok | dots
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    # Household-role scoping (FR-PAA08-001): one member's role never
    # satisfies rules for another member's data.
    household_role: Mapped[str] = mapped_column(String(64), nullable=False)
    # Lifecycle: active | paused | canceled | revoked | deleted (FR-PAA10-002).
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    # Auth method (Fix A): oauth | fallback_bearer. Single credential.
    auth_method: Mapped[str] = mapped_column(String(16), nullable=False, default="oauth")
    # For the conditional fallback: date OAuth verification demonstrably
    # failed (FR-011). NULL when auth_method == "oauth".
    verified_test_date: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (Index("ix_agents_status", "status"),)


class AgentCredential(Base):
    """Exactly one active credential per agent (Fix A).

    The credential SECRET is stored as a hash only (bcrypt) — never the
    raw secret (FR-022). OAuth 2.1 client credentials are stored as
    (client_id, client_secret_hash); the fallback bearer is stored as a
    bearer-token hash. Issuing a second credential for an agent that
    already has an active one is rejected (identity.py enforces).
    """

    __tablename__ = "agent_credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    agent_id: Mapped[str] = mapped_column(String(64), ForeignKey("agents.id"), nullable=False)
    # "oauth" | "fallback_bearer" — mirrors Agent.auth_method at issue time.
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    # For OAuth: the client_id (public part). For fallback: a key id.
    identifier: Mapped[str] = mapped_column(String(128), nullable=False)
    # bcrypt hash of the secret. Raw secret is never persisted.
    secret_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    # Active flag: exactly one credential per agent has active=1 at a time.
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    issued_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    # Console-visible age indicator for the fallback bearer (00 §7 param 1).
    last_rotated_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_agent_credentials_agent", "agent_id"),
        Index("ix_agent_credentials_active", "agent_id", "active"),
    )


# ---------------------------------------------------------------------
# Mandates (FR-PAA01-001)
# ---------------------------------------------------------------------

class Mandate(Base):
    """Standing mandate for an agent session (PAA01).

    Status: active | paused | ended | withdrawn. Evaluated BEFORE any
    tool logic on every call (FR-PAA01-002); expired/paused/withdrawn
    deny with DISTINCT reasons (Round-3 MAJOR-1).

    ``purpose_key`` (M2): exact key into the purpose registry (e.g.
    "work", "personal", "meeting-prep"). Policy rules bind to a declared
    purpose (FR-PAA03-002); a rule with a purpose only matches a call
    whose mandate carries the same purpose_key. NULL = undeclared;
    purpose-bound rules never match an undeclared mandate (fail closed).
    """

    __tablename__ = "mandates"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # mnd_… (128-bit CSPRNG)
    agent_id: Mapped[str] = mapped_column(String(64), ForeignKey("agents.id"), nullable=False)
    purpose: Mapped[str] = mapped_column(Text, nullable=False)
    # Exact purpose-registry key for FR-PAA03-002 purpose binding (M2).
    purpose_key: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    # Allowed tool/action classes (JSON list, e.g. ["email.read", "calendar.*"]).
    allowed_classes: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    expires_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    parent_mandate_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    # Provenance (FR-PAA04-001): who created it and when; inferred vs explicit.
    created_by: Mapped[str] = mapped_column(String(64), nullable=False, default="admin")
    provenance: Mapped[str] = mapped_column(String(16), nullable=False, default="explicit")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    ended_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (Index("ix_mandates_agent", "agent_id"),)


# ---------------------------------------------------------------------
# Policy (M1: versioned rule list with default-deny; evaluator is M2)
# ---------------------------------------------------------------------

class PolicyVersion(Base):
    """Every policy save creates a version (FR-041, 02 §5).

    Material/non-material classification is recorded on every save
    (02 §5): a material change invalidates affected grants and flags
    pending approvals for review (FR-PAA04-003).
    """

    __tablename__ = "policy_versions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, unique=True)
    # Material classification recorded on save (02 §5).
    material_change: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    change_note: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_by: Mapped[str] = mapped_column(String(64), nullable=False, default="admin")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    is_current: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class PolicyRule(Base):
    """One rule in a policy version. M2 evaluates the rule list.

    Default-deny is a pinned, visible row (02 §1.1) — represented by
    ``PolicyEngine.default_deny_row()``, not a DB row, so it can never
    be deleted or reordered.

    Effect vocabulary: "allow" | "deny" | "require_approval"
    (02 §5). The M1-era "sensitive" is accepted on read and normalized
    to "require_approval".

    ``rule_type``: "standard" | "notice". A "notice" rule is the
    template-bound notice rule (FR-PAA07-005, 02 §5): a standing allow
    rule binding audience + template + schedule in ``conditions``.
    """

    __tablename__ = "policy_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    policy_version_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("policy_versions.id"), nullable=False
    )
    # Human-readable rule name (02 §5 rule builder field 1).
    name: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # "standard" | "notice" (template-bound notice rule, FR-PAA07-005).
    rule_type: Mapped[str] = mapped_column(String(16), nullable=False, default="standard")
    # allow | deny | require_approval (sensitive → step-up approval, FR-018).
    effect: Mapped[str] = mapped_column(String(16), nullable=False)
    agent_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)  # None = any
    tool: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)  # None = any
    action_class: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    # Household-role scoping (FR-PAA08-001): None = any role; otherwise
    # the rule only matches agents whose household_role equals this.
    household_role: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    # Declared purpose binding (FR-PAA03-002).
    purpose: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    # Rule conditions (02 §5 field 5): time_window, argument_constraints,
    # agents (multi-agent list), notice (for rule_type "notice").
    conditions: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    rule_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Provenance (FR-PAA04-001).
    created_by: Mapped[str] = mapped_column(String(64), nullable=False, default="admin")
    provenance: Mapped[str] = mapped_column(String(16), nullable=False, default="explicit")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (Index("ix_policy_rules_version", "policy_version_id"),)


# ---------------------------------------------------------------------
# Approvals and grants (Fix B). Grant consumption is M3; the record
# shape lands in M1 so the M3 work has a contract.
# ---------------------------------------------------------------------

class ApprovalRequest(Base):
    """Approval request per 02 §2.8 step 4 (evidence-subset rule).

    Stores: evidence subset in cleartext (approver-visible decision
    fields ONLY — recipient/payee, amount/currency, audience, rendered
    preview with code-like secrets redacted per FR-PAA02-001), the full
    argument set in REDACTED form, and HMAC-SHA256 (gateway-held key) of
    the canonical full arguments. Never plaintext full arguments.
    """

    __tablename__ = "approval_requests"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # apr_… (128-bit CSPRNG)
    agent_id: Mapped[str] = mapped_column(String(64), ForeignKey("agents.id"), nullable=False)
    mandate_id: Mapped[str] = mapped_column(String(64), nullable=False)
    tool: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_version: Mapped[int] = mapped_column(Integer, nullable=False)
    # (agent, tool, argument-hash) dedupe/grant key (02 §2.8 step 3):
    # HMAC-SHA256 of canonical args, tagged with the key id.
    argument_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    # Evidence subset in cleartext (02 §2.8 step 4): limited to the
    # approver-visible decision fields. This is the ONLY cleartext
    # storage allowed (NFR-DATA-001 exception, approvals record only).
    evidence_subset: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    # Full arguments in redacted form (NFR-DATA-001).
    redacted_args: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="pending"
    )  # pending | approved | denied | expired | canceled
    decided_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    decided_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    # Approver note (free text from the console; rendered inert on cards).
    decision_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # PII-redacted result summary — set ONLY when the approved call was
    # executed server-side via the execute-on-approval fallback (02 §2.8,
    # MF-11). Mirrored to the agent via gateway.approval_status as
    # ``result_summary``; absent in the normal poll-and-reinvoke path.
    result_summary: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # M6 (ontology pipeline seam, item d): the ontology decision-snapshot
    # ref and the deciding-entry citation at approval-request creation
    # time, copied from the pipeline CallContext. Additive only.
    ontology_snapshot_ref: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    ontology_ref: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Pillar 1 §2 (quorum approvals, migration m001):
    # approvers needed; 1 = existing single-approver path.
    quorum_required: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    # Per-approver slots, append-only: [{admin_id, session_id,
    # decided_at, approver_index, auth_method}].
    approvals: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    # HMAC(canonical evidence_subset) at creation — the frozen context.
    evidence_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    # {mandate_status, policy_version, counterparty_record_version} at
    # creation — stale context expires the request (context_changed).
    context_fingerprint: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    # "tool_call" | "event_release" (§4: releasing a quarantined event
    # follows the same approval flow).
    request_type: Mapped[str] = mapped_column(String(16), nullable=False, default="tool_call")

    __table_args__ = (
        Index("ix_approvals_agent", "agent_id"),
        Index("ix_approvals_status", "status"),
        Index("ix_approvals_arghash", "agent_id", "tool", "argument_hash"),
    )


class Grant(Base):
    """One-time approval grant, bound to the exact argument hash (M3).

    M1 stores the record shape; consumption semantics (atomic
    compare-and-consume, mandate re-check, policy-supersession check)
    arrive in M3. Internal grant ids never cross the agent boundary.
    """

    __tablename__ = "grants"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    approval_request_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("approval_requests.id"), nullable=False
    )
    agent_id: Mapped[str] = mapped_column(String(64), ForeignKey("agents.id"), nullable=False)
    tool: Mapped[str] = mapped_column(String(64), nullable=False)
    argument_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    mandate_id: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_version: Mapped[int] = mapped_column(Integer, nullable=False)
    # One-time only in MVP (00 §3); TTL 30 min from approval (00 §7 param 21).
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    consumed_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    invalidated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        Index("ix_grants_lookup", "agent_id", "tool", "argument_hash"),
        UniqueConstraint("approval_request_id", name="uq_grants_approval_request"),
    )


class RefusalCooldown(Base):
    """Post-denial refusal cooldown (FR-PAA09-003; 02 §2.8 steps 3/10).

    Keyed by (agent, tool, argument-hash): an identical call inside the
    cooldown is denied with ``cooldown_active`` — no approval request is
    created and no notification fires. Recorded on every deny AND every
    timeout (M3: step 10 covers both). The pair-level denial-streak
    escalation (≥3 denied/expired sensitive for (agent, tool)/24h) is
    derived from ApprovalRequest rows, not stored here.
    """

    __tablename__ = "refusal_cooldowns"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    agent_id: Mapped[str] = mapped_column(String(64), ForeignKey("agents.id"), nullable=False)
    tool: Mapped[str] = mapped_column(String(64), nullable=False)
    # HMAC-SHA256 of the canonical args (same key/tag as ApprovalRequest.argument_hash).
    argument_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        UniqueConstraint("agent_id", "tool", "argument_hash", name="uq_refusal_cooldown"),
        Index("ix_refusal_cooldown_lookup", "agent_id", "tool", "argument_hash"),
    )


class UnknownOutcomeBlock(Base):
    """Retry gate after an unknown call outcome (FR-PAA06-003; 02 §2.7).

    When a connector call ends ambiguously (timeout), the gateway does
    not know whether the upstream executed. Automatic retry of the
    identical (agent, tool, argument-hash) call is blocked until the
    block is resolved via the console (status check through the
    connector's ``transaction_status`` capability where one exists).
    """

    __tablename__ = "unknown_outcome_blocks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    agent_id: Mapped[str] = mapped_column(String(64), ForeignKey("agents.id"), nullable=False)
    tool: Mapped[str] = mapped_column(String(64), nullable=False)
    argument_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    # What was observed (e.g. "TimeoutError from adapter").
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    resolved_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    resolve_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index("ix_unknown_outcome_lookup", "agent_id", "tool", "argument_hash"),
    )


# ---------------------------------------------------------------------
# Counterparty records + decision criteria (PAA05, PAA09)
# ---------------------------------------------------------------------

class CounterpartyRecord(Base):
    """Per-payee record built from audited calls (FR-PAA05-001)."""

    __tablename__ = "counterparty_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # Stable identity key for the counterparty (e.g. email address).
    key: Mapped[str] = mapped_column(String(256), nullable=False, unique=True)
    first_seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    call_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # Last-known-good detail snapshot for delta detection
    # (FR-PAA05-001): e.g. the recipient set of the last audited send.
    # Ken-correctable via the console (diffed, audit-logged).
    details_snapshot: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


class DecisionCriteria(Base):
    """Ken's recorded decision criteria per domain (FR-PAA09-004)."""

    __tablename__ = "decision_criteria"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    domain: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    criteria: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ---------------------------------------------------------------------
# Audit (append-only; lives in the separate audit DB file)
# ---------------------------------------------------------------------

class AuditEntry(Base):
    """One audit row (FR-030/031). Append-only: the audit module
    exposes no update/delete path (FR-032)."""

    __tablename__ = "audit_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # req_… id; every error's request_id matches its audit row (02 §2.7).
    request_id: Mapped[str] = mapped_column(String(64), nullable=False)
    approval_request_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    agent_id: Mapped[str] = mapped_column(String(64), nullable=False)
    tool: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    timestamp: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    # Decision: allowed | denied | approval_required | approved |
    # allowed_via_approval | error … (02 §2.8; 02 §7 filters).
    decision: Mapped[str] = mapped_column(String(32), nullable=False)
    # Safe reason vocabulary only (02 §2.7).
    reason: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    # Redacted arguments only (NFR-DATA-001). Never plaintext PII.
    redacted_args: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    mandate_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    # The scope rule that authorized the call (FR-PAA01-007).
    scope_rule: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    # Ontology decision-snapshot ref (PAA04 traceability): the
    # content-addressed "key_id:hexdigest" of the ontology slice used at
    # decision time (ontology_snapshots table). NULL when the ontology
    # module did not shape the decision. Set additively — no existing
    # write path is affected.
    ontology_snapshot_ref: Mapped[Optional[str]] = mapped_column(
        String(128), nullable=True
    )
    # Input-document versioning (OPA pivot): the fingerprint of the
    # policy data behind the decision ("pv<N>/rules:<sha>/ont:<sha>").
    # NULL when no OPA evaluation ran (meta-tool allow, grant
    # short-circuit). Additive — no existing write path is affected.
    data_snapshot_id: Mapped[Optional[str]] = mapped_column(
        String(128), nullable=True
    )
    # Irreversible-action marker + pending obligations (FR-PAA10-005).
    irreversible: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    irreversible_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index("ix_audit_request", "request_id"),
        Index("ix_audit_agent", "agent_id"),
        Index("ix_audit_tool", "tool"),
        Index("ix_audit_time", "timestamp"),
        Index("ix_audit_decision", "decision"),
        Index("ix_audit_approval", "approval_request_id"),
    )


# ---------------------------------------------------------------------
# Redaction catalog (M5; FR-027; FR-PAA02-001; 00 §7 param 13)
# ---------------------------------------------------------------------

class RedactionPattern(Base):
    """One redaction pattern in the console-editable catalog.

    The catalog ships with PII + code-artifact defaults (see
    ``gateway.inspection.redaction.DEFAULT_PATTERNS``); Ken edits the
    rows from the console (M6 wires the UI to ``RedactionCatalog``).

    Scoping: a pattern applies to a call when the call's tool is in
    ``tools`` (or ``"*"``) AND the agent is in ``agents`` (or ``"*"``).
    ``secret_group`` selects which regex capture group holds the secret
    (0 = the whole match); only that group's span is replaced, so
    surrounding context ("Your verification code is …") is preserved.
    Replacement is always the full ``[redacted:type]`` token — no
    last-4 hints (00 §7 param 13).
    """

    __tablename__ = "redaction_patterns"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    regex: Mapped[str] = mapped_column(Text, nullable=False)
    token: Mapped[str] = mapped_column(String(64), nullable=False)  # e.g. "[redacted:email]"
    # "pii" | "code_artifact" (FR-PAA02-001).
    category: Mapped[str] = mapped_column(String(16), nullable=False, default="pii")
    # Which capture group holds the secret (0 = whole match).
    secret_group: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Lower runs first (code artifacts before generic PII).
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=20)
    # Scope: JSON lists of tool names / agent ids; ["*"] = all.
    tools: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    agents: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    __table_args__ = (Index("ix_redaction_patterns_enabled", "enabled"),)


# ---------------------------------------------------------------------
# Rate counters + admin
# ---------------------------------------------------------------------

class RateCounter(Base):
    """Per-agent rate-limit counters (FR-028). Persisted in SQLite so a
    restart does not reset limits (03 §5)."""

    __tablename__ = "rate_counters"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    agent_id: Mapped[str] = mapped_column(String(64), ForeignKey("agents.id"), nullable=False)
    window: Mapped[str] = mapped_column(String(16), nullable=False)  # "minute" | "day"
    window_start: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    __table_args__ = (
        UniqueConstraint("agent_id", "window", "window_start", name="uq_rate_counter"),
    )


class AdminUser(Base):
    """Single admin in MVP (Ken); admin_id seam for later (00 §3)."""

    __tablename__ = "admin_users"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # e.g. "admin_ken"
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    totp_secret: Mapped[str] = mapped_column(String(64), nullable=True)
    failed_logins: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[Optional[dt.datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ConfigSetting(Base):
    """Console-editable config overrides (M6, Vault & Settings page).

    Key/value overrides for the whitelisted Settings fields
    (see gateway.console.settings_store.EDITABLE_SETTINGS). Env vars
    remain the base values; these rows are the console-editable layer.
    Every change is audit-logged as an admin action (FR-041).
    """

    __tablename__ = "config_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    updated_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ---------------------------------------------------------------------
# Pillar 1 — money-movement policy pack (MVP; migration m002)
# ---------------------------------------------------------------------

class MoneyLedger(Base):
    """One row per moved payment (Pillar 1 §1.4).

    Written post-execute by the money pack's record hook — denied or
    failed calls write no row; only moved money consumes budget.
    ``dry_run=1`` rows exercise the full pipeline including velocity
    accounting but are excluded from budget sums. Personal-gateway
    volumes make per-event rows cheap and auditable; rolling windows
    are SUM/COUNT over indexed occurred_at ranges. Retention: pruned
    older than GATEWAY_MONEY_LEDGER_RETENTION_DAYS (default 90) via
    the existing retention job.
    """

    __tablename__ = "money_ledger"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    agent_id: Mapped[str] = mapped_column(String(64), ForeignKey("agents.id"), nullable=False)
    # Set when vault namespaces land (§5); NULL = pre-namespace.
    namespace_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    mandate_id: Mapped[str] = mapped_column(String(64), nullable=False)
    counterparty_key: Mapped[str] = mapped_column(String(256), nullable=False)
    amount_cents: Mapped[int] = mapped_column(Integer, nullable=False)
    # payment.initiate | payment.cancel
    tool: Mapped[str] = mapped_column(String(64), nullable=False)
    # req_ linkage to the audit row.
    request_id: Mapped[str] = mapped_column(String(64), nullable=False)
    dry_run: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    occurred_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    __table_args__ = (
        Index("ix_money_ledger_agent", "agent_id"),
        Index("ix_money_ledger_namespace", "namespace_id"),
        Index("ix_money_ledger_mandate", "mandate_id"),
        Index("ix_money_ledger_payee", "counterparty_key"),
        Index("ix_money_ledger_time", "occurred_at"),
    )


class CounterpartyAllowlist(Base):
    """Operator-curated counterparty allowlist (Pillar 1 §1.6).

    DISTINCT from the auto-built ``counterparty_records`` (which are
    written from audited calls, FR-PAA05-001). The allowlist is
    operator-curated: payee key (account fingerprint), label, details
    snapshot (last-4 of the operator's own routing/account tails only —
    the single exception to the no-last-4 rule; full numbers are never
    stored), and verification state. Edits are data, not rules: they
    bump ``record_version`` (freezing/expiring in-flight quorum
    requests via the context check) instead of creating policy
    versions.
    """

    __tablename__ = "counterparty_allowlist"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # Per-client allowlist (§5); NULL until namespaces land.
    namespace_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    payee_key: Mapped[str] = mapped_column(String(256), nullable=False)
    label: Mapped[str] = mapped_column(String(256), nullable=False)
    details_snapshot: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    # "verified" | "pending" | "blocked".
    verification_state: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    verified_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    verified_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    # Bumped on every edit; feeds the quorum context freeze (§2.5).
    record_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")

    __table_args__ = (
        Index("ix_allowlist_namespace", "namespace_id"),
        Index("ix_allowlist_payee", "payee_key"),
        # (namespace_id, payee_key) is logically unique; the service
        # layer coalesces NULL namespaces for lookup (SQLite treats
        # NULL as distinct in unique constraints, so this stays an
        # index rather than a constraint).
    )


class MoneyPairCooldown(Base):
    """(agent, payee) denial cooldown (Pillar 1 §1.3).

    Separate from ``RefusalCooldown`` because the key is the payee, not
    the argument hash. After a deny on (agent, payee), no new approval
    request for that pair until expiry.
    """

    __tablename__ = "money_pair_cooldowns"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    agent_id: Mapped[str] = mapped_column(String(64), ForeignKey("agents.id"), nullable=False)
    counterparty_key: Mapped[str] = mapped_column(String(256), nullable=False)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        UniqueConstraint(
            "agent_id", "counterparty_key", name="uq_money_pair_cooldown"
        ),
        Index("ix_money_pair_cooldown_lookup", "agent_id", "counterparty_key"),
    )


# ---------------------------------------------------------------------
# Pillar 2 — security-agent runtime state (MVP: red-team agent)
# ---------------------------------------------------------------------

class AgentSchedule(Base):
    """One schedule row per security agent (Pillar 2 §1.3).

    Cron-driven via croniter; the console "Run now" inserts an
    ``agent_runs`` row with trigger='manual'. Schedules seed with
    ``enabled=False`` — no security agent runs until the operator
    starts it (default-off). ``config`` holds per-agent JSON (scenario
    checkboxes, rate limits, severity threshold, daily cap).
    """

    __tablename__ = "agent_schedules"

    agent_id: Mapped[str] = mapped_column(String(64), ForeignKey("agents.id"), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Cron expression (e.g. "0 2 * * *") or "interval" for interval agents.
    cron_expr: Mapped[str] = mapped_column(String(64), nullable=False, default="0 2 * * *")
    timezone: Mapped[str] = mapped_column(String(64), nullable=False, default="America/New_York")
    interval_seconds: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    next_run_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    config: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class AgentRun(Base):
    """One dispatched agent run (Pillar 2 §1.3)."""

    __tablename__ = "agent_runs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # run_… id
    agent_id: Mapped[str] = mapped_column(String(64), ForeignKey("agents.id"), nullable=False)
    # "scheduled" | "manual" | "global_stop" | "redteam_critical"
    trigger: Mapped[str] = mapped_column(String(16), nullable=False, default="scheduled")
    # "requested" | "running" | "ok" | "findings" | "error" | "stopped" | "rate_limited"
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="requested")
    started_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    run_log: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    input: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        Index("ix_agent_runs_agent", "agent_id"),
        Index("ix_agent_runs_status", "status"),
    )


class AgentHeartbeat(Base):
    """Heartbeat after every run and every scheduler tick for interval
    agents (Pillar 2 §1.4). The fleet dashboard's health rule reads the
    latest row per agent: >2× interval amber, >5× red + banner."""

    __tablename__ = "agent_heartbeats"

    agent_id: Mapped[str] = mapped_column(String(64), ForeignKey("agents.id"), primary_key=True)
    run_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    # ok | findings | error | denied | mandate_missing |
    # mandate_forbidden | credential_missing | paused | stopped
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="ok")
    note: Mapped[str] = mapped_column(Text, nullable=False, default="")
    ts: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
