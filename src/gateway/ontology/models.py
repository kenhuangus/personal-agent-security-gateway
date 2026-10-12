"""Personal ontology data model (PAA03 context scoping, PAA08 household,
PAA04 provenance).

Concepts (structured personal ontology; decision-only governance):
- Principals: people, agents, services — with directed relationships
  between them (e.g. household membership, ownership, delegation).
- Resources: data/tools with a label class (work/private/family) and an
  owning principal.
- Actions: named capabilities with a default sensitivity.
- Context dimensions: named axes (purpose, location, ...) with a closed
  set of allowed values.
- Dimension groups: named dimension=value combos ("scenario slices").
- Preference groups: per-combo constraints (allow / require_approval /
  deny tool selectors) that can only further restrict a decision, never
  widen it.
- Ontology snapshots: immutable, content-addressed records of the slice
  used at a decision (PAA04 traceability).

All tables live on the shared config-DB Base (``gateway.models.Base``);
no new database files, no new infrastructure. The engine judges
authorization — it never executes anything itself (default-deny).

License note: the concepts here are reimplemented independently from a
plain-language description. No code was copied, ported, vendored, or
translated from any third-party repository (see docs/build-log.md).
"""

from __future__ import annotations

import datetime as dt
import secrets
from typing import Optional

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from ..models import Base, utcnow


# ---------------------------------------------------------------------
# Vocabularies (closed sets; extend by editing here, never silently)
# ---------------------------------------------------------------------

PRINCIPAL_KINDS: tuple[str, ...] = ("person", "agent", "service")

#: Directed relationship types between principals.
RELATIONSHIP_TYPES: tuple[str, ...] = (
    "household_member_of",
    "owns",
    "delegates_to",
    "acts_for",
)

#: Data-label classes (FR-PAA03-001 vocabulary).
LABEL_CLASSES: tuple[str, ...] = ("work", "private", "family")

#: Constraint lists a preference group may carry. They only restrict:
#: a matching "deny" denies, a matching "require_approval" escalates;
#: "allow" is documentation (policy rules remain the authority).
PREFERENCE_CONSTRAINT_KEYS: tuple[str, ...] = (
    "allow",
    "require_approval",
    "deny",
)

#: The only rule-level "requires" value the policy engine understands.
REQUIRES_OWNER_APPROVAL = "owner_approval"

#: Provenance vocabulary (FR-PAA04-001). Inferred entries are always
#: distinguished from explicit ones: ``"inferred:<source>"`` vs
#: ``"explicit:<source>"``. Sources are free-form but SHOULD be one of
#: the _SOURCE constants below so the console can group them.
PROVENANCE_EXPLICIT = "explicit"
PROVENANCE_INFERRED = "inferred"

#: Known provenance sources (advisory — the store does not hard-fail
#: unknown sources, but discovery/feedback/presets use these).
PROVENANCE_SOURCES: tuple[str, ...] = (
    "audit-log",     # discovery over the audit log
    "accounts",      # discovery over connected-account metadata
    "pipeline",      # feedback from decision outcomes
    "mandates",      # feedback from mandate narrow/pause/end/withdraw
    "counterparty",  # feedback from counterparty-record corrections
    "console",       # explicit console action
    "seed",          # seed_household / manual seeding
    "preset",        # preset application
    "manual",        # direct store authoring (the fallback path)
)

#: Candidate entity kinds the discovery module may propose.
CANDIDATE_KINDS: tuple[str, ...] = (
    "principal",
    "relationship",
    "resource",
    "action",
    "dimension",
    "dimension_group",
    "preference_group",
)

#: Candidate lifecycle states. Nothing with status
#: ``pending_confirmation`` is authority — it only becomes authority
#: through ``confirm_candidate`` (FR-PAA04-002: no auto-promotion).
CANDIDATE_STATUSES: tuple[str, ...] = (
    "pending_confirmation",
    "confirmed",
    "rejected",
)

#: Review-queue item states (surfaced for the M6 console; the queue
#: flags, it never auto-mutates).
REVIEW_STATUSES: tuple[str, ...] = ("open", "resolved", "dismissed")

#: Feedback event kinds.
FEEDBACK_KINDS: tuple[str, ...] = (
    "decision",      # allowed / denied / approved outcome
    "correction",    # counterparty / instruction / redaction correction
    "mandate",       # mandate narrow / pause / end / withdraw / expired
    "stale",         # stale-candidate sweep
)


def new_ontology_id() -> str:
    """Mint a 128-bit ``ont_`` id (same shape as req_/apr_/mnd_)."""
    return f"ont_{secrets.token_hex(16)}"


# ---------------------------------------------------------------------
# Principals and relationships (PAA08 household seeding)
# ---------------------------------------------------------------------

class OntologyPrincipal(Base):
    """A principal: a person, an agent, or a service.

    Household roles (PAA08) are seeded as person principals linked by
    ``household_member_of`` relationships (see OntologyStore.seed_household).
    """

    __tablename__ = "ontology_principals"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)  # person|agent|service
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    # Provenance (FR-PAA04-001): "explicit:<source>" or
    # "inferred:<source>". Discovery writes "inferred:*" here only via
    # the candidate-confirmation path.
    provenance: Mapped[str] = mapped_column(
        String(64), nullable=False, default="explicit:manual"
    )
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )


class OntologyRelationship(Base):
    """A directed relationship between two principals.

    Both ends must exist (validated in the store — no dangling
    references). ``relation_type`` is one of RELATIONSHIP_TYPES.
    """

    __tablename__ = "ontology_relationships"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source_principal_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("ontology_principals.id"), nullable=False
    )
    relation_type: Mapped[str] = mapped_column(String(32), nullable=False)
    target_principal_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("ontology_principals.id"), nullable=False
    )
    provenance: Mapped[str] = mapped_column(
        String(64), nullable=False, default="explicit:manual"
    )
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    __table_args__ = (
        Index("ix_ont_rel_source", "source_principal_id"),
        Index("ix_ont_rel_target", "target_principal_id"),
        UniqueConstraint(
            "source_principal_id", "relation_type", "target_principal_id",
            name="uq_ont_relationship",
        ),
    )


class OntologyAgentBinding(Base):
    """Binds a gateway agent id to an ontology principal.

    Lets ``evaluate_call`` resolve the calling principal from the agent
    when the caller did not pass ``principal_id`` explicitly in
    ``ontology_ctx``. One binding per agent.
    """

    __tablename__ = "ontology_agent_bindings"

    agent_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    principal_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("ontology_principals.id"), nullable=False
    )
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )


# ---------------------------------------------------------------------
# Resources and actions
# ---------------------------------------------------------------------

class OntologyResource(Base):
    """A governed resource: data or capability with a label class and an
    owning principal (PAA03 label classes, PAA08 ownership)."""

    __tablename__ = "ontology_resources"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    label_class: Mapped[str] = mapped_column(String(16), nullable=False)  # work|private|family
    owner_principal_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("ontology_principals.id"), nullable=False
    )
    provenance: Mapped[str] = mapped_column(
        String(64), nullable=False, default="explicit:manual"
    )
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    __table_args__ = (Index("ix_ont_resource_owner", "owner_principal_id"),)


class OntologyAction(Base):
    """A named action/capability with a default sensitivity."""

    __tablename__ = "ontology_actions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    default_sensitivity: Mapped[str] = mapped_column(
        String(16), nullable=False, default="standard"
    )  # standard | sensitive
    provenance: Mapped[str] = mapped_column(
        String(64), nullable=False, default="explicit:manual"
    )
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )


# ---------------------------------------------------------------------
# Context dimensions, dimension groups, preference groups
# ---------------------------------------------------------------------

class OntologyDimension(Base):
    """A context dimension with a closed set of allowed values
    (e.g. purpose: [work, personal, family])."""

    __tablename__ = "ontology_dimensions"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    allowed_values: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    provenance: Mapped[str] = mapped_column(
        String(64), nullable=False, default="explicit:manual"
    )


class OntologyDimensionGroup(Base):
    """A named set of dimension=value pairs — a "scenario slice"
    (e.g. "at_office": {purpose: work, location: office})."""

    __tablename__ = "ontology_dimension_groups"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    dimensions: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    provenance: Mapped[str] = mapped_column(
        String(64), nullable=False, default="explicit:manual"
    )
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )


class OntologyPreferenceGroup(Base):
    """Per-dimension-combo constraints.

    Binds a dimension group to per-tool constraints. At evaluation, a
    group whose dimensions are all satisfied by the call's declared
    dimensions can only RESTRICT the policy decision (deny or
    require_approval) — never widen it.
    """

    __tablename__ = "ontology_preference_groups"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    dimension_group_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("ontology_dimension_groups.id"), nullable=False
    )
    # {"allow": [...], "require_approval": [...], "deny": [...]} —
    # entries are tool selectors, supporting "prefix.*" wildcards.
    constraints: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    provenance: Mapped[str] = mapped_column(
        String(64), nullable=False, default="explicit:manual"
    )
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )


# ---------------------------------------------------------------------
# Decision snapshots (PAA04 traceability)
# ---------------------------------------------------------------------

class OntologySnapshot(Base):
    """Immutable, content-addressed snapshot of the ontology slice used
    at a decision.

    ``id`` is the tagged HMAC-SHA256 digest (``key_id:hexdigest``) of the
    canonical payload — the ref doubles as the address (same convention
    as ``hmac_util``). There is deliberately NO update/delete API:
    snapshots are write-once. Decision/audit rows carry the ref in
    ``ontology_snapshot_ref``.
    """

    __tablename__ = "ontology_snapshots"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)  # kid:hexdigest
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )


# ---------------------------------------------------------------------
# Discovery candidates, review queue, feedback events
# (the "living ontology" loop — PAA04)
# ---------------------------------------------------------------------

class OntologyCandidate(Base):
    """A discovery-proposed ontology entry awaiting confirmation.

    Candidates are NOT authority: nothing with
    ``status="pending_confirmation"`` is consulted by the policy
    engine. ``confirm_candidate`` promotes a candidate into a real
    entity (provenance ``"inferred:<source> -> explicit:confirmed"``);
    ``reject_candidate`` drops it. ``dedupe_key`` keeps repeated
    discovery sweeps from proposing the same entry twice.
    """

    __tablename__ = "ontology_candidates"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    provenance: Mapped[str] = mapped_column(
        String(64), nullable=False
    )  # "inferred:<source>"
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default="pending_confirmation"
    )
    dedupe_key: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True
    )
    # Full provenance chain once decided, e.g.
    # "inferred:audit-log -> explicit:confirmed".
    provenance_chain: Mapped[Optional[str]] = mapped_column(
        String(256), nullable=True
    )
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    decided_at: Mapped[Optional[dt.datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (Index("ix_ont_candidate_status", "status"),)


class OntologyReviewItem(Base):
    """A flagged entry needing human review (PAA04).

    The feedback loop FLAGS stale/conflicting entries here — it never
    auto-mutates authority. Surfaced by the M6 console; resolution is
    explicit (resolved/dismissed with the reviewer's identity in the
    audit log).
    """

    __tablename__ = "ontology_review_queue"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    entry_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    entry_id: Mapped[str] = mapped_column(String(128), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    detected_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="open"
    )
    provenance: Mapped[str] = mapped_column(String(64), nullable=False)
    context: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    __table_args__ = (Index("ix_ont_review_status", "status"),)


class OntologyFeedbackEvent(Base):
    """An immutable record that something in the world changed in a way
    the ontology should know about: a decision outcome, a correction,
    a mandate lifecycle event. Write-only for the pipeline; the
    feedback module turns these into review-queue flags — never into
    silent authority changes."""

    __tablename__ = "ontology_feedback_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    summary: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    provenance: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    __table_args__ = (Index("ix_ont_feedback_kind", "kind"),)
