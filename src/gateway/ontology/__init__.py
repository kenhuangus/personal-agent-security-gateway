"""Personal ontology governance module.

A structured personal ontology (principals, resources, actions, context
dimensions, scenario slices) plus a default-deny decision integration
for the policy engine. The module judges authorization — it never
executes anything.

Concepts reimplemented independently; no third-party code was copied
(see docs/build-log.md).
"""

from .discovery import discover_from_accounts, discover_from_audit
from .feedback import (
    detect_conflicts,
    record_correction,
    record_decision_outcome,
    record_mandate_event,
    sweep_stale,
)
from .integration import (
    ONTOLOGY_CLAUSE_KEYS,
    OntologyCallState,
    ScopedView,
    applicable_dimension_groups,
    applicable_preference_groups,
    clause_holds,
    deciding_preference_group,
    preference_upgrade,
    resolve_ctx,
    resolve_ctx_for_agent,
    scoped_view,
    validate_ontology_clause,
    validate_ontology_conditions,
)
from .models import (
    CANDIDATE_KINDS,
    CANDIDATE_STATUSES,
    FEEDBACK_KINDS,
    LABEL_CLASSES,
    PREFERENCE_CONSTRAINT_KEYS,
    PRINCIPAL_KINDS,
    PROVENANCE_EXPLICIT,
    PROVENANCE_INFERRED,
    PROVENANCE_SOURCES,
    RELATIONSHIP_TYPES,
    REQUIRES_OWNER_APPROVAL,
    REVIEW_STATUSES,
    OntologyAction,
    OntologyAgentBinding,
    OntologyCandidate,
    OntologyDimension,
    OntologyDimensionGroup,
    OntologyFeedbackEvent,
    OntologyPreferenceGroup,
    OntologyPrincipal,
    OntologyRelationship,
    OntologyResource,
    OntologyReviewItem,
    OntologySnapshot,
    new_ontology_id,
)
from .snapshots import (
    SnapshotInput,
    build_payload,
    capture_snapshot,
    get_snapshot,
    verify_snapshot,
)
from .presets import PRESET_NAMES, apply_preset, list_presets
from .store import ADMIN_TOOL, OntologyError, OntologyStore

__all__ = [
    "ONTOLOGY_CLAUSE_KEYS",
    "ADMIN_TOOL",
    "CANDIDATE_KINDS",
    "CANDIDATE_STATUSES",
    "FEEDBACK_KINDS",
    "LABEL_CLASSES",
    "PREFERENCE_CONSTRAINT_KEYS",
    "PRINCIPAL_KINDS",
    "PROVENANCE_EXPLICIT",
    "PROVENANCE_INFERRED",
    "PROVENANCE_SOURCES",
    "RELATIONSHIP_TYPES",
    "REQUIRES_OWNER_APPROVAL",
    "REVIEW_STATUSES",
    "OntologyAction",
    "OntologyAgentBinding",
    "OntologyCallState",
    "OntologyCandidate",
    "OntologyDimension",
    "OntologyDimensionGroup",
    "OntologyError",
    "OntologyFeedbackEvent",
    "OntologyPreferenceGroup",
    "OntologyPrincipal",
    "OntologyRelationship",
    "OntologyResource",
    "OntologyReviewItem",
    "OntologySnapshot",
    "OntologyStore",
    "PRESET_NAMES",
    "ScopedView",
    "SnapshotInput",
    "applicable_dimension_groups",
    "applicable_preference_groups",
    "apply_preset",
    "build_payload",
    "capture_snapshot",
    "clause_holds",
    "deciding_preference_group",
    "detect_conflicts",
    "discover_from_accounts",
    "discover_from_audit",
    "get_snapshot",
    "list_presets",
    "new_ontology_id",
    "preference_upgrade",
    "record_correction",
    "record_decision_outcome",
    "record_mandate_event",
    "resolve_ctx",
    "resolve_ctx_for_agent",
    "scoped_view",
    "sweep_stale",
    "validate_ontology_clause",
    "validate_ontology_conditions",
    "verify_snapshot",
]
