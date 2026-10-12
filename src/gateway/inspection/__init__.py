"""M5 inspection package: input hardening + output inspection.

- ``validation``: strict format validators, control-char rejection,
  canonicalization before hashing;
- ``rate_limit``: per-agent call budgets (FR-028);
- ``urgency_flags``: false-urgency / deceptive-relationship-claim
  detection on trigger content (FR-PAA09-002);
- ``injection_scan``: prompt-injection pattern scanning of tool
  outputs (FR-026);
- ``redaction``: PII + code-artifact redaction catalog (FR-027,
  FR-PAA02-001, NFR-DATA-001);
- ``context_labels``: cross-context leakage flagging (FR-PAA03-003);
- ``output``: the real ``InspectOutputStage`` (03 §1.2 step 8).
"""

from .context_labels import (
    LeakageReport,
    check_leakage,
    extract_labeled_facts,
    log_leakage_event,
)
from .injection_scan import InjectionFinding, ScanResult, redact_findings, scan_output
from .output import InspectOutputStage, InspectionConfig
from .rate_limit import APPROVAL_STATUS_TOOL, RateLimiter
from .redaction import (
    DEFAULT_PATTERNS,
    RedactionCatalog,
    RedactionEvent,
    redact_ctx_for_audit,
    redact_text,
    redact_value,
)
from .urgency_flags import scan_trigger_content, urgency_flags_for_approval_record
from .validation import (
    STRICT_FORMAT_CHECKER,
    canonicalize_args,
    find_control_chars,
    validate_against_schema,
    walk_strings,
)

__all__ = [
    "STRICT_FORMAT_CHECKER",
    "APPROVAL_STATUS_TOOL",
    "DEFAULT_PATTERNS",
    "InspectOutputStage",
    "InspectionConfig",
    "InjectionFinding",
    "LeakageReport",
    "RateLimiter",
    "RedactionCatalog",
    "RedactionEvent",
    "ScanResult",
    "canonicalize_args",
    "check_leakage",
    "extract_labeled_facts",
    "find_control_chars",
    "log_leakage_event",
    "redact_ctx_for_audit",
    "redact_findings",
    "redact_text",
    "redact_value",
    "scan_output",
    "scan_trigger_content",
    "urgency_flags_for_approval_record",
    "validate_against_schema",
    "walk_strings",
]
