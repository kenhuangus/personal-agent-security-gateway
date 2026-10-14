"""Output inspection stage (M5; 03 §1.2 step 8).

Order inside the stage: injection scan → PII/code-artifact redaction →
context-leakage flags → (urgency flags were computed earlier, at
validate time, because the approval card needs them at step 5 —
see urgency_flags.py).

- Injection hit: block (``injected_output_blocked``) or redact the
  matched spans, per the per-tool ``injection_action`` policy hook
  ("block" default). EVERY detection is audit-logged (AC-06).
- Redaction: the catalog applies to outputs before agent delivery
  (NFR-DATA-001); events are audit-logged.
- Leakage: private/family-labeled facts in a work-purpose response are
  flagged and redacted per the per-tool ``leakage_action`` hook
  ("redact" default); events are audit-logged (FR-PAA03-003).

Fail-closed (03 §7): ANY exception inside this stage denies the call
with ``injected_output_blocked`` — output is never passed through
uninspected.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from .. import errors as _errors
from . import injection_scan
from .context_labels import check_leakage, log_leakage_event
from .redaction import RedactionCatalog, redact_value


@dataclass
class InspectionConfig:
    """Per-tool policy hooks for output inspection (the "per policy"
    in FR-026/FR-027/FR-PAA03-003).

    Mappings are tool name → action; anything unlisted takes the
    default. The M2 policy engine can bind these per agent later; for
    M5 they are gateway-level with per-tool overrides.
    """

    # tool → "block" | "redact" (default "block")
    injection_action: dict[str, str] = field(default_factory=dict)
    # tool → "redact" | "flag" (default "redact")
    leakage_action: dict[str, str] = field(default_factory=dict)

    def injection_action_for(self, tool: str) -> str:
        action = self.injection_action.get(tool, "block")
        return action if action in ("block", "redact") else "block"

    def leakage_action_for(self, tool: str) -> str:
        action = self.leakage_action.get(tool, "redact")
        return action if action in ("redact", "flag") else "redact"


class InspectOutputStage:
    """Step 8: output inspection (real M5 implementation).

    ``audit`` is the shared ``AuditLog`` (detection events); ``catalog``
    the ``RedactionCatalog``; ``config`` the per-tool policy hooks.
    All are optional for unit-test construction — the stage fails
    closed (deny) rather than passing output through uninspected when a
    dependency is missing or raises.

    ``judge`` is an optional ``gateway.judge.JudgeInspectionHook``
    (default None = hook not installed). When installed it fires only
    after the deterministic injection scan flagged suspicion, or on
    every output when the hook's ``always_on`` is set
    (``GATEWAY_JUDGE_ALWAYS_ON=1``). A high-confidence judge "yes"
    reuses the EXISTING ``injected_output_blocked`` halt; any other
    outcome (no / unsure / unavailable) leaves the deterministic
    verdict untouched — the hook can only add friction, never remove
    it.
    """

    name = "inspect_output"

    def __init__(
        self,
        audit: Any = None,
        catalog: Optional[RedactionCatalog] = None,
        config: Optional[InspectionConfig] = None,
        judge: Optional[Any] = None,
    ) -> None:
        self.audit = audit
        self.catalog = catalog if catalog is not None else RedactionCatalog()
        self.config = config if config is not None else InspectionConfig()
        self.judge = judge

    def run(self, ctx: Any) -> Optional[_errors.GatewayError]:
        from ..pipeline import timing_span  # lazy: pipeline imports this module

        try:
            with timing_span(ctx, "inspect_output"):
                return self._inspect(ctx, timing_span)
        except Exception:
            # Fail closed (03 §7): a scanner error denies the call —
            # output is never delivered uninspected.
            return _errors.make_error(
                "injected_output_blocked",
                f"{ctx.tool}: output inspection failed; failing closed",
                ctx.request_id,
                {"tool": ctx.tool, "scanner_error": True},
            )

    def _inspect(self, ctx: Any, timing_span: Any) -> Optional[_errors.GatewayError]:
        # -- 1. prompt-injection scan (FR-026) ---------------------------
        with timing_span(ctx, "inspect.injection_scan"):
            scan = injection_scan.scan_output(ctx.result, ctx.tool)
        if scan.hit:
            self._log_injection_event(ctx, scan, acted=True)
            action = self.config.injection_action_for(ctx.tool)
            if action == "block":
                return _errors.make_error(
                    "injected_output_blocked",
                    f"{ctx.tool}: tool output blocked (prompt-injection pattern detected)",
                    ctx.request_id,
                    {"tool": ctx.tool, "patterns": scan.pattern_ids},
                )
            # "redact": strip the matched spans, keep the call alive.
            with timing_span(ctx, "inspect.injection_redact"):
                ctx.result = injection_scan.redact_findings(ctx.result, scan)

        # -- 1b. judge manipulation scan (advisory; friction-additive) --
        # Pre-filter gate: fires only when the deterministic scanner
        # flagged suspicion, or on every output when the hook's
        # always_on is set (GATEWAY_JUDGE_ALWAYS_ON=1). A
        # high-confidence judge "yes" reuses the EXISTING
        # injected_output_blocked halt (no new deny code); no / unsure /
        # unavailable leaves the deterministic verdict untouched.
        # Note: a deterministic block above already returned, so this
        # gate can only escalate a "redact" outcome or an always_on
        # pass — never clear a deterministic finding.
        if self.judge is not None and (scan.hit or self.judge.always_on):
            with timing_span(ctx, "inspect.judge"):
                judge_error = self.judge.check(ctx, ctx.result)
            if judge_error is not None:
                return judge_error

        # -- 2. PII / code-artifact redaction (FR-027, FR-PAA02-001) ------
        with timing_span(ctx, "inspect.redaction"):
            redacted, events = redact_value(
                ctx.result, self.catalog, tool=ctx.tool, agent_id=ctx.agent_id)
        if events:
            ctx.result = redacted
            self._log_redaction_event(ctx, events, scope="result")

        # -- 3. cross-context leakage (FR-PAA03-003) ----------------------
        with timing_span(ctx, "inspect.leakage"):
            leaked, report = check_leakage(
                ctx, ctx.result,
                leakage_action=self.config.leakage_action_for(ctx.tool),
            )
        if report.hit:
            ctx.result = leaked
            log_leakage_event(self.audit, ctx, report)
        # The report (incl. the "unlabeled" marker count) rides on the
        # context for observability; labels are never guessed.
        ctx.inspection_notes["leakage"] = {
            "flagged": len(report.flagged),
            "unlabeled": report.unlabeled_count,
            "action": report.action,
        }
        return None

    # -- audit events ----------------------------------------------------

    def _log_injection_event(self, ctx: Any, scan: Any, acted: bool) -> None:
        if self.audit is None:
            return
        action = self.config.injection_action_for(ctx.tool)
        redacted_args: dict[str, Any] = {
            "patterns": scan.pattern_ids,
            "fields": sorted({f.field for f in scan.findings}),
            "acted": acted,
        }
        # GH #15: the byte budget blinds the scanner past the cap —
        # record that (and how much) so the blind spot is auditable.
        if getattr(scan, "truncated", False):
            redacted_args["scan_truncated"] = True
            redacted_args["scan_truncated_fields"] = list(
                getattr(scan, "truncated_fields", []))
            redacted_args["scan_truncated_field_count"] = getattr(
                scan, "truncated_field_count", 0)
        self.audit.append(
            agent_id=ctx.agent_id,
            tool="inspection.injection_scan",
            decision="denied" if action == "block" else "allowed",
            request_id=ctx.request_id,
            reason="injected_output_blocked" if action == "block"
                   else "injected_output_redacted",
            redacted_args=redacted_args,
        )

    def _log_redaction_event(self, ctx: Any, events: list, scope: str) -> None:
        if self.audit is None:
            return
        self.audit.append(
            agent_id=ctx.agent_id,
            tool="inspection.redaction",
            decision="allowed",
            request_id=ctx.request_id,
            reason="pii_redacted",
            redacted_args={
                "scope": scope,
                "fields": sorted({e.field for e in events}),
                "patterns": sorted({e.pattern for e in events}),
                "replacements": sum(e.count for e in events),
            },
        )
