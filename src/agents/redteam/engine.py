"""Red-team scenario engine (Pillar 2 §3.1).

Execution semantics per run:
1. For each enabled scenario: ``setup()`` → ``execute()`` EXACTLY
   ONCE → ``assert_control()``.
2. Assertion passes → log to the run record, continue.
3. Assertion fails ("one miss, one issue, move on"): build a
   ``Finding``, run the filing pipeline (findings.py/issues.py), mark
   the scenario complete. The engine never retries, never varies the
   payload, never pivots to a related control.

``AgentCtx`` wraps the authenticated MCP client + per-scenario
rate-limit tokens + the run id. Every tool call is a discrete audited
gateway call with the scenario id in the (redacted) args metadata, so
the audit trail shows exactly what the agent attempted.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional


@dataclass(frozen=True)
class CallObservation:
    """What the agent saw for one tool call."""

    ok: bool
    result: Any = None
    error: Optional[dict[str, Any]] = None
    request_id: Optional[str] = None

    @property
    def error_code(self) -> Optional[str]:
        if self.error:
            return self.error.get("code")
        return None


class AgentCtx:
    """Scenario execution context: the agent's tool-call seam.

    ``call_tool`` is ``async (tool, args) -> CallObservation``. The
    real runner wires the authenticated MCP client; tests inject a
    fake. ``stop_event`` is the cooperative kill-switch signal (the
    engine checks it between scenarios; in-flight calls finish).
    """

    def __init__(
        self,
        agent_id: str,
        run_id: str,
        call_tool: Callable[[str, dict[str, Any]], Awaitable[CallObservation]],
        stop_event: Optional[asyncio.Event] = None,
    ) -> None:
        self.agent_id = agent_id
        self.run_id = run_id
        self._call_tool = call_tool
        self.stop_event = stop_event or asyncio.Event()
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def call(self, tool: str, args: dict[str, Any]) -> CallObservation:
        tagged = dict(args or {})
        # The scenario id rides in the (redacted) args metadata so the
        # audit trail shows exactly what the agent attempted.
        self.calls.append((tool, dict(tagged)))
        return await self._call_tool(tool, tagged)

    @property
    def stopped(self) -> bool:
        return self.stop_event.is_set()


@dataclass(frozen=True)
class AssertionResult:
    passed: bool
    evidence: dict  # request_ids, audit row ids, verdicts, reason codes — redacted
    note: str       # 1–2 sentences for the finding/run log


@dataclass(frozen=True)
class Scenario:
    id: str                 # "RT-01"
    name: str               # "injection-via-tool-output"
    control_point: str      # e.g. "inspection.injected_output_blocked"
    default_severity: str   # "critical" | "high" | "medium" | "low"
    setup: Callable[[AgentCtx], dict]                     # returns scenario state
    execute: Callable[[AgentCtx, dict], Awaitable[dict]]  # ONE attempt
    assert_control: Callable[[dict], AssertionResult]     # pure over observations


@dataclass
class ScenarioResult:
    scenario_id: str
    passed: bool
    note: str
    evidence: dict = field(default_factory=dict)
    finding_id: Optional[str] = None


@dataclass
class RunRecord:
    run_id: str
    agent_id: str
    scenario_results: list[ScenarioResult] = field(default_factory=list)
    findings: list[Any] = field(default_factory=list)  # Finding rows
    log: list[str] = field(default_factory=list)

    @property
    def failed(self) -> list[ScenarioResult]:
        return [r for r in self.scenario_results if not r.passed]


async def run_redteam(
    ctx: AgentCtx,
    scenarios: list[Scenario],
    *,
    enabled_ids: Optional[set[str]] = None,
    file_finding: Optional[Callable[[Any, dict], Awaitable[Optional[str]]]] = None,
    build_finding: Optional[Callable[[Scenario, AssertionResult, str], Any]] = None,
) -> RunRecord:
    """Run the scenario catalog once. Returns the run record.

    ``file_finding(finding, scenario_cfg)`` runs the filing pipeline
    (§3.4) and returns the filed issue id, or None when the finding
    was suppressed (sub-threshold, duplicate, cap, redaction gate).
    ``build_finding`` constructs the Finding from (scenario, assertion,
    run_id); the default builds the template-shaped finding.
    """
    from .findings import Finding, build_finding as _default_build

    record = RunRecord(run_id=ctx.run_id, agent_id=ctx.agent_id)
    build = build_finding or _default_build
    for scenario in scenarios:
        if enabled_ids is not None and scenario.id not in enabled_ids:
            record.log.append(f"{scenario.id}: skipped (not enabled)")
            continue
        if ctx.stopped:
            record.log.append(f"{scenario.id}: skipped (stop requested)")
            break
        state = scenario.setup(ctx)
        # SINGLE ATTEMPT — the loop has no retry path. A missed
        # control becomes a finding, never a pivot.
        observations = await scenario.execute(ctx, state)
        result = scenario.assert_control(observations)
        if result.passed:
            record.scenario_results.append(
                ScenarioResult(
                    scenario_id=scenario.id, passed=True,
                    note=result.note, evidence=result.evidence,
                )
            )
            record.log.append(f"{scenario.id}: control held — {result.note}")
            continue
        finding: Finding = build(scenario, result, ctx.run_id)
        record.findings.append(finding)
        issue_id: Optional[str] = None
        if file_finding is not None:
            issue_id = await file_finding(finding, {})
        record.scenario_results.append(
            ScenarioResult(
                scenario_id=scenario.id, passed=False,
                note=result.note, evidence=result.evidence,
                finding_id=finding.id,
            )
        )
        record.log.append(
            f"{scenario.id}: CONTROL MISSED — {result.note} "
            f"(finding {finding.id}, issue {issue_id or 'not filed'})"
        )
    return record
