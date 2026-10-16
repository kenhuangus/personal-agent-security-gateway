"""Red-team agent: scheduled attack-scenario prober (Pillar 2 §3).

Deterministic scenario code — no LLM dependency. Scenarios are
single-attempt with assertion: once a control fails, the agent records
the finding and stops that scenario. It does not pivot, escalate, or
retry variants. "One miss, one issue, move on" is structural (the
loop has no retry path), not just a prompt instruction.
"""

from .engine import (
    AgentCtx,
    AssertionResult,
    CallObservation,
    RunRecord,
    Scenario,
    ScenarioResult,
    run_redteam,
)
from .scenarios import SCENARIOS

__all__ = [
    "AgentCtx",
    "AssertionResult",
    "CallObservation",
    "RunRecord",
    "Scenario",
    "ScenarioResult",
    "SCENARIOS",
    "run_redteam",
]
