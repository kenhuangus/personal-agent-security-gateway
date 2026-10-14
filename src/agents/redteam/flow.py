"""Red-team runner flow: the ``redteam`` agent's run function.

Wires the scenario engine to the authenticated MCP client and the
filing pipeline. ``codehost.issue_open`` is sensitive-gated, so the
filing call goes through the full Fix-B loop: call → approval_required
→ poll ``gateway.approval_status`` → approved → re-invoke → issue
filed. The human approves the rendered issue body on the card (Path A,
approval-per-issue, the default).
"""

from __future__ import annotations

import asyncio
from typing import Any, Callable, Optional

from sqlalchemy.orm import Session

from ..mcp_client import AgentMCPClient, CredentialMissing, load_agent_credentials
from .engine import AgentCtx, CallObservation, run_redteam
from .findings import Finding
from .issues import FilingConfig, FilingOutcome, file_finding
from .rate_limit import TokenBucket
from .scenarios import SCENARIOS

#: Bounded approval polling for the filing loop (the agent waits for
#: the human; it does not wait forever).
_FILING_POLL_ATTEMPTS = 40
_FILING_POLL_INTERVAL_S = 5.0


def _to_observation(raw: Any, request_id: Optional[str] = None) -> CallObservation:
    """Convert a FastMCP tool result / error into a CallObservation."""
    # FastMCP Client.call_tool returns a result object; error envelopes
    # surface as exceptions or isError results depending on the
    # transport. Normalize both shapes here.
    text = ""
    is_error = False
    result: Any = None
    if raw is not None:
        is_error = bool(getattr(raw, "is_error", False))
        content = getattr(raw, "content", None)
        if content:
            text = "".join(
                getattr(block, "text", "") for block in content
                if getattr(block, "type", "") == "text"
            )
        else:
            text = str(raw)
            result = raw
    if is_error:
        import json

        try:
            payload = json.loads(text)
            error = payload.get("error", {"code": "upstream_failure", "message": text[:500]})
        except (ValueError, AttributeError):
            error = {"code": "upstream_failure", "message": text[:500]}
        return CallObservation(ok=False, error=error, request_id=request_id)
    import json

    try:
        result = json.loads(text) if text else result
    except ValueError:
        result = text
    return CallObservation(ok=True, result=result, request_id=request_id)


async def run_redteam_agent(
    *,
    agent_id: str,
    agent_key: str,
    run_id: str,
    trigger: str,
    run_input: dict[str, Any],
    credential_id: str,
    stop_event: asyncio.Event,
    settings: Any,
    session_factory: Callable[[], Session],
    # Test seams: inject the MCP client and issue opener.
    mcp_client: Optional[AgentMCPClient] = None,
    issue_opener: Optional[Any] = None,
) -> dict[str, Any]:
    """Run one red-team agent run. Returns the scheduler outcome dict."""
    try:
        creds = load_agent_credentials(agent_key)
    except CredentialMissing as exc:
        return {"status": "error", "note": str(exc)}
    transport = "oauth"  # the seed registers agents via OAuth (Fix A)
    gateway_url = f"http://{settings.host}:{settings.port}"
    from ..mcp_client import build_authorization_header

    client = mcp_client or AgentMCPClient(
        agent_id=agent_id,
        gateway_url=gateway_url,
        authorization_header=build_authorization_header(creds, transport),
    )
    await client.connect()
    try:
        bucket = TokenBucket(
            max_per_hour=int(settings.redteam_max_attempts_hour),
            max_per_day=int(settings.redteam_max_attempts_day),
        )
        semaphore = asyncio.Semaphore(int(settings.redteam_max_concurrency))

        async def call_tool(tool: str, args: dict[str, Any]) -> CallObservation:
            raw = await client.call_tool(tool, args)
            return _to_observation(raw)

        async def filing_call_tool(tool: str, args: dict[str, Any]) -> Any:
            """The filing seam: full Fix-B loop for codehost.issue_open."""
            obs = await call_tool(tool, args)
            if obs.error_code != "approval_required":
                return {"issue_id": (obs.result or {}).get("issue_id", "")}
            apr_id = (obs.error or {}).get("details", {}).get("approval_request_id")
            for _ in range(_FILING_POLL_ATTEMPTS):
                await asyncio.sleep(_FILING_POLL_INTERVAL_S)
                poll = await call_tool(
                    "gateway.approval_status", {"approval_request_id": apr_id}
                )
                status = (poll.result or {}).get("status")
                if status == "approved":
                    final = await call_tool(tool, args)
                    return {"issue_id": (final.result or {}).get("issue_id", "")}
                if status in ("denied", "expired", "not_found"):
                    return {"issue_id": "", "filing_blocked": status}
            return {"issue_id": "", "filing_blocked": "poll_timeout"}

        ctx = AgentCtx(
            agent_id=agent_id, run_id=run_id,
            call_tool=_rate_limited_call(call_tool, bucket, semaphore),
            stop_event=stop_event,
        )
        enabled_ids = set(run_input.get("scenarios") or [s.id for s in SCENARIOS])

        async def file_one(finding: Finding, _cfg: dict) -> Optional[str]:
            if issue_opener is None:
                return None
            outcome: FilingOutcome = await file_finding(
                finding,
                FilingConfig(
                    issue_threshold=str(settings.redteam_issue_threshold),
                    daily_issue_cap=int(settings.redteam_daily_issue_cap),
                    repo=str(settings.codehost_issues_repo or ""),
                    call_tool=filing_call_tool,
                    issue_opener=issue_opener,
                ),
            )
            return outcome.issue_id or None

        record = await run_redteam(
            ctx, SCENARIOS, enabled_ids=enabled_ids, file_finding=file_one
        )
        status = "findings" if record.findings else "ok"
        if stop_event.is_set():
            status = "stopped"
        return {
            "status": status,
            "note": f"{len(record.scenario_results)} scenarios, "
                    f"{len(record.failed)} missed, {len(record.findings)} findings",
            "log": {
                "run_id": run_id,
                "trigger": trigger,
                "scenarios": [
                    {
                        "scenario_id": r.scenario_id, "passed": r.passed,
                        "note": r.note, "finding_id": r.finding_id,
                    }
                    for r in record.scenario_results
                ],
                "log": record.log,
            },
        }
    finally:
        await client.close()


def _rate_limited_call(
    call_tool: Callable[[str, dict[str, Any]], Any],
    bucket: TokenBucket,
    semaphore: asyncio.Semaphore,
) -> Callable[[str, dict[str, Any]], Any]:
    """Wrap the call seam with the agent-side token bucket + semaphore."""

    async def wrapped(tool: str, args: dict[str, Any]) -> CallObservation:
        # One token per scenario execute() call is enforced by the
        # engine (it calls once per scenario); the bucket here guards
        # the raw call rate as well.
        if not bucket.consume():
            return CallObservation(
                ok=False,
                error={"code": "rate_limited",
                       "message": "red-team agent-side rate limit exhausted",
                       "details": {"reason": "rate_limited"}},
            )
        async with semaphore:
            return await call_tool(tool, args)

    return wrapped
