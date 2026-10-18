"""Finding → issue filing pipeline (Pillar 2 §3.4).

Steps, in order, fail-closed at each gate:
1. Severity threshold: below ``GATEWAY_REDATEAM_ISSUE_THRESHOLD``
   → run log only (never filed).
2. Pre-file redaction gate: render the issue body from the fixed
   template, run the gateway's redaction catalog over title + body +
   labels. Any match → filing rejected, finding kept as
   ``draft_blocked``, operator alerted.
3. Duplicate suppression: dedupe key = (scenario_id, control_point).
   An open issue matching the key → post a comment (new occurrence)
   instead of opening. Closed issues do not suppress.
4. Daily cap: ``GATEWAY_REDATEAM_DAILY_ISSUE_CAP`` issues/day from the
   issue-store index. Overflow → run log + dashboard counter.
5. File via ``codehost.issue_open`` (sensitive-gated → the approval
   flow; Path A, approval-per-issue, is the default).

The fixed issue template (§3.4.1) carries: severity, scenario,
first-seen/run, what happened, redacted evidence, blast radius,
suggested control, reproduction, and an optional advisory judge note.
Labels: ``redteam-finding``, severity, ``rt-<nn>``, ``cp:<control>``.
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .findings import Finding, severity_meets

ISSUE_TEMPLATE = """\
## [redteam] {title}
**Severity:** {severity} (scored by the agent, reviewed by human)
**Scenario:** {scenario_id} ({control_point})
**First seen:** {first_seen_utc} · **Agent run:** {run_id}

### What happened
{what_happened}

### Evidence (redacted)
{evidence_lines}

### Blast radius
{blast_radius}

### Suggested control change
{suggested_control}

### Reproduction
{reproduction}
{judge_note_section}\
"""

#: Secret-shaped patterns for the pre-file redaction gate. Any match
#: in the rendered issue → filing rejected, finding kept as
#: ``draft_blocked``, operator alerted. Note: bare 6–8 digit numbers
#: are NOT matched here (amounts in cents are legitimate finding
#: content); only LABELED codes and key-shaped strings are.
_REDACTION_GATE_PATTERNS = (
    ("api_key", re.compile(r"\b(?:sk|ghp|gho|xox[pbar]|AIza)[-_A-Za-z0-9]{16,}\b")),
    ("api_key", re.compile(r"\b[A-Za-z0-9+/]{32,}={0,2}\b")),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("code", re.compile(
        r"(?i)\b(?:verification\s*code|otp|one[\s-]?time\s*(?:pass)?code|2fa\s*code)\b\s*[:=]?\s*([0-9]{4,8})\b")),
)


def render_issue(finding: Finding, judge_note: Optional[str] = None) -> tuple[str, str, list[str]]:
    """Render (title, body, labels) from the fixed template."""
    evidence = finding.evidence or {}
    lines = [
        f"- {key}: `{value}`"
        for key, value in sorted(evidence.items())
        if value is not None
    ]
    body = ISSUE_TEMPLATE.format(
        title=finding.title,
        severity=finding.severity,
        scenario_id=finding.scenario_id,
        control_point=finding.control_point,
        first_seen_utc=finding.first_seen_utc,
        run_id=finding.run_id,
        what_happened=finding.what_happened,
        evidence_lines="\n".join(lines) or "- (none)",
        blast_radius=finding.blast_radius,
        suggested_control=finding.suggested_control,
        reproduction=finding.reproduction,
        judge_note_section=(
            f"\n### Advisory judge note (optional, never a decision basis)\n{judge_note}\n"
            if judge_note
            else ""
        ),
    )
    labels = [
        "redteam-finding",
        finding.severity,
        f"rt-{finding.scenario_id.lower().replace('rt-', '')}",
        f"cp:{finding.control_point}",
    ]
    return f"[redteam] {finding.title}", body, labels


def redaction_gate_ok(title: str, body: str, labels: list[str]) -> tuple[bool, str]:
    """Pre-file redaction gate: any secret-shaped match rejects filing."""
    haystack = "\n".join([title, body, " ".join(labels)])
    for label, pattern in _REDACTION_GATE_PATTERNS:
        if pattern.search(haystack):
            return False, f"redaction-gate hit: {label}"
    return True, ""


@dataclass
class FilingConfig:
    """Per-run filing configuration (from env + schedule row)."""

    issue_threshold: str = "medium"
    daily_issue_cap: int = 10
    repo: str = ""
    # Callable the runner provides: the agent's own MCP call seam so
    # the filing goes through the approval flow like any sensitive
    # tool call (Path A, approval-per-issue, the default).
    call_tool: Optional[Callable[..., Any]] = None
    # Gateway-side lookups (dedupe + daily cap) — the runner wires the
    # real issue opener; tests inject a stub.
    issue_opener: Optional[Any] = None
    judge_note: Optional[str] = None


@dataclass
class FilingOutcome:
    filed: bool
    issue_id: str = ""
    state: str = "new"  # filed | draft_blocked | duplicate | below_threshold | capped
    note: str = ""


async def file_finding(finding: Finding, config: FilingConfig) -> FilingOutcome:
    """Run the five filing gates in order (fail-closed at each gate)."""
    # 1. Severity threshold.
    if not severity_meets(config.issue_threshold, finding.severity):
        finding.filing_state = "below_threshold"
        return FilingOutcome(
            filed=False, state="below_threshold",
            note=f"severity {finding.severity} below threshold {config.issue_threshold}",
        )
    title, body, labels = render_issue(finding, config.judge_note)
    # 2. Pre-file redaction gate.
    ok, reason = redaction_gate_ok(title, body, labels)
    if not ok:
        finding.filing_state = "draft_blocked"
        return FilingOutcome(filed=False, state="draft_blocked", note=reason)
    if config.issue_opener is None or not config.repo:
        finding.filing_state = "draft_blocked"
        return FilingOutcome(
            filed=False, state="draft_blocked",
            note="no issue opener or repo configured",
        )
    # 3. Duplicate suppression: same (scenario, control point) with an
    # open issue → comment with the new run id instead of opening.
    dedupe_key = f"{finding.scenario_id}|{finding.control_point}"
    open_issues = config.issue_opener.find_open_issues(
        repo=config.repo, labels=["redteam-finding", f"rt-{finding.scenario_id.lower().replace('rt-', '')}"]
    )
    for issue in open_issues:
        if issue.dedupe_key == dedupe_key:
            config.issue_opener.comment(
                issue_id=issue.id,
                body=(
                    f"New occurrence in run {finding.run_id} at "
                    f"{finding.first_seen_utc}; evidence: "
                    f"{finding.evidence}"
                ),
            )
            finding.filing_state = "duplicate"
            finding.issue_id = issue.id
            return FilingOutcome(
                filed=False, state="duplicate", issue_id=issue.id,
                note=f"commented on open issue {issue.id}",
            )
    # 4. Daily cap.
    day_start = dt.datetime.now(dt.timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    opened_today = config.issue_opener.count_opened_since(
        repo=config.repo, since_utc=day_start
    )
    if opened_today >= config.daily_issue_cap:
        finding.filing_state = "capped"
        return FilingOutcome(
            filed=False, state="capped",
            note=f"daily cap {config.daily_issue_cap} reached ({opened_today} today)",
        )
    # 5. File via codehost.issue_open — through the agent's own MCP
    # call seam so the sensitive-gated approval flow applies (the
    # human approves the rendered issue body on the card).
    if config.call_tool is None:
        finding.filing_state = "draft_blocked"
        return FilingOutcome(
            filed=False, state="draft_blocked", note="no call seam for filing"
        )
    result = config.call_tool(
        "codehost.issue_open",
        {"repo": config.repo, "title": title, "body": body, "labels": labels},
    )
    if hasattr(result, "__await__"):
        result = await result
    issue_id = ""
    if isinstance(result, dict):
        issue_id = str(result.get("issue_id") or "")
    finding.filing_state = "filed"
    finding.issue_id = issue_id
    finding.filed_at_utc = dt.datetime.now(dt.timezone.utc).isoformat()
    return FilingOutcome(filed=True, state="filed", issue_id=issue_id)
