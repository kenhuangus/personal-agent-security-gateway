"""Security-agent mandate validation (Pillar 2 §2.4).

The four agents observe, draft, and escalate — they never pause
agents, block payees, revoke credentials, change policy, or engage
global stop. ``validate_security_mandate`` refuses forbidden tool
patterns; it is called at seed time, at console schedule-enable time,
and at every run start against the *resolved* DB allowlist. The
pipeline's own mandate check (``mandate_scope_exceeded``) remains the
runtime backstop.

Wildcard-aware: ``vault.*`` matches ``vault.read`` and ``vault.*``
both; a bare ``*`` matches everything.
"""

from __future__ import annotations

FORBIDDEN_SECURITY_AGENT_TOOL_PATTERNS: tuple[str, ...] = (
    # Policy WRITES only: policy.inspect and policy.dry_run are the
    # read tools the seed allowlists (§2.1) — the agents observe and
    # draft, so reads are in scope. (The arch draft said "policy.*";
    # narrowed because the seed's own allowlists require the reads.)
    "policy.save", "policy.rollback", "policy.delete",
    "vault.*",           # credential material — never agent-visible
    "agent.revoke", "agent.delete", "agent.pause", "agent.cancel",
    "mandate.create", "mandate.end", "mandate.withdraw",
    "mandate.pause", "mandate.narrow",
    "gateway.global_stop",
    "code.pr.merge",     # deferred out of MVP regardless
)


class ForbiddenMandateError(ValueError):
    """A security agent's mandate allowlist contains a forbidden tool."""


def _pattern_matches(pattern: str, tool: str) -> bool:
    if pattern == "*":
        return True
    if pattern.endswith(".*"):
        prefix = pattern[:-2]
        return tool == prefix or tool.startswith(prefix + ".")
    return tool == pattern


def _forbidden_match(allowed_class: str) -> str | None:
    """Return the forbidden pattern matching *allowed_class*, if any.

    The allowlist entry itself may be a wildcard (e.g. ``vault.*``);
    expansion is checked both ways: a forbidden pattern matches when
    the allowed class could authorize a forbidden tool.
    """
    for forbidden in FORBIDDEN_SECURITY_AGENT_TOOL_PATTERNS:
        if _pattern_matches(forbidden, allowed_class):
            return forbidden
        # The allowed class is broader than (or equal to) the forbidden
        # pattern: e.g. allowed "vault.*" vs forbidden "vault.read",
        # or allowed "*" vs anything.
        if allowed_class == "*" or (
            allowed_class.endswith(".*")
            and _pattern_matches(allowed_class, forbidden.rstrip("*").rstrip("."))
        ):
            # Direct check: does the forbidden pattern's namespace fall
            # under the allowed wildcard?
            namespace = forbidden.split(".")[0]
            if allowed_class == "*" or allowed_class == f"{namespace}.*":
                return forbidden
    return None


def validate_security_mandate(allowed_classes: list[str]) -> None:
    """Raise ``ForbiddenMandateError`` on any forbidden tool pattern.

    Called at seed time, at console schedule-enable, and at every run
    start against the resolved DB allowlist (defense in depth against
    hand-edited mandates).
    """
    for cls in allowed_classes or []:
        hit = _forbidden_match(str(cls))
        if hit is not None:
            raise ForbiddenMandateError(
                f"security-agent mandate forbids tool class {cls!r} "
                f"(matches forbidden pattern {hit!r}): agents observe, "
                "draft, and escalate — they never pause agents, block "
                "payees, revoke credentials, change policy, or stop the "
                "gateway"
            )
