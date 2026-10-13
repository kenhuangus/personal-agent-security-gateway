"""Demo connector tools for the one-command docker-compose demo.

Enabled ONLY when ``GATEWAY_DEMO_TOOLS=1`` (the compose ``gateway``
service sets it; default off everywhere else). Two routine tools with
canned responses:

- ``demo.read``  — the seeded policy contains an explicit allow rule
  for the demo agent, so a call exercises the full ALLOW path
  (auth → validate → mandate → policy → execute).
- ``demo.write`` — no allow rule covers it, so a call exercises the
  pinned default-deny (DENY path).

Both are ``routine`` sensitivity so no approval step is involved; the
smoke test asserts the pure policy decisions. These tools exist for
the demo only and must never be enabled in production.
"""

from __future__ import annotations

from typing import Any

from .pipeline import ToolDescriptor


def _read(ctx: Any, args: dict[str, Any]) -> dict[str, Any]:
    return {"demo": "read-ok", "echo": args}


def _write(ctx: Any, args: dict[str, Any]) -> dict[str, Any]:
    # Unreachable while the seeded policy has no allow rule for
    # demo.write (default-deny); kept for symmetry if a reviewer adds
    # one.
    return {"demo": "write-ok", "echo": args}


def make_demo_tools() -> list[ToolDescriptor]:
    """Build the demo connector's tool descriptors."""
    return [
        ToolDescriptor(
            name="demo.read",
            description=(
                "Demo read tool. The seeded demo policy allows this for "
                "the demo agent."
            ),
            input_schema={"type": "object"},
            sensitivity="routine",
            handler=_read,
        ),
        ToolDescriptor(
            name="demo.write",
            description=(
                "Demo write tool. The seeded demo policy has no allow "
                "rule for this, so it is denied by the pinned "
                "default-deny."
            ),
            input_schema={"type": "object"},
            sensitivity="routine",
            handler=_write,
        ),
    ]
