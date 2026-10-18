"""AI security agents (Pillar 2).

The four agents run in a dedicated ``agents-runner`` process and call
back into the gateway as ordinary MCP clients over Streamable HTTP,
authenticating with their own Fix-A credentials. No in-process
pipeline bypass — every agent call goes through auth → validate →
mandate → policy → approval → execute → inspect → audit exactly like
any other agent.

Deterministic-first: red-team scenarios and sentinel detectors are
deterministic code with no LLM dependency, so the MVP ships and tests
with zero model, zero network, zero GPU.
"""

__all__ = ["runner", "scheduler", "mandates", "mcp_client", "llm", "seed"]
