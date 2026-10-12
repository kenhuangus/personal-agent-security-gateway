# PAA10 Provider-Side Sub-Controls — Input Brief for the OWASP Project

**Source:** Personal Agent Security Gateway PAA10 mapping (`05-paa10-mapping.md`, completed 2026-10-12 ~15:35 EDT).
**Status:** Input for the proposed OWASP "Top 10 for Personal AI Agents" project. Not a gateway feature list — these controls sit outside anything a gateway-class intermediary can enforce.

## Why this exists

The gateway mapping traced every PAA01–PAA10 entry through a corrected tool-call flow
(authenticate → validate inputs → check mandate liveness → evaluate policy → approval →
mint token → execute → inspect output → audit) and found 44 new functional requirements
it *can* enforce. It also found 14 sub-controls that are load-bearing for the risk
categories but fundamentally require the platform or the connected service to cooperate.
These belong in the PAA10 project's provider-facing material (provider companion /
responsible-layer analysis), not in gateway code.

## The 14 provider-side sub-controls

1. **Mandate propagation into platform subagents (PAA01).** Platforms must carry
   delegation context into subagents/sub-sessions and expose it to the MCP server;
   otherwise mandate chains stop at the platform boundary.
2. **No bypass action paths (PAA01, PAA07).** Platforms must not offer built-in tools
   that act on the same systems outside the gateway; any bypass voids gateway enforcement.
3. **Client identity stability (PAA01, PAA02).** Stable, verifiable per-agent client
   identity from the platform.
4. **Independent recovery channels (PAA02).** Recovery must live outside the concentrated
   assistant; recovery-change events must be API-visible to the gateway.
5. **No code leakage through platform tools (PAA02).** Platforms must not pass
   verification codes into model context via their own built-in paths.
6. **Upstream sensitivity metadata (PAA03, PAA08).** Connected services must expose
   visibility/sensitivity labels and per-person ownership metadata with enough
   granularity to filter on.
7. **Platform-side context isolation (PAA03).** The platform must isolate contexts in
   model memory and retrieval; the gateway can only filter what crosses its boundary.
8. **Platform memory provenance, correction, deletion (PAA04).** Entirely platform
   territory: provenance records, correction propagation into indexes and scheduled
   work, deletion-scope verification.
9. **Independent counterparty verification services (PAA05).** Account-name
   verification and sender-authentication APIs the gateway can call; trustworthy claim
   metadata from services.
10. **Transaction status and receipt APIs (PAA06).** Outcome/status/receipt endpoints
    for retry gating and receipt verification; cost reporting for aggregate spend
    ceilings.
11. **Service-side origin labeling (PAA07).** Mail and code-host services label
    agent-originated actions; no platform send paths outside the gateway.
12. **Platform access-boundary enforcement (PAA08).** Separate storage/memory boundaries
    per household role inside the platform; service-level bystander notice/correction.
13. **Incentive disclosure at recommendation time (PAA09).** Platforms must disclose paid
    placement and material incentives in the agent's recommendations — the gateway sees
    only tool-call time, not the recommendation moment.
14. **Platform session/worker termination (PAA10).** Platforms must expose termination
    of their own sessions and workers, plus provider-owned recovery flows; the gateway
    stops and reports only gateway-visible work.

## Caveats (flagged, not asserted)

The mapping marks 8 open assumptions the project should not promise on: whether
Gmail/Calendar APIs expose forwarding/filter settings and per-item sensitivity flags
at needed granularity; whether platform-spawned subagent calls are distinguishable
from the parent's; whether any platform exposes incentive/sponsor metadata to MCP
servers; whether MVP connectors expose transaction-status endpoints; that a "global
stop" has no meaning for work outside gateway tool calls. Full list: `05-paa10-mapping.md`
§(ii), AQ-1…AQ-8.

## Suggested use

Hand to the proposed co-leads as scenario/evaluation input (Iftach: control tests need
provider cooperation — these are the boundaries a reference implementation cannot
cross alone) and as provider-companion material (Dean: the "which layer is responsible"
analysis the project roadmap calls for).
