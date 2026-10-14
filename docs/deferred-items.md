# Deferred items

Tracked post-MVP work: implemented-or-designed pieces with no production
wiring yet. Each entry names the seam, what's missing, and what "done"
looks like. Nothing here blocks the MVP — these are explicit,
reviewed decisions, not forgotten TODOs.

## Ontology feedback loop (GH #29) — DEFERRED post-MVP

**Where the seam is.** `src/gateway/ontology/feedback.py`
(`record_decision_outcome`, `record_correction`, `record_mandate_event`,
`sweep_stale`, `detect_conflicts`) and `src/gateway/ontology/discovery.py`
(`discover_from_accounts`, `discover_from_audit`) plus the store methods
they build on (`OntologyStore.propose_candidates`,
`confirm_candidate`, `reject_candidate`, `flag_for_review`,
`list_review_items`, `resolve_review_item`, `record_feedback_event`).
The intended call sites:

1. `record_decision_outcome` — in the pipeline's terminal audit path
   (next to `AuditStage`), once per call, carrying the decision,
   agent, tool, declared dimensions, principal, and snapshot ref.
2. `record_mandate_event` — in the mandate lifecycle
   (`MandateService` narrow/pause/resume/end/withdraw/expired).
3. `record_correction` — at the counterparty-correction and
   redaction-catalog-edit admin actions.
4. `sweep_stale` / `detect_conflicts` — on a schedule (cron) or an
   admin-console action; `discover_from_audit` on the same cadence.
5. The M6 console review-queue page — list/resolve/dismiss review
   items; confirm/reject candidates (the ONLY promotion path from
   inferred to authority).

**What's missing.** All five call sites: zero production callers today
(unit tests only). Wiring just (1) without (4)+(5) would grow an
unconsumed event log — recorded outcomes with no detector runs and no
human review surface — so the loop is deferred as a unit, not
half-wired.

**Why deferring is safe.** The "living ontology" loop is advisory and
observational: it flags candidates for human review, never auto-mutates
authority (hard rule in `feedback.py`). Enforcement is already real —
`ontology_ctx` resolution at policy time, preference-group restrict-only
upgrades, decision snapshots on the audit row. Deferring the loop loses
continuous self-improvement, not enforcement.

**What "done" looks like.**
- `record_decision_outcome` fires on the terminal audit path behind a
  setting (default on; the write is one indexed row — measure it
  against the AC-11 budget first).
- Mandate/correction hooks (2)+(3) wired at their owning services.
- A scheduled sweep (cron or console action) runs `sweep_stale`,
  `detect_conflicts`, and `discover_from_audit`.
- The console review-queue page renders flags and candidates with
  confirm/reject/resolve/dismiss.
- A soak test: N days of production traffic → review queue shows sane
  flags, zero auto-promotions, no hot-path latency regression.

## kev-4B promotion (GH #33) — documented, pending GPU host

Tracked in `docs/judge-model-runbook.md` (host sizing, serve command,
env knobs, acceptance criteria). Close the issue when the runbook's
acceptance run passes on a GPU host.
