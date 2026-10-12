# Review Log — Personal Agent Security Gateway planning docs

**Scope:** `00-build-plan.md`, `01-requirements.md`, `02-design.md`, `03-architecture.md`, `04-review.md` (historical — read-only), `05-paa10-mapping.md`, `mockups/dashboard.html`, all under `~/workspace/mcp-gateway/docs/`.
**Method:** 3 strictly sequential rounds. Each round: a FRESH adversarial reviewer (new agent, no prior-round exposure) attacked all docs for (a) internal contradictions, (b) security holes in auth/approval/audit, (c) honest-claims violations, (d) MVP feasibility, (e) traceability gaps, (f) verification that prior-round fixes actually landed. A fixer then resolved ALL blockers and majors (and cheap minors), quoting each change. Non-regression constraints throughout: Fix A (auth wall — single credential per agent, OAuth 2.1 primary, gated conditional fallback only, no third rung, exactly two token layers) and Fix B (approval workflow — validate-first, caller-bound approval_status, inert card rendering, grant-before-rule evaluation, anti-CSRF, queue caps, one-time grants, idempotent/atomic grant handling). Neither was weakened by any fix; both were strengthened.

**Totals:** Round 1: 8 blockers, 19 majors, 13 minors — all fixed. Round 2: 2 blockers, 4 majors, 11 minors (+1 residual) — all fixed; 39/40 Round-1 items verified (1 partial → fixed). Round 3: 0 blockers, 7 majors, 14 minors — all fixed; all Round-2 items verified. **79 findings, 79 resolved. Zero open blockers/majors/minors.**

---

## Round 1 (reviewer: fresh agent #1; fixer: applied 2026-10-12)

Headline: the plan (00) stated the corrected Fix A/Fix B behavior, but design artifacts (02, 03) still contradicted Fix A in load-bearing places and omitted the Fix B validation gate; the 44 new PAA10 requirements had no milestone, no console home, and two referenced nonexistent tools.

### Blockers — all fixed
| ID | Finding | Fix (location) |
|---|---|---|
| B-1 | 02 §6.1/§6.2 instructed dual credential issuance by default (Fix A violation) | Rewritten to single-credential issuance with gated fallback; §4.2 checklist records verified auth method + test date |
| B-2 | 03 §2.3 recommended "dual-auth" with a weak fallback gate | Rewritten to single-credential rule; fallback only after demonstrably FAILED OAuth verification |
| B-3 | 03 AOQ-1 retained an IP-allowlist third rung | Marked explicitly REJECTED; refusal floor stated |
| B-4 | 01 §9 OQ-1/OQ-3 recommended building dual-auth | Rewritten to gated single-credential fallback; added to §10.11 tracked-amendments list |
| B-5 | 03 §6 T2 overstated derived-token binding (claimed (agent,tool,action) containment that isn't cryptographic) | Honest blast radius stated (live bearer within connector scopes until expiry); mitigations corrected (5-min TTL, vault-side only, rotation) |
| B-6 | FR-013's per-(agent,tool,action) scoping unimplementable for OAuth upstreams; 3 tokens described vs Fix A's 2 layers | 03 §2.2 two-token-layer table; FR-013 → FR-013a (gateway claims) / FR-013b (upstream scopes; binding is bookkeeping, not cryptographic) |
| B-7 | 02 §2.8 approval flow omitted the validate-first gate | Validation step inserted before apr_ creation; invalid_input never creates a request |
| B-8 | No exactly-once execution (duplicate apr_ on retry; non-atomic grant consumption) | Idempotent apr_ creation on (agent,tool,argument-hash); atomic compare-and-consume |

### Majors — all fixed
| ID | Finding | Fix (location) |
|---|---|---|
| M-1 | 44 FR-PAAxx-xxx had no milestone; 00 §3/M0–M6 and 02 §8 ignored them | All 48 milestone-tagged (42 MVP, 6 conditional); 00 §3/M0–M6 and 02 §8 traceability updated |
| M-2 | Console IA had no home for PAA10 console FRs | 9 pages (Mandates + Context boundaries added); global stop; per-item status; per-agent pause |
| M-3 | FR-PAA02-002 / FR-PAA07-001 referenced nonexistent tools | email.draft, email.settings.read, email.settings.write added to inventory with schemas; FRs amended with forward rules |
| M-4 | Stale FR-029 cost-budget refs vs 00's MF-13 move-out | FR-029 post-MVP; removed from MVP lists; budget_exceeded defer-labeled |
| M-5 | FR-011/012, AC-04/05/11/12 still pre-review text; MF-10 admin FRs missing | Rewritten/amended; FR-039/040/041 added (admin auth audit, login lockout, policy-change audit) |
| M-6 | MF-6 inert rendering absent from card spec (02 §4.4) | §4.4 rewritten: inert rendering, untrusted-content label, consequence-first, all PAA sections |
| M-7 | CSRF on approval-decision endpoint unspecified | Anti-CSRF specified (02 §2.6); FR-042; per-decision re-auth for destructive scopes |
| M-8 | approval_status caller-binding missing from its own spec | Bound to caller identity; not-found (never denied) semantics |
| M-9 | MF-11 execute-on-approval fallback not designed | Added to 02 §2.8, 03 §1.2, AC-04 |
| M-10 | MF-12 history dry-run endpoint missing | POST /api/policy/dry-run specified (02 §2.6) |
| M-11 | Approval cap missing from 02/01; T5 missing mitigations | FR-028 cap (default 5) + approval_queue_full; T5 mitigations added |
| M-12 | Windowed grants in 02 vs one-time-only MVP | Windowed removed (deferred-post-MVP notes only) |
| M-13 | code.pr.merge in MVP inventory vs 00 deferral | Removed from MVP inventory (deferred note) |
| M-14 | Approval-notification transport unspecified (M3/M4 circularity) | Dedicated exempt system notification path; M3 decoupled from M4 |
| M-15 | Validation milestone split (M3 claims, M5 builds) | M3 minimal vs M5 hardened validator defined (00 §4) |
| M-16 | Approvals-table PII storage unspecified | Redacted args + hash (later superseded by HMAC + evidence subset, R2/R3) |
| M-17 | Session-auth semantics unspecified | Per-request credential validation; session-ID theft in T2 |
| M-18 | Superlatives retained; Streamable HTTP asserted without versions | Labeled as architect's judgment or removed; versions → M0 spike |
| M-19 | Trust boundaries lacked logical-in-MVP labels | Labels added (03 §1.3) |

### Minors — all fixed
m-1: 02 §10 stale non-decision → points at 03 §2. m-2: FR-PAA06-002 canonical-JSON-before-hashing rule. m-3: approval_status polls exempt from FR-030 per-call rows. m-4: safe policy_denied reason vocabulary. m-5: invalid_input never echoes offending args. m-6: grant TTL 30 min from approval. m-7: FR-PAA09-003 cooldown key = (agent,tool,argument-hash). m-8: "timely, not speculative" deleted; designer judgment labeled. m-9: MCP char-set claim → M0 verification. m-10: 4 orphan FRs added (FR-PAA01-008, FR-PAA02-005, FR-PAA05-005, FR-PAA07-005). m-11: 03 §5 archives to object storage. m-12: allowed_via_approval in 02 §7 filter. m-13: approval_status separate rate budget.

---

## Round 2 (reviewer: fresh agent #2; fixer: applied 2026-10-12)

Headline: Round-1 fixes verified real (39/40; M-11 partial — cap missing from card spec → fixed as residual). Two new blockers at the approval/mandate intersection; four new majors.

### Blockers — all fixed
| ID | Finding | Fix (location) |
|---|---|---|
| BLOCKER-1 | Grant short-circuit skipped the mandate check: withdrawn mandate + unexpired grant → allowed | Live-mandate re-check at grant consumption (02 §2.8 step 9, 03 §1.2 step 4); withdrawal/expiry/pause invalidates approved-but-unconsumed grants; FR-PAA01-004 extended; mandate_withdrawn reason |
| BLOCKER-2 | Card evidence requirements vs redacted-arg storage mutually unsatisfiable | Evidence-subset rule (02 §2.8 step 4, 03 §1.2 step 5): cleartext approver-visible fields (recipient/payee, amount/currency, audience, rendered preview) + redacted full args + HMAC-SHA256 (gateway-held key); NFR-DATA-001 named exception (approvals record only) |

### Majors — all fixed
| ID | Finding | Fix (location) |
|---|---|---|
| MAJOR-1 | 00 §3 "7 pages" vs M6 "nine pages" | 00 §3 updated to nine pages, all named |
| MAJOR-2 | FR-PAA09-003 cooldown had no mechanism; step 10 re-presented denied requests | Cooldown stage (02 §2.8 steps 3/10): 24h default, tunable; cooldown_active code; no request, no notification inside cooldown; FR-PAA09-003 amended; §8 traceability fixed |
| MAJOR-3 | Notifier credential gap (M3 "does not wait for M4" but email needs credentials) | Bootstrap deploy-time secret in platform secret store (NOT the M4 vault); NFR-SEC-002 scope note; content limits (agent/tool/timestamp/link only); rate limits; 03 §5 storage row |
| MAJOR-4 | No agent-facing error for paused/canceled agents (FR-PAA10-004) | agent_paused + agent_canceled codes (02 §2.7); mapped in 02 §2.8 step 1 and 03 §1.2 step 1 |

### Minors — all fixed
1. Notification channel decided once (00 §7 param 7, 00 §9 decision 3 closed, 02 §9 DQ-1). 2. tools/list + initialize require agent credential (02 §2.1, 03 §1.2 step 1). 3. 03 §2.3 mTLS row explicitly REJECTED. 4. grant_id removed from approval_status schema; mockup uses apr_/req_ prefixes. 5. Execute-on-approval result delivery made coherent (console relay + result_summary mirror). 6. upstream_failure blocks retry after unknown outcome until status check. 7. Destructive-action examples → calendar.delete / email.settings.write. 8. HMAC-SHA256 replaces plain SHA-256. 9. Dedupe runs before cap check. 10. Real citation added: GHSA-qx49-fqc8-xw99 (2026-09-28) for the MCP SDK OAuth flaw; FR-005/AC-10 reference it. 11. AC-11 p95 isolation method specified (gateway-internal spans; adapter upstream timer subtracted).

### Residual
M-11-residual: cap state missing from card spec → 02 §4.4 shows slot usage ("3 of 5") and expiry-countdown interplay. Fixed.

---

## Round 3 (reviewer: fresh agent #3; fixer: applied 2026-10-12)

Headline: **0 blockers.** All Round-2 items verified. 7 majors + 14 minors, all fixed.

### Majors — all fixed
| ID | Finding | Fix (location) |
|---|---|---|
| MAJOR-1 | Mandate-deny collapsed withdrawn/expired/paused into mandate_withdrawn, violating FR-PAA10-004 and 05's test expectations | Distinct reasons per state in 02 §2.8 step 9 and 03 §1.2 step 4 (withdrawn→mandate_withdrawn, expired→mandate_expired, paused→mandate_paused); invalidation applies to all three |
| MAJOR-2 | Replay-after-consumption contradiction (step 4 vs step 9); execute-on-approval double-execution hazard | New terminal code already_executed (02 §2.7): re-invoke of consumed grant → terminal, no new apr_, no re-execution; steps 3/4/9/10 rewritten to one consistent lookup chain; execute-on-approval consumes the grant atomically at approval time; delivery wording fixed (console relay = human path, result_summary = its machine mirror) |
| MAJOR-3 | "Grants survive policy version changes" vs FR-PAA04-003 correction propagation; no re-validation design home | Material/non-material change classification on every policy save (02 §5); material changes invalidate affected grants + flag pending approvals; policy-supersession check in step 9 (deny reason policy_superseded); 00 §2 Fix B bullet qualified |
| MAJOR-4 | FR-PAA07-005 orphan; §8 over-claimed; tension with DQ-3 | Template-bound recurring notices implemented as a standing POLICY RULE type (02 §5) — no third grant type; FR-PAA07-005 amended; §8 fixed; DQ-3 resolved explicitly |
| MAJOR-5 | FR-039/040/041 had no design home; §8 omitted FR-039–FR-042 | Admin auth endpoints in 02 §2.6 (FR-039 audit, FR-040 rate-limit/lockout); policy-change audit in 02 §5 (FR-041); §8 rows added for FR-039–FR-042 |
| MAJOR-6 | Cooldown bypassed by trivial argument mutation | Denial-streak escalation: 3 denials for same (agent,tool) within 24h → per-(agent,tool) 24h cooldown regardless of arguments (02 §2.8 steps 3/10, 02 §2.7, FR-PAA09-003) |
| MAJOR-7 | Exempt notifier path: no threat analysis, rotation, mechanized content limits, provisioning, failure semantics | T13 STRIDE row (03 §6); rotation via platform secret store (90-day max, audit-logged); fixed field-allowlist construction (02 §2.8 step 5); deploy-chosen sender identity; bounce/delay → in-console fallback; 15-min window from request creation; FR-024 clarified |

### Minors — all fixed
1. Canonical order now "authenticate → validate inputs → check mandate liveness → evaluate policy → …" (00 §2, 03 §1.2, 05 guide). 2. approval_status input renamed approval_request_id (collision resolved). 3. Decision enum standardized on approval_required. 4. Grant TTL (30 min) added as 00 §7 parameter 21. 5. Dedupe hash named HMAC-SHA256 (02 §2.8 step 3, 03 §1.2 step 5). 6. OAuth discovery/metadata/authorization/JWKS carved out as the only public exceptions (02 §2.1). 7. Backup blobs encrypted at rest (03 §5). 8. HMAC key in platform secret store with rotation (03 §5; referenced in 02 §2.8 step 4). 9. Destructive-action registry table added (02 §2.7); referenced by FR-042 and 00 §7 param 3. 10. Verification codes/OTPs/API-key-shaped strings redacted even in evidence preview (02 §2.8 step 4, §4.4). 11. T2b anomaly alerting: recorded OUT of MVP with rationale (03 §6). 12. Mockup synced: cleartext recipient, cap-state line, untrusted-content badge, 9-page sidebar, global stop control, no code.pr.merge. 13. SSRF connector-review checklist REQUIRED for MVP adapters (folded into FR-009 acceptance). 14. OAuth 2.1 terminology standardized (OIDC kept only where identity-specific).

---

## Final verification pass (coordinator, 2026-10-12)

Targeted re-scan of the docs after Round 3's fixes. Result: **zero open blockers, zero open majors, zero open minors.**

- Distinct mandate reasons (`mandate_withdrawn` / `mandate_expired` / `mandate_paused`) present in 02 §2.8 step 9, 03 §1.2 step 4, and the §2.7 vocabulary. ✓
- `already_executed` terminal code present (5 refs in 02); consistent lookup chain pending→`apr_` / consumed→`already_executed` / cooldown→`cooldown_active` in 02 §2.8 and 03 §1.2. ✓
- Policy-supersession check + `policy_superseded` reason present; material/non-material classification in 02 §5; 00 §2 Fix B bullet qualified. ✓
- Template-bound notice rule in 02 §5; FR-PAA07-005 amended; §8 traceability accurate; DQ-3 resolved. ✓
- FR-039–FR-042 have design homes (02 §2.6, §5) and §8 rows. ✓
- Denial-streak escalation present (02 §2.8, 02 §2.7, FR-PAA09-003). ✓
- T13 STRIDE row present; notifier rotation/content/provisioning/failure specified. ✓
- Destructive-action registry present (02 §2.7). ✓
- HMAC-SHA256 everywhere a hash is named (no plain "SHA-256 hash of the canonical" remains). ✓
- Regression greps clean: no `dual-auth`/`dual issuance`; IP-allowlist only in explicit REJECTED marking (AOQ-1) and the pre-existing AOQ-7 console-hosting question; `windowed` only in deferred-post-MVP notes; `budget_exceeded` only as deferred code; `grant_id`/`grt_` zero; `approval-required` (hyphen) zero; `7 pages` zero (nine pages named consistently); `code.pr.merge` only in deferred-out-of-MVP notes; mockup clean. ✓
- `04-review.md` untouched (historical record preserved). ✓
- Fix A and Fix B intact and strengthened (mandate-liveness re-check, `already_executed`, denial-streak escalation, mTLS explicitly rejected). ✓

## Remaining minors

**None.** All minors from all three rounds were fixed. No minor was left open with a deferral rationale.

## Accepted limitations (not defects — recorded design positions)

- 6 of the 48 FR-PAAxx-xxx are tagged "(MVP — conditional)": they degrade visibly (never silently) if upstream/provider support is unverified.
- OpenAI Dots integration path stays provisional — no MVP build; flagged, not asserted.
- All performance numbers are labeled design targets, not promises (docs' convention).
- T2b new-network-origin anomaly alerting is OUT of MVP (recorded decision with rationale).
- Infrastructure decisions (hosting, KMS, deploy pipeline) are deferred per Ken's direction; open decisions live in 00 §9.
- Google/Microsoft/GitHub OAuth app registrations remain Ken's action (his developer accounts; verification lead times are the top schedule risk).

## Readiness verdict

**The planning docs are review-clean and ready for Ken's implementation go-ahead.** Three full adversarial rounds found 79 issues (10 blockers, 30 majors, 39 minors); all 79 are resolved in the docs with quoted changes, verified by the next round's fresh reviewer and by a final coordinator grep pass. Fix A (auth wall) and Fix B (approval workflow) survived all three rounds intact and were strengthened. Traceability holds both directions for 48/48 FR-PAAxx-xxx. No implementation code was written; implementation remains gated on Ken's explicit approval.

## Files touched (all rounds)

- `docs/00-build-plan.md`
- `docs/01-requirements.md`
- `docs/02-design.md`
- `docs/03-architecture.md`
- `docs/05-paa10-mapping.md`
- `docs/mockups/dashboard.html`
- `docs/06-review-log.md` (this file — new)
- `docs/04-review.md` — intentionally untouched (historical record)
