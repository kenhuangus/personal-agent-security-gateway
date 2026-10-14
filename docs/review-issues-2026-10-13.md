# Production-Readiness Review — Issue List (2026-10-13)

Deep review of `src/gateway/` on branch `hackathon/readiness` (plus
`docker-compose.yml`, `docker/`, `scripts/`), by a 3-reviewer team.
Lens: security gaps → fail-closed violations → correctness → resilience →
observability → config/secrets → testing/docs. The 79 findings in
`docs/06-review-log.md` were excluded unless verified missing in code.
Every issue below cites a concrete file + line and is actionable; no
fixes were implemented.

---

## 1. Give UpstreamTokenIssuer a credential path for the production OAuth exchange

**Severity:** high
**Where:** `src/gateway/vault/minter.py:46-60` (protocol), `:105-128` (mint)
**What/why:** `mint()` reads the vault credential into `_stored` and then
drops it on the floor — `UpstreamTokenIssuer.issue(agent_id, scopes,
ttl_seconds)` receives no credential, and the docstring's claim that
"`_stored` is used for the exchange inside the issuer" is false in code.
The mock works because it mints fake tokens, but a production
Google/Microsoft `refresh_token` exchange has no way to receive the
refresh token. The build log's claim that production wiring "plugs in
here without touching the pipeline" is therefore wrong: the protocol
itself must change, which means changing the minter. This blocks the
core credential-isolation flow in production.
**Suggested fix:** Extend the protocol (e.g.
`issue(credential: str, agent_id, scopes, ttl)`) or give the issuer a
credential-provider callback; keep the credential out of logs, ledger,
and audit either way.

## 2. Bind content_hash to the bytes that actually execute

**Severity:** high
**Where:** `src/gateway/approval_card.py:140-148` vs `:160-163`
(`email.send`); `:220-222` vs `:227-228` (`code.pr.open`)
**What/why:** `content_hash` is computed over the raw
`{"subject", "body"}`, but `replay_args["body"]` is
`redact_code_like_secrets(body)`. Two consequences: (1) the PAA07
"approval binds audience-hash + content-hash" promise is broken — the
hash attests to bytes that never execute, and the bytes that do execute
have no hash binding, so the hash can never be recomputed or verified
at replay time; (2) execute-on-approval silently sends corrupted
payloads — the redactor replaces any bare 6–8 digit run with
`[redacted:code]`, so invoice numbers, order IDs, or dates like
`20261013` in an approved email go out mangled, invisibly to the
approver.
**Suggested fix:** Compute `content_hash` over exactly the
`replay_args` dict that will execute (single source of truth); keep
redaction in `body_preview` (display) only, never in what executes.

## 3. Enforce account-level admin lockout independent of client IP

**Severity:** high
**Where:** `src/gateway/console/admin_auth.py:196-243` (`login`,
`_on_failure`)
**What/why:** `user.failed_logins` is incremented on every failure but
never compared against any threshold; the persisted `locked_until` is
only set from the per-IP `LoginGuard` lockout, which fires every 5th
failure from the *same* IP. An attacker rotating IPs gets unlimited
password guesses at 4 attempts per IP with no account lockout ever
triggering. The per-IP guard caps at a 60-minute lockout per IP, which
a botnet or proxy rotation defeats trivially.
**Suggested fix:** Lock the account after N total consecutive failures
(e.g. 15) regardless of source IP, in addition to the per-IP guard;
reset the counter only on successful login.

## 4. Set the Secure flag on the admin session cookie

**Severity:** high
**Where:** `src/gateway/console/admin_auth.py:226-233`
(`set_session_cookie`)
**What/why:** The cookie sets `samesite="strict"`, `httponly=True`,
`path="/"` — but no `secure=True`. This is the password+TOTP admin
session for a security gateway's console, with a 12-hour TTL. If the
console is ever served over plain HTTP, or behind a TLS-terminating
proxy that forwards internally over HTTP (a common docker-compose
deployment — and this branch just added compose), the session cookie
travels in cleartext and is trivially sniffable. There is no setting
for it anywhere, so this cannot be fixed by configuration.
**Suggested fix:** Add `secure=True` to `set_session_cookie`, with a
`console_cookie_secure` setting defaulting to true so local HTTP dev
still works.

## 5. Pin artifact digests, stop unpickling downloads, drop root in the kev image

**Severity:** high
**Where:** `docker/kev/entrypoint.sh:62-71` (byte-size check), `:83`
(`torch.load(..., weights_only=False)`); `docker/kev/Dockerfile:29-34`
(torch wheel, no hash), `:44-46` (kev tarball, commit-pinned only, no
digest); no `USER` directive (runs as root)
**What/why:** First boot downloads three artifacts from HuggingFace and
a torch wheel + kev.serve tarball at build time with no integrity
verification beyond byte-exact size checks — a tampered file of
identical size passes. The entrypoint then runs `torch.load(head.pt,
weights_only=False)` on a network-downloaded pickle: full arbitrary
code execution if the HF repo, a mirror, or the transfer is
compromised. The container also runs as root (unlike the gateway
image, which drops to `appuser`), maximizing blast radius.
**Suggested fix:** Record SHA-256 digests of `adapter_model.safetensors`,
`model.safetensors`, `head.pt`, the torch wheel, and the kev tarball;
abort boot on mismatch. Load `head.pt` with `weights_only=True` (the
code only asserts it is a dict) and add a non-root `USER`.

## 6. Configure a SQLite busy timeout for concurrent writers

**Severity:** medium
**Where:** `src/gateway/db.py:36-40` (`_apply_sqlite_pragmas`)
**What/why:** WAL mode allows concurrent readers, but writers still
serialize, and the default SQLite busy timeout is 0. The hot path
performs writes on every call: `last_seen_at` in `authenticate()`,
the terminal audit append, and the rate-counter increment. Under
concurrent load these will collide with `SQLITE_BUSY`, surfacing as
unhandled 500s — including in the middle of the auth and audit stages.
**Suggested fix:** Add `PRAGMA busy_timeout=5000` (or
`connect_args={"timeout": 5}`) in `_apply_sqlite_pragmas`.

## 7. Stop exposing raw connector exception text to agents

**Severity:** medium
**Where:** `src/gateway/pipeline.py:583`
**What/why:** `ExecuteStage` puts `str(exc)[:200]` into the
agent-facing error envelope's `details`. Upstream provider errors
routinely embed request IDs, key prefixes, account hints, or PII. The
agent — which may itself be compromised or merely curious — receives
all of it. The envelope contract is otherwise careful about
safe-vocabulary reasons; this one field breaks it.
**Suggested fix:** Log the exception server-side with the request_id;
return a generic `"connector call failed"` detail in the envelope.

## 8. Bound pipeline execution with a deadline

**Severity:** medium
**Where:** `src/gateway/mcp_server.py:271` (`_gateway_tool`)
**What/why:** `pipeline.execute()` runs synchronously with no overall
deadline. A hung connector handler (infinite loop, blocking I/O without
its own timeout) ties up the worker indefinitely; enough hung calls
exhaust the worker pool and the gateway stops serving — a cheap
application-layer DoS. `TimeoutError` is only caught when the handler
raises it itself, which a truly hung handler never does.
**Suggested fix:** Run `execute()` under a deadline (worker thread +
timeout), map expiry to `upstream_failure` through the unknown-outcome
gate so retries stay blocked until the console resolves them.

## 9. Make the rate-limiter increment atomic

**Severity:** medium
**Where:** `src/gateway/inspection/rate_limit.py:99-140` (`_check_window`)
**What/why:** The pattern is read (`select(RateCounter)...`), Python-side
`row.count += 1`, then `commit()` — with no row lock (`SELECT ... FOR
UPDATE`) or atomic increment. Concurrent in-flight requests for the
same agent interleave read-read-write-write, so N concurrent requests
can all observe `count < limit` and all be admitted; the per-minute and
per-day budgets can be exceeded by up to the concurrency factor.
SQLite serializes commits but does not prevent the lost-update
interleaving across sessions. Classic TOCTOU on an abuse control.
**Suggested fix:** Use an atomic increment (`UPDATE ... SET count =
count + 1 ... RETURNING`) or `with_for_update()` on the select;
alternatively enforce the limit in a single conditional UPDATE.

## 10. Cache the compiled redaction catalog; survive config-DB outages

**Severity:** medium
**Where:** `src/gateway/inspection/redaction.py:304-340`
(`active_patterns` → `_compiled` → `_rows`)
**What/why:** Every tool call runs `redact_value` (output inspection)
and `redact_ctx_for_audit` (pre-audit hook), each of which calls
`active_patterns()` — a full `select(RedactionPattern)` plus
`re.compile()` of every pattern, with no caching (only
`ensure_seeded` is guarded). That is per-call DB round-trips and regex
compilation on the hot path. Worse, availability coupling: if the
config DB hiccups, `_rows()` raises, `InspectOutputStage.run` catches
it and returns `injected_output_blocked` — every call in the gateway
is denied until the DB recovers. Fail-closed is preserved, but a
config-DB blip becomes a full outage.
**Suggested fix:** Cache the compiled catalog in-process with
invalidation on console edits (add/toggle/delete already go through
`RedactionCatalog` methods — bump a version there), and fall back to
the last-known-good compiled set on DB error instead of raising.

## 11. Redact PII in counterparty correction audit rows

**Severity:** medium
**Where:** `src/gateway/counterparty.py:197-211`
(`CounterpartyService.correct`)
**What/why:** `correct()` builds `before`/`after` dicts containing
`details_snapshot` — for `email.send` that snapshot is `{"to": [...],
"cc": [...], "bcc": [...]}` of raw recipient email addresses — and
writes them verbatim into `audit.append(..., redacted_args={"before":
before, "after": after, ...})`. The audit module's own contract
(`audit.py` docstring, NFR-DATA-001) is "Redacted args ONLY — never
plaintext PII". The console correction path passes admin-supplied
`details` straight through, so PII lands in the append-only audit
store permanently.
**Suggested fix:** Redact email-shaped values in `before`/`after`
before the audit write (reuse the redaction catalog), or log only the
diff keys, never the addresses.

## 12. Harden notify_new_request: catch-all and don't burn cooldown on failure

**Severity:** medium
**Where:** `src/gateway/notifier.py:258-297` (`notify_new_request`),
called from `src/gateway/approvals.py:584`
**What/why:** The docstring promises `notify_new_request` "Never
raises," but the `try` only catches `(NotifierError, VaultError)`.
`self._secrets.read()` or a deploy-chosen custom transport's `send()`
can raise anything else (`OSError`, `KeyError`, `TimeoutError`) — and
the call site in `_create_request` ignores the return value with no
guard, so the exception propagates out of `ApprovalStage.run` and out
of `Pipeline.run` entirely: no error envelope, no audit row, 500 to
the agent, for a notification side-effect. Separately, `_cooldown_ok`
stamps `self._last_sent[agent_id] = now` *before* delivery is
attempted, so a failed send burns the 5-minute per-agent cooldown — a
subsequent genuine approval request in that window notifies nobody.
**Suggested fix:** Catch `Exception` in `notify_new_request` (log +
return `fallback`, per the documented failure semantics); stamp
`_last_sent` only after successful delivery.

## 13. Cap JSON depth and size at ingress; make validators total

**Severity:** medium
**Where:** `src/gateway/inspection/validation.py:118-135`
(`walk_strings`), `:150-169` (`canonicalize_args`);
`src/gateway/pipeline.py:370-409` (`ValidateInputsStage.run`)
**What/why:** `walk_strings`, `canonicalize_args`, the redaction
walkers, and the injection scanner's per-field walker are all recursive
over agent-supplied JSON, and `ValidateInputsStage.run` has no
try/except (unlike `InspectOutputStage`, which fails closed). A deeply
nested argument payload (JSON parses fine at any depth) triggers
`RecursionError` in validation — which propagates out of
`Pipeline.run` before the terminal audit stage, so there is no error
envelope and no audit row for the attempted call. The call doesn't
execute (not fail-open), but it is an unaudited crash path reachable
by any agent. Related: `validate_against_schema` only catches
`ValidationError` — a `SchemaError` from a bad tool schema would take
the same unhandled path.
**Suggested fix:** Enforce a max JSON depth/size at ingress (before
validation) and return `invalid_input`; or convert the walkers to
iterative implementations.

## 14. Cap the bytes scanned by the injection scanner per call

**Severity:** medium
**Where:** `src/gateway/inspection/injection_scan.py:142-183`
(`scan_output`); also `src/gateway/inspection/redaction.py:449-486`
(`redact_value`)
**What/why:** `scan_output` walks every string in the tool result and
runs the full pattern catalog plus a base64-decode attempt per 100+
char blob — with no cap on output size. Tool outputs are
attacker-influenced and unbounded (`email.read` bodies and
`code.file.read` content have no size limit in the schemas; only
`email.send` *inputs* are capped). A single large or pathological
output (megabytes of base64-ish text, triggering repeated `b64decode`
attempts) burns CPU on the synchronous hot path per call — a cheap
application-layer DoS that just gets slow rather than denied.
**Suggested fix:** Cap the scanned bytes per call (e.g. first N KB per
field / total, recording truncation in the audit event); consider a
time budget around the scan.

## 15. Enforce the 90-day notifier secret rotation (no vacuous pass)

**Severity:** medium
**Where:** `src/gateway/notifier.py:225-239` (`_secret_age_ok`)
**What/why:** The module docstring and `config.py` both document "max
age 90 days" / "the notifier refuses to send when the secret is older
than 90 days." But when `GATEWAY_NOTIFIER_SECRET_ISSUED_AT` is unset
(the default), `_secret_age_ok` returns `(True, "secret age
unknown...")` — the rotation control passes vacuously. A deploy that
never sets the timestamp gets no rotation enforcement at all, with
only a detail string buried in a debug field noting it. Fail-open on
a documented security control.
**Suggested fix:** Fail closed — treat an unset/unparseable issued-at
as expired (or refuse to start the notifier in configured mode) unless
an explicit documented escape hatch is set.

## 16. Verify the external OPA bundle version before serving decisions

**Severity:** medium
**Where:** `src/gateway/opa_client.py:250-290`
(`_start_external_locked`); `DECISION_PATH`
**What/why:** In `GATEWAY_OPA_URL` mode the gateway trusts whatever
decision the external server returns, with no check that it is serving
the pinned policy bundle. A misconfigured URL, a stale bundle after a
bad rollout, or (in the compose's plain-HTTP internal network) a
redirected endpoint silently enforces the wrong policy with no alarm —
on the highest-privilege component in the system. The sidecar mode at
least launches the binary itself against the repo's `policies/v1`.
**Suggested fix:** At startup (and periodically) fetch a bundle
version/hash from the external OPA and compare against the repo's
pinned bundle; refuse to serve (fail closed) on mismatch.

## 17. Make the terminal audit write resilient (retry + dead-letter)

**Severity:** medium
**Where:** `src/gateway/pipeline.py:735-739`
(`self.audit_stage.run(ctx)`); `src/gateway/audit.py:92-96`
**What/why:** `audit.append` does add+commit with no retry. If the
commit fails (lock contention, disk full, corruption) *after*
`ExecuteStage` ran, the upstream action executed but no audit row
exists — an FR-030 gap — and the agent receives a 500 instead of its
result, inviting a retry that double-executes non-idempotent actions.
The audit trail is the product's compliance backbone; a single failed
commit should not silently lose it.
**Suggested fix:** Retry the audit write with backoff; on persistent
failure spill the row to a local dead-letter file and alert, rather
than losing it.

## 18. Add TLS awareness: warn or refuse non-loopback binds without TLS termination

**Severity:** medium
**Where:** `src/gateway/config.py` (no TLS settings);
`src/gateway/mcp_server.py` (`main`)
**What/why:** Fix A requires per-agent secrets "over TLS," but nothing
in config or startup checks for it. Binding `0.0.0.0:8000` with no
TLS-terminating proxy sends OAuth client secrets and bearer tokens in
cleartext with zero warning — and the compose file publishes port 8000
to the host with no TLS story at all.
**Suggested fix:** Add a `GATEWAY_TLS_TERMINATED` / trusted-proxy
setting; log a loud warning (or refuse to start) when binding a
non-loopback address without it; document the TLS requirement in the
README and compose file.

## 19. Gate first-run /setup to loopback or a setup token

**Severity:** medium
**Where:** `src/gateway/console/app.py:215-252`
**What/why:** `/setup` is in `_OPEN_PATHS` (no auth) whenever no admin
exists. If the console is reachable on the network before first setup,
anyone who reaches it can claim the admin account with a password+TOTP
of their choosing — full gateway control (mandates, policies, vault
wiring, approvals). The `dev_no_auth` escape hatch is correctly
parameter-only, but the first-run window itself is unguarded.
**Suggested fix:** Serve `/setup` on loopback only, or require a
single-use setup token printed at first boot; log loudly while the
gateway has no admin.

## 20. Enforce the fallback-bearer 90-day max age

**Severity:** medium
**Where:** `src/gateway/identity.py:278-296` (`bearer_age_days`);
`src/gateway/config.py` (`fallback_bearer_max_days`)
**What/why:** Config documents "mandatory rotation" and the console
shows the bearer age, but `bearer_age_days()` only *reports* — nothing
denies authentication when the age exceeds the max. The rotation
control is advisory-only, so a forgotten fallback bearer lives
forever.
**Suggested fix:** In `authenticate()`, deny `fallback_bearer`
credentials older than `fallback_bearer_max_days` with a distinct code
directing the admin to rotate.

## 21. Define production semantics for derived-token validation

**Severity:** medium
**Where:** `src/gateway/vault/minter.py:162-190` (`validate_token`)
**What/why:** Adapter-side validation calls
`self._issuer.validate(token.raw())`, but real OAuth providers
(Google/Microsoft) offer no access-token introspection endpoint — the
mock's local-dict check has no production equivalent. The production
behavior of this check is therefore undefined: always-fail breaks
calls, no-op makes it dead code, and whichever it becomes will be
discovered in production, not in review.
**Suggested fix:** Define the contract explicitly (ledger hit +
unexpired + binding match is sufficient; drop the issuer call for
opaque upstream tokens, or use provider tokeninfo endpoints where
they exist).

## 22. Re-check policy supersession in execute_approved_call

**Severity:** medium
**Where:** `src/gateway/pipeline.py:987-1060`
**What/why:** The MF-11 replay path takes `policy_version` as a
parameter but never compares it to current. A material policy change
landing between approval (when the grant was consumed, with the
supersession check) and the server-side replay executes under the old
policy — bypassing the `policy_superseded` invariant that the normal
grant path enforces. The window is usually small, but the invariant
should not depend on timing luck.
**Suggested fix:** Compare against `_current_policy_version` at replay
start; deny with `policy_superseded` on mismatch.

## 23. Carry traceability fields through _maybe_escalate

**Severity:** medium
**Where:** `src/gateway/policy.py:1489-1512`
**What/why:** When counterparty escalation converts allow →
require_approval, the new `EvaluationResult` keeps only
`policy_version` and `escalation_reason`, dropping `matched_rule_id`,
`scope_rule`, `ontology_snapshot_ref`, `ontology_ref`, and
`data_snapshot_id`. The approval record and audit row for an escalated
call therefore lose: which rule allowed it (the FR-PAA01-007
`scope_rule`), the PAA04 ontology snapshot ref, and the
input-document version — i.e. traceability is dropped for exactly the
highest-risk calls.
**Suggested fix:** Carry the fields over into the escalated result.

## 24. Capture the PAA04 snapshot for ontology-clause deny decisions

**Severity:** medium
**Where:** `src/gateway/policies/v1/authz.rego:161-168`
(`trace_info`); `src/gateway/policy.py:1413-1415`
**What/why:** `trace_info` emits `ontology_shaped: true` only when
`rule_effect(rule) == "allow"`, and the Python capture condition
mirrors it — but the Python comment claims the condition is "deciding
rule had an ontology clause or a preference group was applicable,"
which is also true of deny-effect rules with matching ontology
clauses. Those denies get no `ontology_shaped`, no snapshot, and no
`ontology_ref`: the entry citation and decision snapshot are missing
for ontology-driven denies, and the comment is a doc-vs-code gap.
**Suggested fix:** Emit `trace_info`/`ontology_shaped` for deny
effects too (or capture the snapshot for ontology-clause deny rules in
Python); fix the comment to describe the actual condition.

## 25. Validate rule time windows (and tool selectors) at save time

**Severity:** medium
**Where:** `src/gateway/policy.py` (`validate_rule_dict`,
`~468-545`); `src/gateway/policies/v1/authz.rego`
(`rule_problems`)
**What/why:** Neither the Python validator nor the Rego
`rule_problems` checks the `time_window` shape. A malformed window
(e.g. `"start": "9"`, or `"days": ["funday"]`) silently never matches
— fail-closed, but undebuggable: the admin gets a rule that looks fine
in the console and can never fire, with `opa check` at save time
catching nothing. Same sharp edge: a tool selector of bare `"*"`
matches nothing (only `"prefix.*"` and exact names work), also
silently.
**Suggested fix:** Validate `start`/`end` as HH:MM and `days` against
the weekday vocabulary (and the selector format) in
`validate_rule_dict`, so bad rules are rejected at save time.

## 26. Make HmacKeyRing.matches return False (not raise) on unknown key ids

**Severity:** low
**Where:** `src/gateway/hmac_util.py:88-101`
**What/why:** `matches()` calls `self._key(kid)`, which raises
`ValueError` for unknown key ids instead of returning False.
`verify_snapshot` (`ontology/snapshots.py:150`) lets it escape, so a
snapshot ref with an unregistered key id (retired key removed from the
ring, or a malformed/forged ref) crashes the caller instead of failing
verification. A verification function taking untrusted input should be
total.
**Suggested fix:** Catch the unknown-key case and return False.

## 27. Catch ValueError (not KeyError) in the redaction delete/toggle routes

**Severity:** low
**Where:** `src/gateway/console/pages.py:746-748`
(`redaction_delete`); `set_enabled` path for `redaction_toggle`
**What/why:** The route wraps `delete_pattern(name)` in `except
KeyError: pass`, but `_require` raises `ValueError("unknown redaction
pattern ...")` — the `except` is dead code. Deleting a nonexistent
pattern (stale UI, double-submit) raises unhandled → FastAPI 500, and
the `_admin_audit(... "delete" ...)` line below never runs, so the
failed attempt isn't logged either. `redaction_toggle` has the same
exposure via `set_enabled` with no handler at all.
**Suggested fix:** Catch `ValueError` in both routes; return 404/400
with an audit-logged failed attempt.

## 28. Wire the ontology feedback loop or document it as deferred

**Severity:** low
**Where:** `src/gateway/ontology/feedback.py`
(`record_decision_outcome`, `detect_conflicts`, `sweep_stale`),
`src/gateway/ontology/discovery.py`
**What/why:** The feedback/discovery functions have zero production
callers — only tests. The module docstrings describe a "living
ontology" loop where the pipeline records decision outcomes and
detectors flag stale entries, but nothing calls it from the pipeline
or console. Enforcement hooks and provenance tracking are real; the
"living/evolving" half of the directive is aspirational until outcomes
are recorded. (Checked as requested: bootstrapping via presets,
provenance, and Rego enforcement hooks are genuinely wired.)
**Suggested fix:** Wire `record_decision_outcome` into the pipeline
audit path, or explicitly document the loop as deferred post-MVP.

---

## Deferred items reframed as actionable issues

## 29. Replace the vendored 69MB OPA binary with a checksum-pinned download at build time

**Severity:** medium
**Where:** `third_party/opa/opa` (69MB), `scripts/verify_opa.sh`,
`docker-compose.yml` (pins `openpolicyagent/opa:1.8.0` separately)
**What/why:** The repo carries a 69MB binary blob — every clone pays
for it, and binary blobs in git are unauditable by reviewers. The
checksum gate exists, but the artifact itself should not live in the
repo. Note the version is now pinned in two places (the vendored
binary and the compose image tag) with no single source of truth.
**Suggested fix:** Download at build/CI time from the official release
with SHA-256 pinning (extend `verify_opa.sh`); keep one
`OPA_VERSION` source of truth consumed by both.

## 30. Supervise the kev-serve model server across restarts

**Severity:** medium
**Where:** `~/workspace/kev-serve` (outside the repo; serving
`127.0.0.1:8009`)
**What/why:** The local kev-0.8b server died on VM restart (observed
2026-10-13) and had to be restarted by hand. Any production or demo
setup depending on the judge backend silently loses it — the judge
fails closed to `JudgeUnavailable`, so calls still work, but the
manipulation-detection and risk-scoring coverage quietly disappears
with no alert.
**Suggested fix:** Add a systemd unit (or compose service — already
exists in `docker-compose.yml`) with restart policy, plus a readiness
alert when the judge backend is unreachable for N minutes.

## 31. Auto-wire the counterparty judge hook into ValidateInputsStage

**Severity:** low
**Where:** `src/gateway/judge/counterparty_hook.py`
**What/why:** Known deferred item: the hook exists and is tested, but
nothing installs it in the pipeline — counterparty judge signals never
reach the approval record in production. The seam
(`judge_signals_for_approval_record`) is documented; only the wiring
is missing.
**Suggested fix:** Install the hook in `build_pipeline` behind
`GATEWAY_JUDGE_ENABLED`, mirroring the inspection hook and risk
scorer.

## 32. Promote kev-4B on a GPU host

**Severity:** low
**Where:** `src/gateway/judge/kev.py` (`DEFAULT_MODEL`)
**What/why:** Known deferred item: tests run against kev-0.8b locally
(the weakest checkpoint — weak confidences, one missed choice test),
with kev-4B documented as the production recommendation. The client is
model-agnostic, so this is a config + validation task, not a code
change — but it needs a tracked decision with acceptance criteria
(accuracy re-run on the live tier, latency re-measurement against the
AC-11 budget on the deploy target).
**Suggested fix:** Provision a GPU host (or ~16GB RAM), run the live
tier against kev-4B, record accuracy/latency, flip the default model.

---

## Self-assessment

Confidence is highest in the **high** bucket: all five were verified
against the exact code cited (the issuer protocol genuinely has no
credential parameter; the card hash/replay mismatch is line-verified;
the lockout counter is provably write-only; the cookie flags were
grepped repo-wide; the entrypoint unpickles with `weights_only=False`
after a size-only check). Confidence is good in **medium**: each was
re-read after drafting and several weaker candidates were dropped
(e.g. a suspected pre-audit redaction ordering bug that proved wrong,
a feared judge step-up bypass that `policy.py` provably closes, and an
OPA `depends_on` concern the entrypoint's seed-retry already covers).
The most likely place I am wrong is severity calibration on the
performance-flavored mediums (busy timeout, redaction recompile,
scanner byte caps) — on a single-user gateway these bite later than on
a multi-tenant one, so a reviewer could fairly demote them. I
deliberately did NOT report: the 79 fixed findings from
`docs/06-review-log.md` (re-verified a sample in code rather than
re-listing them); stylistic nits, naming, and comment drift (except
where a comment makes a false security claim, as in #24); hypothetical
threats with no code path (e.g. SSRF in connectors — the adapters are
mock-only with no URL parameters, so there is genuinely no surface
today); and anything requiring a live external system to confirm
(Jev's hosted wire shape, Glimmer behavior on a GPU).
