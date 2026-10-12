# Build Log — Personal Agent Security Gateway

Append-only. Deviations from the specs need a written rationale here.
Spec conflicts are flagged with the exact doc section, never silently resolved.

## M0 — Spike results (2026-10-12, coordinator)

Environment: Python 3.12.3, fresh venv, packages installed from PyPI.

### S1 — SDK version floor — PASS
- `mcp` 2.3.0 installed (floor: 1.30.0/2.2.0 lineage per FR-005/AC-10, GHSA-qx49-fqc8-xw99). Floor satisfied with headroom.
- `fastmcp` 4.1.0 installed.
- `mcp.server.auth` present with `provider`, `routes`, `middleware`, `settings` — OAuth authorization-server helpers available for the gateway's Fix A OAuth 2.1 role.

### S2 — MCP tool-name charset — PASS
- Dotted names (`email.search`, `email.send`, `gateway.approval_status`) registered in FastMCP and survived a full Streamable HTTP wire round-trip (raw HTTP: initialize → tools/list; names returned verbatim).
- Tool-name charset assumption in 02 §2.1 confirmed for this SDK line.

### S3 — Streamable HTTP transport — PASS
- FastMCP 4.1.0 serves Streamable HTTP (session establishment, `Mcp-Session-Id` returned, `tools/list` over POST). Endpoint path is `/mcp` (no trailing slash; `/mcp/` 307-redirects).

### S4 — Platform spikes (Muse OAuth / Grok OAuth / poll-and-retry / Dots) — NOT VERIFIABLE HERE
- No live platform accounts or browser in this environment; cannot test Muse Custom Connector OAuth support, Grok MCP client auth, agent poll-and-retry behavior, or the Dots plugin-inheritance path.
- Recorded per 00 §4 M0: auth method per platform stays undecided until Ken runs the live spikes. Build proceeds per Fix A (OAuth 2.1 primary, gated conditional bearer fallback recorded with test date) and MF-11 (console "execute on approval" fallback ships in M3 regardless), so both outcomes are covered without rework.

### S5 — OAuth app registrations — NOT DONE (Ken's action)
- Google/Microsoft/GitHub OAuth app registrations require Ken's developer accounts. Build uses env-based credential config + mock OAuth providers for tests; real credentials plug in later without code changes (03 §2.1).

### Environment quirk (recorded for the build)
- FastMCP 4.x vendors `httpx2`, whose `no_proxy` parsing raises `InvalidURL` on bracketed IPv6 entries (`[::1]`, `[fd8b:...]`) present in this sandbox's `NO_PROXY`. The gateway MUST sanitize `no_proxy`/`NO_PROXY` at process startup (drop bracketed entries or unset) before any FastMCP import touches the network stack. Not a FastMCP defect for our purposes — a deployment-environment note.

### M0 exit (adjusted)
- Spike results recorded per platform above; auth method per platform: decided-when-Ken-tests (both code paths built); OAuth apps: Ken's action, pending; hosting: Ken's decision, pending (deferred per his direction — build stays hosting-agnostic).

## M1 — Endpoint, identity, audit (2026-10-12, foundation builder)

### Files created
- `pyproject.toml` — Python ≥3.12; deps installed into `.venv/` (`pip install -e .[test]`);
  SDK floor pinned `mcp>=2.2.0` with the GHSA-qx49-fqc8-xw99 citation comment
  (FR-005/AC-10). Installed: mcp 2.3.0, fastmcp 4.1.0 (matches M0 spike).
- `src/gateway/`: `__init__.py`, `config.py`, `db.py`, `models.py`, `ids.py`,
  `errors.py`, `hmac_util.py`, `identity.py`, `mandates.py`, `audit.py`,
  `pipeline.py`, `mcp_server.py`, `mock_oauth.py`.
- `tests/test_foundation.py` — 73 tests, **all green** (2026-10-12).
- `README.md` — layout, test command, env vars, transport contract, M0 pointer.

### What was verified
- Unit: credential auth (valid/invalid/revoked/paused/canceled), single-credential
  invariant (incl. gated fallback: requires test date, deactivates OAuth, still one
  active credential), mandate lifecycle with distinct deny reasons, audit
  append-only/search/export (+export is itself logged), error envelope for every
  02 §2.7 code, id formats, HMAC rotation, pipeline stage order
  (validate-before-policy) with stub stages, timing spans recorded (AC-11 seam).
- Wire (live uvicorn, raw Streamable HTTP JSON-RPC): unauthenticated
  initialize/tools/list/tools/call all rejected with `auth_failed`; valid
  credential → session + dotted tool names (`test.echo`) in tools/list;
  default-deny over the wire returns the isError `policy_denied`/`no_allow_rule`
  envelope (AC-03); revoked agent gets `agent_revoked`.

### Interpretations and deviations (rationale recorded; no silent spec changes)
1. **Multi-mandate check semantics** (`mandates.py`). 02 §2.8 step 9 / 03 §1.2
   step 4 describe the single-mandate case. M1 implements: allow if ANY live
   mandate covers the tool; otherwise distinct deny reasons with precedence
   withdrawn > ended > paused > expired when no mandate is live. Single-mandate
   behavior matches the spec exactly. Rationale: agents will hold standing +
   delegated mandates; denying because the *first-created* mandate doesn't cover
   the tool would break delegation (FR-PAA01-005).
2. **Revoked agents resolve to `agent_revoked`, not generic `auth_failed`**
   (`identity.py`). `find_agent_id_by_credential_identifier` resolves inactive
   credentials (latest first) so `authenticate()` can report the lifecycle state
   distinctly per FR-PAA10-004 ("name the state, never a silent hang").
   `revoke()` still deactivates the credential immediately (FR-015).
3. **`ended` mandate → `mandate_withdrawn` reason; no-mandate → deny with
   `mandate_withdrawn`.** The 02 §2.7 safe vocabulary has no `mandate_ended`
   code; `ended` is terminal like withdrawal. Documented in `mandates.py`.
4. **M1 credential transport contract** (`mcp_server.py`): OAuth client creds as
   `Authorization: Basic base64(client_id:client_secret)`; fallback bearer as
   `Authorization: Bearer <key_id>.<raw_token>`. The gateway-as-OAuth-
   authorization-server code exchange (token endpoint, JWKS) is a later
   milestone — platform OAuth spikes (OQ-1/OQ-3) are Ken's action and the M0
   spike recorded them not-verifiable-here. Both Fix-A paths are built.
5. **OAuth public-endpoint carve-out (02 §2.1) preserved by construction.**
   The auth middleware guards only MCP `initialize`/`tools/list`/`tools/call`;
   no blanket HTTP auth layer exists, so the future OAuth
   discovery/metadata/authorization/JWKS endpoints will be public without
   rework. `gateway.approval_status` is NOT registered in M1 (M3 owns it).
6. **One credential validation per request.** The middleware bcrypt-validates
   on every request (03 §3.1); the pipeline's `AuthenticateStage` adopts the
   validated `AuthResult` via request-scoped contextvar instead of
   re-validating. Direct pipeline users (tests/console) present via
   `AuthenticateStage.presented` and get full validation there.
7. **Audit runs exactly once per call** (`pipeline.py`): the audit stage is
   terminal and invoked once after the stage loop, not as a loop member
   (avoids double-audit on the success path). Fix-B order preserved.
8. **M1 redaction is a pass-through stub** (`pipeline.py` `AuditStage`): the
   M5 redaction catalog owns real redaction (NFR-DATA-001/AC-07). The audit API
   only accepts `redacted_args`, so the guarantee hardens without API change.
9. **`as_utc` normalization** (`models.py`): SQLite returns naive datetimes
   for `DateTime(timezone=True)`; they are treated as UTC at comparison points
   (mandate expiry, credential expiry, bearer age).
10. **`notifications/initialized` is not auth-guarded.** Only the methods named
    in 02 §2.1 (initialize/tools/list/tools/call) are guarded; the notification
    only follows a successfully authenticated initialize, and every subsequent
    request is per-request validated.

### Open for later milestones (not M1 gaps — owned elsewhere)
- M2: replace `PolicyStage` default-deny stub with the rule evaluator
  (grant-before-rule, scope_rule on audit rows per FR-PAA01-007).
- M3: replace `ApprovalStage` no-op with the Fix-B flow; minimal validator in
  `ValidateInputsStage`; register `gateway.approval_status`; exempt notifier path.
- M5: harden `ValidateInputsStage`, real injection scan + redaction catalog in
  `InspectOutputStage`, rate limits.
- W2: `GatewayApp.register_connector_tools(connector, [ToolDescriptor, ...])`
  registers on both the pipeline registry and the MCP surface (FR-009).
- W3: replace `StubTokenMinter` with the vault-backed `TokenMinter.mint(ctx)`
  (layer-2 derived token; raw vault credential never leaves the vault).
- AC-11: `timing_span(ctx, name)` records gateway-internal spans per call
  (`ctx.spans["stage:<name>"]`); the CI gate + production measurement use these.

## M4 — Vault and credential-backed connectors (2026-10-12, vault builder)

### Files created
- `src/gateway/vault/__init__.py` — package exports + isolation contract.
- `src/gateway/vault/kms.py` — `KmsProvider` protocol (`get_data_key()`,
  `key_id`); `EnvKmsProvider` (base64 32-byte key from `GATEWAY_KMS_KEY`,
  id from `GATEWAY_KMS_KEY_ID`); `generate_kms_key()` + `--generate` CLI
  (never hardcoded; test keys generated at test time only). Fly-secrets /
  GCP-Secret-Manager binding documented as the production provider
  (interface only, no cloud calls).
- `src/gateway/vault/models.py` — `VaultBase` (separate from the
  config/audit Base) + `VaultEntry` (id, connector, label, wrapped DEK,
  payload nonce/ciphertext, key_id, status active|superseded|revoked,
  rotation timestamps, admin_id seam).
- `src/gateway/vault/store.py` — `VaultStore`: encrypted SQLite secrets
  file (third DB file, WAL), envelope encryption, CRUD, `rotate` with
  graceful expiry, `revoke`, `rekey` (KMS rotation = re-wrap DEKs),
  console-safe `list_entries()`. Every read audit-logged (FR-024);
  rotation/revocation/rekey logged as admin actions (FR-041). Reserved
  connectors `system`/`notifier` are refused (notifier split).
- `src/gateway/vault/minter.py` — `VaultTokenMinter` (the `TokenMinter`
  protocol): audited vault read → upstream exchange → 5-min derived
  token bound to (agent, tool, action) in bookkeeping + audit;
  `validate_token` with TTL + optional agent/tool binding checks.
- `src/gateway/vault/mock_oauth_issuer.py` — adapts W1's
  `MockOAuthProvider` to the `UpstreamTokenIssuer` protocol for tests.
- `src/gateway/vault/notifier_secret.py` — `NotifierSecretProvider`:
  the explicit NON-vault path for the M3 exempt-notification bootstrap
  secret (platform secret store via `GATEWAY_NOTIFIER_SECRET` locally;
  Fly secrets / GCP Secret Manager in prod), reads audit-logged
  (FR-024), repr redacted.
- `tests/test_vault.py` — 34 tests, all green.

### W1 touch-points (both additive, no M1 regression)
- `config.py`: new `vault_db_path` setting (`GATEWAY_VAULT_DB`,
  default `data/vault.db`).
- `pipeline.py`: `build_m1_pipeline(..., minter=None)` — pass
  `VaultTokenMinter` to replace `StubTokenMinter` (default unchanged);
  `TokenMintStage.run` now catches mint exceptions and fails closed to
  `upstream_failure` naming the tool only (03 §7; FR-022).

### Interpretations and deviations (rationale recorded; no silent spec changes)
1. **DerivedToken material is the layer-2 derived access token, NOT the
   vault's stored credential** (03 §2.1, 03 §2.2, FR-012b, FR-022). The
   task's "`.raw()` yields the upstream credential" is read as the
   derived call token: the minter reads the stored refresh credential /
   API key (audited), exchanges it via the `UpstreamTokenIssuer`, and
   the stored value is never placed in a `DerivedToken`. This matches
   03 §2.1 ("the adapter asks the vault for a derived, short-lived
   access token ... and discards it") and is strictly stronger than
   FR-022's floor.
2. **Envelope choice** (03 §5): KMS KEK wraps per-credential random DEKs
   (AES-256-GCM; credential id as AAD on the payload) rather than the
   KEK encrypting payloads directly. Rationale: KMS rotation becomes
   DEK re-wrapping (`rekey`) instead of payload re-encryption; KEK
   usage is minimized.
3. **Graceful expiry = TTL, not revocation** (FR-023): rotation
   supersedes the old entry; already-minted derived tokens stay valid
   until their own ≤5-min expiry (nothing is actively killed). The
   issued-token ledger is in-process memory (03 §5: short-lived token
   state; loss on restart acceptable).
4. **Test doubles, not shipped code**: `AllowPolicyStage` (stands in for
   M2's rule evaluator) and the mock connectors (`email.send`,
   `calendar.write`, `codehost.repo_read`) live in `tests/test_vault.py`
   only. W2 owns the real connectors; the pipeline wiring point is the
   `minter` parameter.
5. **Credential id prefix `cred_`** (128-bit CSPRNG, same shape as
   req_/apr_/mnd_ in `ids.py`; 00 §7 param 12). Vault-internal; new
   prefix documented here rather than extending `ids.py`'s agent-facing
   prefix registry.

### What was verified (M4 exit criteria)
- **Amended AC-05**: full pipeline call (`email.send` through real auth +
  mandate + vault minter + mock adapter) — the stored vault secret and
  the derived token value appear in no agent-visible output, no error
  envelope, and no audit row (export_json asserted). DB file grepped:
  no plaintext.
- **AC-08 re-verified with credential-backed calls**: call succeeds →
  agent revoke → subsequent calls denied `agent_revoked`; connector
  credential revoke → subsequent calls denied `upstream_failure`
  (fail-closed), envelope secret-free; expired derived tokens rejected
  by the adapter.
- **Rotation drill passes**: old + new derived tokens both valid during
  grace; old invalid after its TTL lapses; new reads return the rotated
  credential; rotation audit-logged as an admin action (FR-041).
- Full suite: **107 passed** (73 M1 + 34 M4), 2026-10-12.

### Non-regression (06-review-log)
- Fix A (auth wall, single credential, two token layers) and Fix B
  (approval workflow order) untouched.
- The 03 §2.2 two-token-layer table and the (agent, tool, action)
  bookkeeping-not-cryptographic statement are not modified — the
  minter's docstring quotes them.
- Evidence-subset / HMAC rules (02 §2.8 step 4) untouched — M3 owns
  approvals; the vault only uses the existing `AuditLog.append` API.
- `docs/04-review.md` untouched (historical record).

### Open for later milestones (not M4 gaps — owned elsewhere)
- W2: real connectors (`email`, `calendar`, `codehost`) with handlers
  that validate the derived token via `VaultTokenMinter.validate_token`
  before presenting `.raw()` upstream; SSRF checklist per FR-009.
- M3: exempt notifier path consumes `NotifierSecretProvider`
  (fixed field allowlist, 02 §2.8 step 5); console rotation UI for the
  bootstrap secret (platform operation, ≤90d).
- M6: Vault & Settings console page over `VaultStore.list_entries()`
  (metadata only) + rotation action; production KMS binding
  (Fly secrets / GCP Secret Manager → `GATEWAY_KMS_KEY`).
- Ken's actions (unchanged): OAuth app registrations, hosting choice
  (drives the KMS binding), repo name before any push.

## M2 — Policy engine, connectors, minimal console (2026-10-12, policy+connectors builder)

### Files created
- `src/gateway/policy.py` — hand-rolled JSON rule evaluator (03 §8): `PolicyEngine`
  (rule loading, `evaluate_call` → `(decision, matched_rule_id|None, requires_approval)`,
  immutable `save_version` with material/non-material classification on every save,
  `classify_change`/`diff_versions`), condition evaluators (time windows, argument
  constraints, purpose binding, household-role scoping, template-bound notice rules),
  `dry_run` (history replay + synthetic cold-start corpus), and the real `PolicyStage`.
- `src/gateway/connectors/` — `base.py` (Connector plugin interface: tools, upstream
  scopes, `health_check()` → credential-valid + API-reachable, `ssrf_checklist()`),
  `mock_upstream.py` (in-memory MockGmail/MockCalendar/MockGitHub incl. traceable
  `SYNTHETIC-TRACE-FACT-PAA03-*` facts and the `transaction_status` stub for
  FR-PAA06-003), `email.py` (6 tools), `calendar.py` (4 tools), `codehost.py` (2 tools).
  No `code.pr.merge` tool exists (deferred per 00 §3).
- `src/gateway/console/` — `app.py` (`create_console_app` FastAPI factory) + Jinja2
  templates for the TWO M2 pages: Agents (register/inspect/pause/revoke, secret shown
  once) and Audit Log (filter + JSON/CSV export, export audit-logged per FR-033).
- `tests/test_policy.py` — 45 tests; `tests/test_connectors.py` — 31 tests.

### What was verified
- Full suite: **183 passed** (73 M1 foundation + 45 policy + 31 connectors + 34 vault
  from the concurrent W3 worker — no conflicts).
- allow/deny/require_approval per agent/tool end-to-end through `build_pipeline`;
  default-deny AC-03 with no policy versions (reason `no_allow_rule`); explicit-deny
  reason + first-match priority; pinned visible default-deny row in listings.
- Denial rows logged with safe-vocabulary reasons; no rule text/ids in errors.
- Purpose binding (FR-PAA03-002): purpose-bound rule denies a call whose mandate
  `purpose_key` differs, even when the tool is otherwise allowed; undeclared purpose
  never matches a bound rule (fail closed).
- Household-role scoping (FR-PAA08-001): a rule scoped to one member's role never
  matches another member's agent.
- Versioning: immutable versions, auto material/non-material classification
  (widening → material; renames/descriptions/reorder → non-material), explicit
  override respected; old versions evaluate with their own rules.
- `dry_run`: history counts + changed_calls against seeded audit rows; synthetic
  corpus (12 hand-written calls, labeled) when history is empty.
- Template-bound notice rules (FR-PAA07-005) as a standing policy rule type:
  matching notice allowed + audit-logged; audience expansion, content mismatch,
  oversize body, and out-of-schedule executions denied.
- Every connector tool executed end-to-end through the pipeline against mock
  upstreams; sensitivity flags match the 02 §2.2 inventory; `raw()` is called only
  inside adapters and the token material never reaches agent-visible results/errors.
- Minimal validator: schema failures return `invalid_input` naming the field (never
  the value) and halt at `validate_inputs` before policy/approval.

### SSRF checklist outcomes (FR-009 acceptance, per adapter)
- EmailConnector: PASS — in-process MockGmail, no network egress; no tool accepts a
  URL; no HTTP client exists (metadata endpoints unreachable); no tool accepts
  credentials (02 §2.4).
- CalendarConnector: PASS — same, in-process MockCalendar.
- CodeHostConnector: PASS — in-process MockGitHub; repos addressed by owner/name
  strings only (no open-ended URL fetch); no merge tool to abuse.
- Recorded in each adapter's `ssrf_checklist()`; asserted by
  `test_ssrf_checklist_passes` / `test_no_tool_accepts_url` /
  `test_no_tool_accepts_credentials`.

### Interpretations and deviations (rationale recorded; no silent spec changes)
1. **Two PolicyStage classes** (`pipeline.py` M1 stub kept; `policy.py` holds the real
   one). The M1 stub stays so M1's tests keep importing `pipeline.PolicyStage`;
   `build_pipeline()` (new, in `pipeline.py`) assembles the M2 pipeline with the real
   stage, and `mcp_server._make_tool_fn` now uses `build_pipeline`. Lazy import in
   `build_pipeline` avoids a pipeline↔policy import cycle.
2. **Effect vocabulary** (02 §5): "allow | deny | require_approval" primary; the M1-era
   "sensitive" is accepted on read and normalized to "require_approval" (M1 stored no
   rules in tests, so nothing breaks).
3. **Mandate.purpose_key added** (nullable, 01 §10.3 FR-PAA03-002): exact purpose-registry
   key on the mandate; `create_mandate(..., purpose_key=...)`. Default mandates leave it
   unset → purpose-bound rules fail closed. The free-text `purpose` field is untouched.
4. **evaluate_call signature**: `PolicyEngine.evaluate_call(agent, tool, args,
   policy_version, purpose=None, now=None)` — the mandated 4-tuple plus optional
   purpose (from `mandate.purpose_key`) and clock injection for tests. Returns an
   `EvaluationResult` NamedTuple `(decision, matched_rule_id, requires_approval, …)`
   so positional unpacking matches the spec.
5. **Grant-before-rule is an M3 seam**: `PolicyEngine(grant_checker=...)`; None in M2
   (no grants exist). The short-circuit shape (`allowed_via_approval`, `via_grant`)
   is in place for M3 to wire.
6. **require_approval halts at the policy stage in M2** with the final
   `approval_required` error shape; M3's ApprovalStage rework will create the approval
   request at the approval step instead. Decision vocabulary is unchanged.
7. **Minimal validator implemented in M2** per the task (00 §4 M3 note): jsonschema
   with FormatChecker (type/enum/required/format/maxLength subset as used by the
   inventory schemas). M5 hardens it. `invalid_input` names the field, never the value.
8. **dry_run re-evaluates redacted args** (the audit log never holds plaintext —
   acknowledged approximation, noted in the docstring). Rows for unknown tools,
   unknown agents, or unmapped decisions are skipped via the `known_tools` filter.
9. **email.read / calendar.update / calendar.delete schemas** are M2 definitions —
   02 §2.3 gives representative schemas only for the others.
10. **Audit deny_reason fallback** (`pipeline.py`): when an error carries no "reason"
    key but its code is safe vocabulary (e.g. `invalid_input`), the audit row records
    the code as the reason. Error envelopes unchanged.
11. **jinja2 added** to dependencies (console templates).
12. **Console has no admin auth/CSRF in M2** — M6 owns FR-036/039/040/042; marked in
    code comments and templates.
13. **No cost budgets** (FR-029/MF-13): no connector reports cost; `budget_exceeded`
    is never emitted (errors.py already raises on it).

### Open for later milestones (not M2 gaps — owned elsewhere)
- M3: ApprovalStage rework (approval-request creation at the approval step,
  grant-before-rule wiring via the `grant_checker` seam, `gateway.approval_status`,
  caps, idempotent lookup chain, exempt notifier path).
- M5: harden ValidateInputsStage; real injection scan + redaction catalog in
  InspectOutputStage; rate limits; code-artifact redaction; cross-context leakage
  flagging.
- M6: remaining seven console pages + admin auth + CSRF; `POST /api/policy/evaluate`
  and `POST /api/policy/dry-run` HTTP wiring (core functions already exist);
  dry-run cold-start corpus already hand-written per 00 §7 param 17.
- W3 (in flight): vault-backed TokenMinter replaces StubTokenMinter.
- Fix A / Fix B and all 06-review-log items: untouched, no regressions (full suite
  green, including the concurrent W3 vault tests).

## Ontology governance module (2026-10-12, ontology builder)

Additive-only: new package `src/gateway/ontology/` + three narrow hooks
in shared files. M3 (approvals) and M5 (inspection) files untouched;
no console UI (explicitly out of scope).

### Files created
- `src/gateway/ontology/__init__.py` — package exports.
- `src/gateway/ontology/models.py` — 9 tables on the SHARED config-DB
  `Base` (imported from `gateway.models`; no new DB files, no new
  infrastructure): `ontology_principals` (person|agent|service),
  `ontology_relationships` (directed; household_member_of, owns,
  delegates_to, acts_for), `ontology_agent_bindings` (agent→principal),
  `ontology_resources` (kind, label class work|private|family, owner),
  `ontology_actions` (name, default sensitivity), `ontology_dimensions`
  (name + allowed values), `ontology_dimension_groups` (named
  dimension=value combos — "scenario slices"),
  `ontology_preference_groups` (per-combo constraints:
  allow/require_approval/deny tool selectors), `ontology_snapshots`
  (write-once, content-addressed).
- `src/gateway/ontology/store.py` — `OntologyStore`: full CRUD for all
  entities, reference validation before every write (no dangling
  principals/resources, dimension values inside allowed sets, no
  deleting referenced rows), `seed_household()` (owner + members linked
  `household_member_of` → feeds PAA08), relationship queries. Every
  mutation audit-logged as an admin action (`tool="ontology.admin"`,
  `action="<entity>.<op>"`, `decision="allowed"`) via the existing
  audit API.
- `src/gateway/ontology/integration.py` — the policy-engine bridge:
  `resolve_ctx` (fail-closed dimension/principal validation),
  `clause_holds`, `preference_upgrade` (restrict-only: deny >
  require_approval; never widens), `validate_ontology_clause`
  (structural) + `validate_ontology_conditions` (store-aware: dimension
  names/values, group names, principal ids — the M6 console calls this
  before `save_version`).
- `src/gateway/ontology/snapshots.py` — `capture_snapshot` /
  `get_snapshot` / `verify_snapshot`: immutable, content-addressed
  snapshots (tagged HMAC-SHA256 `key_id:hexdigest` via the existing
  `hmac_util` ring; no timestamp inside the hashed payload so identical
  slices → identical refs; no update/delete API). Feeds PAA04
  traceability; the decision/audit record carries the ref.
- `tests/test_ontology.py` — 41 tests, all green.

### Shared-file edits (all additive; existing behavior unchanged)
- `src/gateway/models.py`: `AuditEntry.ontology_snapshot_ref`
  (nullable String(128)) — the content-addressed decision-snapshot ref.
- `src/gateway/policy.py`:
  - `PolicyEngine.__init__(..., hmac_ring=None)` (new optional param).
  - `evaluate_call(..., ontology_ctx=None)` (new optional kwarg;
    `{"principal_id": ..., "dimensions": {...}}`). Rules WITHOUT an
    ontology clause evaluate exactly as before; with `ontology_ctx=None`
    the code path is behavior-identical (all 183 pre-existing tests pass
    unchanged).
  - `EvaluationResult` gains `ontology_snapshot_ref` (optional, default
    None) — positional 3-tuple unpacking still works.
  - `validate_rule_dict` structurally validates `conditions.ontology`
    (unknown keys/types/`requires` values → ValueError before storage).
- `src/gateway/audit.py`: `AuditLog.append(..., ontology_snapshot_ref=None)`
  (new optional kwarg); the ref is included in `_row`/JSON/CSV exports.

### Ontology rule-schema extension (for M6 console work)
`conditions.ontology` supports four sub-keys (AND together):
`{"dimension": {"purpose": "work", "location": "office"}}`,
`{"dimension_group": "<named group>"}`,
`{"relationship": {"type": "household_member_of", "target": "<principal_id>"}}`,
`{"requires": "owner_approval"}`. Semantics: dimension clauses must be
satisfied by the call's declared dimensions; relationship clauses are
resolved against the calling principal (explicit `principal_id` or the
agent→principal binding); `requires: owner_approval` upgrades a matched
`allow` to `require_approval` (feeds M3's pending-approval queue — the
engine never approves itself); unknown dimension names/values or unknown
principals fail CLOSED to the pinned default-deny (never a silent pass);
ontology-scoped rules cannot match without an `ontology_ctx`.

### What was verified
- Full suite: **224 passed** (183 pre-existing unchanged + 41 new),
  2026-10-12.
- Dimension-scoped rule allows in `purpose=work`, denies in
  `purpose=personal` (default-deny, `matched_rule_id=None`).
- Household rule (relationship + `requires: owner_approval`) surfaces as
  `require_approval` with a snapshot ref; non-members default-deny.
- Preference groups: `require_approval`/`deny` selectors (incl. `email.*`
  wildcards) restrict only; outside the slice plain rules apply.
- Snapshots: deterministic refs, tamper → `verify_snapshot` False,
  audit row round-trips the ref.
- Default-deny on unknown dimension name AND unknown dimension value.
- `EvaluationResult.ontology_snapshot_ref` is set whenever an ontology
  clause or preference group shaped the decision (and a ring is
  configured).

### GPL-3.0 avoidance statement
The inspiration repository (anydefai/personal-ontology, GPL-3.0) was
NEVER fetched, cloned, read, copied, ported, translated, or adapted.
No code, snippet, or file from it exists in this tree. Only the
high-level concepts (structured personal ontology; principals/resources/
actions/context dimensions; a default-deny decision engine that judges
but never executes; scenario slices as per-dimension preference groups;
audit records carrying rule references + decision-time snapshots;
per-program/per-capability authorization feeding a pending-approval
queue) were reimplemented independently in original code. The
implementation carries no GPL obligations.

### Interpretations and deviations (rationale recorded; no silent spec changes)
1. **Ontology tables live in `src/gateway/ontology/models.py`, not in
   `src/gateway/models.py`.** They are declared on the SAME shared
   `Base`, so `Database.create_all()` creates them in the config SQLite
   with zero shared-file table edits. Rationale: package cohesion; the
   "add new tables to the existing Base" requirement is satisfied by the
   shared Base/metadata, not by file location.
2. **KNOWN SEAM — hot-path wiring deferred.** `PolicyStage` does not yet
   pass `ontology_ctx`, and the pipeline's `AuditStage` does not yet
   thread the ref into the audit row (M3 is concurrently editing
   `pipeline.py`; touching it here risks a merge conflict). The
   `evaluate_call` contract and `AuditLog.append(ontology_snapshot_ref=...)`
   are in place and tested; M3/M6 wire: (a) the pipeline sets
   `ontology_ctx` from the session/agent binding, (b) approval-request
   creation copies `EvaluationResult.ontology_snapshot_ref`, (c)
   `AuditStage` passes it to `append`. No behavior changes until then.
3. **Store-aware rule validation is separate from `validate_rule_dict`.**
   `validate_rule_dict` (called by `save_version`) does structural
   validation only — it has no DB access. `validate_ontology_conditions(db,
   conditions)` does the store-aware checks (dimension names/values,
   group names, principal ids); the M6 console MUST call it before
   `save_version`. Evaluation stays fail-closed regardless.
4. **`dry_run` does not pass `ontology_ctx`.** History rows carry no
   declared dimensions; ontology-scoped rules evaluate as non-matching
   in dry-run (documented approximation, same class as the existing
   redacted-args approximation in M2 deviation 8).
5. **Preference-group `allow` lists are documentation only.** Only
   `deny`/`require_approval` selectors affect decisions (restrict-only);
   policy rules remain the sole authority for allows.

### Non-regression (06-review-log)
- Fix A (auth wall) and Fix B (approval workflow order) untouched.
- Existing rule semantics unchanged: with `ontology_ctx=None`, rule
  matching is the identical code path; `EvaluationResult` positional
  unpacking preserved; audit `append` signature backward compatible.
- Evidence-subset / HMAC rules (02 §2.8 step 4) untouched — snapshots use
  the same `hmac_util` ring convention (`key_id:hexdigest`).
- `docs/04-review.md` untouched (historical record).

### Open for later milestones (not ontology gaps — owned elsewhere)
- M3: copy `ontology_snapshot_ref` from the evaluation result into the
  approval request record; consume `requires: owner_approval` as
  owner-routed approval context.
- M5: none (no inspection touch-points).
- M6: console pages for ontology CRUD; `validate_ontology_conditions`
  before policy save; `POST /api/policy/evaluate` accepts `ontology_ctx`;
  pipeline wiring per deviation 2.
- Ken's actions (unchanged): household member list for `seed_household`
  (currently seeded in tests only), OAuth app registrations, hosting choice.

## Ontology "beyond" refinement (2026-10-12, ontology builder)

Ken's five directives on the ontology module (2026-10-12 ~17:30 EDT):
discovery-first bootstrap, gateway-side per-agent scoped views, living
ontology with provenance, presets/templates, enforcement-first
citations. Additive-only: three new modules + additive columns/methods;
`pipeline.py`, `approvals.py`, and `src/gateway/inspection/` untouched
(M3 owns the first two); the `PolicyStage`→`ontology_ctx` threading seam
stays exactly as documented in the previous section's deviation 2.

### Files created
- `src/gateway/ontology/discovery.py` — `discover_from_accounts`
  (connected-account metadata → person-principal + resource candidates)
  and `discover_from_audit` (recurring (agent, tool) tuples →
  candidate resources + candidate `purpose` dimension values; mandate
  purpose text first, tool-class heuristics as low-confidence fallback;
  time patterns only when a `time_of_day` dimension already exists,
  ≥80% concentration, confidence 0.4 — never invents time/location
  dimensions from logs). Every candidate: `provenance="inferred:<source>"`,
  confidence 0..1, `status="pending_confirmation"`. Candidates are not
  authority — `confirm_candidate` is the only promotion path.
- `src/gateway/ontology/feedback.py` — `record_decision_outcome`,
  `record_correction`, `record_mandate_event`, `sweep_stale`,
  `detect_conflicts`. Feedback is recorded as immutable events; stale /
  conflicting entries are FLAGGED into the review queue, never silently
  mutated. Mandate end/withdraw/expired with a purpose key flags every
  preference group and dimension group scoped to that purpose.
- `src/gateway/ontology/presets.py` — `apply_preset` /
  `list_presets`: `work_personal_separation`, `spending_thresholds`,
  `social_send_approval`, `household_boundaries`. Each seeds/updates
  principals, dimensions, dimension groups, preference groups, and
  sensitive-action registry entries, then saves a NEW policy version
  carrying the preset's rules (material-classified; non-preset rules
  carried over; the preset's own previous rules replaced — idempotent,
  never duplicates).
- `tests/test_ontology_beyond.py` — 41 tests, all green.

### Shared-file edits (all additive; existing behavior unchanged)
- `src/gateway/ontology/models.py`: `provenance` column
  (`"explicit:<source>"` / `"inferred:<source>"`, default
  `"explicit:manual"`) on the 7 entity tables (FR-PAA04-001); three new
  tables on the shared config-DB Base: `ontology_candidates`,
  `ontology_review_queue`, `ontology_feedback_events`.
- `src/gateway/ontology/store.py`: `propose_candidates` (inferred-only
  provenance enforced; dedupe by kind+payload), `confirm_candidate(id,
  corrections)` (merges corrections, promotes with full provenance
  chain `inferred:<source> -> explicit:confirmed`), `reject_candidate`,
  `flag_for_review` / `list_review_items` / `resolve_review_item` /
  `dismiss_review_item`, `record_feedback_event` /
  `list_feedback_events`; `provenance` kwarg on all create methods and
  `seed_household`.
- `src/gateway/ontology/integration.py`: `ScopedView` +
  `scoped_view(agent_id, mandate_purpose_keys)` (bound principal,
  transitive `acts_for` closure, `delegates_to` in-edges, household
  member→owner one direction only — PAA08; resource clearance;
  mandate-applicable dimension groups); `resolve_ctx_for_agent`
  (fail-closed on principal/dimension-value/resource outside the view,
  citing the defining entry); `deciding_preference_group` (the group
  whose selector actually matched — for citations).
- `src/gateway/policy.py`: `EvaluationResult.ontology_ref`
  (`{"entry_id", "entry_kind", "snapshot_ref"}`); `evaluate_call`
  enforces scoped views for bound agents (scope denial captures a
  decision snapshot when a ring is configured) and cites the deciding
  preference group on pref-deny and the relationship target principal
  on `requires: owner_approval` step-ups.
- `src/gateway/errors.py`: `policy_denied(..., ontology_ref=None)` —
  additive `details["ontology_ref"]`; the safe-vocabulary check on
  `reason` is unchanged (entry ids are opaque `ont_` config ids, never
  rule text).

### Concept → enforcement-hook table (directive 5 audit)
| Concept | Concrete pipeline hook |
|---|---|
| Principal | `resolve_ctx` existence validation; scoped-view act-for scope; cited as `entry_kind: principal` in owner_approval asks |
| Relationship | `clause_holds` relationship predicate; `requires: owner_approval` step-up; discovery proposes `acts_for` from account use |
| AgentBinding | `resolve_ctx` principal fallback; the root that defines an agent's `ScopedView`; cited in scope denials |
| Resource | `resolve_ctx_for_agent` `resource_id` scoping (fail-closed); `scoped_view.resource_ids` clearance = resources owned by in-scope principals |
| Action | Sensitivity registry — presets register sensitive actions AND materialize them as `require_approval` rules; policy rules remain the sole authority (no direct evaluation hook by design — see deviation 5) |
| Dimension | `resolve_ctx` validation (unknown name/value → deny); scoped-view `dimension_values` restriction (purpose ← mandate keys) |
| DimensionGroup | `clause_holds` group predicate; preference-group applicability; scope-denial snapshots |
| PreferenceGroup | `preference_upgrade` (restrict-only); `deciding_preference_group` cited in deny/ask `ontology_ref` |
| Snapshot | `ontology_snapshot_ref` on decisions + audit rows; `verify_snapshot` tamper-evidence |
| Candidate | `propose/confirm/reject`; the ONLY path from inferred to authority; `sweep_stale` → review queue |
| ReviewItem | M6 console surface (list/resolve/dismiss); flags only, never auto-mutates |
| FeedbackEvent | Immutable input log for the living-ontology loop (no update/delete API) |

### Interpretations and deviations (rationale recorded; no silent spec changes)
1. **Unbound agents keep the legacy path.** `resolve_ctx_for_agent`
   enforces the scoped view only when the agent has an ontology
   binding; without one there is no view to enforce (existing tests
   such as `test_explicit_principal_id_in_ctx` rely on this). M6
   SHOULD bind every agent at the pipeline layer (checklist item f).
2. **Preference-guard deny/require_approval fires only when a policy
   rule matches** (pre-existing semantic from the first build's
   deviation 5). A deny with no matching rule is still a deny (pinned
   default-deny) but carries no `ontology_ref` — there is no deciding
   entry to cite.
3. **Discovery never invents time/location dimensions** from audit logs
   (the directive said "cautiously"): time patterns are proposed only
   when the dimension already exists, at 0.4 confidence, as
   `pending_confirmation` candidates.
4. **Provenance columns are additive with defaults** — fresh
   `create_all()` in tests; no migration for existing dev DBs (MVP;
   the config DB is local).
5. **Action has no direct evaluation hook by design.** Wiring it into
   decisions would make the registry a second authority beside policy
   rules (against FR-PAA04-002's spirit). It is wired through presets
   (registry entry + generated rule together) and stays inspectable.
6. **`approval_required` envelope already supports `ontology_ref`.**
   `make_error`/`GatewayError` place no vocabulary constraint on that
   code's details — M3 only needs to copy
   `EvaluationResult.ontology_ref` into the approval record and
   `_approval_required` details (`approvals.py` untouched per task).

### Forward-compatibility note (Rego direction, 2026-10-12 ~17:35 EDT)
Ken briefed the ontology → intent → open-policy chain with OPA/Rego
replacing the hand-rolled JSON evaluator (spike first). The scoped-view
resolution, snapshot capture, and `ontology_ref` citation live in the
ontology package and the `EvaluationResult` contract — not in the JSON
evaluator — so they port unchanged: the Rego input becomes
intent + ontology snapshot + mandate/grant state, and the decision
contract (allow/deny/ask + `ontology_ref`) is evaluator-agnostic.

### What was verified
- Full suite: **352 passed, 0 failed** (311 pre-existing — the
  concurrent M3/M5 builders added tests since the 269 baseline — plus
  41 new), 2026-10-12.
- Discovery over synthetic audit rows proposes sane candidates
  (resource owned by the bound principal, purpose values from mandate
  text); confirm/reject flows with provenance chains; dedupe across
  sweeps; no auto-promotion (candidates invisible to the engine).
- Scoped views: transitive `acts_for`, `delegates_to` in-edges,
  household member→owner one-way (PAA08); agent A denied acting for
  agent B's principal with `ontology_ref` citing the binding;
  purpose values outside the agent's mandates denied citing the
  dimension; resources outside clearance denied citing the resource.
- Living ontology: mandate withdrawal flags dependent preference
  groups AND dimension groups without mutating them; denied-vs-allow
  documentation conflicts detected; repeated denials flagged;
  corrections recorded as events + flags; stale candidates swept;
  review queue resolve/dismiss.
- Presets: each applies cleanly and evaluates as documented —
  work/personal email allow vs guard-escalated require_approval,
  `payment.*` always require_approval, social/email require_approval,
  household member family-photos require_approval (owner-routed) vs
  non-member default-deny; re-apply is idempotent; versions are
  material-classified; existing rules preserved.
- Citations: `policy_denied` details carry `ontology_ref`; safe
  vocabulary still enforced; plain-rule decisions carry no
  `ontology_ref`; envelope shape unchanged otherwise.

### GPL-3.0 avoidance statement (reaffirmed for the new code)
The inspiration repository (anydefai/personal-ontology, GPL-3.0) was
NEVER fetched, cloned, read, copied, ported, translated, or adapted —
for this refinement either. `discovery.py`, `feedback.py`, and
`presets.py` are original code from the task's plain-language
directives. No GPL obligations attach.

### M6 wiring checklist (precise; the seam from deviation 2, extended)
- (a) `PolicyStage.run`: build `ontology_ctx` from the session/agent
  binding — `{"principal_id": ..., "dimensions": {...},
  "resource_id": ...}` (resource_id only when a tool→resource mapping
  exists) — pass to `evaluate_call` with `purpose=<mandate.purpose_key>`.
- (b) `AuditStage`: pass `EvaluationResult.ontology_snapshot_ref` to
  `AuditLog.append`.
- (c) On policy-stage deny/ask: copy `EvaluationResult.ontology_ref`
  into `policy_denied(..., ontology_ref=...)` details.
- (d) Approval-request creation (M3, `approvals.py`): copy
  `ontology_snapshot_ref` + `ontology_ref` into the approval record;
  `_approval_required` details include `ontology_ref` (envelope
  already supports it — no errors.py change needed).
- (e) Console: ontology CRUD pages; review-queue page
  (list/resolve/dismiss); candidate confirm/reject UI;
  `validate_ontology_conditions` before `save_version`;
  `POST /api/policy/evaluate` accepts `ontology_ctx`.
- (f) Bind every agent to a principal — unbound agents are not
  scoped-view enforced (deviation 1).
- (g) `dry_run` still passes no `ontology_ctx` (documented
  approximation, unchanged).

## M5 — Inspection pipeline (2026-10-12, inspection builder)

### Files created
- `src/gateway/inspection/__init__.py` — package exports.
- `src/gateway/inspection/validation.py` — hardened validator: strict
  RFC 3339 `date-time` + `email` format checkers, `additionalProperties`
  honored where schemas opt in, per-tool `pattern` constraints (native
  JSON Schema), control-character rejection in string fields,
  `canonicalize_args` (recursive key sort + integral-float
  normalization) before hashing. `invalid_input` names the field only.
- `src/gateway/inspection/rate_limit.py` — `RateLimiter`: 60/min +
  1000/day per-agent tool budgets (Settings-tunable); separate
  `gateway.approval_status` poll budget (02 §2.5); counters in the
  config DB `rate_counters` table (window `minute`/`day`/`poll_minute`),
  surviving restarts; `rate_limited` with `retry_after` seconds.
- `src/gateway/inspection/urgency_flags.py` — false-urgency +
  deceptive-relationship-claim scan of trigger content (FR-PAA09-002);
  additive hook `urgency_flags_for_approval_record(ctx)` for M3.
- `src/gateway/inspection/injection_scan.py` — pattern-based
  prompt-injection scan of tool outputs (FR-026): instruction override,
  delimiter smuggling, role-play/jailbreak markers, base64-blob hints,
  system-instruction impersonation. Residual documented in docstring
  (novel phrasings missed; semantic judge out of MVP — 00 §8 risk 4).
- `src/gateway/inspection/redaction.py` — `RedactionCatalog` CRUD over
  the config DB `redaction_patterns` table (console-editable from day
  one); 10 seeded defaults (email, phone_intl, phone_domestic, ssn,
  iban, api_key, secret_assignment, verification_code, otp,
  reset_link); full `[redacted:type]` tokens, no last-4 (00 §7 param 13).
  `redact_ctx_for_audit` redacts args before the audit write.
- `src/gateway/inspection/context_labels.py` — cross-context leakage
  (FR-PAA03-003): reads adapter-surfaced labels (mock message `labels`,
  calendar `visibility`); private/family fact in a work-purpose response
  → flag + redact per `leakage_action` hook; unlabeled passes with an
  "unlabeled" marker, never guessed.
- `src/gateway/inspection/output.py` — real `InspectOutputStage`
  (03 §1.2 step 8): injection scan → PII/code-artifact redaction →
  leakage flags; fail-closed (03 §7): any scanner exception denies the
  call with `injected_output_blocked`, never pass-through. Every
  detection is audit-logged (AC-06).
- `tests/test_inspection.py` — 43 tests: AC-06 (block + redact modes),
  AC-07 (redacted pre-delivery AND pre-audit-write; raw bytes absent
  from the audit DB file), schema hardening, OTP/reset-link redaction,
  leakage with `SYNTHETIC-TRACE-FACT-PAA03-*`, urgency flags + hook,
  rate limits + restart persistence + poll budget, fail-closed,
  catalog CRUD.

### Files modified (all M5-owned or shared pipeline skeleton)
- `src/gateway/pipeline.py` — `ValidateInputsStage` hardened in place
  (rate limit → strict schema → control chars → canonicalize →
  urgency scan); `InspectOutputStage` stub replaced by the real stage
  from `gateway.inspection.output`; `CallContext` gains
  `urgency_flags` + `inspection_notes`; `Pipeline` gains an optional
  `pre_audit_hook` (see deviation 2); both builders wire the
  rate limiter, catalog, inspection config, and the hook.
- `src/gateway/models.py` — ADDED `RedactionPattern` table only; no
  existing table touched.

### Interpretations and deviations (rationale recorded; no silent spec changes)
1. **Urgency flags computed in `validate_inputs` (step 2), not in
   `inspect_output` (step 8).** FR-PAA09-002 requires the flags to be
   surfaced ON THE APPROVAL CARD, and approval (step 5) precedes output
   inspection (step 8). Computing them at step 8 could never satisfy
   the card requirement. Exact doc section: 01 FR-PAA09-002 vs
   00 §4 M5 step-8 list. The flags ride on `ctx.urgency_flags`; M3's
   approval service reads them via the additive
   `urgency_flags_for_approval_record()` hook (documented contract:
   store under the approval record's `inspection_flags` JSON key).
   No M3-owned file was modified.
2. **Pre-audit redaction as a `Pipeline`-level hook, not inside
   `AuditStage`.** NFR-DATA-001 requires redaction before the audit
   write on ALL paths (including calls halted at validate/policy/
   approval, which never reach `inspect_output`). The M5 task forbids
   touching the audit stage, so `Pipeline.execute` runs an optional
   `pre_audit_hook` (redact args + log event) immediately before the
   terminal audit write. Exact doc section: 01 NFR-DATA-001.
   Fail-closed: hook failure replaces args with a marker dict rather
   than writing plaintext PII.
3. **Redaction scope defaults to all tools (`["*"]`).** FR-027 says
   "per policy (per-agent, per-tool rules)"; the catalog rows carry
   per-tool/per-agent scope lists, defaulting to `["*"]`, console-
   editable (Ken narrows them in M6). Exact doc section: 01 FR-027.
4. **Rate limiting inside `ValidateInputsStage`, not a new stage.**
   The Fix-B stage order is load-bearing ("never reordered"); adding a
   stage would renumber it. The limiter runs first inside step 2, so
   every attempt (valid or not) counts. Exact doc section: 00 §2 Fix B.
5. **Leakage rule is private/family-in-work only.** 01 FR-PAA03-003
   names that case; work-labeled facts in personal-purpose responses
   are not treated as leaks (no spec basis for the reverse rule).
6. **Detection-event audit rows use pseudo-tools
   `inspection.injection_scan` / `inspection.redaction` /
   `inspection.context_leakage`.** One row per call (02 §4.4 design
   principle 4) is preserved for the call decision itself; these are
   separate security-event rows correlated by `request_id`.

### Non-regression (06-review-log)
- Fix A (auth wall) and Fix B (stage order) untouched: the recorded
  Fix-B order test (`authenticate, validate_inputs, mandate, policy,
  approval, mint_token, execute, inspect_output, audit`) still passes
  unchanged; validate still precedes policy/approval (MF-4).
- `invalid_input` still names the field, never the value (04 NH-2);
  `policy_denied` safe vocabulary untouched; error envelope (02 §2.7)
  unchanged — `rate_limited` carries `retry_after`, as the spec's
  retryable mapping (`after_retry_after`) requires.
- `ApprovalRequest` / `Grant` models and all M3-owned surfaces
  untouched (no approvals.py exists yet; the urgency-flag contract is
  additive-only).
- HMAC argument hashing untouched (`hmac_util.canonical_json` still
  the hash input; in-place canonicalization is order-preserving for
  hashing and consistent across re-invokes since every pipeline pass
  canonicalizes).
- NFR-DATA-001 approvals-record exception (evidence subset cleartext)
  unaffected: the pre-audit hook runs after the approval stage.
- Full suite: 269 passed (225 pre-existing + 44 new M5 tests),
  zero failures (M3's in-progress `tests/test_approvals.py` excluded —
  6 of its tests fail standalone against M3's own unfinished code;
  unrelated to M5).

### Concurrent-edit collision repair (M3's notifier, repaired by M5)
- While M5 was running, the M3 worker added `src/gateway/notifier.py`
  with four broken imports (`from ..audit`, `from ..config`,
  `from ..models`, `from .notifier_secret`) — all one level too high /
  wrong module. Any `build_pipeline` call with an approval service
  crashed with `ImportError`, failing
  `TestMcpWire::test_tools_call_default_deny_ac03` and the M3 approval
  path. M5 repaired the four import lines to
  `from .audit` / `from .config` / `from .models` /
  `from .vault.notifier_secret` (the provider lives in
  `gateway/vault/notifier_secret.py`). Typo-level fix only; no M3 logic
  touched. M3 should review. M5's own wiring in `build_pipeline`
  (catalog, rate limiter, inspection config, pre-audit hook) survived
  the concurrent edit intact, and M3's new `execute_approved_call`
  correctly reuses M5's `redact_ctx_for_audit` + `InspectOutputStage`.

## OPA/Rego spike — PASS, sidecar recommended (2026-10-12, coordinator)

Ken's direction: authorization chain becomes ONTOLOGY → INTENT → OPEN POLICY (Rego). ("Ragu" read as Rego; nothing in docs or memory contradicts this — the docs' anti-OPA notes in 00 §5 and 03 §8 are the standing decision this pivot re-evaluates, not a contradiction.)

Spike (read-only, scratch in /tmp/opa-spike/, binary kept at ~/workspace/opa-spike-bin/opa):
- Packaging PASS: official `opa` v1.8.0 linux/amd64 binary from github.com/open-policy-agent/opa releases; SHA-256 verified against official checksum `7c2105efa744ec5519d38ac7463fb1eed1e9b4a352891ca53a8de549192abd11` — match. `opa run --server --addr 127.0.0.1:8181` + `POST /v1/data/gateway/authz/decision` verified live (12/12 test inputs correct). `opa-python-client` 3.0.0 (MIT) usable as REST client. `opa-golib-python-bindings` REJECTED (needs Python ≥3.14; we run 3.12). `opa-py-wasm` too slow (see below).
- Latency PASS: sidecar, keep-alive HTTP, ≥1000 calls: p50 2.64 ms / p95 7.28 ms / p99 11.6 ms. OPA-internal eval 0.111 ms — the ~2.3 ms is OPA's HTTP layer, not Rego. Rego authoring lesson (measured): candidate-set + max() priority form evaluated at 7.4 ms inside OPA; idiomatic else-chain (first-match-wins, mirrors our top-down semantics) dropped it to 0.111 ms — 66x. Hand-rolled baseline: p50 3.47 / p95 17.5 ms (dominated by 2 SQLite queries/call). Against the AC-11 budget (policy+inspection <100 ms p95): Rego's share is single-digit ms — passes, but re-measure on the deploy target; consider unix-socket transport to cut the HTTP cost.
- CI PASS: `opa test` 5/5 in 104 ms; `opa check` + `opa fmt` verified. CI needs pinned binary + sha256 download, then `opa fmt --check && opa check && opa test`.
- License PASS: OPA v1.8.0 LICENSE opens "Apache License, Version 2.0, January 2004" — verified at build time against tag v1.8.0; checksum links binary to official release. No artifact rejected on license grounds.
- Recommendation: (a) sidecar — one supervised `opa` process per gateway instance; hot path = intent input doc → keep-alive POST → {effect: allow|deny|ask, rule}; `ask` maps to require_approval; standing data (ontology allow-lists) pushed via PUT /v1/data/ontology at policy-save time; grants/mandate-liveness stay Python-side as pre-OPA short-circuit (high-churn DB state; Fix-B ordering preserved).
- Honest cost to flag: the pivot's real cost is not Rego eval (0.1 ms) — it is a second supervised process + the HTTP hop (~2–7 ms), and it retires the "dependency-free evaluator" rationale in 03 §8.
- Implementation worker's first steps: (1) Rego authoring choice — generate from existing JSON rule schema (keeps console rule builder) vs hand-authored Rego; (2) freeze input-document schema {agent:{id,household_role}, tool, action_class, args, purpose, dimensions, time}, missing-field → no-match (fail closed); (3) decision contract data.gateway.authz.decision = {"effect": "allow"|"deny"|"ask", "rule": id|"default_deny"}; (4) `opa check` at rule-save time (replaces validate_rule_dict); (5) re-run AC-11 on deploy target incl. inspection pipeline.
- M2's connector work is unaffected by this pivot (connectors call adapters, not the evaluator).

## M3 — Approval workflow (Fix B) (2026-10-12, approval-workflow builder)

Implements 00 §2 Fix B (all 8 bullets) and the M3 exit criteria.

### Files created
- `src/gateway/approvals.py` — `ApprovalService` + `ApprovalStage`
  (replaces the M1 stub), `GrantService`, `GrantCheckResult`,
  `UnknownOutcomeService`, `make_approval_status_tool`.
- `src/gateway/approval_card.py` — approval card data model (02 §4.4)
  + inert HTML renderer + per-tool evidence builders with
  `replay_args` for execute-on-approval (WYSIWYE).
- `src/gateway/counterparty.py` — per-payee records (FR-PAA05-001),
  new/changed-details assessment, `counterparty_escalator` for the
  policy stage (FR-PAA05-002), console `correct()` (FR-PAA05-003).
- `src/gateway/notifier.py` — exempt email-to-Ken notifier (02 §2.8
  step 5): fixed field allowlist, `NotifierSecretProvider` reads,
  90-day max secret age, per-agent cooldown, bounce → in-console
  fallback, `MockNotifierTransport` + stdlib `SmtpNotifierTransport`.
- `src/gateway/console/csrf.py` — `CsrfProtector` (SameSite=Strict
  cookie + X-CSRF-Token, server-side registry) and
  `ConfirmationTokenIssuer` (single-use, apr-bound, 10-min TTL,
  FR-042).
- `src/gateway/console/approvals.py` — Approvals page + API
  (pending queue, card, decision, counterparty review/correct,
  unknown-outcome resolve, CSRF token endpoint).
- `src/gateway/console/templates/approvals.html` — queue, card
  (inert), approve/deny, history, counterparty correction, block
  resolution.
- `tests/test_approvals.py` — 42 tests (see below).

### Files modified
- `models.py`: `ApprovalRequest.result_summary`/`decision_note`,
  `CounterpartyRecord.details_snapshot`, new `RefusalCooldown`,
  `UnknownOutcomeBlock` tables.
- `mandates.py`: the default mandate template now includes
  `gateway.*` (agents must be able to poll their own approvals).
- `config.py`: notifier tunables + `console_base_url`.
- `errors.py`: `ToolHalt` (pipeline-internal control flow).
- `policy.py`: `EvaluationResult` +4 M3 fields, `META_TOOLS`
  (`gateway.approval_status` is routine/meta, halt-at-policy
  exempt), grant branch honors `GrantCheckResult`.
- `pipeline.py`: `CallContext` M3 fields (`needs_approval`,
  `via_grant`, `approval_request_id`, `escalation_reason`,
  `argument_hash`, `skip_audit`, `raw_args`); `ApprovalStage` wired
  via lazy re-export (keeps `from gateway.pipeline import
  ApprovalStage` working); `ExecuteStage` catches `ToolHalt` +
  TimeoutError→unknown-outcome block; `AuditStage` counterparty hook
  + `skip_audit` + `approval_request_id`; `execute()` computes
  `argument_hash` and sets `allowed_via_approval`; `build_pipeline(...
  approvals=True/approval_service/minter)`; `execute_approved_call`
  (MF-11 fallback, reuses M5 redaction + inspection).
- `mcp_server.py`: live path uses `approvals=True` when the HMAC ring
  is present, else warns + degrades to the M2 halt-at-policy
  behavior; `GatewayApp.__init__` registers `gateway.approval_status`.
- `console/app.py`: CSRF on all state-changing routes (incl. the M2
  agent POSTs), approval routes, revoke kills grants.
- `tests/test_connectors.py`: console POSTs now fetch/pass CSRF
  tokens; new `test_state_changing_routes_reject_missing_csrf`.

### Deviations / spec clarifications (exact doc sections)
1. **Live-agent AC-04 demonstration is Ken's action.** 00 §4 M3 exit
   asks for the extended AC-04 "as far as verifiable here": the full
   loop (sensitive → approval_required → poll → approve → poll →
   re-invoke → executes, 3 linked audit rows) is tested against the
   gateway. The LIVE-agent (real Muse/Grok client) demonstration
   needs platform accounts this environment does not have — no
   platform accounts here, per the build rules. Exact doc section:
   00 §4 M3 exit criteria.
2. **Email-to-Ken uses the exempt notifier path, not `email.send`.**
   02 §2.8 step 5 + 03 §5: the notifier is deliberately outside the
   policy-gated connectors (M3 does not wait on M4's credential
   wiring). Exact doc section: 02 §2.8 step 5.
3. **M6 owns console admin auth.** The Approvals page currently has
   no login (like the M2 console); the decision endpoints are
   CSRF-protected and one-time-scoped, but authentication/authorization
   of the human operator is M6. Exact doc section: 00 §4 (M6).
4. **Counterparty payee model is email.send + code.pr.open in MVP.**
   FR-PAA05-002 names "commitment-adjacent actions"; the MVP keys
   payees for `email.send` (first `to` recipient) and `code.pr.open`
   (repo). Calendar/finance payee models are M5+/M6. Exact doc
   section: 01 FR-PAA05-002.
5. **Execute-on-approval replays the card-visible (redacted) args.**
   The gateway stores redacted full args only (02 §2.8 step 4); true
   args are never retained server-side. The MF-11 fallback therefore
   replays exactly what Ken saw on the card (WYSIWYE) — e.g. a body
   containing `[redacted:code]`. Full-fidelity execution remains the
   agent re-invoke path (grant binds the HMAC of the true args; the
   card's content-hash binds Ken's approval to the true content).
   Exact doc section: 02 §2.8 step 4 + §4.4.
6. **`ctx.raw_args` added for the counterparty hook.** M5's pre-audit
   hook rebinds `ctx.args` to the redacted copy (NFR-DATA-001) before
   the terminal audit write; the FR-PAA05-001 hook needs the
   plaintext payee key. `CallContext.raw_args` snapshots pre-redaction
   args; the audit row keeps the redacted args. Exact doc sections:
   01 NFR-DATA-001 vs 01 FR-PAA05-001.
7. **Poll budget enforced by the validate-stage limiter.** 02 §2.5's
   "own rate budget" is the existing `RateLimiter`'s
   `APPROVAL_STATUS_TOOL` branch (`approval_status_polls_per_minute`);
   a handler-level duplicate was removed to avoid dual-counter drift.
   A rate-limited poll is a denied outcome → audit-logged per the
   02 §2.5 carve-out (EXCEPT denied/expired/not-found). Exact doc
   section: 02 §2.5.
8. **Grant consumption is at the policy stage; a failed later stage
   leaves the grant consumed** (terminal `already_executed`). Rationale:
   the grant is a one-time capability; re-issuing after a downstream
   failure would break the exactly-once guarantee. Exact doc section:
   02 §2.8 step 9.
9. **Missing notifier bootstrap secret degrades to in-console
   fallback** (audit-logged), not a crash. An EXPIRED (>90d) secret
   refuses loudly (`secret_expired`). Exact doc sections: 02 §2.8
   step 5, 03 §5.

### Non-regression (06-review-log)
- Fix A (auth wall) and Fix B (stage order) untouched; M2's
  halt-at-policy default preserved (`defer_approval=False` unless the
  M3 wiring opts in) — the pre-existing tests needed zero changes on
  that axis.
- M5's inspection pipeline untouched: `redact_ctx_for_audit` +
  `InspectOutputStage` reused by `execute_approved_call`; the
  `raw_args` addition is additive.
- Full suite: 352 passed (42 new M3 tests), zero failures, zero
  errors. (An earlier full-suite run showed 9 transient fixture
  errors in test_vault.py plus a transient collection miss; neither
  reproduces — reruns are clean. The TestRateLimits minute-boundary
  flake noted below is the only known recurring flake.)
  `tests/test_connectors.py` console tests updated for CSRF.

### Known flake (pre-existing, not M3)
- `tests/test_inspection.py::TestRateLimits` (M5) is sensitive to
  minute-boundary rollover: `test_minute_budget_enforced` /
  `test_counters_survive_restart` fail when the test straddles a
  wall-clock minute (observed standalone). Not touched by M3;
  recommend M5 use a fake clock or freeze the window.

### M3 exit criteria status
- Full approval loop vs the gateway: DONE
  (test_full_loop_three_linked_rows).
- Validate-first, caller binding, dedupe, already_executed, cooldown
  + streak escalation, cap, grant TTL, atomic consume, mandate
  withdrawal/pause/expiry, policy supersession (material vs
  non-material), CSRF, notifier allowlist/fallback/90-day,
  execute-on-approval single-execution, destructive confirmation
  tokens, decision idempotency, counterparty new/changed/correct,
  unknown-outcome block/resolve, evidence subset shape, inert
  rendering, poll budget: DONE (42 tests).
- Live-agent AC-04 demo: KEN'S ACTION (no platform accounts here).

### Interfaces added for M5/M6
- `ApprovalService` / `GrantService` / `UnknownOutcomeService` /
  `CounterpartyService` (M6 console + M5 hardening).
- `gateway.approval_status` meta tool; `POST
  /api/approvals/{id}/decision`; `GET /api/csrf-token`
  (M6: put admin auth in front).
- `ConfirmationTokenIssuer` (M6: bind to the admin session).
- `Notifier` with `MockNotifierTransport` (M6: production SMTP
  config + secret rotation).
- Per-tool evidence builders in `approval_card.py` (M5: extend
  `redact_code_like_secrets` into the full FR-PAA02-001 catalog;
  harden the provisional urgency/relationship/sponsor detectors).

## ONTOLOGY → INTENT → OPEN POLICY pivot (2026-10-12, pivot builder)

Ken's direction (17:35 EDT): the authorization chain becomes ONTOLOGY → INTENT → OPEN POLICY (Rego). The OPA spike (above) PASSED with the sidecar recommendation; this entry records the implementation. 00 §5 and 03 §8's anti-OPA notes are superseded by this pivot — see "Deviations" below.

### Rego authoring choice (spike step 1): generate from the JSON rule schema
**Chosen: generate-from-JSON-rule-schema.** The console rule builder (02 §5) keeps producing the existing JSON rule dicts; `PolicyEngine.rule_to_input_data` normalizes each rule to the frozen input shape and the Rego in `policies/v1/authz.rego` interprets that shape. Rationale: (a) 02 §5's no-DSL rule builder is a shipped contract — hand-authored Rego per rule would fork the authoring surface and strand the M6 console work; (b) `validate_rule_dict` is replaced by `opa check` + a `rule_problems(rule)` Rego predicate evaluated at save time (`PolicyEngine.opa_check_rules`, fail-closed), so the JSON schema keeps a machine-checked validator; (c) the Python reference matchers (`rule_matches` et al.) are kept as documented reference implementations and cross-checked against Rego on generated cases (tests/test_rego.py::TestPythonRegoCrossCheck, 34 cases + 4 notice cases), so the port stays provably identical. Hand-authored Rego survives only where JSON cannot reach: the five versioned default policies in `policies/v1/` (work_personal, spending, social_send, household, paa10), each with an `opa test` suite (70/70 green).

### Files created
- `src/gateway/intent.py` — the Intent layer: `Intent` dataclass + `normalize_intent(call_ctx, db)` (pipeline path: principal falls back explicit → agent→principal binding → None; unbound agents get `ontology_context=None`, the legacy path) + `intent_from_parts(...)` (explicit-ctx path used by `evaluate_call`; when `ontology_ctx` is omitted it stays None — no scope is invented from purpose alone, exactly matching pre-pivot `evaluate_call(ontology_ctx=None)`).
- `src/gateway/opa_client.py` — supervised sidecar: `opa run --server`, keep-alive `POST /v1/data/gateway/authz/decision`; UDS transport default (`--addr unix://…`), TCP fallback (`unix_socket=""`); `OpaUnavailable` fail-closed; auto-restart on unexpected death, deny when restart fails; binary resolution order explicit > `GATEWAY_OPA_BIN` > `third_party/opa/opa` > `~/workspace/opa-spike-bin/opa`; `benchmark_transport()` helper. `trust_env=False` on the httpx clients: this runtime's proxy env breaks httpx URL parsing even for localhost (`InvalidURL Invalid port: ':1]'`), and sidecar traffic must never traverse an egress proxy.
- `src/gateway/policies/v1/authz.rego` — the decision library (`package gateway.authz`): ordered first-match over `input.rules` (else-chain form per the spike's 66x lesson), all 7 constraint ops, purpose binding, per-tz wall-clock time windows (Python precomputes `now_by_tz`; Rego has no tz database), notice rules, ontology clauses, preference groups (restrict-only, deny>ask), `rule_problems(rule)` save-time validation. `opa check` + `opa fmt --fail` clean.
- `src/gateway/policies/v1/{work_personal,spending,social_send,household,paa10}.rego` + `*_test.rego` — versioned, immutable default policies (four preset families + PAA10-derived); `household` exposes `rules_for(owner_id)`.
- `src/gateway/policies/__init__.py`, `src/gateway/policies/defaults.py` — Python-canonical defaults: `seed_defaults()` (4 presets via `apply_preset` + PAA10 rules as a material version); decision-equivalence with the Rego defaults enforced by test.
- `third_party/opa/opa` + `third_party/opa/SHA256SUMS` (sha256 `7c2105efa744ec5519d38ac7463fb1eed1e9b4a352891ca53a8de549192abd11`, matches the spike's verified artifact), `scripts/verify_opa.sh`, `.github/workflows/ci.yml` (pinned binary + checksum, `opa fmt --fail`, `opa check`, `opa test`, pytest — file only, no GitHub ops).
- `tests/test_intent.py` (13), `tests/test_rego.py` (58).

### Shared-file edits (contracts preserved)
- `src/gateway/policy.py` — `PolicyEngine` keeps its signature and contract (`evaluate_call`, `dry_run`, `validate_rule_dict`, `EvaluationResult`, grant-checker seam, Fix-B order: meta-tool allow → grant short-circuit → mandate liveness → OPA). Internals: JSON evaluator replaced by intent → `_build_input_document` → sidecar `decide` → `_result_from_decision` (`ask` → `require_approval`, unchanged Fix-B flow). Grants/mandate-liveness stay Python-side as pre-OPA short-circuit per the spike. New: `rule_to_input_data`, `rules_timezones`, `now_by_tz`, `data_snapshot_id()` (`pv<N>/rules:<sha16>/ont:<sha16|none>`), `opa_check_rules()` at save (replaces `validate_rule_dict` as the authority; `validate_rule_dict` kept as a thin wrapper), `shared_opa_client()`, `PolicyEngine(..., opa_client=...)`. `PolicyStage.run` now does `normalize_intent(ctx, db)` → `engine.evaluate_intent` and wires the M6 checklist: (a) ontology_ctx from binding + mandate purpose, (b) `ctx.data_snapshot_id` / `ctx.ontology_snapshot_ref` / `ctx.ontology_ref` for the audit row, (c) `ontology_ref` copied into `policy_denied` details.
- `src/gateway/pipeline.py` — `CallContext` gains `data_snapshot_id`, `ontology_snapshot_ref`, `ontology_ref`; `AuditStage.run` passes the first two to `audit.append`.
- `src/gateway/models.py` / `src/gateway/audit.py` — `AuditEntry.data_snapshot_id` (additive, nullable `String(128)`); `append(..., data_snapshot_id=None)`; `_row` + CSV fieldnames extended (additive columns only).
- M2 `src/gateway/connectors/` untouched.

### Frozen input-document schema (`intent-policy-input/v1`)
`{schema_version, policy_version, data_snapshot_id, agent:{id, household_role}, intent:{agent_id, principal_on_whose_behalf, action, resource_type, resource_id, params, purpose, ontology_context, mandate_refs, grant_refs}, ontology_snapshot, mandates, grants, rules, now, now_by_tz}`. Decision contract: `data.gateway.authz.decision = {"effect": "allow"|"deny"|"ask", "rule": <id|"default_deny">, "ontology_ref"?, "ontology_shaped"?, "dimension_group_ids"?, "preference_group_ids"?}`. Missing/unknown fields → no match → pinned `default_deny` (fail closed); malformed sidecar decisions raise at the engine boundary → deny.

### What was verified
- Full suite: **423 passed, 0 failed** (352 baseline + 13 intent + 58 rego). `opa test` 70/70. Zero adaptations to existing tests — the pivot needed none.
- Cross-check: 34 generated rule cases + 4 notice cases agree Python-reference vs Rego (selectors, purpose, all time-window forms, all 7 constraint ops incl. domain ops, notice templates).
- Defaults equivalence: preset-generated JSON rules vs `v1/*.rego` decide identically on probes (work_personal, spending, social_send, paa10; household via `rules_for`).
- Fail-closed: unknown dimension → deny (Python pre-check); sidecar unrestartable → deny `opa_unavailable`; malformed decision → deny; empty input → pinned `default_deny`.
- Audit traceability: `data_snapshot_id` deterministic per policy data (same rules → same id across calls; rule change → new id); ontology-shaped decisions carry both `data_snapshot_id` (`/ont:<sha>`) and `ontology_snapshot_ref` on the row.
- AC-11 (policy stage, sidecar in loop, n=500, idle VM): `evaluate_call` **p50 3.24 ms / p95 6.43 ms / p99 10.34 ms**; raw sidecar `decide` (UDS) p50 1.24 ms / p95 2.77 ms. Against the 00 §5 budget (policy+inspection <100 ms p95): the policy share is single-digit ms — passes with ~15x headroom for inspection. Transport choice: UDS default (p50 1.46 ms vs TCP 1.80 ms over n=300; UDS also immune to the proxy-env hazard above).

### Interpretations and deviations (rationale recorded; no silent spec changes)
1. **00 §5 ("no OPA / dependency-free evaluator") and 03 §8 (anti-OPA rationale) are SUPERSEDED** by Ken's 17:35 EDT pivot direction and the passing spike. The honest cost from the spike stands: a second supervised process + ~1–6 ms per decision.
2. **No `PUT /v1/data/ontology`** (spike recommendation): the ontology slice is per-decision (agent-scoped views differ per call), so there is no standing sidecar data to push. Instead the slice travels inside the input document — the sidecar stays stateless and the decision is a pure function of the input, which is exactly what `data_snapshot_id` fingerprints for audit replay. Static policy logic ships as files loaded at sidecar start.
3. **`data_snapshot_id` fingerprints rule data + ontology input slice** (`pv<N>/rules:<sha>/ont:<sha|none>`), not the post-decision snapshot ref: the id versions the *input*; the PAA04 decision snapshot travels separately as `ontology_snapshot_ref`.
4. **Time windows**: Rego has no tz database, so Python precomputes `now_by_tz` (per-tz wall-clock weekday/minutes for every tz referenced by the version's rules); Rego only compares. Timezone validation stays Python-side at save.
5. **`/tmp` was full** (512M tmpfs) during the build — scratch went to `~/workspace/tmp-rego/`.

### Non-regression (06-review-log)
- Fix A (auth wall) / Fix B (grant→mandate→policy order, ask→require_approval flow) untouched; M2 halt-at-policy default preserved; connectors untouched.
- One transient `OperationalError` observed in test_ontology.py during the build (2026-10-12); passes standalone and in full-suite reruns — same class of flake as the M3 notes.

### Interfaces for M6's console
- Policy CRUD: `PolicyEngine.save_version(rules, change_note, created_by, material_change)` (runs the OPA gate; raises `ValueError` naming the problem), `version_rules_as_dicts()`, `dry_run(...)`; ontology ctx shape `{"principal_id"?, "dimensions"?, "resource_id"?}` validated by `validate_ontology_conditions` (unchanged).
- Seeding: `gateway.policies.seed_defaults(engine, db, owner_display_name, member_display_names)`.
- Per-call trace: `EvaluationResult.data_snapshot_id`, `.ontology_snapshot_ref`, `.ontology_ref`; audit rows carry `data_snapshot_id` (+ CSV).
- Sidecar: `gateway.opa_client.OpaClient` / `shared_opa_client()`; `GATEWAY_OPA_BIN` override; `benchmark_transport()` for deploy-target AC-11 re-measurement (spike step 5: re-measure on the deploy target including the inspection pipeline).


## M6 — Console completion + hardening (2026-10-12, final build worker)

All nine console pages ship; admin auth, health checks, CI hardening,
and the ontology seam items (d) (+ verify of (a)/(b)/(c)) are done.
Full suite: 453 passed (423 baseline + 30 new `tests/test_console.py`),
`opa test` 70/70. No Fix A / Fix B regressions (full suite green,
including the Fix-B stage-order test and the approval-loop tests).

### Files created
- `src/gateway/console/admin_auth.py` — password + TOTP admin auth
  (FR-036; 02 §2.6): `AdminAuth` (AdminUser-backed; first-run `/setup`
  with QR provisioning via `qrcode`, one-shot), HMAC-signed session
  cookie (`gw_admin`), `LoginGuard` per-IP rate limiting with lockout
  + exponential backoff (1,2,4… min, cap 60; FR-040; persisted on
  `AdminUser.locked_until`), EVERY attempt audit-logged
  (`admin.login` allowed/denied + reason; FR-039), TOTP re-issue.
- `src/gateway/console/health.py` — `HealthMonitor`: per-connector
  health checks (credential-valid + API-reachable, 00 §7 param 16)
  every 5 min via a daemon thread + synchronous baseline at console
  boot; console banner on any failure (FR-038).
- `src/gateway/console/settings_store.py` — `SettingsStore` over the
  new `config_settings` KV table: console-editable overrides for the
  8 whitelisted keys (token lifetimes, rate limits, approval cap,
  retention); `effective_settings()` merges them over env values at
  console boot. Every change audit-logged (FR-041).
- `src/gateway/console/pages.py` — the six remaining pages + ontology
  review queue: Dashboard (status cards, agents table, pending badge,
  audit tail, GLOBAL STOP with received-vs-enforced ack + per-item
  status — FR-PAA10-001/003/004), Connectors (registry/tools/scopes/
  health + "run now"), Policies (rule list + pinned default-deny,
  no-DSL builder, raw JSON/**YAML**, version history + diff +
  rollback-as-new-version, dry-run preview; `POST /api/policy/dry-run`
  AC-12 shape and `POST /api/policy/evaluate` per 02 §2.6, both
  admin-only + CSRF), Vault & Settings (metadata-only entries,
  rotation, settings, redaction-catalog editor, recorded decision
  criteria FR-PAA09-004), Mandates (list/history, pause/resume/narrow/
  end/withdraw; pause/end/withdraw cancel pending approvals +
  invalidate grants — FR-PAA01-004), Context boundaries (purpose
  registry, label classes, leakage events), Ontology (review queue
  resolve/dismiss, candidate confirm/reject).
- `src/gateway/console/templates/` — `login.html`, `setup.html`,
  `dashboard.html`, `connectors.html`, `policies.html`,
  `settings.html`, `mandates.html`, `context.html`,
  `ontology.html`; `base.html` now carries the nine-page nav,
  pending-approval badge, health banner, admin identity, and a
  `localtime` filter (UTC storage → `GATEWAY_DISPLAY_TZ`, default
  America/New_York — 00 §7 param 15).
- `tests/test_console.py` — 30 tests (auth, lockout, CSRF, nine pages,
  global stop, policy save/rollback/diff, dry-run + evaluate shapes,
  health banner, vault rotation, settings, redaction catalog,
  criteria, mandates, context, ontology queue, ontology seam).
- `scripts/ac11_load.py` — AC-11 CI gate: 10 concurrent sessions × 50
  iters (+10 warmup), FAILS when local p95 > 100 ms.
- `scripts/check_sdk_floor.py` — mcp ≥ 1.30.0/2.2.0 assertion
  (GHSA-qx49-fqc8-xw99).
- `scripts/check_cve.py` — pip-audit (CycloneDX) gate blocking HIGH+.

### Shared-file edits (all additive)
- `console/app.py` — admin-auth middleware (all routes except
  /login, /setup, /logout, / gated; 401 for /api/*, 302 otherwise),
  login/setup/logout/TOTP-reset routes, `dev_no_auth` TEST-ONLY flag
  (default off), health monitor wiring, M6 page registration,
  FR-041 audit on agent pause/resume/revoke, `localtime` filter.
  Pre-M6 test fixtures pass `dev_no_auth=True` (2 one-line fixture
  edits; behavior unchanged).
- `console/approvals.py` — `ApprovalConsoleDeps` gains `vault_store`
  + `connectors` (additive); new `ApprovalService.cancel_mandate_requests`
  (FR-PAA01-004; per-item ids returned for FR-PAA10-003).
- `models.py` — `ApprovalRequest.ontology_snapshot_ref` +
  `ontology_ref` (M6 seam (d)); new `ConfigSetting` KV table.
- `approvals.py` — `_create_request` copies `ctx.ontology_snapshot_ref`
  / `ctx.ontology_ref` (M6 seam (d), additive); `_approval_required`
  details include `ontology_ref` when present (envelope already
  supported it).
- `policy.py` — process-level hot-path rule cache (see below);
  `clear_rules_cache()` for tests.
- `opa_client.py` — `ensure_running()` is now readiness-aware
  (M6 AC-11 race fix: concurrent callers no longer observe a
  starting sidecar as "running" before its socket exists).
- `config.py` — `display_tz` (`GATEWAY_DISPLAY_TZ`, default
  America/New_York).
- `pyproject.toml` — `qrcode[pil]>=7.4` (TOTP QR), `pyyaml>=6.0`
  (raw YAML policy editor).
- `.github/workflows/ci.yml` — added SDK-floor assertion, CVE scan
  (blocks HIGH+), AC-11 load gate; fixed `.[dev]` → `.[test]`
  (the `dev` extra does not exist) and added pip-audit install.

### AC-11 local numbers (2026-10-12, this VM)
- `scripts/ac11_load.py --sessions 10 --iters 50 --warmup 10`
  (500 measured calls, policy hot path incl. OPA sidecar UDS hop):
  p50 22.2 ms / **p95 64.6 ms** / p99 85.7 ms → PASS (budget ≤ 100 ms).
  Two more runs: p95 50.5 ms and p95 71.6 ms — 3/3 PASS.
- Single-threaded baseline (unchanged): p50 3.1 ms / p95 7.3 ms
  (matches the pivot worker's p50 3.24 / p95 6.43).
- Two hardening fixes were REQUIRED to pass honestly:
  1. **Sidecar startup race** (`opa_client.py`): 10 threads could
     observe `running=True` before the UDS socket existed →
     fail-closed denies + 250 ms stalls. `ensure_running()` now
     checks socket existence and serializes on `start()`'s lock.
  2. **Hot-path rule cache** (`policy.py`): per-call ORM overhead
     (version row ×2 + rules + mandates ≈ 1 ms GIL-bound) serialized
     10 threads to p50 ~42 ms. Immutable version rule data is now
     cached process-wide per (db URL, version); the current-version
     pointer is still re-queried every call (one indexed read), so
     new versions apply immediately. No semantic change (full suite
     green, incl. the Python↔Rego cross-checks).
- Honest caveats: the gate measures the policy hot path (evaluate_call
  incl. sidecar), not the full inspection pipeline; the production
  AC-11 measurement on the deploy target is still Ken's action
  (spike step 5), as is re-measuring with the inspection stages wired.

### CVE / SDK gates (2026-10-12, local)
- `scripts/check_sdk_floor.py`: PASS — mcp 2.3.0 ≥ 2.2.0.
- `scripts/check_cve.py` (pip-audit 2.10.1, CycloneDX): PASS — no
  HIGH/CRITICAL CVEs.

### M6 exit criteria → evidence
- Nine pages (02 §3.2): all render (test_all_nine_pages_render);
  nav labels per spec. Mockups untouched.
- Mandates page + Context boundaries page: render + actions tested.
- Counterparty review/correction (AOQ-12): M3's Approvals page (kept).
- Recorded-criteria settings (AOQ-13 / FR-PAA09-004): upsert/delete
  tested; criteria surface on M3 approval cards (pre-existing).
- Global stop + per-item status (FR-PAA10-001/003): tested incl.
  received-vs-enforced ack (FR-PAA10-004).
- Per-agent pause in the agent danger zone: Agents page (M2, kept).
- History dry-run endpoint (AC-12): shape asserted (counts keys,
  changed_calls list, corpus label).
- Admin auth (FR-036/039/040), CSRF (FR-042), admin-action audit
  (FR-041: policy.save/rollback, agent.revoke, vault.rotate,
  audit.export + settings/redaction/criteria/mandate/global-stop/
  login/setup actions) — all tested.
- AC-10: SDK floor + CVE scan in CI (workflow file only, no GitHub ops).
- AC-11: CI gate added; local numbers above; production measurement
  remains Ken's action (no deploy here).
- AC-04 live-agent demo: still Ken's action (no platform accounts
  here) — recorded in the M3 entry; unchanged by M6.

### Remaining gaps (not M6 defects — owned elsewhere)
- **Ken's actions (unchanged):** OAuth app registrations, hosting
  choice (drives KMS binding + the production AC-11 number), live
  Muse/Grok approval-loop demo (AC-04), household member list for
  `seed_household`, repo name before any push.
- **Ontology checklist (f)** from the beyond-build: bind every agent
  to a principal at the pipeline layer — unbound agents keep the
  legacy unscoped path (documented deviation, ontology builder).
- **`dry_run` passes no `ontology_ctx`** (documented approximation,
  unchanged).
- **M2/M3 console templates** (agents/audit/approvals) still render
  UTC timestamps; the `localtime` filter is applied on the M6 pages.
  (One-line-per-template follow-up if Ken wants uniformity.)
- **`/tmp` full (512M tmpfs, stale root-owned pytest dirs):** the OPA
  sidecar's UDS socket defaults to `tempfile.gettempdir()` — a full
  /tmp breaks sidecar startup (fail-closed denies). Not an M6 defect,
  but production deploys should point TMPDIR at a sized volume.
- Known pre-existing flakes (not M6): `TestRateLimits`
  minute-boundary flake (M5 note); one transient `OperationalError`
  in test_ontology.py (pivot note).

### Deviations (exact doc sections)
1. **CSRF token/cookie rotation per page GET** (02 §2.6 "anti-CSRF
   tokens" + M3 `csrf.py`): every server-rendered page issues a fresh
   token + cookie, so a token copied from an earlier page is rejected.
   This is the M3 double-submit pattern working as designed; the M6
   tests fetch a fresh pair per POST.
2. **`dev_no_auth` test flag** (`create_console_app`): pre-M6 console
   fixtures opt out of the admin-auth middleware so their page-level
   coverage is unchanged; all M6 tests exercise real auth. Default
   off; documented TEST ONLY.
3. **Hot-path rule cache** (`policy.py`): new behavior, but
   semantically neutral — versions are immutable by design (02 §5),
   so caching per (db, version) cannot serve stale rules; the
   `is_current` pointer is re-queried per call. Recorded here per
   the build-log convention, not as a spec change.
4. **`ensure_running` readiness check** (`opa_client.py`): fixes a
   real concurrency race found by the AC-11 gate; no API change.
5. **Dashboard display timezone** defaults to `America/New_York`
   (00 §7 param 15: Ken's local timezone; his messages are EDT);
   override with `GATEWAY_DISPLAY_TZ`. Storage stays UTC.

### Final verification (2026-10-12, post-compaction re-run on final code)
- **Full pytest suite: 453 passed, 0 failed** (973 s) — 423 pre-M6
  + 30 new `tests/test_console.py`. EXIT=0.
- **OPA: 70/70 PASS** (`third_party/opa/opa test
  src/gateway/policies/v1`).
- `tests/test_console.py` standalone re-run: **30/30 PASS** (97 s).
- AC-11 two more clean runs: p95 **49.27 ms** and **41.39 ms**
  (5/5 PASS on a quiet machine; p95s: 64.6, 50.5, 71.6, 49.3, 41.4).
- Flake note (not a code defect): one `test_console.py` standalone
  run showed 6 failures while the full suite was running concurrently
  on the same VM (120 s vs ~100 s — contention; one AC-11 run in the
  same window also exceeded budget at p95 111.58 ms). Both the
  console file and AC-11 pass cleanly with the machine quiet, and
  the full suite on final code is 453/453. No code change was made
  in response; recorded here so a future red run is compared
  against this baseline before blaming the code.
