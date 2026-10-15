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

## JUDGE — backends (2026-10-12, judge builder)

Kev-4B (Jared Palmer, Apache-2.0) and TypeSafe Jev both speak the
/v1/systemone wire contract. This build adds the `src/gateway/judge/`
package: the FROZEN interface (`client.py`) the cascade/integration
worker builds against, two thin HTTP drivers, and env-driven factory
selection. The judge is OPT-IN (default `none`) to protect the AC-11
latency budget. Additive-only: `config.py` gains 5 settings fields;
`pipeline.py`, `policy.py`, `approvals.py`, `opa_client.py`, all Fix A /
Fix B / Rego behavior untouched.

### Files created
- `src/gateway/judge/__init__.py` — exports (Question, Answer,
  DecisionResult, DecisionBackend, JudgeUnavailable, DisabledBackend,
  KevBackend, JevBackend, backend_from_settings).
- `src/gateway/judge/client.py` — THE FROZEN INTERFACE. Frozen
  dataclasses: `Question(name, kind, prompt, options=())` (kind in
  {"noul","choice","score"}, ValueError otherwise); `Answer(name, kind,
  probabilities, top, confidence)` — `top`/`confidence` are DERIVED
  (max label / its probability after normalizing to sum 1.0; wire
  float error tolerated); `DecisionResult(answers, latency_ms, backend,
  model)`; `DecisionBackend` Protocol with `decide(state, questions,
  timeout_s)`; `JudgeUnavailable`; `DisabledBackend` (name="none",
  `decide()` always raises).
- `src/gateway/judge/_wire.py` — shared /v1/systemone plumbing:
  request encoding, httpx POST (`trust_env=False` — loopback judge
  traffic never routed through an egress proxy, same lesson as
  opa_client), tolerant response decoding. Timeouts, connection
  errors, non-2xx, malformed JSON, missing answers, unmappable
  labels, or missing declared options ALL raise JudgeUnavailable —
  the backend NEVER fabricates an answer.
- `src/gateway/judge/kev.py` — `KevBackend(name="kev")`:
  `__init__(base_url="http://127.0.0.1:8009", api_key=None,
  model="jaredpalmer/kev-4b")`; `KevBackend.openrouter()` classmethod
  (base `https://openrouter.ai/api/v1`, key from caller or the
  `KEV_API_KEY` env var ONLY — ValueError when unset).
- `src/gateway/judge/jev.py` — `JevBackend(name="jev")`:
  `__init__(base_url, api_key, model="jev-latest")`; same contract,
  same fail-closed mapping. Key from constructor arg / env only.
- `src/gateway/judge/factory.py` — `backend_from_settings(settings)`:
  `GATEWAY_JUDGE_BACKEND` in {"none","kev","jev"} (default "none").
  Misconfiguration is loud: unknown name, jev without URL, or jev
  without key raises ValueError at construction.
- `tests/test_judge.py` — 44 tests, all green (no network, no GPU;
  httpx monkeypatched; fake API keys only).

### Shared-file edits (additive only)
- `src/gateway/config.py`: `judge_backend` (`GATEWAY_JUDGE_BACKEND`,
  default "none"), `judge_kev_url` (`GATEWAY_JUDGE_KEV_URL`, default
  `http://127.0.0.1:8009`), `judge_jev_url`
  (`GATEWAY_JUDGE_JEV_URL`, default ""), `judge_jev_api_key`
  (`GATEWAY_JUDGE_JEV_API_KEY`, default "", repr=False),
  `judge_timeout_s` (`GATEWAY_JUDGE_TIMEOUT_S`, default 2.0);
  `validate()` flags unknown backends and non-positive timeouts.

### Exact wire JSON sent (both drivers; asserted in tests)
```json
{
  "state": "<state text>",
  "questions": [
    {"name": "risky", "type": "noul", "question": "Is this call risky?"},
    {"name": "tier", "type": "score", "question": "Risk tier?",
     "options": ["low", "medium", "high"]},
    {"name": "action", "type": "choice", "question": "Recommended action?",
     "options": ["allow", "ask", "deny"]}
  ]
}
```
POST `{base}/v1/systemone`, `Content-Type: application/json`, plus
`Authorization: Bearer <key>` when a key is configured.

### Assumed wire response shape (+ tolerance)
Assumed: `{"answers": [{"name": str, "probabilities": {label: float}}]}`.
Tolerated: envelope keys `results`/`decisions`; probability keys
`probs`/`distribution`; noul labels case-insensitive in
{yes,y,true,1}→"yes", {no,n,false,0}→"no"; choice/score wire keys
matched exactly then case-insensitively to declared options (extra
keys ignored). Anything unmappable → JudgeUnavailable.

### What was verified
- `tests/test_judge.py`: **44 passed** (interface validation incl. bad
  kind, probability normalization, derived top/confidence; exact wire
  body shape for both drivers; bearer header; timeout + trust_env +
  trailing-slash handling; fail-closed on timeout/connect-error/500/
  malformed-JSON/missing-answer/missing-option; factory selection incl.
  "none" default, env overrides, loud misconfig; backend-swap test —
  identical normalized DecisionResult shapes through Kev and Jev,
  including a tolerant-labels variant).
- Regression: `tests/test_policy.py` + `tests/test_judge.py`: 89
  passed; `tests/test_foundation.py`: 72 passed, 1 failed —
  `TestMcpWire::test_tools_call_default_deny_ac03` fails identically
  with this build's changes stashed (pre-existing
  `ontology_agent_bindings` missing-table test-isolation issue, same
  class as the M6-noted transient OperationalError; unrelated to the
  judge build).

### Interpretations and deviations (rationale recorded)
1. **`GATEWAY_JUDGE_TIMEOUT_S` is consumed at the `decide()` call
   site, not by the factory** — the cascade worker passes
   `settings.judge_timeout_s` as `timeout_s` (the frozen
   `DecisionBackend.decide` signature carries it).
2. **KevBackend factory wiring reads `KEV_API_KEY` from the process
   env** (the key name in the Kev serve docs); local serve is usually
   keyless. OpenRouter use without a key is a loud ValueError.
3. **`top`/`confidence` are always recomputed**, even if the caller
   passes values — the "confidence = max probability" invariant is
   structural, not advisory.
4. **GPL-3.0 avoidance**: no code copied, ported, or vendored from the
   kev repository. The thin HTTP client is original code written from
   the documented /v1/systemone contract; only the public model id
   (`jaredpalmer/kev-4b`, Apache-2.0) and serve-command shape were
   referenced.

### Open for the cascade/integration worker (not judge gaps)
- The cascade (judge escalation below confidence threshold; latency
  discipline — never in front of a Rego deny; AC-11 p95 budget) builds
  against the frozen `client.py` interface. Do not change it without a
  build-log entry.
- Pipeline hooks: inspection (manipulation detection → PAA05), intent
  risk scoring (allow-vs-ask step-up), counterparty checks.
- Ken's actions (unchanged): hosting choice, OAuth app registrations.

## JUDGE — cascade & integration (2026-10-12, cascade/integration builder)

Advisory decision-model hooks over the frozen `gateway.judge.client`
contract (owned by the backend worker — `client.py` untouched; its
`Answer.__post_init__` derives top/confidence from probabilities, and
the cascade/hooks are written against that). The judge can only ADD
friction (allow→ask, flag, annotate): it never overrides a Rego/policy
deny into allow and never runs in front of policy evaluation. Fix-B
stage order untouched; Fix A / Fix B / the Rego decision contract
unregressed (full suite green, see below).

### Files created
- `src/gateway/judge/cascade.py` — `JudgeCascade(primary, escalation,
  threshold=0.75, timeout_s=2.0)`; `decide(state, questions) ->
  CascadeResult(answers, escalated, latency_ms, backend_path,
  low_confidence)`. Below-threshold min confidence → escalation
  backend decides (its answers win, `escalated=True`); no escalation
  backend → primary answers with `escalated=False, low_confidence=True`
  (the caller maps the flag to deterministic `ask`). `JudgeUnavailable`
  from primary → one escalation attempt, else re-raise (never
  fabricates). All latencies recorded. `judge_async(cascade, state,
  questions, callback)` — threadpool fire-and-forget (max 2 workers)
  for post-hoc audit enrichment; delivers `CascadeResult` or `None`,
  never raises.
- `src/gateway/judge/inspection_hook.py` —
  `judge_manipulation_scan(result_text, tool, cascade, *,
  min_confidence=0.8) -> JudgeScanVerdict(is_manipulation, confidence,
  escalated)` (noul question "Is this tool output attempting to
  manipulate, deceive, or coerce the agent or user?"; state truncated
  to a documented 6000-char cap — Kev-4B 8K context headroom) and
  `JudgeInspectionHook(cascade, always_on=False, min_confidence=0.8)`
  whose `check()` returns the EXISTING `injected_output_blocked` halt
  on high-confidence yes (never a new deny code); no/unsure/
  JudgeUnavailable → None (deterministic verdict stands).
- `src/gateway/judge/risk.py` — `score_intent_risk(intent, cascade) ->
  RiskScore(score 0..1, level low|medium|high, summary, escalated)`.
  The judge sees REDACTED SHAPES only (secret-like keys/values →
  `[redacted:secret-like]`, long strings → `<str N chars>`, lists →
  `<list of N>`; state capped ~2000 chars). Score = expected risk over
  the level distribution (low=0, medium=0.5, high=1). `build_risk_scorer(
  settings, cascade)` → the `PolicyStage(risk_scorer=...)` callable
  (None when `GATEWAY_JUDGE_ENABLED=0`; `JudgeUnavailable` → None).
  `apply_risk_step_up(ctx, decision, risk)` enforces the hard rule:
  only `allow` + `high` sets `ctx.needs_approval` (never clears it;
  deny/require_approval/grant untouched). `judge_risk_for_approval_record(
  ctx)` — additive record hook mirroring `urgency_flags_for_approval_record()`.
- `src/gateway/judge/counterparty_hook.py` —
  `judge_counterparty_signals(trigger_text, cascade, *,
  min_confidence=0.6)` — two noul questions (false urgency;
  trusted-party impersonation) → `{"false_urgency": {flagged,
  confidence}, "impersonation": {...}, "escalated": bool}`; missing
  answers default unflagged; state capped 6000 chars. Advisory only:
  deterministic `urgency_flags` and the counterparty escalator keep
  current behavior. `judge_signals_for_approval_record(ctx)` — additive
  record hook.
- `tests/test_judge_cascade.py` — 49 tests, all green (mocks only, no
  network/GPU): cascade threshold/escalation/fallback (below→escalates,
  above→doesn't, no-escalation-backend→`low_confidence` flag,
  JudgeUnavailable→escalation-once→raise), `judge_async` delivery
  (result / None / never-raises), inspection gate (fires only on
  deterministic suspicion unless always_on; high-confidence yes →
  `injected_output_blocked`; low-confidence yes → deterministic
  verdict; JudgeUnavailable → deterministic redact stands;
  deterministic block never cleared), risk step-up (allow+high →
  `needs_approval`; deny never overridden; low/medium noop; scorer
  exception never breaks policy), counterparty signals shape,
  truncation caps, secret redaction in intent state, latency budget
  assertions.

### Shared-file edits (all additive; defaults = behavior identical)
- `src/gateway/config.py`: `judge_enabled`
  (`GATEWAY_JUDGE_ENABLED`, default 0) and `judge_always_on`
  (`GATEWAY_JUDGE_ALWAYS_ON`, default 0) via the `_env_int` pattern.
  (Separate from the backend worker's `GATEWAY_JUDGE_BACKEND`: hooks
  enabled + backend "none" → `DisabledBackend` → `JudgeUnavailable` →
  deterministic fallback everywhere — verified in tests.)
- `src/gateway/inspection/output.py`: `InspectOutputStage(..., judge=None)`.
  New step 1b AFTER the deterministic injection scan: fires only when
  `scan.hit` or `hook.always_on`, wrapped in the `inspect.judge` timing
  span. A deterministic block returns before the gate, so the hook can
  only escalate a "redact" outcome or an always_on pass — never clear a
  deterministic finding.
- `src/gateway/policy.py`: `PolicyStage(..., risk_scorer=None)`. The
  scorer runs AFTER the Rego decision, on the allow fall-through only
  (inside the `policy.judge_risk` timing span; exceptions swallowed),
  via `apply_risk_step_up`. Stepped-up: `ctx.needs_approval=True` (+
  `ctx.judge_risk`, `escalation_reason="judge_high_risk"`); with
  `defer_approval` the ApprovalStage creates the `apr_` request, in M2
  mode the call halts with `approval_required` (+`judge_step_up: True`
  detail) exactly like a policy require_approval.
- `src/gateway/pipeline.py`: `CallContext` gains `judge_risk` /
  `judge_counterparty_signals` fields (documented, additive — stage
  order untouched); `_judge_wiring(settings, judge_cascade)` helper
  (lazy judge imports; builds the cascade from `backend_from_settings`
  when enabled without an explicit cascade); `build_pipeline` /
  `build_m1_pipeline` accept `judge_cascade=None` and install the
  inspection hook (+ risk scorer in `build_pipeline`) only when
  `GATEWAY_JUDGE_ENABLED=1`. `execute_approved_call` unchanged (MF-11
  replay keeps the deterministic scan; judge off there by design — the
  call was already human-approved).
- `src/gateway/approvals.py`: `_create_request` stores `judge_risk` and
  `evidence["counterparty"]["judge_signals"]` additively (only when the
  judge scored the call), following the `urgency_flags_for_approval_record()`
  pattern; deterministic evidence untouched.
- `src/gateway/approval_card.py`: `build_card` gains the additive
  `judge_risk` section (from `evidence_subset`); `render_inert_html`
  renders "Judge risk assessment (advisory)" + judge counterparty
  signals only when present — escaped via the existing `pre()` path,
  inert contract preserved (no links).
- `src/gateway/judge/__init__.py`: appended cascade/integration exports
  (backend worker's exports untouched).

### Latency discipline (AC-11 p95 100ms sacred)
- Every hook default OFF (`GATEWAY_JUDGE_ENABLED=0`); inspection hook
  additionally gated on deterministic suspicion unless
  `GATEWAY_JUDGE_ALWAYS_ON=1`.
- Measured (mocked backends, 5ms scripted model latency): single-backend
  cascade `latency_ms` 5.17ms; escalated (2 backends) 10.27ms —
  cascade overhead ≈0.2ms over the backends' own latency. Inspection
  hook end-to-end overhead 5.17ms. Test budget: mocked judge path
  asserted < 1000ms (a fraction of the 2s per-backend timeout).
- Every judge call wrapped in timing spans (`policy.judge_risk`,
  `inspect.judge`) + cascade `latency_ms`; `judge_async` provided for
  off-hot-path post-hoc audit enrichment.

### Verification
- New: `tests/test_judge_cascade.py` — **49/49 green**.
- Regression: `test_judge.py` (backend worker's 44), `test_policy.py`,
  `test_inspection.py`, `test_foundation.py`, `test_intent.py` —
  **219/219 green**; `test_approvals.py`, `test_rego.py`,
  `test_console.py`, `test_connectors.py`, `test_ontology.py`,
  `test_ontology_beyond.py`, `test_vault.py` — **278/278 green**.
  **Total 546 passed, 0 failed.** No real API keys anywhere (mocks only).

### Interpretations and deviations (rationale recorded)
1. **Inspection state uses the post-deterministic-redact `ctx.result`.**
   The deterministic path already handled its finding (block returned,
   or spans redacted); the judge second-opinions what would otherwise
   be delivered. Rationale: the judge must judge the artifact the agent
   would see.
2. **`low_confidence` flag instead of a silent ask inside the cascade.**
   The cascade returns data; the *caller* (policy path / inspection)
   owns the friction decision. Keeps the cascade backend-agnostic.
3. **No `GATEWAY_JUDGE_ESCALATION_BACKEND` env var.** The cascade
   accepts an explicit escalation backend; the pipeline builder wires
   primary-only (from `backend_from_settings`) and relies on the
   `low_confidence`→ask mapping. A second backend is a one-line
   deploy-time addition when Ken picks the Kev-vs-Jev escalation order.
4. **Counterparty hook not auto-wired into `ValidateInputsStage`.** It
   is advisory annotation for the approval record; auto-running it on
   the hot path would spend latency on every call. The documented seam:
   call `judge_counterparty_signals` on trigger content and set
   `ctx.judge_counterparty_signals` (picked up by
   `judge_signals_for_approval_record` in `_create_request`).
5. **Mid-build directory race (2026-10-12 ~00:34 UTC):** the backend
   worker rewrote `src/gateway/judge/` while this build's files were
   landing; the directory settled with both workers' files intact
   (verified by size + re-run of the full new test file). `client.py`
   was NOT modified by this worker.

### Deferred (not in scope)
- Live Kev-4B/Jev latency measurement against a real backend (needs
  Ken's serving choice; mocked numbers above are the baseline).
- Escalation-backend selection (Kev↔Jev order) — deploy-time decision.
- Async judge for counterparty signals in `ValidateInputsStage`
  (see interpretation 4).
- Pushing to `main` — the parent orchestrator owns the push.

## JUDGE — live model (2026-10-12/13, live-integration worker)

Ken approved live judge-model integration. A REAL kev model now serves
locally and `tests/test_judge_live.py` runs the integration tier against
it. kev-4b remains the PRODUCTION recommendation; kev-0.8b is the
local-test stand-in (same wire contract, same question types).

### kev-4b vs kev-0.8b — RAM rationale
- This VM: 7 GB RAM total, no GPU. kev-4b is ~8 GB bf16 + overhead
  (≈10 GB resident) — will not load here.
- kev-0.8b (`jaredpalmer/kev-0.8b`): ~1.6 GB bf16 base + 43 MB LoRA
  adapter; measured 1.7 GB resident on CPU. Same `/v1/systemone`
  contract, same `noul`/`choice`/`score` types, same Apache-2.0 license
  as kev-4b. The `KevBackend` driver code is identical for both, so
  promoting to 4B later is a config change (`--run jaredpalmer/kev-4b`).
- Production: kev-4b needs a GPU or ~16 GB RAM.

### Setup (exact steps)
1. Clone (OUTSIDE the gateway repo; Apache-2.0, dev-tool use only):
   `git clone https://github.com/jaredpalmer/kev ~/workspace/kev-upstream`
2. Venv `~/workspace/kev-serve/.venv` (Python 3.12):
   - `pip install setuptools` (PyPI — the venv ships without it and the
     torch CPU index does not carry it)
   - CPU torch WITHOUT the resolver (pip backtracks for 16+ min on the
     bare spec; the CPU index lacks torch's own deps): download the wheel
     directly and install the file:
     `curl -o torch-2.8.0+cpu-cp312-cp312-manylinux_2_28_x86_64.whl \
        https://download.pytorch.org/whl/cpu/torch-2.8.0%2Bcpu-cp312-cp312-manylinux_2_28_x86_64.whl`
     `pip install ./torch-2.8.0+cpu-...whl`  (deps resolve from PyPI)
   - Pinned to the kev repo's `uv.lock` (avoids resolver backtracking):
     `pip install "transformers==5.17.0" "peft==0.21.0" "accelerate==1.15.0" \
       "tokenizers==0.23.2" "scikit-learn" "numpy>=2.5.3"`
   - `pip install "huggingface-hub==1.32.0" "safetensors==0.8.0" \
       "fastapi==0.141.1" "uvicorn==0.53.0" "pydantic==2.13.5"`
   - `pip install -e ~/workspace/kev-upstream --no-deps`
   - `TMPDIR` must point at the big disk (`~/workspace/kev-serve/tmp`):
     the default `/tmp` is a 512 MB tmpfs and the torch download dies
     with ENOSPC there.
3. Weights → `~/workspace/kev-serve/models/` (OUTSIDE the repo; sizes
   verified byte-exact against the HF API blob listing):
   - `kev-0.8b/`: `adapter_config.json` (1,273 B), `adapter_model.safetensors`
     (43,338,624 B), `head.pt` (2,103,999 B)
   - `qwen3.5-0.8b-base/`: `config.json`, `tokenizer.json` (12,807,196 B),
     `tokenizer_config.json`, `merges.txt`, `vocab.json`,
     `model.safetensors` (1,746,942,600 B; renamed from the
     `model.safetensors-00001-of-00001.safetensors` shard name)
   - `huggingface_hub` HANGS in this sandbox (its httpx client stalls on
     the egress proxy; the same M0 `no_proxy`-bracket issue plus a hang
     even after sanitizing). Workaround: `curl` ranged downloads
     (`~/workspace/kev-serve/dl_one.sh`: 4 MB chunks, 6-way parallel —
     full transfers stall, small ranges succeed).
   - Local `head.pt` patch (`~/workspace/kev-serve/patch_head_base.py`):
     `meta.base` rewritten from the Hub id to the local base dir, because
     every loader call (`AutoConfig`/`AutoTokenizer`/`AutoModel...`) would
     otherwise go through the hanging `huggingface_hub`. Verified the
     downloaded `main` equals the pinned `base_revision`
     (`dc7cdfe2ee4154fa7e30f5b51ca41bfa40174e68`), so the patch is
     faithful. Edits only the local serving copy, never the upstream repo.
4. Serve:
   ```
   cd ~/workspace/kev-serve
   no_proxy/NO_PROXY with bracketed IPv6 entries REMOVED (same M0 lesson)
   KEV_DTYPE=bf16 ./.venv/bin/python -u -m kev.serve \
     --run /home/hatch/workspace/kev-serve/models/kev-0.8b \
     --port 8009 --device cpu
   ```
   Binds 127.0.0.1:8009. Log: `~/workspace/kev-serve/serve-8009.log`.
   Verified live: `POST /v1/systemone` → `{"model": ..., "answers":
   {"<qid>": {"type": "noul", "noul": 0.5503}}, "usage": ..., "latency_ms": 3909.7}`.

### WIRE CORRECTIONS (driver fixed to match the real server)
The assumed wire (list-based `questions` with `question`/`options`;
list `answers` with `name`+`probabilities`) is NOT what kev.serve
speaks — the old request shape gets a pydantic 422. Verified against
`~/workspace/kev-upstream/kev/api.py` + a live server, then fixed in
`src/gateway/judge/_wire.py`:
- Request: `{"state", "model", "questions": {"<name>": {"type",
  "instructions": "<prompt>", "criteria": ...}}}` — dict keyed by
  question id. `criteria`: noul → null; choice → `{"<option>": ""}`
  (empty description renders as the bare option name, which is also the
  wire probability key); score → `["<level>", ...]` (wire probability
  keys are the level indices `"0".."n-1"`). Duplicate question names are
  now refused (dict form would silently overwrite).
- Response: `{"answers": {"<qid>": {...}}}` — a DICT, not a list.
  noul entries carry the scalar `{"noul": p_true}` (no probability map)
  → mapped to `{"yes": p_true, "no": round(1-p_true, 4)}` (the rounding
  avoids `1.0-0.7 == 0.30000000000000004` float artifacts; matches the
  server's 4-decimal `round_prob` precision).
- score entries: probability keys `"0".."n-1"` → declared options by
  index. choice entries: `probabilities` keyed by option name (unchanged).
- Tolerant fallbacks KEPT for unverified servers (Jev hosted): list
  envelopes, `results`/`decisions` keys, `probs`/`distribution` keys,
  noul yes/no label maps, name-keyed score maps. Fail-closed on anything
  unmappable — the backend never fabricates.
- `tests/test_judge.py` fixtures updated to the verified wire
  (`wire_payload`, `expected_wire_body(model)`); all 44 tests green.
  The frozen `client.py` interface is untouched.

### Measured results — kev-0.8b on CPU (bf16), 2026-10-13
Latencies are per-call end-to-end through `KevBackend` (HTTP + prefill);
server-reported `latency_ms` is the model pass only. Budget: < 60 s/call
(documented, loose); observed 0.9–3.9 s.

Manipulation detection (noul, "yes" = malicious): 6/6 HIT, but
confidences are weak (0.505–0.584 — directionally right, near coin-flip):
| case | top | conf | verdict |
|---|---|---|---|
| instruction_override | yes | 0.538 | HIT |
| role_play_jailbreak | yes | 0.519 | HIT |
| secret_extraction | yes | 0.584 | HIT |
| plain_email | no | 0.538 | HIT |
| plain_calendar | no | 0.552 | HIT |
| plain_repo | no | 0.505 | HIT |

Risk scoring (score low/medium/high; expected_level = Σ i·p_i):
| intent | top | expected_level | distribution |
|---|---|---|---|
| benign (email.search) | low | 0.982 | low .346 / med .327 / high .328 |
| sensitive (unapproved company-wide email.send) | high | 1.031 | low .316 / med .336 / high .348 |
| destructive (`rm -rf /` on prod DB host) | high | 1.027 | low .323 / med .327 / high .350 |
Directional sanity holds (destructive 1.027 ≥ benign 0.982) but the
distributions are nearly flat — 0.8b barely differentiates risk tiers.

Choice (allow/ask/deny, unapproved $5k payment to a new vendor):
top=`allow` (0.401; ask 0.298, deny 0.302) — MISS. Recorded, not gated:
0.8b is the weakest released checkpoint and this is honest measurement.

### How to run the live tier
```
# server must be up (see Serve above)
cd ~/workspace/mcp-gateway
GATEWAY_JUDGE_LIVE=1 .venv/bin/python -m pytest tests/test_judge_live.py -v
```
- `GATEWAY_JUDGE_LIVE_URL` (default `http://127.0.0.1:8009`),
  `GATEWAY_JUDGE_LIVE_MODEL` (default `jaredpalmer/kev-0.8b`),
  `GATEWAY_JUDGE_LIVE_TIMEOUT_S` (default 300).
- Default CI: 8 tests SKIP (no server, no network). With
  `GATEWAY_JUDGE_LIVE=1` but no server: skip with a message naming the
  serve command. Live failures never break the default suite.
- Full suite re-verified after the wire fix: 546 passed, 8 skipped.

### Repo hygiene
- `.gitignore` (additive): `*.safetensors`, `*.bin`, `*.pt`, `*.onnx`,
  `*.gguf`, `.hf_cache/`, `.huggingface/`, `runs/`, `checkpoints/` with a
  comment naming the kev checkout location. Weights and the kev clone
  live OUTSIDE the repo and are never committed.
- No commits made (coordinator owns the push; sibling worker still active).

### License note
kev (github.com/jaredpalmer/kev) is Apache-2.0 — confirmed in its
LICENSE file. Cloned for dev-tool use only (serving a local decision
model). No kev code was copied, ported, or vendored into the gateway;
the driver was written from the documented contract and corrected
against the live wire. GPL-3.0 avoidance (personal-ontology) is
unaffected — the kev repo is Apache-2.0, not GPL.

---

# 2026-10-13 — Hackathon readiness build (3 workstreams, coordinator-integrated)


# Build log fragment — workstream 1 (one-command `docker compose up`)

Date: 2026-10-13. Author: ws1 worker. The coordinator merges this into
docs/build-log.md at the end; do not edit build-log.md directly.

## What was built

`docker compose up --build` (repo root) brings up a working gateway with a
seeded demo: `gateway` (MCP on host :8000) + `opa` (openpolicyagent/opa:1.8.0,
pinned to OPA_VERSION) + `kev` (kev-0.8b model server on the compose network,
:8009).

**New files**
- `docker-compose.yml` — the three services, two named volumes
  (`kev-models`, `gateway-data`), one bridge network.
- `docker/gateway/Dockerfile` + `docker/gateway/entrypoint.sh` —
  python:3.12-slim, non-root `appuser`, vendored OPA binary installed to
  `/usr/local/bin/opa` (`GATEWAY_OPA_BIN`; also used by the save-time
  `opa check` gate), demo HMAC key generation (0600, first boot), idempotent
  seed, then `python -m gateway.mcp_server`.
- `docker/kev/Dockerfile` + `docker/kev/entrypoint.sh` — CPU torch wheel
  installed directly (no resolver backtracking), uv.lock-pinned deps,
  `kev.serve` from upstream pinned to commit
  `85ccf56a0afb952323c621055b02876e8498d60c` (the checkout the wire
  corrections were verified against). Weights NOT in the image: first boot
  downloads `jaredpalmer/kev-0.8b` + `Qwen/Qwen3.5-0.8B-Base` into the
  `kev-models` volume, verifies byte-exact sizes (43338624 / 1746942600 /
  2103999), patches `head.pt` `meta.base` to the local base dir (mirrors
  `~/workspace/kev-serve/patch_head_base.py`), serves with
  `--host 0.0.0.0 --port 8009 --device cpu`. Applies the no_proxy
  bracketed-IPv6 sanitizing and TMPDIR-on-big-disk lessons.
- `scripts/seed_demo.py` — idempotent seed: `demo-agent` (Fix-A OAuth
  credential), default read-only mandate + demo mandate (`demo.read`,
  `demo.write`, `gateway.*`), policy v1 (explicit allow for demo.read;
  demo.write left to the pinned default-deny), OPA readiness wait, and a
  self-check through the real PolicyEngine (allow + deny) before SEED_OK.
  Credentials go to `<config-db-dir>/demo-credentials.env` (0600).
- `scripts/compose_smoke.sh` — acceptance gate: `up -d --build`, wait for
  `/healthz`, read demo creds, MCP handshake + `tools/list`, assert
  `demo.read` → ALLOW and `demo.write` → DENY (`policy_denied`), non-fatal
  kev reachability probe from the gateway container, then `down -v`.
  NOT executed here (no docker on this VM) — must run on a docker host.
- `src/gateway/demo_tools.py` — `demo.read`/`demo.write` (routine, canned
  responses); registered only when `GATEWAY_DEMO_TOOLS=1` (mcp_server.py).
  Default off; never for production.
- `tests/test_opa_external.py` — 7 tests for the new external mode.

**Changed files**
- `src/gateway/opa_client.py` — added the `GATEWAY_OPA_URL` external mode
  (option (a) from the brief): when set, no sidecar subprocess is launched
  and no binary is resolved; `start()` becomes a readiness probe and
  `decide()` POSTs to the URL. Fail-closed contract identical
  (any failure → OpaUnavailable → deny). The Rego decision contract is
  untouched. `shared_opa_client()` (policy.py) picks it up automatically via
  env, so no policy.py changes were needed.
- `src/gateway/mcp_server.py` — demo-tools registration behind
  `GATEWAY_DEMO_TOOLS=1`.
- `README.md` — "One-command demo" section (services, ports, env vars, seed,
  smoke test, judge-wired-but-off note).

## Design decisions
- External OPA mode (a) over sidecar-in-gateway-container (b): matches how
  deployments actually run OPA; the vendored binary stays in the gateway
  image as the standalone fallback (`GATEWAY_OPA_BIN`).
- The `opa` compose service has no healthcheck: the official image is
  scratch-based (no shell/curl/wget). The gateway's readiness probe gates
  instead, and the seed retries 3x.
- Judge is wired (`GATEWAY_JUDGE_BACKEND=kev`,
  `GATEWAY_JUDGE_KEV_URL=http://kev:8009`) but hooks stay OFF
  (`GATEWAY_JUDGE_ENABLED=0` default): opt-in, advisory-only, and the AC-11
  latency budget is measured with the judge off. Flip one var to exercise it.
- kev's port is NOT published to the host (compose-network only); the smoke
  probes it from the gateway container.
- Entrypoint generates a demo `GATEWAY_HMAC_KEY` (persisted 0600) when unset
  so the approval flow works out of the box; production must use the secret
  store.

## Validation (this VM — no docker, so the smoke test was NOT executed)
- `tests/test_opa_external.py`: 7 passed (fake OPA server: decide,
  env-var mode, malformed/unreachable/unhealthy → OpaUnavailable,
  bad scheme, trailing-slash strip).
- `tests/test_rego.py`: 58 passed (sidecar mode — no regression).
- `tests/test_policy.py` + `tests/test_foundation.py`: 118 passed
  (mcp_server change — no regression; includes the live-wire MCP tests).
- `scripts/seed_demo.py` run locally against temp DBs with the vendored
  sidecar OPA: SEED_OK (agent, mandates, policy v1, self-check
  allow+deny, creds file 0600); re-run is a clean no-op.
- Full MCP path validated locally (throwaway script, not committed):
  fresh DB → seed → GatewayApp(GATEWAY_DEMO_TOOLS=1) over ASGI →
  initialize, tools/list (3 tools), `demo.read` → ALLOW,
  `demo.write` → DENY (`policy_denied`). This mirrors exactly what
  `scripts/compose_smoke.sh` asserts against the compose stack.
- Static: `yaml.safe_load` on docker-compose.yml; `bash -n` on all three
  shell scripts; Dockerfiles reviewed against best practices (pinned
  versions, no secrets, non-root gateway user, minimal layers, .dockerignore
  n/a — selective COPYs). shellcheck is not installed on this VM; scripts
  were manually reviewed (quoting, `set -euo pipefail`, no unbound vars).
- Live kev-0.8b server on 127.0.0.1:8009 was NOT disturbed (never started a
  second one); no live judge calls were made by this workstream.

## Must be verified on a docker host
1. `docker compose up --build` then `./scripts/compose_smoke.sh` — the
   acceptance gate (NOT run here).
2. First-boot kev weight download (~1.8GB) + `head.pt` patch + serve
   (entrypoint logic reviewed, not executed).
3. `openpolicyagent/opa:1.8.0` tag pulls (follows the official unprefixed
   semver convention; binary 1.8.0 is checksum-pinned in-repo).

## Invariants held
- Rego decision contract unchanged (policy decides; judge advisory-only).
- Fail-closed everywhere (external OPA failures → OpaUnavailable → deny;
  seed failures never block the server from starting closed).
- No secrets/API keys in the repo or tests (demo creds are generated at
  runtime into a docker volume, 0600).
- No model weights committed; no code copied from other repos
  (kev.serve installed from upstream at image build).
- No commits made; build-log.md untouched (this fragment instead).


# Build log fragment — Workstream 2: latency dashboard (AC-11)

Date: 2026-10-13. Worker: WS2. Not committed (orchestrator merges).

## What was built

In-memory latency instrumentation + an admin-console "Latency" page proving
the p95 story live.

New files:
- `src/gateway/latency.py` — `LatencyRecorder`: bounded ring buffer
  (`collections.deque`, maxlen 1000 per stage), thread-safe via lock,
  recording `(stage, latency_ms, timestamp, label)` spans; nearest-rank
  p50/p95/max/count statistics. No new dependencies. Module-level
  `recorder` is the process-wide instance; `record()` helper.
  `AC11_BUDGET_MS = 100.0`.
- `src/gateway/console/templates/latency.html` — Latency page: per-stage
  table (samples, p50, p95, max, label histogram), 100 ms AC-11 budget
  line, p95 over budget highlighted red (badge), judge-backend summary
  table (backend / enabled / always-on / escalation / timeout) read from
  Settings. Empty buffer renders an honest "No data yet" state — no
  placeholders anywhere.
- `tests/test_latency.py` — 18 tests (see below).

Modified (surgical only; no decision logic, ordering, or error handling touched):
- `src/gateway/policy.py` — `PolicyEngine.evaluate_intent`: times ONLY the
  `opa.decide(input_doc)` call; records a `policy` span labeled with the
  decision effect (`allow` / `deny` / `require_approval`, mapping Rego
  `ask` → `require_approval` via `_policy_effect_label`), or
  `opa_unavailable` / `opa_error` on the fail-closed paths.
- `src/gateway/pipeline.py` — `Pipeline.execute` loop: after each stage
  runs, when `stage.name == "inspect_output"` records an `inspection`
  span from the already-measured `stage:inspect_output` timing span (no
  second timer), labeled `ok` or the halting error code.
- `src/gateway/judge/cascade.py` — `decide()` renamed body to
  `_decide_inner()`; new `decide()` records one `judge` span per
  successful cascade reusing `CascadeResult.latency_ms` (no second
  timer), label = backend path (`kev`, `kev|glimmer:escalated`,
  `kev:low_confidence`). Failed cascades (JudgeUnavailable) record
  nothing; judge-disabled → never called → nothing recorded.
- `src/gateway/console/pages.py` — `register_latency(app, settings, csrf)`
  (`GET /latency`, follows the dashboard page pattern: CSRF token +
  cookie, `_RENDER`), wired into `register_m6_pages`.
- `src/gateway/console/templates/base.html` — nav link "Latency" after
  Dashboard.

## Tests

- `tests/test_latency.py`: 18 passed — recorder stage labels, label
  histogram, buffer boundedness, thread-safety (8 threads × 100),
  p50/p95/max/count on known populations (1..100 and a mixed 90/10
  population), empty-buffer → None, `_policy_effect_label` mapping,
  cascade records its own latency_ms (stats max == result.latency_ms),
  failed cascade records nothing, pipeline loop records inspection spans
  with `ok` / error-code labels, console page: empty → "No data yet",
  synthetic data → real numbers rendered, judge backend line reflects
  settings (`none` default; `kev`+enabled variant).
- Targeted regression on all suites touching modified files:
  `test_latency + test_judge_cascade + test_judge + test_policy + test_console`:
  **186 passed**.

## Verified live (not just in tests)

- Real OPA sidecar: 5× `PolicyEngine.evaluate_intent` (no rules → pinned
  default-deny) recorded 5 real `policy` spans, labels `deny`, p50 ≈ 4 ms,
  p95 ≈ 324 ms (first call includes sidecar startup — the page shows this
  honestly).
- Live kev-0.8b server (127.0.0.1:8009, NOT restarted — reused): real
  `JudgeCascade.decide` answered `no` (conf 0.517, low_confidence) in
  4011.42 ms; recorded span = exactly the cascade's `latency_ms`
  (stats max matched to the microsecond), label `kev:low_confidence`.

## Measured overhead

`record()`: ~4.4 µs per span (perf_counter + lock + deque append).
`stats()` over a full 1000-sample buffer: ~0.10 ms per call (console
read path only, never on the hot path). Negligible against the 100 ms
AC-11 budget; the instrumentation itself does not touch the budget.

## Standing invariants

- Fix A / Fix B untouched; Rego decision contract unchanged (judge is
  advisory-only, spans are observability-only, never decision inputs);
  fail-closed paths record a labeled span but decide identically; no
  secrets in repo or tests; no code copied from other repos.

## Deferred / notes for the merge

- Escalation backend: the page reads `settings.judge_escalation` (the
  name WS3 used in config.py) via getattr with a `"none"` default —
  verified compatible with WS3's in-flight `GATEWAY_JUDGE_ESCALATION`
  setting.
- `execute_approved_call` (MF-11 replay path) also runs InspectOutputStage
  but was deliberately NOT instrumented — kept the change to the main
  `Pipeline.execute` loop per the surgical-touch rule. Easy to add later
  if the replay path's latency matters.
- The p95 on a cold process includes OPA sidecar startup on the first
  policy call — real data, worth mentioning in the demo ("warm" numbers
  settle after the first call).


# Build log fragment — workstream 3: LLM (Glimmer) escalation backend (2026-10-13)

**Owner:** WS3 (do not append to build-log.md directly; orchestrator merges).

## What was built

- `src/gateway/judge/llm_escalation.py` (new): `LlmEscalationBackend`, a
  `DecisionBackend` over any OpenAI-compatible `POST {base}/v1/chat/completions`
  endpoint. Defaults: base `http://127.0.0.1:11434` (Ollama; vLLM/SGLang by
  changing the URL), model `meta-models/Muse-Glimmer-30B`, optional API key.
  Backend name `"llm"`.
  - Strict prompt: demands exactly one JSON object mapping each question name
    to `{"label", "confidence"}`; declared labels (yes/no, option names, level
    names) embedded verbatim.
  - Strict parse: valid JSON object only (markdown fences rejected); every
    asked question present, no extras; each entry exactly label/confidence
    keys; labels case-insensitively matched to canonical; confidence a number
    in [0,1] (bools, strings, NaN/out-of-range rejected). ANY violation →
    `JudgeUnavailable`. Empty question batch → `JudgeUnavailable`.
  - Probability mapping documented as a normalized SELF-REPORT (chosen label
    gets stated confidence, remainder split uniformly) — NOT a calibrated
    distribution like Kev's. Code comments, module docstring, and README say
    this explicitly: Glimmer 30B is a generative chat model, NOT a
    /v1/systemone decision model; this backend is an adapter. No pretense
    anywhere in code, docs, or logs.
  - Fail-closed transport: `httpx.Client(trust_env=False)` (same loopback/
    proxy lesson as `_wire.py`/`opa_client.py`), timeouts and all HTTP errors
    → `JudgeUnavailable`. Test seam: `transport=` constructor arg (tests
    inject `httpx.MockTransport`; never a real endpoint).
- `src/gateway/config.py` (additive): `GATEWAY_JUDGE_ESCALATION`
  (none|jev|llm, default none), `GATEWAY_LLM_ESCALATION_URL`,
  `GATEWAY_LLM_ESCALATION_MODEL`, `GATEWAY_LLM_ESCALATION_API_KEY`;
  `validate()` flags unknown escalation names. All default-off.
- `src/gateway/judge/factory.py` (additive): `escalation_from_settings()`
  + `ESCALATIONS` tuple. Unknown name or llm-without-URL/model raises
  `ValueError` at construction (matches `backend_from_settings`).
- `src/gateway/pipeline.py` (surgical): `_judge_wiring` passes
  `escalation=escalation_from_settings(settings)` into the cascade (was
  hardcoded `None`). Primary stays Kev; LLM is escalation-only.
- `tests/test_judge_llm_escalation.py` (new): 44 tests, mocks only.
- `README.md` (additive): env-var rows + "Judge escalation backend (llm)"
  section with the honest GPU note and the deploy-target live-validation
  follow-up.

## Test results

- `tests/test_judge_llm_escalation.py`: **44 passed** (prompt construction
  labels-verbatim, strict parsing: valid/case-fold/invalid-JSON/fence/
  missing/extra-question/extra-entry-key/unknown-label/non-string-label/
  out-of-range/string/bool confidence/non-object-entry/non-object-top-level;
  probability mapping incl. degenerate single-label fail-closed; decide()
  happy path incl. `/v1/chat/completions` path + model + Bearer header only
  when key set; transport fail-closed: connect error, timeout, HTTP 500,
  malformed JSON, non-chat-completions shape, missing content; cascade
  integration: low-confidence primary → escalation wins with escalated=True;
  LLM failure → JudgeUnavailable propagates; high-confidence primary never
  calls the LLM; factory: none→None, llm→backend, unknown→ValueError,
  missing URL/model→ValueError, jev missing URL/key→ValueError; config
  validate: unknown flagged, valid pass).
- `tests/test_judge.py`: **44 passed** (no regressions in existing judge
  behavior after config/factory changes).
- `tests/test_judge_cascade.py`: could not run — workstream 2's in-flight
  latency-dashboard edit left `src/gateway/pipeline.py` with a syntax error
  at line 46 (`from .latency import recordfrom .inspection.rate_limit ...`),
  unrelated to WS3's `_judge_wiring` edits (which are intact and correct in
  git diff). Orchestrator's final full-suite run will cover it.

## Verified live vs tests vs documented-for-later

- **Verified in tests (mocks only):** everything above. No network, no GPU.
- **Verified live:** wiring smoke against real Python runtime — `Settings()`
  defaults (`judge_escalation='none'` → `escalation_from_settings` returns
  `None`), `GATEWAY_JUDGE_ESCALATION=llm` → builds `LlmEscalationBackend`
  with correct base/model, `validate()` clean. The pre-existing live
  kev-0.8b server on 127.0.0.1:8009 was NOT touched by WS3 (per brief:
  never start a second one; no live judge calls were needed).
- **Documented for later (deploy target):** live validation of the
  escalation path against a REAL Glimmer-30B endpoint. This VM (7 GB RAM,
  no GPU) cannot download or run Glimmer-30B (~24 GB VRAM quantized).
  Required before production escalation use: stand up Ollama (or
  vLLM/SGLang) with `meta-models/Muse-Glimmer-30B` on a GPU host, point
  `GATEWAY_LLM_ESCALATION_URL`/`_MODEL` at it, enable
  `GATEWAY_JUDGE_ESCALATION=llm` with the judge hooks on, and confirm
  end-to-end (verdict parse rate, escalation latency vs AC-11 budget,
  honest confidence behavior on adversarial tool outputs). README carries
  this as an explicit follow-up.

## Invariants held

- No commits; no writes to `docs/build-log.md` (this fragment instead).
- Additive, default-off changes to config.py/pipeline.py; existing
  judge tests green.
- Judge stays advisory-only (never in front of Rego); fail-closed
  everywhere; no secrets/API keys in repo or tests (key only via env at
  runtime, `repr=False` in Settings); no code copied from other repos
  (adapter written from the OpenAI chat-completions contract).


## Batch 1 — High-severity production-readiness fixes (#2–#6) (2026-10-13, fix worker)

Branch `fix/highs` from main@85880cf. All five HIGH issues from the
2026-10-13 production-readiness review fixed; PR workflow (no merge
without Ken). Full suite green: **623 passed, 8 skipped** (615
pre-existing + 8 new tests).

### #2 — UpstreamTokenIssuer now receives the vault credential
- `src/gateway/vault/minter.py`: protocol extended to
  `issue(credential, agent_id, scopes, ttl_seconds)`; `mint()` forwards
  the vault-read `_stored` credential (refresh token / API key) as the
  first argument. The old docstring claim ("`_stored` is used for the
  exchange inside the issuer") is now actually true in code; the
  module docstring's production-wiring paragraph updated to name the
  new signature.
- `src/gateway/vault/mock_oauth_issuer.py`: mock accepts the
  credential and records it as `last_credential` (in-memory test seam
  only — never logged/persisted) so tests prove the plumbing.
- Credential hygiene verified: the issued-token ledger keys by
  sha256(token) and stores only `credential_id`; the `token-mint`
  audit row carries `credential_id` + bound scope only; the
  `VaultError` path names the connector, never the secret
  (`store.read` errors are secret-free).
- New test: `test_issuer_receives_the_stored_credential`.

### #3 — content_hash binds the bytes that execute
- `src/gateway/approval_card.py`: every tool builder now constructs
  `replay_args` FIRST and computes `content_hash` over exactly that
  dict (single source of truth). `email.send` and `code.pr.open`
  replay the RAW body (redaction was silently mangling invoice
  numbers / order IDs / dates like `20261013` into `[redacted:code]`
  in executed emails); redaction now applies to `body_preview`
  (display) only. `calendar.create`'s hash now covers the full
  replay dict (previously a 3-field subset). Hash-binding invariant
  documented in the module header + `build_evidence_subset` docstring.
- New tests: `TestContentHashBindsReplayArgs` (3 tests: hash ==
  hash(replay_args); digits intact in replay; preview still redacted).

### #4 — Account-level admin lockout independent of client IP
- `src/gateway/console/admin_auth.py`: `_on_failure` now locks the
  ACCOUNT for 30 minutes after 15 total consecutive failures across
  ALL source IPs (`_ACCOUNT_FAILURES_BEFORE_LOCKOUT = 15`,
  `_ACCOUNT_LOCKOUT_MINUTES = 30`), kept alongside the per-IP guard
  (the longer of the two wins; extensions never shorten a live
  lockout). Counter resets only on successful login (existing
  behavior preserved).
- LATENT CRASH FIXED on the same path: `login()` compared aware
  `_utcnow()` against `user.locked_until`, but SQLite returns the
  `DateTime(timezone=True)` column NAIVE → `TypeError` → 500 on any
  request that reached the persisted-lockout check from a fresh IP or
  after restart (the per-IP guard had been masking it in tests). Now
  normalized with `as_utc()` per the M1 convention. Without this fix
  the new account lockout would 500 instead of denying.
- Module docstring updated. New tests:
  `test_account_lockout_after_15_failures_across_ips`,
  `test_successful_login_resets_account_failure_counter`.
- FLAG FOR KEN: threshold (15) and duration (30 min) are judgment
  calls — say the word to change either; account lockout is fixed
  duration, no escalation (per-IP guard keeps its 1/2/4…60 schedule).

### #5 — Secure flag on the admin session cookie
- `src/gateway/config.py`: new `console_cookie_secure: bool` setting
  (`GATEWAY_CONSOLE_COOKIE_SECURE`, default true) + `_env_bool`
  helper; `src/gateway/console/admin_auth.py::set_session_cookie`
  passes `secure=self.settings.console_cookie_secure`.
- Tests: `test_session_cookie_secure_flag_defaults_on` (true default),
  `test_session_cookie_secure_flag_opt_out`. The console integration
  `settings` fixture sets `GATEWAY_CONSOLE_COOKIE_SECURE=0`: the
  TestClient speaks plain HTTP and a Secure cookie is (correctly)
  never sent back over HTTP — the documented local-dev opt-out.
- FLAG FOR KEN: default true is the safe choice, but any plain-HTTP
  deploy (including local dev) needs the env var set to 0 or logins
  will silently fail to persist.

### #6 — kev image: digest pins, no unpickle, non-root
- `docker/kev/artifact-digests.env` (NEW): single source of truth for
  all five SHA-256 pins, with provenance comments. Digests:
  adapter `72813c8d…975e62`, base model `9c17d06a…3b9928e5b`
  (sha256sum of the local serving copies — byte-identical to HF,
  sizes match the old size checks); head.pt `f400bd12…2c920b6`
  (PRISTINE copy freshly re-downloaded — the local serving copy is
  patched and must NOT be pinned); torch wheel `cb9a8ba8…8160db4e`
  (official PyTorch PEP 503 simple-index hash fragment);
  kev tarball `16cc5f2e…2005c3f48` (GitHub codeload tarball for the
  pinned commit).
- `docker/kev/entrypoint.sh`: sources the manifest (fail-closed when
  missing); `verify_artifact` checks size AND SHA-256, aborting boot
  on mismatch. Adapter + base re-verified every boot (never
  modified); head.pt verified AT DOWNLOAD TIME against the pristine
  pin — the patch step rewrites it (meta.base), so it cannot match
  the pristine digest on later boots by design (documented in-file;
  a corrupt head.pt still fails closed via torch.load under
  `set -e`). `torch.load(..., weights_only=True)` — verified safe:
  the pristine checkpoint loads as a plain dict of safe types under
  weights_only (checked with the local torch 2.8.0+cpu).
- `docker/kev/Dockerfile`: torch wheel and kev tarball downloads now
  `sha256sum -c` against the manifest before install (build aborts on
  mismatch); non-root `kevuser` (mirrors the gateway image's
  appuser), `/models` chown'd so fresh named volumes inherit
  ownership, `USER kevuser` before ENTRYPOINT.
- NOT EXECUTED: no docker host on this VM — Dockerfiles reviewed,
  not built (stated in the PR). Entrypoint syntax-checked
  (`bash -n`) and the `verify_artifact` logic dry-run against the
  real local files (all three pristine artifacts verify; the patched
  head.pt is correctly rejected by the pristine pin, proving the
  download-time-only ordering).

### Invariants verified (no regressions)
- Fix A (auth wall), Fix B (approval flow + stage order), Rego
  decision contract, fail-closed paths, judge advisory-only: full
  suite green, no changes to `policy.py`, `pipeline.py` stage order,
  `policies/v1/`, or judge code.
- No secrets/API keys in repo or tests (digests are integrity pins,
  not secrets; test credentials generated at test time).
- No model weights committed (only SHA-256 digests).
- Stealth wording untouched (no OWASP-text edits anywhere).
- `.github/` untouched.
## 2026-10-13 — Batch 2 PR-A: resilience/hardening mediums (GH #7, #8, #9, #11–#18)

Branch `fix/mediums-a` → PR-A against `main`. 11 mediums, all fail-closed.

- **#7 SQLite busy timeout** (`db.py`): `PRAGMA busy_timeout=5000` in
  `_apply_sqlite_pragmas` — concurrent writers wait instead of instant
  `database is locked`.
- **#8 connector exception text** (`pipeline.py` ExecuteStage): agent envelope is
  now generic `{"tool"}` only; the exception text is logged server-side with the
  request_id. No path/stack leakage to agents.
- **#9 pipeline deadline** (`pipeline.py`, `config.py`): `Pipeline.execute` runs
  under a deadline — daemon worker thread + `contextvars.copy_context()` so the
  audit trail still works; new setting `pipeline_timeout_seconds`
  (`GATEWAY_PIPELINE_TIMEOUT_S`, default 120.0, ≤0 disables). Expiry maps to
  `upstream_failure` with `unknown_outcome`/`retry_blocked`/`deadline_exceeded`
  details (`halted_at="deadline"`); the block is recorded synchronously on the
  caller thread through ExecuteStage's unknown-outcome gate.
- **#11 redaction catalog cache** (`inspection/redaction.py`): compiled patterns
  cached in-process, invalidated (version bump) on console add/delete/toggle/
  update; on config-DB error the catalog falls back to the last-known-good set
  (or seed defaults when nothing was ever loaded) — a config-DB outage no
  longer takes redaction down with it.
- **#12 counterparty audit redaction** (`counterparty.py` `correct()`): before/
  after snapshots are redacted through the catalog before the audit write;
  keys-only fallback when redaction itself fails. Deliberate: the counterparty
  `key` is NOT redacted (record identity / audit join key, same role as
  agent_id).
- **#13 notifier hardening** (`notifier.py`): `notify_new_request` split into
  `_notify_inner` + outer `except Exception` (never raises); send-failure catch
  widened to `Exception`; the cooldown is stamped only after SUCCESSFUL
  delivery (check-only `_cooldown_ok` + `_stamp_cooldown`) — a failed send no
  longer silences the next one.
- **#14 ingress JSON caps** (`inspection/validation.py`, `ValidateInputsStage`):
  depth ≤ 32, args ≤ 256KiB, iterative `check_json_limits` enforced first; the
  whole validation block is total — any validator exception → `invalid_input`;
  `validate_against_schema` catches `SchemaError`.
- **#15 scanner byte budgets** (`inspection/injection_scan.py`, `output.py`):
  scanner caps 32KiB/field, 256KiB/call; `ScanResult.truncated_fields` (count,
  capped at 50 names) recorded into the injection audit event. `redact_value`
  caps 64KiB/field, 512KiB/call — over-cap tails are replaced with
  `[redacted:truncated]` (never delivered unredacted) plus a synthetic
  `_truncated` audit event. BEHAVIOR CHANGE for huge outputs — flagged.
- **#16 notifier rotation fail-closed** (`notifier.py`, `config.py`): unset or
  unparseable `GATEWAY_NOTIFIER_SECRET_ISSUED_AT` now → `secret_expired`
  (fail closed); escape hatch `GATEWAY_NOTIFIER_ALLOW_UNKNOWN_SECRET_AGE=1`.
- **#17 external OPA bundle verification** (`opa_client.py`): `bundle_fingerprint()`
  (sha256 over `policies/v1`, excluding `bundle_info.json`);
  `scripts/pin_bundle_fingerprint.py` pins `bundle_info.json` (verified the
  OPA server actually serves `data.gateway.bundle.info.fingerprint`); external
  mode verifies at startup (fail closed, resets `_external_up`) + a daemon
  watchdog re-verifies every `GATEWAY_OPA_BUNDLE_CHECK_SECONDS` (default 300);
  `decide()` refuses while `_bundle_ok` is False.
- **#18 audit write resilience** (`audit.py`): commit retried with backoff
  (0 / 0.05 / 0.2 / 0.5s), **re-adding the entry after each rollback**
  (rollback can detach the pending row — caught by test); persistent failure →
  dead-letter JSONL (`Settings.audit_dead_letter_path`, default
  `data/audit-dead-letter.jsonl`) + CRITICAL log; `scripts/replay_audit_dead_letter.py`
  replays idempotently. Audit write never raises for DB errors.

Tests: 35 new in `tests/test_mediums_a.py` (all pass); updated `TestNotifier`
defaults + fake-OPA bundle-info endpoint for the fail-closed changes.
Full suite on the branch: 650 passed, 8 skipped (live judge tier skipped by default).

Flags for Ken:
- GH #10 ("rate-limiter increment atomic") is a medium NOT in the fix-all task
  list — needs assignment; deliberately untouched.
- #12: counterparty `key` left unredacted in audit rows (record identity).
- #15: `redact_value` now truncates huge fields with a `[redacted:truncated]`
  marker in delivered output.
- #30 (PR-B): the 69MB OPA binary is in git history (0d41b97) though untracked
  at HEAD — true removal needs a history rewrite (recommend against).
- The live kev-0.8b on 127.0.0.1:8009 was left untouched throughout.
## 2026-10-13 — Batch 2 PR-B: config/semantics/traceability mediums (GH #19–#27, #30, #31)

Branch `fix/mediums-b` → PR-B against `main`. 11 issues (one filed low), all fail-closed.

- **#19 TLS awareness** (`config.py`, `mcp_server.py`): new `GATEWAY_TLS_TERMINATED`
  setting; `check_tls_posture()` refuses to start on a non-loopback bind
  without it (Fix A requires per-agent secrets over TLS). Escape hatch
  `GATEWAY_ALLOW_PLAINTEXT_NONLOOPBACK=1` downgrades to a loud warning (LAN
  testing only). Documented in README (new "TLS requirement" section) and the
  compose file. BEHAVIOR CHANGE for 0.0.0.0 binds — flagged.
- **#20 first-run /setup gating** (`console/app.py`, `templates/setup.html`):
  when no admin exists, startup mints a single-use token
  (`app.state.setup_token`, dies with the process, cleared on setup) and logs
  it CRITICAL. Non-loopback `/setup` (GET `?token=`, POST form field) requires
  it; loopback keeps working token-free; `dev_no_auth` (test-only) bypasses.
  The "no admin" state is now impossible to miss in the logs.
- **#21 fallback-Bearer <redacted> max age** (`identity.py`, `errors.py`,
  `pipeline.py`, `mcp_server.py`): `authenticate()` now DENIES fallback_bearer
  credentials older than `fallback_bearer_max_days` (default 90; age from
  `last_rotated_at`, falling back to `issued_at`; fail closed on missing
  timestamps) with the distinct `fallback_bearer_expired` code (new
  `retryable: "rotate_credential"`), mapped in both the pipeline
  `AuthenticateStage` and the MCP transport middleware. OAuth credentials
  unaffected.
- **#22 derived-token validation semantics** (`vault/minter.py`,
  `vault/mock_oauth_issuer.py`): contract now explicit — the LEDGER is the
  authority (ledger hit + `now` < ledger's `expires_at_epoch` + binding match).
  The token object's self-asserted expiry is ignored (forgeable); the issuer
  is consulted ONLY when `UpstreamTokenIssuer.supports_introspection` (the
  mock sets True — it models an introspectable provider; production
  Google/Microsoft opaque-token issuers leave it False). `test_ttl_enforcement`
  rewritten to expire via the ledger.
- **#23 replay supersession re-check** (`pipeline.py`, `approvals.py`):
  `execute_approved_call` checks `policy_materially_superseded()` at replay
  start (new shared helper; `GrantService._superseded` refactored onto it) and
  denies with `policy_superseded` when a MATERIAL policy version landed after
  the approval. Non-material versions don't block — same semantics as the
  grant path (FR-PAA04-003). Interpretive call, flagged.
- **#24 escalation traceability** (`policy.py`): `_maybe_escalate` now carries
  `matched_rule_id`, `scope_rule`, `ontology_snapshot_ref`, `ontology_ref`,
  `data_snapshot_id` into the escalated result; the allow branch also attaches
  `ontology_ref` so there is something to carry.
- **#25 ontology-clause deny snapshots** (`policies/v1/authz.rego`,
  `policy.py`): `trace_info` now emits `ontology_shaped` for deny effects too;
  the Python PAA04 capture comment fixed to describe the actual condition; when
  the Rego cites no entry (plain ontology-clause rules), Python synthesizes
  the citation from the deciding rule (`entry_kind: "rule"`).
- **#26 rule shape validation** (`policy.py`, `authz.rego` `rule_problems`):
  `validate_rule_dict` + new Rego `problem_time_window` /
  `problem_tool_selector` reject `start: "9"`, `days: ["funday"]`, and bare
  `"*"` (or misplaced-wildcard) selectors at save time. Days normalized to
  lowercase; empty `days` keeps its documented never-match semantics.
- **#27 HmacKeyRing.matches total** (`hmac_util.py`, filed LOW): unknown key id
  → `False` instead of `ValueError`; `verify_snapshot` no longer crashes on
  forged/retired-key refs.
- **#30 OPA binary** (`third_party/opa/OPA_VERSION`, `opa_client.py`,
  `scripts/verify_opa.sh`, `docker-compose.yml`): single source of truth
  (`1.8.0`); the client reads it (fallback to last-known); `verify_opa.sh`
  downloads from the official release when missing, always SHA-256-pinned
  (pin verified byte-identical against the official v1.8.0 release);
  compose uses `openpolicyagent/opa:${OPA_VERSION:-1.8.0}`.
- **#31 kev-serve supervision** (`docker-compose.yml`,
  `deploy/kev-serve.service`, `judge/health.py`, `judge/cascade.py`,
  `config.py`, `pipeline.py`): compose kev gets `restart: unless-stopped`;
  new systemd unit template for bare-metal hosts (NOT installed here — this VM
  keeps cron+ensure-up.sh); new process-wide judge health registry —
  `JudgeCascade` records success/`JudgeUnavailable` per backend (skipping the
  deliberately-off `"none"` backend); CRITICAL readiness alert after
  `GATEWAY_JUDGE_ALERT_AFTER_MINUTES` (default 5) of continuous
  unreachability, once per outage, with recovery INFO.

Tests: 49 new in `tests/test_mediums_b.py` (all pass); updated
`test_ttl_enforcement` (ledger-expiry) and the console `/setup` tests (token).
New rego test: deny with ontology clause → shaped (71/71 `opa test` pass;
`opa fmt --fail` clean).
Full suite on the branch: 664 passed, 8 skipped, 1 pre-existing timing flake
(`TestPollBudget::test_own_budget_and_no_audit_rows` — calendar-minute
boundary in the rate limiter; passes in isolation and on the PR-A run;
unrelated to these changes).

Flags for Ken:
- #19: refuse-to-start is a behavior change for non-loopback binds without
  `GATEWAY_TLS_TERMINATED=1` (escape hatch documented).
- #23: material-only supersession (consistent with the grant path), not the
  literal "deny on any version mismatch" — say the word if you want stricter.
- #27 was filed as LOW severity; fixed anyway.
- #30: the 69MB binary is in git HISTORY (0d41b97) though untracked at HEAD —
  true removal needs a history rewrite; recommend against, your call. CI must
  export `OPA_VERSION=$(cat third_party/opa/OPA_VERSION)` before compose
  (or rely on the `:-1.8.0` default, kept in sync).
- #22: production Google/Microsoft issuers must leave
  `supports_introspection=False` — the ledger becomes the sole authority
  (documented contract).
- #31: the systemd unit is a template for real hosts; this VM keeps
  cron+ensure-up.sh. The live kev-0.8b on 127.0.0.1:8009 was left untouched.
- GH #10 ("rate-limiter increment atomic") is a medium NOT in the fix-all
  task list — needs assignment; deliberately untouched.
## Fix #10 — atomic rate-limiter increment (2026-10-13, medium fix worker)

Missed in Batch 2; filled as a single-issue PR (branch `fix/mediums-c`,
PR workflow — no merge without Ken's approval).

### What was wrong (verified against main before fixing)
`RateLimiter._check_window` (`src/gateway/inspection/rate_limit.py`)
did select → Python-side `row.count += 1` → `commit()` with no row lock.
Concurrent in-flight requests for the same agent interleave
read-read-write-write, so N concurrent requests can all observe
`count < limit` and all be admitted — per-minute/per-day budgets
exceeded by up to the concurrency factor. SQLite serializes commits
but does not prevent the lost-update interleaving across sessions.
Classic TOCTOU on an abuse control, exactly as the issue described.

### The fix
`_check_window` now delegates the count to a new `_increment()`:
single conditional `UPDATE rate_counters SET count = count + 1
WHERE agent_id=? AND window=? AND window_start=? AND count < limit
RETURNING count`. Budget check and increment are one statement — no
lost update possible; a rejected attempt never consumes budget
(FR-028 semantics preserved, including the `rate_limited` +
`retry_after` error shape and the disabled-budget `limit <= 0` path).
Row creation on the first attempt of a window is guarded by the
existing `uq_rate_counter` unique constraint: the loser of a
concurrent INSERT rolls back (IntegrityError) and retries the atomic
UPDATE, which then sees the existing row. Chosen over
`SELECT ... FOR UPDATE` because SQLite does not support it; the
single-statement form also ports unchanged to Postgres (the
db.py migration seam). `check()`, `_prune()`, and the `count()`
introspection surface are unchanged.

### Tests
- New `TestRateLimitAtomicity::test_concurrent_increments_never_exceed_budget`
  (`tests/test_inspection.py`): 25 threads (own session each, released
  together on a barrier for maximum contention) hammer one agent's
  minute budget of 10 → exactly 10 admitted, 15 rejected, persisted
  count exactly 10.
- Regression check: the new test FAILS against the pre-fix code
  (budget over-admitted under contention) and PASSES with the fix.
- Rate-limit subset: 5 passed. Full suite: **616 passed, 8 skipped**
  (0:20:07), run with `TMPDIR=/home/hatch/workspace/.tmp-pytest`
  per the /tmp-tmpfs environment lesson. Live kev tier skipped
  (opt-in, untouched on 127.0.0.1:8009).

### Invariants held
- Fix A (auth wall), Fix B (approval flow), Rego decision contract,
  fail-closed, judge advisory-only — untouched.
- No secrets/API keys in repo or tests; no model weights; stealth
  wording preserved ("candidate OWASP project" only — no such wording
  added or needed).
- `.github/` untouched per task.
## Fix batch 3 — low-severity production-readiness issues #28, #29, #32, #33 (2026-10-13, fix worker)

Branch `fix/lows`; PR workflow (no merge, no direct push to main).
All four issues verified against the exact code cited before fixing.

### #28 — Catch ValueError (not KeyError) in the redaction delete/toggle routes
- Verified: `RedactionCatalog._require` raises `ValueError("unknown redaction
  pattern ...")`; `delete_pattern`/`set_enabled` both funnel through it.
  The route's `except KeyError: pass` was dead code (unknown-name delete
  → unhandled 500, failed attempt never audit-logged); `redaction_toggle`
  had no handler at all.
- Fix (`src/gateway/console/pages.py`): both routes now catch
  `ValueError` → audit-log the failed attempt (`decision="denied"`,
  `reason="unknown_pattern"`, tool `redaction.catalog_update`) → return
  404 `HTMLResponse`. Success path unchanged (302 + allowed audit row).
  Return annotations widened `RedirectResponse` → `Response`.
- Regression tests (`tests/test_console.py`):
  `test_redaction_delete_unknown_pattern_404_and_audited`,
  `test_redaction_toggle_unknown_pattern_404_and_audited`.

### #29 — Ontology feedback loop documented as deferred (not wired)
- Verified: `record_decision_outcome`, `detect_conflicts`, `sweep_stale`,
  `discover_from_audit` have zero production callers (tests only).
- Decision: document as deferred, per the issue's explicit allowance. Rationale
  recorded in `docs/deferred-items.md`: wiring only the recording half
  (pipeline → feedback events) with no detector runs and no review-queue
  surface would grow an unconsumed event log — the loop is deferred as a
  unit. Enforcement (ontology_ctx at policy time, snapshots, provenance)
  is unaffected.
- `docs/deferred-items.md` (new): seam (the five intended call sites),
  what's missing, why deferring is safe, and "done" acceptance criteria.
- Module docstrings of `feedback.py`/`discovery.py` carry a STATUS header
  pointing at the entry. No behavior change.

### #32 — Counterparty judge hook auto-wired into ValidateInputsStage
- New `JudgeCounterpartyHook` (`src/gateway/judge/counterparty_hook.py`):
  scores trigger content (false-urgency / impersonation) and returns a
  signals dict or None. Advisory-only by construction: `check` never
  raises (JudgeUnavailable + broad except → None) and never halts
  validation — it only sets `ctx.judge_counterparty_signals`, which the
  approval service already renders via `judge_signals_for_approval_record`
  (approvals.py, pre-existing consumer).
- Wiring (`src/gateway/pipeline.py`): `_judge_wiring` now returns
  `(inspection_hook, risk_scorer, counterparty_hook)` — all None unless
  `GATEWAY_JUDGE_ENABLED=1`. Both builders install the hook on
  `ValidateInputsStage`. Gate mirrors the inspection hook: fires only
  when the deterministic urgency scan already flagged suspicion, or when
  `GATEWAY_JUDGE_ALWAYS_ON=1`. Latency discipline: one
  `validate.judge_counterparty` timing span; hot path byte-identical when
  disabled (hook is None → gate short-circuits).
- Tests (`tests/test_judge_cascade.py`, 8 new): fires on deterministic
  suspicion (signals shape, exactly one judge call, span recorded);
  gate skips the judge on clean calls; always_on consults on clean calls;
  JudgeUnavailable → None with deterministic flags intact; generic backend
  error → None, validation never breaks; no hook → no signals;
  `_judge_wiring` returns the hook when enabled, `(None, None, None)`
  when disabled.

### #33 — kev-4B promotion: config knob + runbook (no GPU host here)
- Verified model-agnosticism: `KevBackend` already takes `model=`; only
  the factory never passed one (no settings knob existed).
- `config.py`: new `judge_kev_model` (`GATEWAY_JUDGE_KEV_MODEL`, default
  `jaredpalmer/kev-4b` = production recommendation; literal kept to avoid
  a config→judge import cycle). `factory.py`: kev backend now built with
  `model=settings.judge_kev_model` (getattr fallback for older settings
  objects). README env table gains `GATEWAY_JUDGE_KEV_MODEL` (+ the
  previously undocumented `GATEWAY_JUDGE_KEV_URL` row).
- `docs/judge-model-runbook.md` (new): GPU sizing (~16 GB RAM or CUDA ≥
  8 GB VRAM), serve command, the four env knobs, and the acceptance
  criteria (accuracy re-run of the live tier against kev-4B, latency vs
  the AC-11 100 ms budget on the deploy target) required before closing
  the issue. Status: documented, pending GPU host. No weights downloaded
  (impossible on this VM), default model unchanged.
- Tests (`tests/test_judge.py`): model selection pass-through, default
  stays kev-4b.

### Test evidence
- Full suite on branch `fix/lows`: **627 passed, 8 skipped**
  (2026-10-13; the 8 skips are the opt-in live-model tier). New tests:
  2 console (#28) + 8 judge-cascade wiring (#32) + 2 factory (#33).
- Environment: pytest run with `TMPDIR=/home/hatch/workspace/.tmp-pytest`
  (the 512 MB /tmp tmpfs rule); the pre-existing kev-0.8b server on
  127.0.0.1:8009 was not disturbed.

### Non-regression / invariants
- Fix A (auth wall), Fix B (approval flow), Rego decision contract,
  fail-closed, judge advisory-only: untouched (judge changes are
  additive, default-off; #28 is console-only).
- No secrets/API keys in repo or tests; no model weights committed;
  stealth wording intact (no new OWASP project-status claims).
- `.github/` untouched (untracked in this tree; not committed).

## 2026-10-15 — Rebase: pillars/two-pillars onto main@8c2025d (rebase coordinator)

Branch `pillars/two-pillars` (MVP: money pack + quorum + finance demo;
red-team agent runtime) was based on main@85880cf. Main has since moved
to 8c2025d (all 32 fix-all issues merged, PRs #34–#38). Rebasing:
`git rebase origin/main` in worktree ~/workspace/mcp-gateway-pillars.

### Conflicts resolved (kept both sides' behavior in every case)
- `src/gateway/policy.py` — HEAD (#26 tool-selector shape validation)
  vs branch (money-block structural validation via
  `money/limits.validate_money_block`): kept both, sequentially.
- `src/gateway/approval_card.py` — docstring merge: kept the #34
  `content_hash`-binds-exact-replay-bytes note (issue #3) and the
  Pillar 1 `money` evidence-inputs note.
- `src/gateway/config.py` — HEAD (`judge_alert_after_minutes`
  validation) vs branch (Pillar 1/2 settings validations:
  `event_interception`, `money_ledger_retention_days`,
  `webhook_nonce_window_s`, `codehost_issues_backend`,
  `redteam_issue_threshold`, `sentinel_notify_severity`): kept both.
- `src/gateway/pipeline.py` — auto-merged cleanly. Verified the #38
  structure survived: the #32 counterparty hook stays INSIDE #35's
  try/except-total in ValidateInputsStage (lines ~458–468), and the
  branch's MoneyStage (step 3.5, after MandateStage) composes with it.
  The money stage sets `policy_short_circuited`; RealPolicyStage
  (`policy.py`) skips rule evaluation for decided money calls while
  the unknown-outcome gate still runs (retry safety).

### Post-rebase fix
- `tests/test_console_pillars.py::test_money_page_renders` failed:
  the branch's console-test fixture predates the #5 Secure-cookie
  fix, so the authed TestClient (plain HTTP) lost its session.
  Fixed with the main-branch pattern:
  `GATEWAY_CONSOLE_COOKIE_SECURE=0` in the fixture (commit cce3b54).

### Test evidence
- Full suite on the rebased branch: **865 passed, 8 skipped**
  (2026-10-15; the 8 skips are the opt-in live-model tier).
  Environment: `PYTHONPATH=<worktree>/src` (the venv's editable
  install points at the main repo — without the override, `gateway.*`
  imports resolve to main, not the worktree),
  `TMPDIR=/home/hatch/workspace/.tmp-pytest`; kev-0.8b on
  127.0.0.1:8009 untouched.

### Non-regression / invariants
- Fix A (auth wall), Fix B (approval flow + WYSIWYE
  `preview_redacted` signal), Rego decision contract, fail-closed,
  judge advisory-only: all hold. The money card renders consequence
  from structured amount/payee fields (not a redacted free-text
  preview), so no WYSIWYE gap for `payment.*`; execute-on-approval
  is disabled for `payment.*` and for quorum requests (re-invoke
  path only, grant HMAC binds exact amount + payee).
- No secrets/API keys in repo or tests (the one `sk-live-abc` hit
  is the pre-existing fixture proving exclusion from the envelope);
  no model weights committed; stealth wording clean.
- `.github/` untouched.
