# Personal Agent Security Gateway

One public MCP endpoint (Streamable HTTP) that Ken's personal AI agents —
Meta Muse (Custom Connectors), Grok Bot (custom MCP), OpenAI Dots (provisional) —
register once. The gateway mediates every tool call: agent identity, short-lived
scoped tokens, per-agent/per-tool allow/deny policies, step-up human approval for
sensitive actions, server-side credential vault, input validation, tool-output
prompt-injection scanning, PII redaction, rate limits, and a full redacted audit
log. Agents never hold raw credentials.

Planning docs (review-clean, 3 adversarial rounds, 79/79 findings resolved):
`docs/00-build-plan.md` (build plan + Fix A/Fix B) · `docs/01-requirements.md`
· `docs/02-design.md` · `docs/03-architecture.md` · `docs/05-paa10-mapping.md`
· `docs/06-review-log.md` · `docs/build-log.md` (spike results + build journal).

**Current milestone: M1** — endpoint, identity, audit. The pipeline skeleton is
in place with injectable stage hooks; policy (M2), approval (M3), vault-backed
token minting (W3), connectors (W2), and inspection (M5) plug into documented
seams.

## Layout

```
pyproject.toml          Python ≥3.12; MCP SDK floor pinned (GHSA-qx49-fqc8-xw99)
.venv/                  project venv (pip install -e . already run here)
src/gateway/
  config.py             env-based settings (lifetimes, caps, rate limits, secrets)
  db.py                 TWO SQLite files (config + audit), WAL, Postgres seam via ORM
  models.py             Agent, AgentCredential, Mandate, PolicyVersion/Rule,
                        ApprovalRequest, Grant, CounterpartyRecord,
                        DecisionCriteria, AuditEntry, RateCounter, AdminUser
  ids.py                128-bit CSPRNG ids: req_ / apr_ / mnd_
  errors.py             MCP isError envelope + all 02 §2.7 codes + safe vocabulary
  hmac_util.py          HMAC-SHA256 of canonical JSON args (key-id tagged, rotation seam)
  identity.py           Fix-A auth: exactly one credential/agent, gated fallback,
                        per-request validation, immediate revocation
  mandates.py           PAA01 mandates: default at registration, liveness check
                        BEFORE any tool logic, distinct deny reasons, delegation
  audit.py              append-only audit: search/filter, JSON/CSV export
                        (no update/delete API exists by design)
  pipeline.py           Fix-B pipeline skeleton + ConnectorRegistry (W2) +
                        TokenMinter seam (W3) + timing spans (AC-11)
  mcp_server.py         FastMCP over Streamable HTTP at /mcp; auth middleware
                        rejects unauthenticated initialize/tools/list/tools/call
  mock_oauth.py         in-process mock OAuth provider for tests (fake tokens, expiry)
tests/test_foundation.py  73 tests (unit + live-wire over real uvicorn server)
docs/                   planning docs (read-only; append to build-log.md only)
```

## Run the tests

```bash
cd ~/workspace/mcp-gateway
.venv/bin/python -m pytest tests/ -q
```

107 tests, all green (2026-10-12: 73 M1 + 34 M4 vault). The `TestMcpWire` class boots a real
uvicorn server on an ephemeral port and speaks raw Streamable HTTP JSON-RPC.

## Environment variables

| Variable | Default | Notes |
|---|---|---|
| `GATEWAY_CONFIG_DB` | `data/config.db` | config SQLite file |
| `GATEWAY_AUDIT_DB` | `data/audit.db` | audit SQLite file (separate) |
| `GATEWAY_VAULT_DB` | `data/vault.db` | **M4:** encrypted secrets SQLite file (separate) |
| `GATEWAY_KMS_KEY` | (empty) | **M4:** base64 32-byte vault KEK, from the platform secret store (Fly secrets / GCP Secret Manager); generate with `python -m gateway.vault.kms --generate` |
| `GATEWAY_KMS_KEY_ID` | `local-dev-1` | **M4:** KEK version tag recorded on wrapped DEKs (KMS rotation) |
| `GATEWAY_HMAC_KEY` | (empty) | gateway-held HMAC key material (≥16 bytes), from the platform secret store — required for approval argument hashing (M3) |
| `GATEWAY_HMAC_KEY_ID` | `k1` | key id tag on stored hashes (rotation seam) |
| `GATEWAY_NOTIFIER_SECRET` | (empty) | exempt approval-notification bootstrap secret (M3; platform secret store, NOT the vault) |
| `GATEWAY_SESSION_TTL_MIN` | `60` | agent session credential lifetime |
| `GATEWAY_DERIVED_TTL_MIN` | `5` | per-call derived token lifetime |
| `GATEWAY_FALLBACK_BEARER_MAX_DAYS` | `90` | fallback bearer max age (mandatory rotation) |
| `GATEWAY_APPROVAL_WINDOW_MIN` | `15` | approval window (M3) |
| `GATEWAY_DESTRUCTIVE_APPROVAL_WINDOW_MIN` | `5` | destructive-action window (M3) |
| `GATEWAY_GRANT_TTL_MIN` | `30` | one-time grant TTL (M3) |
| `GATEWAY_RATE_PER_MIN` / `GATEWAY_RATE_PER_DAY` | `60` / `1000` | per-agent rate limits (M5) |
| `GATEWAY_APPROVAL_CAP` | `5` | per-agent pending-approval cap (M3) |
| `GATEWAY_REFUSAL_COOLDOWN_H` | `24` | post-denial refusal cooldown (M3) |
| `GATEWAY_AUDIT_RETENTION_DAYS` | `90` | audit retention |
| `GATEWAY_HOST` / `GATEWAY_PORT` | `127.0.0.1` / `8000` | server bind |

No real secrets are stored in the repo. Ever.

## M1 credential transport contract

Per-agent secret over TLS; no third rung (Fix A):

- OAuth client credentials: `Authorization: Basic base64(client_id:client_secret)`
- Conditional fallback bearer: `Authorization: Bearer <key_id>.<raw_token>`

The credential is validated on **every** request (the session ID alone never
suffices). The gateway-as-OAuth-authorization-server code exchange arrives in a
later milestone; `mock_oauth.py` covers the token shape for tests.

## M0 spike summary

See `docs/build-log.md`: SDK floor PASS (mcp 2.3.0, fastmcp 4.1.0 — this build
installs exactly those), dotted tool names verified on the wire, Streamable
HTTP at `/mcp` verified, platform OAuth spikes not verifiable here (both Fix-A
paths built), OAuth app registrations are Ken's action. Environment quirk:
`no_proxy`/`NO_PROXY` is sanitized at startup (bracketed IPv6 entries dropped)
before any FastMCP import.
