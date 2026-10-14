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

## One-command demo (`docker compose up --build`)

A reviewer or future customer gets a working gateway with a seeded demo from one
command (repo root):

```bash
docker compose up --build
```

What comes up:

| Service | Image | What it is |
|---|---|---|
| `gateway` | built from `docker/gateway/Dockerfile` (python:3.12-slim) | the MCP control plane; Streamable HTTP on host `:8000` |
| `opa` | `openpolicyagent/opa:1.8.0` (**pinned** — must match `OPA_VERSION` in `src/gateway/opa_client.py`) | policy decision point; serves the versioned Rego bundle mounted read-only from `./src/gateway/policies/v1` |
| `kev` | built from `docker/kev/Dockerfile` (python:3.12-slim) | kev-0.8b decision-model server for the opt-in judge cascade; serves `:8009` inside the compose network only |

First boot, the gateway entrypoint (`docker/gateway/entrypoint.sh`) runs the
idempotent demo seed (`scripts/seed_demo.py`): registers the `demo-agent`
identity (Fix-A OAuth credential), creates the default read-only standing
mandate plus a demo mandate, saves policy version 1 (explicit allow for
`demo.read`; `demo.write` deliberately uncovered so it hits the pinned
default-deny), and writes the one-time credentials to `/data/demo-credentials.env`
(mode 0600, inside the `gateway-data` volume).

The kev entrypoint (`docker/kev/entrypoint.sh`) downloads weights from
HuggingFace on first boot into the `kev-models` named volume (never baked into
the image): the `jaredpalmer/kev-0.8b` adapter (~45 MB) + the
`Qwen/Qwen3.5-0.8B-Base` base (~1.7 GB), verifies byte-exact sizes, patches
`head.pt`'s `meta.base` to the local base dir, then serves
`KEV_DTYPE=bf16 python -u -m kev.serve --run /models/kev-0.8b --host 0.0.0.0 --port 8009 --device cpu`.
`kev.serve` is installed from upstream (Apache-2.0, pinned commit
`85ccf56a0afb952323c621055b02876e8498d60c`) — no kev code is vendored in this repo.
The kev service needs ~2 GB RAM on the docker host.

Smoke test (the acceptance gate — asserts one ALLOW and one DENY through the
real MCP endpoint, then tears the stack down):

```bash
./scripts/compose_smoke.sh   # must run on a docker host
```

Demo-only env vars (namespaced, default-off/safe; set in `docker-compose.yml`,
not in the image):

| Variable | Default | Notes |
|---|---|---|
| `GATEWAY_OPA_URL` | (empty) | **compose:** `http://opa:8181` — external OPA mode: no sidecar subprocess, decisions go to the URL; identical fail-closed contract. Empty = sidecar mode (default). |
| `GATEWAY_SEED_DEMO` | `0` | `1` = run the demo seed at container boot (idempotent). |
| `GATEWAY_DEMO_TOOLS` | (empty) | `1` = register `demo.read` (seeded allow) + `demo.write` (default-deny) on the MCP surface. Demo only — never enable in production. |
| `GATEWAY_HMAC_KEY` | (empty) | compose: when empty, the entrypoint generates + persists a demo key (0600, first boot) so the approval flow works. Production MUST set this from the platform secret store. |

Notes:
- The judge is **wired but off** in the demo: `GATEWAY_JUDGE_BACKEND=kev` +
  `GATEWAY_JUDGE_KEV_URL=http://kev:8009`, while `GATEWAY_JUDGE_ENABLED` stays
  `0` (default). Flip it to `1` to exercise the advisory judge cascade against
  the live model.
- `docker compose down -v` drops both named volumes (fresh seed + fresh weight
  download on the next `up`).
- The `opa` service has no healthcheck: the official image is scratch-based (no
  shell/curl). The gateway's `OpaClient` readiness probe (`GATEWAY_OPA_URL` mode)
  gates on OPA before serving decisions.

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
| `GATEWAY_TLS_TERMINATED` | `0` | **TLS (GH #19):** set `1` when a TLS-terminating reverse proxy / platform ingress sits in front of the gateway. Binding a non-loopback address without this REFUSES to start (Fix A requires per-agent secrets over TLS) |
| `GATEWAY_ALLOW_PLAINTEXT_NONLOOPBACK` | `0` | **TLS escape hatch:** `1` downgrades the refuse-to-start to a loud warning. LAN testing only — never production |
| `GATEWAY_PIPELINE_TIMEOUT_S` | `120.0` | overall bound on one pipeline execution; `≤0` disables (GH #9) |
| `GATEWAY_NOTIFIER_ALLOW_UNKNOWN_SECRET_AGE` | `0` | escape hatch for the fail-closed notifier rotation check (GH #16) |
| `GATEWAY_AUDIT_DEAD_LETTER` | `data/audit-dead-letter.jsonl` | spill file for audit rows when the audit DB is down (GH #18); replay with `scripts/replay_audit_dead_letter.py` |
| `GATEWAY_OPA_BUNDLE_CHECK_SECONDS` | `300` | external-OPA bundle fingerprint re-verification interval (GH #17) |
| `GATEWAY_JUDGE_ALERT_AFTER_MINUTES` | `5` | **JUDGE:** minutes of continuous backend unreachability before the CRITICAL readiness alert (GH #31) |
| `GATEWAY_JUDGE_BACKEND` | `none` | **JUDGE (opt-in):** judge primary — `none`\|`kev`\|`jev` |
| `GATEWAY_JUDGE_ESCALATION` | `none` | **JUDGE (opt-in):** cascade escalation — `none`\|`jev`\|`llm` (see below) |
| `GATEWAY_LLM_ESCALATION_URL` | `http://127.0.0.1:11434` | **JUDGE:** OpenAI-compatible chat-completions base (Ollama default; vLLM/SGLang by URL) |
| `GATEWAY_LLM_ESCALATION_MODEL` | `meta-models/Muse-Glimmer-30B` | **JUDGE:** escalation model id |
| `GATEWAY_LLM_ESCALATION_API_KEY` | (empty) | **JUDGE:** optional key for hosted endpoints (Ollama needs none) |

No real secrets are stored in the repo. Ever.

## M1 credential transport contract

Per-agent secret over TLS; no third rung (Fix A):

- OAuth client credentials: `Authorization: Basic base64(client_id:client_secret)`
- Conditional fallback bearer: `Authorization: Bearer <key_id>.<raw_token>`

The credential is validated on **every** request (the session ID alone never
suffices). The gateway-as-OAuth-authorization-server code exchange arrives in a
later milestone; `mock_oauth.py` covers the token shape for tests.

### TLS requirement (GH #19)

The gateway itself speaks plain HTTP. "Per-agent secret over TLS" (above)
means **you must terminate TLS in front of the gateway** in production — a
reverse proxy (Caddy, nginx, Traefik) or platform ingress with a certificate —
and set `GATEWAY_TLS_TERMINATED=1` so the startup check knows the traffic is
protected.

- Binding a **loopback** address (`127.0.0.1`, the default) needs nothing.
- Binding a **non-loopback** address (`0.0.0.0`, a LAN IP) without
  `GATEWAY_TLS_TERMINATED=1` makes the gateway **refuse to start** rather
  than send OAuth client secrets and Bearer <redacted> in cleartext.
- `GATEWAY_ALLOW_PLAINTEXT_NONLOOPBACK=1` downgrades the refusal to a loud
  warning — LAN testing only, never production.
- The admin console (`/setup`, session cookie) is served by the same
  process: the same TLS requirement applies, and first-run `/setup` from a
  non-loopback address additionally requires the one-time setup token
  printed in the startup log (GH #20).

## Judge escalation backend (`llm`) — bring-your-own escalation model

The judge cascade runs Kev-4B as the fast, calibrated **primary**. When the
primary is low-confidence or unavailable, an optional **escalation** backend
re-decides and its answers win (`escalated=True`); if the escalation fails,
the exception propagates and the caller falls back to the deterministic `ask`
path. The judge stays advisory-only: it never sits in front of Rego policy.

`GATEWAY_JUDGE_ESCALATION=llm` wires a generic OpenAI-compatible
chat-completions adapter (`src/gateway/judge/llm_escalation.py`) as the
escalation layer. The **validated target** is
`meta-models/Muse-Glimmer-30B` (Apache-2.0) served via Ollama
(`ollama pull hf.co/meta-models/Muse-Glimmer-30B`), vLLM, or SGLang —
all expose `POST /v1/chat/completions`.

Be technically honest about what this is: Muse Glimmer 30B is a
**generative agentic chat model, NOT a `/v1/systemone` decision
model**. The adapter asks it for a strict JSON verdict (one
`{"label", "confidence"}` per question, labels restricted to the
declared set) and parses strictly — any unparseable, missing, or
out-of-range field raises `JudgeUnavailable` and the call fails
closed. The returned "probabilities" are a normalized self-report
(chosen label gets its stated confidence, remainder split uniformly),
**not a calibrated distribution like Kev's**. This is why the LLM is
escalation-only: it gets a second opinion when the calibrated model
is uncertain, never the primary vote.

**GPU note (deploy-target task):** Glimmer-30B needs ~24 GB VRAM
quantized — this build's 7 GB, no-GPU VM cannot download or run it.
The backend is implemented and mock-tested here; live validation
against a real Glimmer-30B endpoint (deploy target with a GPU, or a
hosted OpenAI-compatible endpoint) is an explicit follow-up before
any production escalation use. Ollama is the recommended path:
`GATEWAY_LLM_ESCALATION_URL=http://127.0.0.1:11434`
`GATEWAY_LLM_ESCALATION_MODEL=meta-models/Muse-Glimmer-30B`.

## M0 spike summary

See `docs/build-log.md`: SDK floor PASS (mcp 2.3.0, fastmcp 4.1.0 — this build
installs exactly those), dotted tool names verified on the wire, Streamable
HTTP at `/mcp` verified, platform OAuth spikes not verifiable here (both Fix-A
paths built), OAuth app registrations are Ken's action. Environment quirk:
`no_proxy`/`NO_PROXY` is sanitized at startup (bracketed IPv6 entries dropped)
before any FastMCP import.
