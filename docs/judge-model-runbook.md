# Judge Model Deploy Runbook — promoting kev-4B (GH #33)

Status: **documented, pending GPU host** (2026-10-13). No live promotion
was possible on the build VM (no GPU, 7 GB RAM).

## What this decides

The judge decision backend (`KevBackend`, `src/gateway/judge/kev.py`) is
model-agnostic: any checkpoint speaking the TypeSafe `/v1/systemone`
contract works, and the model id is a config knob, not a code change:

| Knob | Env var | Default |
|---|---|---|
| Kev endpoint | `GATEWAY_JUDGE_KEV_URL` | `http://127.0.0.1:8009` |
| Kev model id | `GATEWAY_JUDGE_KEV_MODEL` | `jaredpalmer/kev-4b` |
| Judge primary | `GATEWAY_JUDGE_BACKEND` | `none` (judge off) |
| Hook installation | `GATEWAY_JUDGE_ENABLED` | `0` (hooks off) |

The factory (`src/gateway/judge/factory.py::backend_from_settings`)
passes `GATEWAY_JUDGE_KEV_MODEL` straight into the client; no model
weights live in this repo (the docker `kev` service downloads them into
a named volume on first boot — see README).

## Current state (2026-10-13)

- **Local dev / CI:** kev-0.8b (`jaredpalmer/kev-0.8b`, ~1.6 GB bf16 base
  + 43 MB adapter) served on `127.0.0.1:8009`. This is the weakest
  released checkpoint: weak confidences, one missed choice test in the
  live tier. It exercises the identical wire contract and driver code,
  so it validates the plumbing — not the judgement quality.
- **Production recommendation:** kev-4B (`jaredpalmer/kev-4b`), the
  checkpoint the cascade thresholds (0.75), question budgets, and the
  6000-char state cap were designed around.

## Promoting to kev-4B on a GPU host

### 1. Provision the host

- GPU strongly preferred (any CUDA card with ≥ 8 GB VRAM), or a
  CPU-only host with **~16 GB RAM** (kev-4b is ~8 GB bf16 + serve
  overhead; the 0.8b checkpoint needs ~2 GB, the 4b needs the full 16).
- The host only needs to serve `POST /v1/systemone` — it does not need
  the gateway.

### 2. Serve kev-4B

```bash
# on the GPU host (kev.serve is Apache-2.0; no repo code involved)
python -m kev.serve --run jaredpalmer/kev-4b --host 0.0.0.0 --port 8009 --device cuda
```

Weights come from HuggingFace on first boot. Optionally set
`KEV_API_KEY` on the serve side; the gateway reads the same name.

### 3. Point the gateway at it

```bash
export GATEWAY_JUDGE_BACKEND=kev
export GATEWAY_JUDGE_KEV_URL=http://<gpu-host>:8009
export GATEWAY_JUDGE_KEV_MODEL=jaredpalmer/kev-4b   # the default; set explicitly
# keep hooks OFF until the acceptance run passes:
export GATEWAY_JUDGE_ENABLED=0
```

### 4. Acceptance run (record results in the build log)

1. **Accuracy re-run:** `GATEWAY_JUDGE_LIVE_URL=http://<gpu-host>:8009
   GATEWAY_JUDGE_LIVE_MODEL=jaredpalmer/kev-4b pytest tests/test_judge_live.py`
   — the 0.8b-tier's missed choice test should pass on 4b; confidences
   should clear the 0.75 cascade threshold on the golden questions.
2. **Latency vs the AC-11 budget:** p50/p95 of the judge span against
   the 100 ms gateway-internal budget (the admin-console latency
   dashboard, or the `test_latency.py` harness against the live
   backend). The hooks stay **default-off**; the budget only binds when
   an operator enables them.
3. Only after (1) and (2) pass: flip `GATEWAY_JUDGE_ENABLED=1` on the
   deploy target and note the date in `docs/build-log.md`.

### 5. Close the loop

When the acceptance run passes on the GPU host, close GH #33 with the
measured accuracy/latency numbers. Until then the issue stays open as
"documented, pending GPU host".

## What is deliberately NOT in this runbook

- Downloading weights onto the build VM (no GPU here; 30B weights were
  never fetched and are never committed — same rule as all model
  artifacts).
- Changing the default model id (already `jaredpalmer/kev-4b`, the
  production recommendation) or the cascade thresholds (tune only
  against measured 4b confidences).
