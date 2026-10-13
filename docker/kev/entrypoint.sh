#!/usr/bin/env bash
# kev-0.8b model server entrypoint.
#
# First boot: downloads weights from HuggingFace into the /models named
# volume (never baked into the image), verifies sizes AND pinned SHA-256
# digests (docker/kev/artifact-digests.env; boot aborts on mismatch —
# issue #6), and patches head.pt's meta.base to the local base directory
# (mirrors ~/workspace/kev-serve/patch_head_base.py; edits only the local
# serving copy). Digest verification runs BEFORE the patch step, against
# the pristine downloaded bytes. Subsequent boots reuse the volume.
#
# Then serves:
#   KEV_DTYPE=bf16 python -u -m kev.serve --run /models/kev-0.8b \
#     --host 0.0.0.0 --port 8009 --device cpu
set -euo pipefail

# Defensive no_proxy sanitizing (M0 sandbox lesson): bracketed IPv6
# entries break httpx/huggingface_hub URL parsing.
for var in no_proxy NO_PROXY; do
    raw="${!var:-}"
    [ -z "$raw" ] && continue
    kept="$(printf '%s' "$raw" | tr ',' '\n' | grep -v '^\[' | paste -sd, - || true)"
    if [ -z "$kept" ]; then
        unset "$var"
    else
        export "$var=$kept"
    fi
done

# TMPDIR off the small container /tmp: HF downloads are ~1.8GB.
export TMPDIR=/models/tmp
mkdir -p /models/tmp /models/kev-0.8b /models/qwen3.5-0.8b-base

ADAPTER_DIR=/models/kev-0.8b
BASE_DIR=/models/qwen3.5-0.8b-base

# --- artifact integrity verification (issue #6) ------------------------------
# Pinned SHA-256 digests live in artifact-digests.env (single source of
# truth, also consumed by the Dockerfile). A tampered file of identical
# size no longer passes: boot aborts on ANY mismatch (fail closed).
DIGESTS_FILE="${KEV_DIGESTS_FILE:-/usr/local/etc/kev/artifact-digests.env}"
if [ ! -f "$DIGESTS_FILE" ]; then
    echo "entrypoint: FATAL: digest manifest $DIGESTS_FILE missing" >&2
    exit 1
fi
# shellcheck disable=SC1090
. "$DIGESTS_FILE"

verify_artifact() { # verify_artifact <path> <sha256> <bytes> <label>
    actual_bytes="$(wc -c < "$1" | tr -d ' ')"
    if [ "$actual_bytes" != "$3" ]; then
        echo "entrypoint: FATAL: $4 size is $actual_bytes bytes, want $3" >&2
        exit 1
    fi
    actual_sha="$(sha256sum < "$1" | cut -d' ' -f1)"
    if [ "$actual_sha" != "$2" ]; then
        echo "entrypoint: FATAL: $4 SHA-256 mismatch: got $actual_sha" >&2
        exit 1
    fi
    echo "entrypoint: verified $4 (sha256 ok)"
}

# --- weights (first boot only) -------------------------------------------
if [ ! -f "$ADAPTER_DIR/adapter_model.safetensors" ]; then
    echo "entrypoint: downloading kev-0.8b adapter (~45MB)..."
    huggingface-cli download jaredpalmer/kev-0.8b \
        --include "adapter_config.json" \
        --include "adapter_model.safetensors" \
        --include "head.pt" \
        --local-dir "$ADAPTER_DIR" \
        ${HF_TOKEN:+--token "$HF_TOKEN"}
    # head.pt is verified HERE, at download time, against the pristine
    # pin: the patch step below rewrites the file (meta.base), so on
    # later boots it no longer matches the pristine digest BY DESIGN.
    # (A corrupt head.pt still fails closed: torch.load raises under
    # `set -e` and boot aborts.)
    verify_artifact "$ADAPTER_DIR/head.pt" "$HEAD_PT_SHA256" 2103999 "kev-0.8b head.pt (pristine)"
fi
if [ ! -f "$BASE_DIR/model.safetensors" ]; then
    echo "entrypoint: downloading Qwen3.5-0.8B-Base (~1.7GB, one-time)..."
    huggingface-cli download Qwen/Qwen3.5-0.8B-Base \
        --include "config.json" \
        --include "tokenizer.json" \
        --include "tokenizer_config.json" \
        --include "merges.txt" \
        --include "vocab.json" \
        --include "model.safetensors-00001-of-00001.safetensors" \
        --local-dir "$BASE_DIR" \
        ${HF_TOKEN:+--token "$HF_TOKEN"}
    # kev.serve expects the single-shard name (see build-log.md).
    mv "$BASE_DIR/model.safetensors-00001-of-00001.safetensors" \
       "$BASE_DIR/model.safetensors"
fi

# The adapter and base model are never modified after download, so they
# are re-verified on EVERY boot. head.pt is verified at download time
# (inside the if-block above): the patch step below rewrites it, so it
# no longer matches the pristine pin on later boots by design.
verify_artifact "$ADAPTER_DIR/adapter_model.safetensors" "$ADAPTER_SHA256" 43338624 "kev-0.8b adapter"
verify_artifact "$BASE_DIR/model.safetensors" "$BASE_MODEL_SHA256" 1746942600 "Qwen3.5-0.8B base model"

# --- head.pt: point meta.base at the local base dir ----------------------
# Every loader call (AutoConfig/AutoTokenizer/AutoModelForCausalLM)
# accepts a local directory, so the server never touches the network
# for weights after the first download.
python3 - "$ADAPTER_DIR/head.pt" "$BASE_DIR" <<'EOF'
import sys
import torch

ckpt_path, base_dir = sys.argv[1], sys.argv[2]
# weights_only=True (issue #6): head.pt was already digest-verified
# above, and unpickling a network-downloaded file with full pickle is
# arbitrary code execution. The checkpoint is a plain dict of safe
# types (verified against the pristine copy), so weights-only loading
# is sufficient — the assert below still holds.
meta = torch.load(ckpt_path, map_location="cpu", weights_only=True)
assert isinstance(meta, dict), type(meta)
if meta.get("base") != base_dir or meta.get("base_revision"):
    meta["base"] = base_dir
    meta["base_revision"] = None
    torch.save(meta, ckpt_path)
    print(f"patched head.pt: base -> {base_dir}")
else:
    print("head.pt already points at the local base dir")
EOF

# --- serve ---------------------------------------------------------------
exec env KEV_DTYPE=bf16 python3 -u -m kev.serve \
    --run "$ADAPTER_DIR" \
    --host 0.0.0.0 \
    --port 8009 \
    --device cpu
