#!/usr/bin/env bash
# kev-0.8b model server entrypoint.
#
# First boot: downloads weights from HuggingFace into the /models named
# volume (never baked into the image), verifies byte-exact sizes, and
# patches head.pt's meta.base to the local base directory (mirrors
# ~/workspace/kev-serve/patch_head_base.py; edits only the local serving
# copy). Subsequent boots reuse the volume.
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

# --- weights (first boot only) -------------------------------------------
if [ ! -f "$ADAPTER_DIR/adapter_model.safetensors" ]; then
    echo "entrypoint: downloading kev-0.8b adapter (~45MB)..."
    huggingface-cli download jaredpalmer/kev-0.8b \
        --include "adapter_config.json" \
        --include "adapter_model.safetensors" \
        --include "head.pt" \
        --local-dir "$ADAPTER_DIR" \
        ${HF_TOKEN:+--token "$HF_TOKEN"}
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

# --- byte-exact size verification (sizes from the HF blob listing) -------
check_size() { # check_size <path> <bytes>
    actual="$(wc -c < "$1" | tr -d ' ')"
    if [ "$actual" != "$2" ]; then
        echo "entrypoint: FATAL: $1 is $actual bytes, want $2" >&2
        exit 1
    fi
}
check_size "$ADAPTER_DIR/adapter_model.safetensors" 43338624
check_size "$BASE_DIR/model.safetensors" 1746942600
check_size "$ADAPTER_DIR/head.pt" 2103999
echo "entrypoint: weight sizes verified"

# --- head.pt: point meta.base at the local base dir ----------------------
# Every loader call (AutoConfig/AutoTokenizer/AutoModelForCausalLM)
# accepts a local directory, so the server never touches the network
# for weights after the first download.
python3 - "$ADAPTER_DIR/head.pt" "$BASE_DIR" <<'EOF'
import sys
import torch

ckpt_path, base_dir = sys.argv[1], sys.argv[2]
meta = torch.load(ckpt_path, map_location="cpu", weights_only=False)
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
