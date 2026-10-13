#!/usr/bin/env bash
# Gateway container entrypoint: optional demo seed, then the server.
#
# - Generates + persists a demo GATEWAY_HMAC_KEY (0600, first boot only)
#   when none is provided, so the approval flow works out of the box.
#   Production deployments MUST provide the key from the platform secret
#   store instead.
# - Runs scripts/seed_demo.py when GATEWAY_SEED_DEMO=1 (idempotent).
# - Execs the gateway: src/gateway/mcp_server.py::main() via uvicorn.
set -euo pipefail

# Defensive no_proxy sanitizing (M0 sandbox lesson): bracketed IPv6
# entries break httpx URL parsing. mcp_server.py also sanitizes at
# import, but the seed path uses httpx before that import runs.
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

# Demo HMAC key (approval argument hashing needs a gateway-held key).
if [ -z "${GATEWAY_HMAC_KEY:-}" ]; then
    key_file="$(dirname "${GATEWAY_CONFIG_DB:-/data/config.db}")/.hmac_key"
    if [ ! -f "$key_file" ]; then
        python3 -c "import secrets; print(secrets.token_urlsafe(48))" > "$key_file"
        chmod 600 "$key_file"
        echo "entrypoint: generated demo GATEWAY_HMAC_KEY at $key_file (0600)"
    fi
    GATEWAY_HMAC_KEY="$(cat "$key_file")"
    export GATEWAY_HMAC_KEY
fi

# Demo seed (idempotent): agent identity, standing mandates, policy v1.
if [ "${GATEWAY_SEED_DEMO:-0}" = "1" ]; then
    seeded=0
    for attempt in 1 2 3; do
        if python3 /app/scripts/seed_demo.py; then
            seeded=1
            break
        fi
        echo "entrypoint: seed attempt $attempt/3 failed; retrying in 10s" >&2
        sleep 10
    done
    if [ "$seeded" != "1" ]; then
        echo "entrypoint: seed failed 3 times; starting server anyway" >&2
        echo "entrypoint: (fail-closed: policy denies until the seed succeeds)" >&2
    fi
fi

exec python3 -m gateway.mcp_server
