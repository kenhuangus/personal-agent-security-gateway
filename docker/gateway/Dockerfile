# Personal Agent Security Gateway — demo image.
#
# One-command demo: `docker compose up --build` (repo root).
#
# The image is demo-neutral: compose supplies GATEWAY_OPA_URL,
# GATEWAY_SEED_DEMO=1 and GATEWAY_DEMO_TOOLS=1. Run standalone, the
# image falls back to the vendored OPA sidecar (GATEWAY_OPA_BIN) with
# no demo seed and no demo tools.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# curl: container healthcheck. sqlite3: inspecting the demo DBs.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl sqlite3 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /usr/sbin/nologin appuser

WORKDIR /app

# Vendored OPA binary, pinned to OPA_VERSION in src/gateway/opa_client.py
# (checksum-verified by scripts/verify_opa.sh). Installed outside the
# Python package so both the sidecar fallback (GATEWAY_OPA_BIN) and the
# save-time `opa check` gate (policy.py opa_check_rules) can find it.
COPY third_party/opa/opa /usr/local/bin/opa
RUN chmod +x /usr/local/bin/opa

COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY scripts/ ./scripts/
RUN pip install --no-cache-dir .

# Container-sensible defaults (overridable): bind all interfaces, SQLite
# files under the /data volume.
ENV GATEWAY_HOST=0.0.0.0 \
    GATEWAY_PORT=8000 \
    GATEWAY_CONFIG_DB=/data/config.db \
    GATEWAY_AUDIT_DB=/data/audit.db \
    GATEWAY_VAULT_DB=/data/vault.db \
    GATEWAY_OPA_BIN=/usr/local/bin/opa

RUN mkdir -p /data && chown appuser:appuser /data /app

COPY docker/gateway/entrypoint.sh /usr/local/bin/gateway-entrypoint.sh
RUN chmod +x /usr/local/bin/gateway-entrypoint.sh

USER appuser
EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/gateway-entrypoint.sh"]
