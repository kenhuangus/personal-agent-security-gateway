#!/usr/bin/env bash
# Fetch (when missing) and checksum-verify the pinned OPA binary (GH #30).
#
# The binary is NOT vendored in git: build/CI downloads it from the
# official OPA release with SHA-256 pinning. The recorded SHA256SUMS was
# verified byte-identical against the official v1.8.0 opa_linux_amd64
# release (2026-10-13), so the pin is proven against upstream, not just
# self-consistent.
#
# Single source of truth for the version: third_party/opa/OPA_VERSION
# (also consumed by src/gateway/opa_client.py; docker-compose.yml reads
# it via ${OPA_VERSION} — export OPA_VERSION=$(cat third_party/opa/OPA_VERSION)
# before compose build/up, or rely on the :-1.8.0 default).
#
# Fails closed: any checksum mismatch aborts the build.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OPA_DIR="$ROOT/third_party/opa"
BIN="$OPA_DIR/opa"
VERSION="$(tr -d '[:space:]' < "$OPA_DIR/OPA_VERSION")"
URL="https://openpolicyagent.org/downloads/v${VERSION}/opa_linux_amd64"

if [ ! -f "$BIN" ]; then
  echo "verify_opa: $BIN missing — downloading OPA v${VERSION} from ${URL}" >&2
  curl -fsSL -o "$BIN" "$URL"
  chmod +x "$BIN"
fi
cd "$OPA_DIR"
sha256sum -c SHA256SUMS
echo "verify_opa: OPA v${VERSION} checksum OK"
