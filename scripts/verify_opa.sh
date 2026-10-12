#!/usr/bin/env bash
# Verify the pinned OPA binary against its recorded checksum.
# Fails closed: any mismatch aborts the build.
set -euo pipefail
BIN="$(dirname "$0")/../third_party/opa/opa"
SUMS="$(dirname "$0")/../third_party/opa/SHA256SUMS"
if [ ! -f "$BIN" ]; then
  echo "missing: $BIN" >&2
  exit 1
fi
cd "$(dirname "$SUMS")"
sha256sum -c SHA256SUMS
