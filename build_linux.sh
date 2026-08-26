#!/usr/bin/env bash
# v5 E23/P.3 — reproducible Linux release build + SHA256 hash output.
# Usage: ./build_linux.sh
# Outputs the release bundle + its SHA256, and writes build_hash.txt so the
# IntegrityHeartbeat can verify the running binary against the published build.
set -euo pipefail

# HERMETIC BUILD: Force deterministic timestamps and paths.
# SOURCE_DATE_EPOCH pins build time to last git commit (or current time if no git).
export SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct 2>/dev/null || date +%s)"
export ZERO_AR_DATE=1
export PYTHONHASHSEED=0
export LC_ALL=C

echo "[+] Building Linux release bundle (hermetic)..."

cd "$(dirname "$0")"

echo "==> flutter build linux --release"
flutter build linux --release

BUNDLE="build/linux/x64/release/bundle/vault_crypto"
if [ ! -f "$BUNDLE" ]; then
  echo "ERROR: bundle not found at $BUNDLE" >&2
  exit 1
fi

HASH=$(sha256sum "$BUNDLE" | awk '{print $1}')
echo "==> SHA256 of release binary: $HASH"

# Write the manifest for runtime verification (IntegrityHeartbeat.verifyBinaryHash).
echo "$HASH" > build_hash.txt
echo "==> Wrote build_hash.txt"

echo "==> Done. Publish build_hash.txt alongside the release for community verification."