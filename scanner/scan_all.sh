#!/usr/bin/env bash
# Manual Trivy scan of all lab assets -> scanner/reports/<asset_id>.json
# Usage: ./scan_all.sh [image_name asset_id]
# Without arguments, scans the full inventory from data/assets/inventory.json
set -euo pipefail
cd "$(dirname "$0")/.."

REPORT_DIR="scanner/reports"
mkdir -p "$REPORT_DIR"

CACHE_DIR=".trivy-cache"
mkdir -p "$CACHE_DIR"

# Offline mode: use the locally extracted DB if present (skip download)
SKIP_FLAGS=""
if [ -f "$CACHE_DIR/db/trivy.db" ]; then
  SKIP_FLAGS="--skip-db-update"
  echo "[*] Using local Trivy DB in $CACHE_DIR/db (skip download)"
fi

scan() {
  local image="$1" id="$2"
  echo "[*] Scanning $image -> $REPORT_DIR/${id}.json"
  docker run --rm \
    -v "$(pwd)/$REPORT_DIR:/reports" \
    -v "$(pwd)/$CACHE_DIR:/root/.cache/trivy" \
    aquasec/trivy:latest image \
    --format json \
    --output "/reports/${id}.json" \
    --db-repository ghcr.io/aquasecurity/trivy-db \
    $SKIP_FLAGS \
    --quiet \
    "$image"
}

if [ $# -eq 2 ]; then
  scan "$1" "$2"
  exit 0
fi

jq -c '.[]' data/assets/inventory.json | while read -r asset; do
  id=$(echo "$asset" | jq -r '.asset_id')
  image=$(echo "$asset" | jq -r '.image')
  scan "$image" "$id"
done

echo "[+] All reports saved in $REPORT_DIR/"
