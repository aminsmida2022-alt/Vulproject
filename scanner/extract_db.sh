#!/usr/bin/env bash
# Extract the Trivy vulnerability DB from the ghcr trivy-db image
# (workaround for slow/blocked direct OCI downloads).
set -euo pipefail
cd "$(dirname "$0")/.."

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

echo "[*] Saving trivy-db image to tar..."
docker image save ghcr.io/aquasecurity/trivy-db:2 -o "$WORK/db.tar"

mkdir -p "$WORK/x"
tar -xf "$WORK/db.tar" -C "$WORK/x"

echo "[*] Searching layers for db.tar.gz / metadata.json..."
CACHE=".trivy-cache/db"
mkdir -p "$CACHE"

found=0
for layer in "$WORK/x"/*/layer.tar "$WORK/x"/*/layer*.tar; do
  [ -f "$layer" ] || continue
  if tar -tf "$layer" 2>/dev/null | grep -q '^db.tar.gz$'; then
    echo "[*] Extracting from $(basename "$layer")"
    tar -xf "$layer" -C "$CACHE" db.tar.gz metadata.json
    found=1
    break
  fi
done

if [ "$found" -ne 1 ]; then
  # some builds nest content under a different layout: search whole tar
  tar -xf "$WORK/db.tar" -C "$WORK/x" 2>/dev/null || true
  (cd "$CACHE" && for layer in "$WORK/x"/*/layer.tar; do
     [ -f "$layer" ] && tar -xf "$layer" 2>/dev/null || true
   done)
  found=$( [ -f "$CACHE/db.tar.gz" ] && echo 1 || echo 0 )
fi

[ "$found" -eq 1 ] || { echo "FATAL: db.tar.gz not found"; exit 1; }

echo "[*] Unpacking db.tar.gz -> trivy.db"
tar -xzf "$CACHE/db.tar.gz" -C "$CACHE"
rm -f "$CACHE/db.tar.gz"
ls -lh "$CACHE"
echo "[+] Trivy DB ready in $CACHE — run trivy with --skip-db-update"
