#!/usr/bin/env bash
# Create the workflow labels in the Gitea remediation repo (idempotent).
# Usage: GITEA_TOKEN=xxxx ./scripts/setup_gitea_labels.sh
set -euo pipefail

: "${GITEA_TOKEN:?set GITEA_TOKEN (Gitea API token)}"
GITEA_URL="${GITEA_URL:-http://localhost:3001}"
REPO="${GITEA_REPO:-vulnadmin/remediation-tickets}"
API="$GITEA_URL/api/v1/repos/$REPO/labels"

# name|color|description
LABELS=(
  "P1-CRITICAL|b60205|Contextual priority >= 80 - SLA 7 days"
  "P2-HIGH|d93f0b|Contextual priority 60-79 - SLA 30 days"
  "kev|5319e7|Listed in CISA Known Exploited Vulnerabilities"
  "sla-warning|fbca04|75% of the SLA elapsed"
  "sla-breached|e11d21|SLA deadline passed"
  "escalated|000000|Escalated to the security manager"
  "risk-accepted|0e8a16|Approved risk-acceptance exception (no SLA, no re-ticketing)"
  "verified-fixed|0e8a16|Closed after a rescan proved the finding is gone"
  "verification-failed|e11d21|Rescan still detects the finding"
  "regression|b60205|Finding reappeared after being verified fixed"
)

existing=$(curl -sf -H "Authorization: token $GITEA_TOKEN" "$API?limit=100" | jq -r '.[].name')

for entry in "${LABELS[@]}"; do
  IFS='|' read -r name color desc <<<"$entry"
  if grep -qxF "$name" <<<"$existing"; then
    echo "[=] $name"
    continue
  fi
  curl -sf -X POST -H "Authorization: token $GITEA_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$(jq -n --arg n "$name" --arg c "#$color" --arg d "$desc" \
          '{name:$n,color:$c,description:$d}')" \
    "$API" >/dev/null
  echo "[+] $name"
done
