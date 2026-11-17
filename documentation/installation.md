# Installation & Usage Guide

## 1. Prerequisites

Tested on Ubuntu 24.04. Required:

```bash
docker --version        # >= 20
docker compose version  # >= v2
python3 --version       # >= 3.10 (scripts use the standard library only)
php --version           # >= 8.3 + composer (dashboard)
node --version          # >= 20 (dashboard front-end build)
sudo apt install -y jq curl
```

## 2. Start the stack

```bash
cd vulnerability-management
docker compose up -d
```

| Service | URL | Notes |
|---|---|---|
| Dashboard (Laravel + Inertia/React) | http://localhost:8000 | Started separately (section 4) |
| n8n (SOAR) | http://localhost:5678 | Create your account on first visit |
| Gitea (tickets) | http://localhost:3001 | Create admin `vulnadmin` on first visit |

Port note: Gitea uses host port **3001** because 3000 is reserved for
another application. Container-side it is still 3000 (n8n calls `http://gitea:3000`).

## 3. Gitea + n8n setup (once)

1. In Gitea, log in as `vulnadmin`, create the repository `remediation-tickets`.
2. *Settings -> Applications* -> generate an API token (scopes: issue + repository read/write).
3. Put the token in `docker-compose.yml` (`N8N_GITEA_TOKEN`) and in `dashboard/.env`
   (`VULNMGMT_GITEA_TOKEN`), then `docker compose up -d n8n`.
4. Create the workflow labels:

   ```bash
   GITEA_TOKEN=<token> scripts/setup_gitea_labels.sh
   ```

5. Import and activate the n8n workflows (the JSON files in `n8n/workflows/`
   are the source of truth; import creates a new id each time, so purge the
   old rows first if you re-import):

   ```bash
   docker exec vulnmgmt-n8n n8n import:workflow --input=/home/node/import-workflows/vuln-pipeline.json
   docker exec vulnmgmt-n8n n8n import:workflow --input=/home/node/import-workflows/sla-reminders.json
   docker exec vulnmgmt-n8n n8n import:workflow --input=/home/node/import-workflows/remediation-verification.json
   # then in the n8n UI: activate each workflow (or n8n update:workflow --id=<id> --active=true)
   ```

| Workflow | Trigger | Job |
|---|---|---|
| **Vulnerability Pipeline (A to Z)** | daily 03:00 + `POST /webhook/scan-request` | starts the Trivy scan through the agent API, polls, dedupes, enriches (EPSS + KEV + assets + accepted risks), computes the priority, publishes `findings.json`, creates P1/P2 Gitea tickets with dedupe |
| **SLA Reminder and Escalation** | daily 09:00 + `POST /webhook/sla-check` | P1-CRITICAL due in 48 h, P2-HIGH in 7 days: first breach -> `sla-reminder` label + comment, second pass -> `sla-escalated` + escalation comment |
| **Remediation Verification** | `POST /webhook/verify-request` `{ticket}` | proof scan (raw mode), closes the ticket with evidence if the CVE is gone, reopens it with evidence otherwise |

## 3b. Agent API (Laravel <-> n8n)

The n8n workflows drive the scan and data layer through a token-protected API
(header `X-Agent-Token`, configured as `VULNMGMT_AGENT_TOKEN` in `dashboard/.env`):

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/agent/scan/start` | POST `{mode: pipeline\|raw}` | start a detached Trivy scan |
| `/api/agent/scan/status` | GET | live state (`running` / `enriching` / `done` / `failed`) |
| `/api/agent/reports/raw` | GET | un-enriched findings from all Trivy reports |
| `/api/agent/assets` | GET | asset inventory |
| `/api/agent/kev` | GET | CISA KEV CVE set (cached, weekly refresh) |
| `/api/agent/exceptions` | GET / POST | accepted-risk exceptions (read / add) |
| `/api/agent/findings` | POST | n8n publishes the final ranked dataset (closes the cycle) |
| `/api/agent/open-tickets` | GET | current open Gitea tickets |

Set `VULNMGMT_ORCHESTRATOR=n8n` (default) in `dashboard/.env`. The dashboard
then hands *Start Scan* and *Verify* over to the n8n webhooks; if n8n is
unreachable it falls back to the local scripts automatically.


## 4. Dashboard

```bash
cd dashboard
composer setup          # install, .env, key, migrate, npm build
composer dev            # http://localhost:8000
php artisan schedule:work   # optional: daily scan at 02:00 (VULNMGMT_SCAN_AT)
```

## 5. Trivy database (offline)

The scanner uses a local DB in `.trivy-cache/` (no download at scan time):

```bash
docker pull ghcr.io/aquasecurity/trivy-db:2
scanner/extract_db.sh                 # -> .trivy-cache/db/trivy.db
```

The Java DB (`.trivy-cache/java-db/`) is downloaded once by a normal Trivy run;
after that `scan_all.sh` passes `--skip-db-update --skip-java-db-update --offline-scan`.

## 6. Daily use

**Dashboard**: *Start Scan* hands the whole cycle to the n8n pipeline
(scan -> enrich -> tickets). The status banner shows the Trivy phase, then
"n8n pipeline: enrichment + prioritization + ticketing" until the ranked
findings are published. Tickets appear in the *Remediation tickets* panel;
after a fix click *Verify* on a ticket (or *Verify all*). In a finding's
detail panel, *Accept risk* records a dated, approved exception — the CVE is
then excluded from future pipeline runs.

**n8n** (http://localhost:5678): watch the three workflows' executions; every
step of the A-to-Z run is inspectable there.

**Terminal (local fallback, works without n8n):**

```bash
scanner/scan_all.sh                              # all assets from the inventory
scanner/scan_all.sh nginx:1.28.0 web-server      # one asset
python3 scripts/enrich.py                        # dedupe + EPSS + KEV + score
curl -X POST -H 'Content-Type: application/json' \
  --data-binary @data/vulnerabilities/findings.json \
  http://localhost:5678/webhook/vuln-findings    # tickets (legacy workflow)
curl -X POST http://localhost:5678/webhook/scan-request       # n8n pipeline
curl -X POST http://localhost:5678/webhook/sla-check          # SLA pass now
curl -X POST -H 'Content-Type: application/json' \
  -d '{"ticket":9}' http://localhost:5678/webhook/verify-request  # proof scan
GITEA_TOKEN=<token> python3 scripts/verify.py --ticket 9     # local verification
GITEA_TOKEN=<token> python3 scripts/verify.py --all          # verify all open tickets
python3 scripts/evaluate.py                      # CVSS-only vs contextual report
```

### Remediation verification rules (n8n workflow + local fallback)

| Rescan result | Ticket action | Evidence |
|---|---|---|
| CVE gone | evidence comment, **closed** | "NO LONGER present … closed with scan evidence" |
| CVE still present | evidence comment, **reopened** | "STILL PRESENT … did not hold" |
| CVE back after being closed | verification workflow reopens with evidence | proof scan comment |

Evidence: `tickets/evidence/<ticket>-<timestamp>.json` (image ID, scan time,
Trivy DB version, report SHA-256, matching packages). Audit trail:
`tickets/verification_log.jsonl` (local mode).

### Risk acceptance (exception)

Either click *Accept risk* on a finding in the dashboard, or:

```bash
curl -X POST http://localhost:8000/api/agent/exceptions \
  -H 'X-Agent-Token: <VULNMGMT_AGENT_TOKEN>' -H 'Content-Type: application/json' \
  -d '{"cve":"CVE-2023-4863","until":"2027-01-31","approver":"CISO","reason":"compensating controls"}'
```

The exception is dated and approved; the n8n pipeline excludes accepted CVEs
before scoring, so no ticket is created for them until the exception expires.

## 7. Priority model

```
P = 0.25*C + 0.30*E + 0.25*K + 0.20*A
```

| Term | Meaning | Range |
|---|---|---|
| C | CVSS v3 base score / 10 x 100 | 0-100 |
| E | EPSS exploitation probability x 100 | 0-100 |
| K | 100 if CVE is in the CISA KEV catalogue | 0 or 100 |
| A | Asset importance from `data/assets/inventory.json` | 0-100 |

Labels: P1-CRITICAL >= 80 · P2-HIGH >= 60 · P3-MEDIUM >= 40 ·
P4-LOW >= 20 · P5-INFORMATIONAL < 20. Tickets are created for P1 and P2.

## 8. Structure

```text
scanner/scan_all.sh          batch Trivy scan of the asset inventory (offline DB)
scanner/extract_db.sh        extract the Trivy DB from the OCI image
scripts/enrich.py            dedupe + EPSS + KEV + priority score
scripts/verify.py            Phase 8 rescan + close/keep-open with evidence
scripts/evaluate.py          Phase 9 CVSS-only vs contextual evaluation
scripts/setup_gitea_labels.sh  Gitea workflow labels
n8n/build_workflows.py       generates n8n/workflows/*.json
dashboard/                   Laravel 12 + Inertia (React) dashboard
data/assets/inventory.json   assets + importance
data/vulnerabilities/        findings.json, kev_cache.json, evaluation.json
tickets/                     verification evidence + audit log
documentation/               this guide, architecture, test report, evaluation
streamlit/                   legacy prototype dashboard (replaced by dashboard/)
```

## 9. Security

Vulnerable lab images are only scanned as images (no containers run);
they are never exposed beyond the local machine. The Gitea token is read
from environment variables by the scripts and by n8n (`$env.N8N_GITEA_TOKEN`).
