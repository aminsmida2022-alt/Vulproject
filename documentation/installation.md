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

5. Import and publish the n8n workflows:

   ```bash
   python3 n8n/build_workflows.py      # regenerates n8n/workflows/*.json
   docker exec vulnmgmt-n8n n8n import:workflow --separate --input=/home/node/import-workflows
   docker exec vulnmgmt-n8n n8n publish:workflow --id=r4BdUkFrYaCkz8FQ
   docker exec vulnmgmt-n8n n8n publish:workflow --id=vmSlaEscalation1
   docker restart vulnmgmt-n8n
   ```

| Workflow | Trigger | Job |
|---|---|---|
| Findings to Tickets | `POST /webhook/vuln-findings` (after every scan) | keep P1/P2, dedupe, create tickets with labels + SLA due date, reopen regressions, skip risk-accepted |
| SLA reminders & escalation | daily 08:00 + `POST /webhook/sla-check` | reminder at 75% of the SLA, escalation when overdue |

SLA: P1-CRITICAL 7 days, P2-HIGH 30 days.

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

**Dashboard**: *Start Scan* runs scan -> enrichment -> n8n. Tickets appear in the
*Remediation tickets* panel. After a fix, click *Verify* on a ticket (or *Verify all*).

**Terminal:**

```bash
scanner/scan_all.sh                              # all assets from the inventory
scanner/scan_all.sh nginx:1.28.0 web-server      # one asset
python3 scripts/enrich.py                        # dedupe + EPSS + KEV + score
curl -X POST -H 'Content-Type: application/json' \
  --data-binary @data/vulnerabilities/findings.json \
  http://localhost:5678/webhook/vuln-findings    # tickets
GITEA_TOKEN=<token> python3 scripts/verify.py --ticket 9     # verify one ticket
GITEA_TOKEN=<token> python3 scripts/verify.py --all          # verify all open tickets
python3 scripts/evaluate.py                      # CVSS-only vs contextual report
```

### Remediation verification rules

| Rescan result | Ticket action | Label |
|---|---|---|
| CVE gone | evidence comment, **closed** | `verified-fixed` |
| CVE still present | evidence comment, stays open | `verification-failed` |
| CVE back after being closed | reopened by n8n on next scan | `regression` |

Evidence: `tickets/evidence/<ticket>-<timestamp>.json` (image ID, scan time,
Trivy DB version, report SHA-256, matching packages). Audit trail:
`tickets/verification_log.jsonl`.

### Risk acceptance (exception)

Add the `risk-accepted` label to the ticket with a comment giving the
justification, approver and review date. The ticket is then ignored by the
SLA workflow and never re-created by the triage workflow.

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
