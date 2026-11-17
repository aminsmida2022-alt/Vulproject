# Vulnerability Management: Fix What Matters, and Prove It

Automated vulnerability management system that identifies, prioritizes, tracks and verifies vulnerabilities.

## Stack

| Component | Technology | Port |
|---|---|---|
| Dashboard | Laravel 12 + Inertia (React) | 8000 |
| SOAR automation | n8n (Docker) | 5678 |
| Ticket management | Gitea + PostgreSQL (Docker) | 3001 |
| Vulnerability scanner | Trivy (Docker, offline DB) | - |
| Enrichment | FIRST EPSS API + CISA KEV | online |

## Pipeline

One n8n workflow, **Vulnerability Pipeline (A to Z)** (`n8n/workflows/vuln-pipeline.json`),
runs the whole cycle from scan to ticket (daily 03:00, or `POST /webhook/scan-request`):

1. **Scan** - start the Trivy scan of every asset in `data/assets/inventory.json`, poll until done.
2. **Dedupe** - one finding per CVE + asset.
3. **Enrich** - EPSS (FIRST API), CISA KEV, asset importance, approved risk exceptions.
4. **Prioritize** - compute P, publish the findings to the dashboard.
5. **Ticket** - for P1/P2: create a Gitea ticket (labels + SLA due date), reopen a closed ticket as
   `regression` if the CVE is back, skip if already open or `risk-accepted`.

Then:

- **SLA** - n8n *SLA Reminder and Escalation* reminds and escalates overdue tickets.
- **Verify** - n8n *Remediation Verification* rescans; closes the ticket only if the CVE is gone, with evidence.
- **Evaluate** - `scripts/evaluate.py` compares contextual priority with CVSS-only.

`scanner/scan_all.sh` + `scripts/enrich.py` remain as the local fallback used by the dashboard when n8n is down.

## Documentation

- [Installation & usage](documentation/installation.md)
- [Architecture diagrams](documentation/architecture.md)
- [Test report (6 scenarios)](documentation/testing.md)
- [Evaluation vs CVSS-only](documentation/evaluation.md)

## Quick start

```bash
docker compose up -d                       # n8n + Gitea
cd dashboard && composer setup && composer dev   # http://localhost:8000
```

Full setup (Gitea token, labels, n8n import): see the installation guide.

## Priority formula

```
P = 0.25*C + 0.30*E + 0.25*K + 0.20*A
```

- **C** = normalized CVSS (0–100)
- **E** = EPSS probability × 100
- **K** = 100 if in CISA KEV catalogue, else 0
- **A** = asset importance (0–100)

## Security note

Vulnerable test containers run in an **isolated Docker network** and are never exposed to the public Internet.
