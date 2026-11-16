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

1. **Scan** - `scanner/scan_all.sh` scans every asset of `data/assets/inventory.json` with Trivy.
2. **Enrich + prioritize** - `scripts/enrich.py` dedupes, adds EPSS + KEV, computes P.
3. **Ticket** - n8n creates Gitea tickets for P1/P2 with SLA due dates (dedupe, regression reopen, risk acceptance).
4. **SLA** - n8n reminds at 75% of the SLA and escalates overdue tickets.
5. **Verify** - `scripts/verify.py` rescans; closes the ticket only if the CVE is gone, with evidence.
6. **Evaluate** - `scripts/evaluate.py` compares contextual priority with CVSS-only.

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
