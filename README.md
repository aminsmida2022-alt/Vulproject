# Vulnerability Management: Fix What Matters, and Prove It

Automated vulnerability management system that identifies, prioritizes, tracks and verifies vulnerabilities.

## Stack

| Component | Technology | Port |
|---|---|---|
| SOAR automation | n8n (Docker) | 5678 |
| Ticket management | Gitea (Docker) | 3000 |
| Vulnerability scanner | Trivy (Docker) | — |
| Dashboard | Streamlit (Python) | 8501 |
| Enrichment | EPSS API + CISA KEV | online |

## Structure

```text
vulnerability-management/
│
├── docker-compose.yml        # n8n, Gitea, lab containers
├── n8n/workflows/            # exported n8n workflows (JSON)
├── scanner/
│   ├── reports/              # Trivy JSON reports
│   └── configurations/       # scan configs / asset inventory
├── dashboard/
│   ├── app.py                # Streamlit dashboard
│   ├── requirements.txt
│   └── components/
├── data/
│   ├── assets/               # asset inventory (importance levels)
│   └── vulnerabilities/      # normalized findings + priority scores
├── tickets/                  # ticket export / state tracking
├── documentation/            # install & usage guides
└── README.md
```

## Quick start

```bash
# 1. Start core services
docker compose up -d

# 2. Dashboard
cd dashboard && pip3 install -r requirements.txt && streamlit run app.py

# 3. A manual scan test
docker run --rm -v $(pwd)/scanner/reports:/reports aquasec/trivy image \
  --format json --output /reports/report.json nginx:latest
```

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
