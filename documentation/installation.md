# Installation & Usage Guide

## 1. Prerequisites

Tested on Ubuntu 24.04. Required:

```bash
docker --version        # >= 20
docker compose version  # >= v2
python3 --version       # >= 3.10
sudo apt install -y python3-pip python3-venv jq
```

## 2. Start the stack

```bash
cd vulnerability-management
docker compose up -d
```

Services:

| Service | URL | Notes |
|---|---|---|
| n8n | http://localhost:5678 | Create your account on first visit |
| Gitea | http://localhost:3001 | Create admin account on first visit |
| Streamlit | http://localhost:8501 | Started separately (below) |

Port note: Gitea uses host port **3001** because 3000 is reserved for
another application. Container-side it is still 3000.

## 3. Dashboard

```bash
cd dashboard
python3 -m venv ../.venv
../.venv/bin/pip install -r requirements.txt
../.venv/bin/streamlit run app.py --server.port 8501
```

## 4. First scan

Two options:

**A. From the dashboard** — click *Start Scan* in the sidebar.

**B. From the terminal:**

```bash
scanner/scan_all.sh                       # all assets from the inventory
scanner/scan_all.sh nginx:1.24-alpine web-server   # one asset
python3 scripts/enrich.py                 # dedupe + enrich + score
```

Reports land in `scanner/reports/<asset_id>.json`; the ranked,
enriched dataset is written to `data/vulnerabilities/findings.json`.

## 5. Priority model

```
P = 0.25*C + 0.30*E + 0.25*K + 0.20*A
```

| Term | Meaning | Range |
|---|---|---|
| C | CVSS v3 base score / 10 × 100 | 0–100 |
| E | EPSS exploitation probability × 100 | 0–100 |
| K | 100 if CVE is in the CISA KEV catalogue | 0 or 100 |
| A | Asset importance from `data/assets/inventory.json` | 0–100 |

Labels: P1-CRITICAL ≥ 80 · P2-HIGH ≥ 60 · P3-MEDIUM ≥ 40 ·
P4-LOW ≥ 20 · P5-INFORMATIONAL < 20

## 6. Structure

```text
scripts/enrich.py        enrichment + priority engine (stdlib only)
scanner/scan_all.sh      batch Trivy scan of the asset inventory
dashboard/app.py         Streamlit dashboard
n8n/workflows/           exported n8n workflow JSON (Phase 6)
data/vulnerabilities/    findings.json + kev_cache.json
```

## 7. Security

Vulnerable lab images are only scanned as images (no containers run);
they are never exposed beyond the local machine.
