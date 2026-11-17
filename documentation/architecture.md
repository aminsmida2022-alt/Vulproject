# Architecture

## 1. Components

n8n is the SOAR orchestrator and runs the project **from A to Z**:
scan -> aggregation/dedupe -> EPSS/KEV/asset enrichment -> priority -> ticket.
Laravel exposes a token-protected **agent API** (`X-Agent-Token` header) that n8n
calls to start/observe scans, fetch raw reports, inventory, KEV and exceptions,
and to publish the final ranked findings. Everything can still run locally
(`VULNMGMT_ORCHESTRATOR=local`) as a fallback.

```mermaid
flowchart LR
    DASH["Dashboard<br/>Laravel + React (Tableau style)<br/>Start Scan · Verify · Accept risk"]
    AGENT["Agent API<br/>/api/agent/*<br/>token protected"]
    subgraph A["1 · Scan"]
        TRIVY["Trivy<br/>offline vuln DB"]
        INV[("Asset inventory<br/>3 lab images")]
    end
    subgraph B["2 · n8n SOAR pipeline (A to Z)"]
        N8N["n8n workflows<br/>W1 pipeline · W2 SLA · W3 verification"]
    end
    subgraph C["3 · Track"]
        GITEA["Gitea<br/>remediation tickets"]
    end
    EPSS["FIRST EPSS API"] --> N8N
    KEV["CISA KEV catalogue"] --> N8N
    DASH -- "Start Scan · Verify (webhooks)" --> N8N
    N8N -- "start / poll / fetch" --> AGENT
    AGENT --> TRIVY
    AGENT <--> INV
    N8N -- "findings.json (ranked)" --> AGENT
    N8N -- "create tickets (dedupe)" --> GITEA
    N8N -- "SLA reminders + escalation" --> GITEA
    N8N -- "proof scan -> close / reopen" --> GITEA
    DASH --> AGENT
```

### n8n workflows (imported from `n8n/workflows/`)

| Workflow | Triggers | What it does |
|---|---|---|
| **Vulnerability Pipeline (A to Z)** | cron `0 3 * * *` + webhook `POST /webhook/scan-request` | starts Trivy via agent API, polls, dedupes raw findings, fetches EPSS (batched), KEV, inventory and accepted risks, computes `P = 0.25C + 0.30E + 0.25K + 0.20A`, publishes `findings.json` back, opens Gitea tickets for P1/P2 with dedupe |
| **SLA Reminder and Escalation** | cron `0 9 * * *` + webhook `POST /webhook/sla-check` | SLA P1-CRITICAL 7 days, P2-HIGH 30 days (ticket due date): at 75% elapsed -> reminder comment + `sla-warning`; deadline passed -> escalation comment + `sla-breached` + `escalated`. Each stage fires once; `risk-accepted` tickets are ignored |
| **Remediation Verification** | webhook `POST /webhook/verify-request` `{ticket}` + Run manually | proof scan (raw mode), compares fresh reports, **closes the ticket with evidence** + `verified-fixed` if the CVE is gone, keeps/reopens it with evidence + `verification-failed` otherwise; records the result in the dashboard (`POST /api/agent/verifications` -> `tickets/evidence/`, `tickets/verification_log.jsonl`) |

## 2. End-to-end flow (scan -> ticket -> fix -> proof)

```mermaid
sequenceDiagram
    autonumber
    actor Analyst
    participant D as Dashboard
    participant N as n8n (W1 pipeline)
    participant T as Trivy
    participant G as Gitea

    Analyst->>D: Start Scan (or 03:00 schedule)
    D->>N: POST /webhook/scan-request
    N->>T: agent API scan/start
    loop until Trivy exits
        N->>T: agent API scan/status
    end
    N->>T: agent API reports/raw
    N->>N: dedupe + EPSS + KEV + assets + exceptions
    N->>N: P = 0.25C + 0.30E + 0.25K + 0.20A
    N-->>D: agent API findings (findings.json, cycle closed)
    N->>G: search open issue (key = CVE + asset)
    N->>G: create P1/P2 tickets (priority table, acceptance criteria)
    Note over N,G: daily W2: reminder at 75% of the SLA (P1 7 d / P2 30 d), escalation when overdue
    Analyst->>Analyst: patch the asset (upgrade image / package)
    Analyst->>D: Verify ticket
    D->>N: POST /webhook/verify-request {ticket}  (W3)
    N->>T: proof scan (raw mode) + poll
    alt CVE gone from fresh reports
        N->>G: evidence comment + close + verified-fixed
    else CVE still present
        N->>G: evidence comment + verification-failed (stays open)
    end
```


## 3. Ticket lifecycle

```mermaid
stateDiagram-v2
    [*] --> Open: n8n creates ticket (P >= 60)
    Open --> Open: 75% of SLA elapsed -> sla-warning
    Open --> Escalated: deadline passed -> sla-breached + escalated
    Open --> Closed: verification passed -> verified-fixed
    Open --> Open: verification failed -> verification-failed
    Open --> Accepted: risk-accepted label / approved exception
    Closed --> Open: next scan finds CVE again -> regression
    Escalated --> Closed: verification passed
    Accepted --> [*]
    Closed --> [*]
```

## 4. Priority model

```mermaid
flowchart LR
    C["CVSS v3<br/>x10 -> 0-100"] -- "x 0.25" --> P(("P"))
    E["EPSS<br/>x100 -> 0-100"] -- "x 0.30" --> P
    K["CISA KEV<br/>0 or 100"] -- "x 0.25" --> P
    A["Asset importance<br/>0-100"] -- "x 0.20" --> P
    P --> L1["P1 >= 80 · SLA 7 d"]
    P --> L2["P2 >= 60 · SLA 30 d"]
    P --> L3["P3-P5 · no ticket"]
```
