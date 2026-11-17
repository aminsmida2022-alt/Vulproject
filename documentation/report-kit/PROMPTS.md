# Report & presentation kit — "Vulnerability Management: Fix What Matters, and Prove It"

Everything needed to produce the **final report** and the **defense presentation**.
All numbers below are real results measured on the lab on 2026-11-16.
Do not change the numbers or make up new ones.

> Fill in before you start: `[STUDENT NAME]`, `[SUPERVISOR]`, `[SCHOOL / COMPANY]`, `[DATE]`, `[LANGUAGE: English / French]`.

---

## 0. What's in this folder

| Folder | File | What it shows | Use it in |
|---|---|---|---|
| `diagrams/` | `d1-architecture` | Components: dashboard, n8n (3 workflows), Laravel agent API, Trivy, Gitea, EPSS/KEV | Report ch. 3 · Slide 5 |
| | `d2-end-to-end-sequence` | Sequence from "Start Scan" to the proven fix | Report ch. 3 · Slide 6 |
| | `d3-ticket-lifecycle` | Ticket states: open, escalated, closed, accepted, regression | Report ch. 4 · Slide 9 |
| | `d4-priority-model` | P = 0.25·CVSS + 0.30·EPSS + 0.25·KEV + 0.20·Asset → P1/P2/P3–P5 | Report ch. 4 · Slide 7 |
| | `d5-n8n-pipeline-workflow` | n8n workflow 1 "Vulnerability Pipeline (A to Z)", all 27 nodes: scan → dedupe → EPSS/KEV/assets → priority → tickets | Report ch. 4 · Slide 8 |
| | `d7-n8n-sla-workflow` | n8n workflow 2 "SLA Reminder and Escalation" (7 nodes) | Report ch. 4 · Slide 9 |
| | `d8-n8n-verification-workflow` | n8n workflow 3 "Remediation Verification" (20 nodes) | Report ch. 4 · Slide 10 |
| | `d6-verification-logic` | Rescan → close with evidence or keep open | Report ch. 4 · Slide 10 |
| `charts/` | `e1-workload` | 413 findings to fix (CVSS-only) vs 15 (contextual) | Report ch. 5 · Slide 12 |
| | `e2-equal-budget` | Same budget of 15 fixes: KEV caught 1/4 vs 4/4 | Report ch. 5 · Slide 13 |
| | `e3-priority-distribution` | 917 findings by priority; only 15 become tickets | Report ch. 5 · Slide 11 |
| `screenshots/` | `01-dashboard-full` | Whole dashboard (tall image) | Report appendix |
| | `02-dashboard-overview` | Dashboard top: last scan, KPIs, 3 charts | Report ch. 4 · Slide 11 |
| | `03-cvss-vs-epss` | Scatter: high CVSS ≠ high exploit probability | Report ch. 2 & 5 · Slide 3 |
| | `05-finding-drilldown` | Click a finding → score breakdown (99.5 = 24.5 + 30 + 25 + 20) | Report ch. 4 · Slide 7 |
| | `06-findings-kev-filter` | The 4 CISA KEV findings, filtered | Report ch. 5 |
| | `07-remediation-tickets` | Ticket table: labels, SLA dates, Verify buttons | Report ch. 4 · Slide 9 |
| | `08-verification-evidence` | Verification history (FIXED / STILL PRESENT) | Report ch. 4 · Slide 10 |
| | `09-dashboard-dark` | Dark-mode version (optional, for a cover) | Optional |
| `screenshots/` (to capture, see §4) | `10`–`15` | n8n canvas + executions, Gitea tickets + evidence comment | Slides 8–10 |

Diagrams come in 3 formats: `.png` (ready to use), `.svg` (sharp at any size), and `.mmd` (Mermaid source, edit it at https://mermaid.live to restyle).

---

## 1. Project facts (give these to any writer or AI tool)

**Problem.** Scanners report hundreds of CVEs per asset. Teams sort them by CVSS severity, but CVSS measures how *bad* a flaw could be, not how *likely* it is to be exploited, and it ignores the asset. The result is endless work and missed real threats. Tickets are also often closed without proof that the fix worked.

**Goal.** An automated pipeline that (1) finds vulnerabilities, (2) ranks them by real risk, (3) opens and follows remediation tickets automatically, and (4) closes a ticket only when a new scan proves the vulnerability is gone.

**Stack (all open source, runs locally with Docker on Ubuntu 24.04):**
- Trivy: container image scanner, offline vulnerability DB
- Python scripts: enrichment, scoring, verification, evaluation
- FIRST EPSS API: probability of exploitation in the next 30 days
- CISA KEV catalogue: CVEs known to be exploited in the wild
- n8n: SOAR orchestrator, runs the whole pipeline (3 workflows)
- Laravel agent API (`/api/agent/*`, token-protected): lets n8n start scans and read/write data
- Gitea + PostgreSQL: ticket management
- Laravel 12 + Inertia/React: dashboard

**Lab (3 deliberately vulnerable assets):**

| Asset | Image | Importance |
|---|---|---|
| Web Server | nginx:1.18.0 | 80 (exposed) |
| Database Server | postgres:11.0 | 100 (critical) |
| Test Server | python:3.7-slim | 20 (low) |

**Priority formula:** `P = 0.25·C + 0.30·E + 0.25·K + 0.20·A`
C = CVSS ×10 · E = EPSS ×100 · K = 100 if in KEV · A = asset importance (all on 0–100).
P1 ≥ 80 (SLA 7 days) · P2 ≥ 60 (SLA 30 days) · P3–P5: no ticket, dashboard only.

**Automation:**
- **Workflow 1, Vulnerability Pipeline (A to Z)** (daily 03:00 or *Start Scan* in the dashboard): n8n starts the Trivy scan through the agent API, waits for it, removes duplicates, fetches EPSS, KEV, asset importance and accepted risks, computes P, sends the ranked findings back to the dashboard, then keeps P1/P2, removes duplicates (key = CVE + asset), creates Gitea tickets with priority/KEV labels and an SLA due date, reopens a closed ticket if the CVE comes back (`regression`), and skips tickets marked `risk-accepted`.
- **Workflow 2, SLA Reminder and Escalation** (daily 09:00): reminder at 75% of the SLA (`sla-warning`), escalation when overdue (`sla-breached` + `escalated`); `risk-accepted` tickets are ignored.
- **Workflow 3, Remediation Verification** (*Verify* button in the dashboard): the analyst clicks *Verify* → the asset is rescanned → CVE gone = ticket closed with an evidence comment (image ID, scan time, DB version, report SHA-256) and the `verified-fixed` label; CVE present = ticket stays open with `verification-failed`.
- A full scan runs automatically every day at 02:00.

**Key results:**

| Metric | Value |
|---|---|
| Scan of 3 images | 2 min 50 s |
| Unique findings | 917 (P1: 3, P2: 12, P3: 157, P4: 549, P5: 196) |
| Findings in CISA KEV | 4 |
| Tickets created automatically | 15 (3 P1 + 12 P2); 0 duplicates on re-run |
| Workload: CVSS-only (CVSS ≥ 7) vs contextual (P ≥ 60) | **413 vs 15 (−96.4%)** |
| KEV efficiency (share of fixes that matter) | 1.0% vs **26.7%** |
| Same budget of 15 fixes: KEV CVEs caught | 1/4 vs **4/4** |
| Same budget: EPSS ≥ 0.10 findings caught | 3 vs **15** |
| Spearman correlation CVSS vs P | 0.66 |
| Verification after patching nginx 1.18.0 → 1.28.0 | 6/6 tickets closed with evidence |
| Rollback to 1.18.0 | 6/6 tickets reopened automatically (regression) |

**Test scenarios (all PASS):** S1 scan + prioritization · S2 ticket creation + dedupe · S3 fix verified → closed · S4 fix missing → stays open · S5 regression → reopened · S6 SLA escalation + risk acceptance.

**Bug found during testing (good to mention):** the first n8n version created 0 tickets when more than one finding qualified (`ExpressionError: Multiple matches found`). The dedupe was moved into a single Code node, then retested with real data.

**Honest limits (must appear in the report):**
- KEV is both a score input and the ground truth, which favours the contextual method on KEV metrics. The EPSS view and the workload figure don't have this bias.
- Small lab (3 images): the results show a trend, not production statistics.
- EPSS changes every day, so scores drift over time.
- The Gitea API token is hardcoded in the lab config. In production it would go in a secrets manager.

Source documents in the repo: `documentation/testing.md`, `documentation/evaluation.md`, `documentation/architecture.md`, `documentation/installation.md`.

---

## 2. Prompt — final report

Copy-paste into the writing tool (Claude, ChatGPT…) together with §1 and the source documents:

```text
You are writing the final report of an engineering project titled
"Vulnerability Management: Fix What Matters, and Prove It".
Language: [LANGUAGE]. Tone: academic but clear, third person, no marketing words.
Length: 35–45 pages excluding appendices.
Author: [STUDENT NAME]. Supervisor: [SUPERVISOR]. Organization: [SCHOOL / COMPANY]. Date: [DATE].

Use ONLY the facts and numbers in the "Project facts" section and the attached
documents (testing.md, evaluation.md, architecture.md, installation.md).
Never invent numbers, tools, or results. If something is missing, write [TO COMPLETE].

Structure:
0. Abstract (≈200 words) + keywords
1. Introduction: context, problem (CVSS-only prioritization, tickets closed without proof),
   objectives, report outline
2. State of the art: CVSS v3, EPSS (FIRST), CISA KEV, risk-based vulnerability management,
   SOAR, related tools (commercial RBVM platforms vs this open-source approach).
   Place figure 03-cvss-vs-epss.png here with the caption:
   "Most high-CVSS findings have a near-zero exploitation probability."
3. Architecture and design: requirements, choice of components, 5-stage pipeline.
   Figures: d1-architecture, d2-end-to-end-sequence.
4. Implementation, one section per phase:
   4.1 Lab and scanning (Trivy, offline DB, 3 assets)
   4.2 Enrichment and priority model (formula, weights, thresholds) - figures d4, 05-finding-drilldown
   4.3 SOAR orchestration in n8n: the 3 workflows (pipeline A to Z, SLA, verification) and the
       Laravel agent API they call - figures d5, d7, d8, n8n screenshots 10-12
   4.4 Ticket management in Gitea (labels, SLA due dates) - figures d3, 07-remediation-tickets, 12
   4.5 Remediation verification with evidence (n8n workflow 3) - figures d6, d8, 08-verification-evidence, 13
   4.6 Dashboard - figure 02-dashboard-overview
5. Tests and evaluation:
   5.1 The 6 scenarios: one table (scenario, steps, expected, observed, result)
   5.2 Contextual vs CVSS-only: method (coverage, efficiency, workload), results with figures
       e1-workload, e2-equal-budget, e3-priority-distribution, discussion
   5.3 Limits (list all four from the facts, including the KEV bias)
6. Conclusion and future work (e.g. more assets, ML-tuned weights, secrets management,
   integration with Jira/GitLab, scanning running hosts not only images)
Appendices: installation guide, n8n workflow summary, full dashboard screenshot (01).

Number all figures and tables, reference each one in the text ("Figure 5 shows…"),
and give each a one-line caption that states what it shows.
```

---

## 3. Prompt — presentation (defense, 15–20 min)

```text
Build a [LANGUAGE] slide deck for a project defense (15–20 minutes, 15 slides)
titled "Vulnerability Management: Fix What Matters, and Prove It".
Style: clean, light background, one idea per slide, max 3 bullets of ≤ 8 words,
large figures, no stock photos, no clip-art. Accent colors: orange #eb6834
(contextual / our method) and blue #2a78d6 (CVSS-only / baseline), red only for KEV.
Add speaker notes (60–90 words) to every slide.
Use ONLY the facts and numbers provided. Do not invent results.

1. Title: project name, [STUDENT NAME], [SUPERVISOR], [DATE]
2. The problem: 917 findings on 3 servers. Which ones first?
3. Why CVSS alone fails: figure 03-cvss-vs-epss.png
4. Objectives: find, prioritize by real risk, automate tickets, prove the fix
5. Architecture: figure d1-architecture
6. End-to-end flow: figure d2-end-to-end-sequence
7. Priority model: formula + figure d4 + 05-finding-drilldown (99.5 = 24.5+30+25+20)
8. n8n runs everything (A to Z): screenshot 10-n8n-pipeline-workflow (or figure d5)
9. Tickets with SLA: screenshot 07-remediation-tickets + figure d3 (+ d7 for the SLA workflow)
10. Proof of remediation: figure d6 + screenshot 13-gitea-evidence-comment
11. Dashboard: screenshot 02-dashboard-overview
12. Result 1: workload 413 → 15 (−96.4%), figure e1-workload
13. Result 2: same 15 fixes, KEV caught 1/4 vs 4/4, figure e2-equal-budget
14. Tests: 6 scenarios, all PASS (one compact table) + the bug found and fixed
15. Limits & future work, then "Questions?"

Optional live demo plan (3 min, put it after slide 11):
Start Scan in the dashboard → watch the n8n *Executions* tab → tickets in Gitea → *Verify* on a ticket → evidence comment in Gitea + evidence panel in the dashboard.
```

---

## 4. Screenshots still to capture by hand (need logins)

Gitea and n8n need a login, so the person who owns the accounts captures these.
Browser window ~1600 px wide, zoom 100%, light theme. Save them in `screenshots/` with these exact names.

To run a workflow from the n8n editor before capturing: click the arrow next to *Execute workflow* and pick **Run manually**.

| File | Where | What to show |
|---|---|---|
| `10-n8n-pipeline-workflow.png` | http://localhost:5678 → *Vulnerability Pipeline (A to Z)* | The whole canvas (press `Shift+1` to fit it on screen) |
| `11-n8n-execution.png` | Same workflow → *Executions* tab → latest successful run | Execution view with green nodes and item counts |
| `12-n8n-verification-workflow.png` | *Remediation Verification* | The canvas with the close / keep-open branches |
| `13-gitea-evidence-comment.png` | Gitea → issue **#14** | The "Verification PASSED" evidence table, then the "Regression detected" comment below it |
| `14-gitea-issue-list.png` | Gitea → remediation-tickets → Issues | List showing the colored labels and due dates |
| `15-gitea-escalation.png` | Gitea → issue **#3** | The "SLA breached - escalated" comment and labels |

Optional live demo recording: use OBS or a screen-to-GIF tool while running the demo plan above.

---

## 5. Prompt — redraw the diagrams in the deck's style (optional)

The PNG/SVG files can be used as they are. To restyle them, give this to the designer
or to a diagram tool (draw.io, Figma, Excalidraw):

```text
Redraw this technical diagram in a flat, minimal style for a slide deck:
white background, rounded rectangles, 1.5 px dark-gray connectors with labels on the arrows,
one accent color (#eb6834) for the core of our method (scoring + n8n + verification),
neutral gray for infrastructure, red (#dc2626) only for "CISA KEV".
Keep every box, label and arrow exactly as in the source; don't add or remove components.
Source (Mermaid): <paste the .mmd file>
```
