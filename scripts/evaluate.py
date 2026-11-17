#!/usr/bin/env python3
"""
Evaluation: contextual priority vs CVSS-only (Phase 9).

Compares two remediation policies on the same enriched findings:

  CVSS-only    fix every finding with CVSS >= 7.0 (High + Critical),
               ranked by CVSS
  Contextual   fix every finding with P >= 60 (P1 + P2),
               ranked by P = 0.25C + 0.30E + 0.25K + 0.20A

Ground truth for "really dangerous" = listed in CISA KEV (exploited in the
wild). A secondary proxy uses EPSS >= 0.10.

Metrics (Jacobs et al., EPSS paper):
  coverage   = dangerous findings remediated / all dangerous findings
  efficiency = dangerous findings remediated / all findings remediated
  workload   = number of findings to remediate

Outputs:
  documentation/evaluation.md
  data/vulnerabilities/evaluation.json

Usage: python3 scripts/evaluate.py
"""

import json
from datetime import date
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
FINDINGS = PROJECT / "data" / "vulnerabilities" / "findings.json"
OUT_MD = PROJECT / "documentation" / "evaluation.md"
OUT_JSON = PROJECT / "data" / "vulnerabilities" / "evaluation.json"

CVSS_THRESHOLD = 7.0
P_THRESHOLD = 60.0
EPSS_PROXY = 0.10


def ranks(values):
    """Average ranks (1 = highest), ties share the mean rank."""
    order = sorted(range(len(values)), key=lambda i: -values[i])
    r = [0.0] * len(values)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
            j += 1
        for k in range(i, j + 1):
            r[order[k]] = (i + j) / 2 + 1
        i = j + 1
    return r


def spearman(a, b):
    ra, rb = ranks(a), ranks(b)
    n = len(a)
    ma, mb = sum(ra) / n, sum(rb) / n
    cov = sum((x - ma) * (y - mb) for x, y in zip(ra, rb))
    va = sum((x - ma) ** 2 for x in ra) ** 0.5
    vb = sum((y - mb) ** 2 for y in rb) ** 0.5
    return cov / (va * vb) if va and vb else 0.0


def policy_metrics(selected, findings, is_bad):
    bad_total = sum(1 for f in findings if is_bad(f))
    bad_hit = sum(1 for f in selected if is_bad(f))
    return {
        "workload": len(selected),
        "dangerous_remediated": bad_hit,
        "dangerous_total": bad_total,
        "coverage": bad_hit / bad_total if bad_total else 0.0,
        "efficiency": bad_hit / len(selected) if selected else 0.0,
    }


def pct(x):
    return f"{x * 100:.1f}%"


def main():
    findings = json.loads(FINDINGS.read_text())
    for f in findings:  # n8n writes null when a CVE has no CVSS / EPSS score
        f["cvss"] = f.get("cvss") or 0.0
        f["epss"] = f.get("epss") or 0.0
    if not findings:
        raise SystemExit("FATAL: findings.json is empty - run scan + enrich first")

    kev = lambda f: f["kev"]
    epss_hi = lambda f: f.get("epss", 0) >= EPSS_PROXY

    cvss_set = [f for f in findings if f["cvss"] >= CVSS_THRESHOLD]
    ctx_set = [f for f in findings if f["priority_score"] >= P_THRESHOLD]

    by_cvss = sorted(findings, key=lambda f: (-f["cvss"], f["cve"]))
    by_ctx = sorted(findings, key=lambda f: -f["priority_score"])
    n_top = len(ctx_set)  # same budget for both policies
    top_cvss, top_ctx = by_cvss[:n_top], by_ctx[:n_top]

    res = {
        "date": date.today().isoformat(),
        "findings": len(findings),
        "assets": len({f["asset_id"] for f in findings}),
        "kev_findings": sum(1 for f in findings if kev(f)),
        "epss_proxy_findings": sum(1 for f in findings if epss_hi(f)),
        "thresholds": {"cvss": CVSS_THRESHOLD, "priority": P_THRESHOLD, "epss_proxy": EPSS_PROXY},
        "policy_threshold": {
            "cvss_only": {"kev": policy_metrics(cvss_set, findings, kev),
                          "epss": policy_metrics(cvss_set, findings, epss_hi)},
            "contextual": {"kev": policy_metrics(ctx_set, findings, kev),
                           "epss": policy_metrics(ctx_set, findings, epss_hi)},
        },
        "equal_budget_top_n": n_top,
        "equal_budget": {
            "cvss_only": {"kev": policy_metrics(top_cvss, findings, kev),
                          "epss": policy_metrics(top_cvss, findings, epss_hi)},
            "contextual": {"kev": policy_metrics(top_ctx, findings, kev),
                           "epss": policy_metrics(top_ctx, findings, epss_hi)},
        },
        "spearman_cvss_vs_priority": spearman([f["cvss"] for f in findings],
                                               [f["priority_score"] for f in findings]),
    }
    t_cvss = res["policy_threshold"]["cvss_only"]["kev"]["workload"]
    t_ctx = res["policy_threshold"]["contextual"]["kev"]["workload"]
    res["workload_reduction"] = 1 - t_ctx / t_cvss if t_cvss else 0.0

    # illustrative cases
    demoted = sorted([f for f in findings if f["cvss"] >= 9.0 and f["priority_score"] < P_THRESHOLD],
                     key=lambda f: (f["priority_score"], -f["cvss"]))[:5]
    promoted = [f for f in ctx_set if f["cvss"] < 9.0][:5]
    res["demoted_examples"] = [{k: f[k] for k in ("cve", "asset_name", "cvss", "epss", "kev", "priority_score")} for f in demoted]
    res["promoted_examples"] = [{k: f[k] for k in ("cve", "asset_name", "cvss", "epss", "kev", "priority_score")} for f in promoted]

    OUT_JSON.write_text(json.dumps(res, indent=2))
    OUT_MD.write_text(render_md(res, top_cvss[:10], top_ctx[:10]))
    print(f"[+] {OUT_JSON.relative_to(PROJECT)}")
    print(f"[+] {OUT_MD.relative_to(PROJECT)}")
    pt = res["policy_threshold"]
    print(f"    workload  CVSS>=7: {t_cvss}  vs  P>=60: {t_ctx}  "
          f"(-{pct(res['workload_reduction'])})")
    print(f"    KEV cov.  CVSS>=7: {pct(pt['cvss_only']['kev']['coverage'])}  "
          f"vs  P>=60: {pct(pt['contextual']['kev']['coverage'])}")
    print(f"    KEV eff.  CVSS>=7: {pct(pt['cvss_only']['kev']['efficiency'])}  "
          f"vs  P>=60: {pct(pt['contextual']['kev']['efficiency'])}")


def row(f):
    return (f"| {f['cve']} | {f['asset_name']} | {f['cvss']:.1f} | "
            f"{f.get('epss', 0) * 100:.2f}% | {'yes' if f['kev'] else '-'} | "
            f"{f['priority_score']:.1f} |")


def metrics_table(block):
    lines = ["| Metric | CVSS-only | Contextual |", "|---|---|---|"]
    c, x = block["cvss_only"], block["contextual"]
    lines.append(f"| Findings to remediate (workload) | {c['kev']['workload']} | {x['kev']['workload']} |")
    for proxy, name in (("kev", "KEV"), ("epss", f"EPSS >= {EPSS_PROXY}")):
        lines.append(f"| {name} findings remediated | {c[proxy]['dangerous_remediated']} / {c[proxy]['dangerous_total']} "
                     f"| {x[proxy]['dangerous_remediated']} / {x[proxy]['dangerous_total']} |")
        lines.append(f"| {name} coverage | {pct(c[proxy]['coverage'])} | {pct(x[proxy]['coverage'])} |")
        lines.append(f"| {name} efficiency | {pct(c[proxy]['efficiency'])} | {pct(x[proxy]['efficiency'])} |")
    return "\n".join(lines)


def render_md(r, top_cvss, top_ctx):
    head = "| CVE | Asset | CVSS | EPSS | KEV | P |\n|---|---|---|---|---|---|"
    ex_head = "| CVE | Asset | CVSS | EPSS | KEV | P |\n|---|---|---|---|---|---|"
    return f"""# Evaluation: contextual priority vs CVSS-only

_Generated by `scripts/evaluate.py` on {r['date']} from `data/vulnerabilities/findings.json`._

## Dataset

| Item | Value |
|---|---|
| Assets scanned | {r['assets']} |
| Unique findings | {r['findings']} |
| Findings listed in CISA KEV (ground truth) | {r['kev_findings']} |
| Findings with EPSS >= {EPSS_PROXY} (secondary proxy) | {r['epss_proxy_findings']} |

## Method

Two remediation policies are applied to the same findings:

- **CVSS-only**: remediate every finding with CVSS >= {CVSS_THRESHOLD} (High + Critical).
- **Contextual**: remediate every finding with P >= {P_THRESHOLD} (P1 + P2), where
  `P = 0.25*CVSS + 0.30*EPSS + 0.25*KEV + 0.20*Asset importance`.

A finding counts as *dangerous* when it is in the CISA KEV catalogue (exploited in the wild).
Because KEV is also an input of P, the EPSS >= {EPSS_PROXY} proxy is reported as a second view.

- **Coverage** = dangerous findings remediated / all dangerous findings
- **Efficiency** = dangerous findings remediated / all findings remediated
- **Workload** = number of findings (tickets) to handle

## Result 1: each policy with its own threshold

{metrics_table(r['policy_threshold'])}

**Workload reduction: {pct(r['workload_reduction'])}** fewer findings to remediate with the contextual policy.

## Result 2: same budget ({r['equal_budget_top_n']} fixes)

Both policies may only fix the top {r['equal_budget_top_n']} findings of their own ranking
(ties in CVSS broken by CVE id).

{metrics_table(r['equal_budget'])}

## Rank agreement

Spearman correlation between CVSS and P: **{r['spearman_cvss_vs_priority']:.2f}**.
CVSS explains only part of the contextual ranking; EPSS, KEV and the asset importance move findings up or down.

## Top 10 by CVSS only

{head}
{chr(10).join(row(f) for f in top_cvss)}

## Top 10 by contextual priority

{head}
{chr(10).join(row(f) for f in top_ctx)}

## Demoted: CVSS >= 9.0 but no ticket (P < {P_THRESHOLD})

{ex_head}
{chr(10).join(f"| {e['cve']} | {e['asset_name']} | {e['cvss']:.1f} | {e['epss'] * 100:.2f}% | {'yes' if e['kev'] else '-'} | {e['priority_score']:.1f} |" for e in r['demoted_examples'])}

## Promoted: CVSS < 9.0 but ticketed (P >= {P_THRESHOLD})

{ex_head}
{chr(10).join(f"| {e['cve']} | {e['asset_name']} | {e['cvss']:.1f} | {e['epss'] * 100:.2f}% | {'yes' if e['kev'] else '-'} | {e['priority_score']:.1f} |" for e in r['promoted_examples'])}

## Limits

- KEV is both an input of P and the ground truth, which favours the contextual policy on KEV metrics;
  the EPSS proxy and the workload figure are not affected by this.
- Small lab (3 container images); results show the trend, not production statistics.
- EPSS changes daily; rerun `scripts/enrich.py` then this script to refresh.
"""


if __name__ == "__main__":
    main()
