#!/usr/bin/env python3
"""
Enrichment + risk priority engine (Phases 4 & 5).

Reads Trivy JSON reports from scanner/reports/, aggregates findings,
removes duplicates, enriches with EPSS + CISA KEV + asset importance,
computes the contextual priority score and writes the normalized
dataset to data/vulnerabilities/findings.json.

Priority formula:  P = 0.25*C + 0.30*E + 0.25*K + 0.20*A
  C = normalized CVSS (0-100)      E = EPSS * 100
  K = 100 if in KEV else 0         A = asset importance (0-100)

Usage: python3 scripts/enrich.py
"""

import json
import urllib.request
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
REPORTS = PROJECT / "scanner" / "reports"
INVENTORY = PROJECT / "data" / "assets" / "inventory.json"
OUTPUT = PROJECT / "data" / "vulnerabilities" / "findings.json"
KEV_CACHE = PROJECT / "data" / "vulnerabilities" / "kev_cache.json"

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")

WEIGHTS = {"cvss": 0.25, "epss": 0.30, "kev": 0.25, "asset": 0.20}


def load_json(path):
    with open(path) as f:
        return json.load(f)


def fetch_json(url, cache=None):
    if cache and cache.exists():
        return load_json(cache)
    with urllib.request.urlopen(url, timeout=60) as r:
        data = json.loads(r.read().decode())
    if cache:
        cache.write_text(json.dumps(data))
    return data


def load_kev_set():
    """Return set of CVE IDs currently listed in the CISA KEV catalogue."""
    data = fetch_json(KEV_URL, cache=KEV_CACHE)
    return {v["cveID"] for v in data.get("vulnerabilities", [])}


def fetch_epss(cves):
    """Batch EPSS lookup (100 CVEs per request max)."""
    scores = {}
    cves = list(cves)
    for i in range(0, len(cves), 100):
        batch = ",".join(cves[i:i + 100])
        url = f"{EPSS_URL}?cve={batch}"
        with urllib.request.urlopen(url, timeout=60) as r:
            data = json.loads(r.read().decode())
        for item in data.get("data", []):
            scores[item["cve"]] = float(item["epss"])
    return scores


def extract_findings(report, asset_id):
    """Extract deduplicated CVE findings from a Trivy JSON report."""
    seen = set()
    findings = []
    for result in report.get("Results", []):
        for vuln in result.get("Vulnerabilities", []) or []:
            cve = vuln.get("VulnerabilityID", "")
            if not cve.startswith("CVE-") or cve in seen:
                continue  # dedupe: same CVE reported for several packages
            seen.add(cve)
            findings.append({
                "cve": cve,
                "asset_id": asset_id,
                "pkg": vuln.get("PkgName"),
                "installed": vuln.get("InstalledVersion"),
                "fixed": vuln.get("FixedVersion"),
                "cvss": (vuln.get("CVSS", {}).get("nvd", {})
                         .get("V3Score")
                         or vuln.get("CVSS", {}).get("redhat", {})
                         .get("V3Score") or 0.0),
                "severity": vuln.get("Severity", "UNKNOWN"),
                "title": vuln.get("Title") or vuln.get("Description", "")[:120],
                "status": vuln.get("Status", "unknown"),
            })
    return findings


def compute_priority(cvss, epss, kev, asset_importance):
    c = min(cvss / 10.0 * 100.0, 100.0)
    e = epss * 100.0
    k = 100.0 if kev else 0.0
    a = float(asset_importance)
    score = (WEIGHTS["cvss"] * c + WEIGHTS["epss"] * e
             + WEIGHTS["kev"] * k + WEIGHTS["asset"] * a)
    return round(score, 2)


def priority_label(score):
    if score >= 80:
        return "P1-CRITICAL"
    if score >= 60:
        return "P2-HIGH"
    if score >= 40:
        return "P3-MEDIUM"
    if score >= 20:
        return "P4-LOW"
    return "P5-INFORMATIONAL"


def main():
    inventory = {a["asset_id"]: a for a in load_json(INVENTORY)}
    findings = []

    for report_file in sorted(REPORTS.glob("*.json")):
        asset_id = report_file.stem
        if asset_id not in inventory:
            continue
        findings.extend(extract_findings(load_json(report_file), asset_id))

    # cross-asset dedupe (keep highest CVSS per cve+pkg+installed)
    unique = {}
    for f in findings:
        key = (f["cve"], f["pkg"], f["installed"])
        if key not in unique or f["cvss"] > unique[key]["cvss"]:
            unique[key] = f

    cves = [f["cve"] for f in unique.values()]
    print(f"[*] {len(findings)} raw findings, "
          f"{len(cves)} unique CVEs -> enriching")

    epss_scores = fetch_epss(cves)
    kev_set = load_kev_set()
    print(f"[*] EPSS scores retrieved: {len(epss_scores)}, "
          f"KEV catalogue loaded: {len(kev_set)} entries")

    for f in unique.values():
        asset = inventory[f["asset_id"]]
        f["epss"] = epss_scores.get(f["cve"], 0.0)
        f["kev"] = f["cve"] in kev_set
        f["asset_name"] = asset["name"]
        f["asset_criticality"] = asset["criticality"]
        f["priority_score"] = compute_priority(
            f["cvss"], f["epss"], f["kev"], asset["importance"])
        f["priority"] = priority_label(f["priority_score"])

    ranked = sorted(unique.values(),
                    key=lambda f: f["priority_score"], reverse=True)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(ranked, indent=2))
    print(f"[+] {len(ranked)} enriched findings -> {OUTPUT.relative_to(PROJECT)}")

    for f in ranked[:10]:
        kev_tag = " [KEV]" if f["kev"] else ""
        print(f"    {f['priority_score']:6.1f} {f['priority']:<15} "
              f"{f['cve']} on {f['asset_name']}{kev_tag}")


if __name__ == "__main__":
    main()
