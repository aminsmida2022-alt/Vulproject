#!/usr/bin/env python3
"""
Remediation verification (Phase 8).

For each remediation ticket: rescan the affected asset with Trivy, check
whether the CVE is still present, store the evidence and update Gitea:

  CVE gone      -> evidence comment + label `verified-fixed` + close ticket
  CVE present   -> evidence comment + label `verification-failed`, stays open

Regressions (a verified-fixed CVE coming back) are reopened by the n8n
workflow on the next scan.

Evidence: tickets/evidence/<ticket>-<timestamp>.json
Audit log: tickets/verification_log.jsonl

Usage:
  GITEA_TOKEN=xxx python3 scripts/verify.py --ticket 9 [--ticket 14]
  GITEA_TOKEN=xxx python3 scripts/verify.py --all          # all open tickets
  ... --no-rescan   reuse the current reports in scanner/reports/
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
INVENTORY = PROJECT / "data" / "assets" / "inventory.json"
REPORTS = PROJECT / "scanner" / "reports"
TRIVY_META = PROJECT / ".trivy-cache" / "db" / "metadata.json"
EVIDENCE = PROJECT / "tickets" / "evidence"
AUDIT_LOG = PROJECT / "tickets" / "verification_log.jsonl"

GITEA_URL = os.environ.get("GITEA_URL", "http://localhost:3001").rstrip("/")
GITEA_REPO = os.environ.get("GITEA_REPO", "vulnadmin/remediation-tickets")
GITEA_TOKEN = os.environ.get("GITEA_TOKEN", "")

TITLE_RE = re.compile(r"\[(P\d-[A-Z]+)\] Fix (CVE-\d{4}-\d+) on (.+)$")


def gitea(method, path, body=None):
    url = f"{GITEA_URL}/api/v1/repos/{GITEA_REPO}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"token {GITEA_TOKEN}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    })
    with urllib.request.urlopen(req, timeout=30) as r:
        raw = r.read().decode()
    return json.loads(raw) if raw else None


def label_ids():
    return {l["name"]: l["id"] for l in gitea("GET", "/labels?limit=100")}


def open_tickets():
    out, page = [], 1
    while True:
        batch = gitea("GET", f"/issues?state=open&type=issues&limit=50&page={page}")
        out.extend(batch)
        if len(batch) < 50:
            return out
        page += 1


def rescan(asset):
    print(f"[*] Rescanning {asset['image']} ({asset['asset_id']})", flush=True)
    subprocess.run(["bash", "scanner/scan_all.sh", asset["image"], asset["asset_id"]],
                   cwd=PROJECT, check=True)


def find_cve(report, cve):
    matches = []
    for result in report.get("Results", []):
        for v in result.get("Vulnerabilities", []) or []:
            if v.get("VulnerabilityID") == cve:
                matches.append({
                    "target": result.get("Target"),
                    "pkg": v.get("PkgName"),
                    "installed": v.get("InstalledVersion"),
                    "fixed": v.get("FixedVersion"),
                })
    return matches


def evidence_for(ticket, priority, cve, asset, report_path):
    report = json.loads(report_path.read_text())
    meta = report.get("Metadata", {})
    db_meta = json.loads(TRIVY_META.read_text()) if TRIVY_META.exists() else {}
    matches = find_cve(report, cve)
    return {
        "ticket": ticket,
        "priority": priority,
        "cve": cve,
        "asset_id": asset["asset_id"],
        "asset_name": asset["name"],
        "image": asset["image"],
        "image_id": meta.get("ImageID"),
        "repo_digests": meta.get("RepoDigests", []),
        "scanned_at": report.get("CreatedAt"),
        "scanner": "trivy",
        "trivy_db_updated_at": db_meta.get("UpdatedAt"),
        "report_file": str(report_path.relative_to(PROJECT)),
        "report_sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
        "total_vulnerabilities": sum(len(r.get("Vulnerabilities") or [])
                                     for r in report.get("Results", [])),
        "verified_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "result": "still-present" if matches else "fixed",
        "matches": matches,
    }


def evidence_comment(ev):
    fixed = ev["result"] == "fixed"
    head = ("### Verification PASSED - finding is gone" if fixed
            else "### Verification FAILED - finding still present")
    rows = [
        ("Result", "**FIXED**" if fixed else "**STILL PRESENT**"),
        ("Image scanned", f"`{ev['image']}`"),
        ("Image ID", f"`{(ev['image_id'] or '')[:19]}`"),
        ("Scan time", ev["scanned_at"]),
        ("Trivy DB", ev["trivy_db_updated_at"] or "n/a"),
        ("Vulnerabilities in image", ev["total_vulnerabilities"]),
        ("Report SHA-256", f"`{ev['report_sha256'][:16]}...`"),
    ]
    lines = [head, "", "| Evidence | Value |", "|---|---|"]
    lines += [f"| {k} | {v} |" for k, v in rows]
    if not fixed:
        lines += ["", "Still detected in:"]
        lines += [f"- `{m['pkg']}` {m['installed']} (fixed in {m['fixed'] or 'n/a'}) - {m['target']}"
                  for m in ev["matches"]]
    lines += ["", f"_Evidence file: `{ev['evidence_file']}`_"]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ticket", type=int, action="append", default=[])
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--no-rescan", action="store_true")
    args = ap.parse_args()

    if not GITEA_TOKEN:
        sys.exit("FATAL: GITEA_TOKEN is not set")
    if not args.ticket and not args.all:
        ap.error("use --ticket N or --all")

    inventory = {a["name"]: a for a in json.loads(INVENTORY.read_text())}
    labels = label_ids()

    if args.all:
        issues = [i for i in open_tickets()
                  if not any(l["name"] == "risk-accepted" for l in i.get("labels", []))]
    else:
        issues = [gitea("GET", f"/issues/{n}") for n in args.ticket]

    todo = []
    for issue in issues:
        m = TITLE_RE.search(issue["title"])
        if not m or m.group(3) not in inventory:
            print(f"[!] #{issue['number']} skipped: unrecognised title/asset")
            continue
        todo.append((issue, m.group(1), m.group(2), inventory[m.group(3)]))

    if not args.no_rescan:
        for asset_id in sorted({t[3]["asset_id"] for t in todo}):
            rescan(next(t[3] for t in todo if t[3]["asset_id"] == asset_id))

    EVIDENCE.mkdir(parents=True, exist_ok=True)
    summary = {"fixed": 0, "still-present": 0}

    for issue, priority, cve, asset in todo:
        n = issue["number"]
        report_path = REPORTS / f"{asset['asset_id']}.json"
        ev = evidence_for(n, priority, cve, asset, report_path)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        ev_file = EVIDENCE / f"{n}-{stamp}.json"
        ev["evidence_file"] = str(ev_file.relative_to(PROJECT))
        ev_file.write_text(json.dumps(ev, indent=2))
        with AUDIT_LOG.open("a") as log:
            log.write(json.dumps({k: ev[k] for k in (
                "ticket", "cve", "asset_id", "image", "result",
                "verified_at", "evidence_file")}) + "\n")

        gitea("POST", f"/issues/{n}/comments", {"body": evidence_comment(ev)})
        if ev["result"] == "fixed":
            gitea("POST", f"/issues/{n}/labels", {"labels": [labels["verified-fixed"]]})
            if "verification-failed" in {l["name"] for l in issue.get("labels", [])}:
                gitea("DELETE", f"/issues/{n}/labels/{labels['verification-failed']}")
            gitea("PATCH", f"/issues/{n}", {"state": "closed"})
            print(f"[VERIFIED] #{n} {cve} on {asset['name']} -> closed")
        else:
            gitea("POST", f"/issues/{n}/labels", {"labels": [labels["verification-failed"]]})
            print(f"[FAILED] #{n} {cve} still present on {asset['name']} -> stays open")
        summary[ev["result"]] += 1

    print(f"[+] verification done: {summary['fixed']} fixed, "
          f"{summary['still-present']} still present")


if __name__ == "__main__":
    main()
