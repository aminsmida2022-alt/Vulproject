#!/usr/bin/env python3
"""Vulnerability Management dashboard (Phase 7 - Streamlit).

Sections: Overview | Findings | Risk Prioritization | Tickets | Scans
"""
import json
import subprocess
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

PROJECT = Path(__file__).resolve().parent.parent
FINDINGS = PROJECT / "data" / "vulnerabilities" / "findings.json"
REPORTS = PROJECT / "scanner" / "reports"
N8N_WEBHOOK = "http://localhost:5678/webhook/start-scan"

st.set_page_config(page_title="Vulnerability Management",
                   page_icon=":shield:", layout="wide")

SECTIONS = ["Overview", "Vulnerability Management", "Risk Prioritization",
            "Remediation Tickets", "Scan History"]


@st.cache_data(ttl=60)
def load_findings():
    if not FINDINGS.exists():
        return pd.DataFrame()
    return pd.DataFrame(json.loads(FINDINGS.read_text()))


def run_scan(image, asset_id):
    """Run Trivy locally on one image, then trigger enrichment."""
    REPORTS.mkdir(parents=True, exist_ok=True)
    cmd = ["docker", "run", "--rm",
           "-v", f"{REPORTS}:/reports",
           "aquasec/trivy:latest", "image",
           "--format", "json", "--output", f"/reports/{asset_id}.json",
           "--quiet", image]
    with st.status(f"Scanning {image} ..."):
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            st.error(f"Trivy failed:\n{proc.stderr}")
            return False
    return True


def main():
    st.sidebar.title(":shield: Vuln Management")
    section = st.sidebar.radio("Navigation", SECTIONS)
    st.sidebar.divider()

    if st.sidebar.button("🔄 Start Scan", type="primary",
                         use_container_width=True):
        with st.spinner("Scanning lab assets with Trivy..."):
            ok = True
            inv = json.loads((PROJECT / "data/assets/inventory.json")
                             .read_text())
            for a in inv:
                ok = run_scan(a["image"], a["asset_id"]) and ok
            if ok:
                subprocess.run(["python3", str(PROJECT / "scripts/enrich.py")],
                               capture_output=True, text=True)
                st.cache_data.clear()
        st.sidebar.success("Scan + enrichment complete")
        st.rerun()

    df = load_findings()
    if df.empty:
        st.info("No findings yet. Click **Start Scan** to run the first scan.")
        return

    if section == "Overview":
        st.header("Overview")
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Unique findings", len(df))
        c2.metric("KEV-listed", int(df["kev"].sum()))
        c3.metric("P1 / P2", int((df["priority_score"] >= 60).sum()))
        c4.metric("Assets scanned", df["asset_id"].nunique())
        st.plotly_chart(
            px.pie(df, names="priority", hole=0.45,
                   title="Findings by priority"),
            use_container_width=True)

    elif section == "Vulnerability Management":
        st.header("Vulnerability Management")
        cols = ["priority_score", "priority", "cve", "severity", "cvss",
                "epss", "kev", "asset_name", "pkg", "installed", "fixed"]
        show = df[cols].sort_values("priority_score", ascending=False)
        sev = st.multiselect("Severity filter", sorted(df["severity"].unique()),
                             default=sorted(df["severity"].unique()))
        st.dataframe(show[show["severity"].isin(sev)], use_container_width=True,
                     height=520)

    elif section == "Risk Prioritization":
        st.header("Risk Prioritization")
        st.caption("P = 0.25·CVSS + 0.30·EPSS + 0.25·KEV + 0.20·Asset")
        top = df.nlargest(20, "priority_score")
        st.plotly_chart(
            px.bar(top, x="priority_score", y="cve", color="priority",
                   orientation="h",
                   hover_data=["cvss", "epss", "kev", "asset_name"],
                   title="Top 20 findings by contextual priority"),
            use_container_width=True)
        c1, c2 = st.columns(2)
        c1.plotly_chart(px.scatter(df, x="cvss", y="epss", color="kev",
                                   hover_name="cve",
                                   title="CVSS vs EPSS (color = KEV)"),
                        use_container_width=True)
        c2.plotly_chart(px.histogram(df, x="priority_score", nbins=20,
                                     title="Priority score distribution"),
                        use_container_width=True)

    elif section == "Remediation Tickets":
        st.header("Remediation Tickets")
        st.info("Gitea tickets will be listed here once the n8n ticket "
                "workflow is connected (Phase 6).")
        st.page_link("http://localhost:3001", label="Open Gitea :arrow_upper_right:")

    elif section == "Scan History":
        st.header("Scan History")
        files = sorted(REPORTS.glob("*.json"),
                       key=lambda f: f.stat().st_mtime, reverse=True)
        for f in files:
            data = json.loads(f.read_text())
            n = sum(len(r.get("Vulnerabilities", []) or [])
                    for r in data.get("Results", []))
            st.write(f"**{f.stem}** — {n} findings — "
                     f"scanned {pd.Timestamp(f.stat().st_mtime, unit='s')}")


main()
