#!/usr/bin/env python3
"""
Builds the n8n workflow JSON files in n8n/workflows/ from readable JS.

  findings-to-tickets.json  Phase 6: enriched findings -> Gitea tickets
                            (filter P1/P2, dedupe, regression reopen,
                            risk-acceptance exceptions, SLA due dates)
  sla-escalation.json       Phase 6: SLA reminders + escalation
                            (daily schedule + manual webhook)

The Gitea token is read inside n8n from $env.N8N_GITEA_TOKEN
(set in docker-compose.yml), never stored in the workflow.

Usage:  python3 n8n/build_workflows.py
Import: docker exec vulnmgmt-n8n n8n import:workflow --separate \
            --input=/home/node/import-workflows
"""
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent / "workflows"

COMMON_JS = r"""
const GITEA = 'http://gitea:3000/api/v1/repos/vulnadmin/remediation-tickets';
const HEADERS = { Authorization: 'token ' + $env.N8N_GITEA_TOKEN, Accept: 'application/json' };
const SLA_DAYS = { 'P1-CRITICAL': 7, 'P2-HIGH': 30 };
const helpers = this.helpers;

const api = (method, path, body) => helpers.httpRequest({
  method, url: GITEA + path, headers: HEADERS, body, json: true,
});

async function allIssues(state) {
  const out = [];
  for (let page = 1; page < 50; page++) {
    const batch = await api('GET', `/issues?state=${state}&type=issues&limit=50&page=${page}`);
    out.push(...batch);
    if (batch.length < 50) break;
  }
  return out;
}

async function labelIds() {
  const labels = await api('GET', '/labels?limit=100');
  return Object.fromEntries(labels.map(l => [l.name, l.id]));
}

const hasLabel = (issue, name) => (issue.labels || []).some(l => l.name === name);
const TITLE_RE = /\[(P\d-[A-Z]+)\] Fix (CVE-\d{4}-\d+) on (.+)$/;
"""

TRIAGE_JS = COMMON_JS + r"""
const THRESHOLD = 60;   // P1-CRITICAL + P2-HIGH only

const payload = $input.first().json;
const body = payload.body ?? payload;
const findings = Array.isArray(body) ? body : (body.findings ?? [body]);

const labels = await labelIds();
const byKey = {};
for (const issue of await allIssues('all')) {
  const m = issue.title.match(TITLE_RE);
  if (!m) continue;
  const key = m[2] + '|' + m[3];
  // keep the most recent issue per CVE+asset
  if (!byKey[key] || issue.number > byKey[key].number) byKey[key] = issue;
}

const stats = { received: findings.length, eligible: 0, created: 0, duplicate: 0, accepted: 0, reopened: 0 };
const toCreate = [];

for (const f of findings) {
  if ((f.priority_score ?? 0) < THRESHOLD) continue;
  stats.eligible++;
  const issue = byKey[f.cve + '|' + f.asset_name];

  if (issue && hasLabel(issue, 'risk-accepted')) { stats.accepted++; continue; }
  if (issue && issue.state === 'open') { stats.duplicate++; continue; }

  if (issue && issue.state === 'closed') {
    // finding was verified fixed but is back in the latest scan -> regression
    await api('PATCH', `/issues/${issue.number}`, { state: 'open' });
    if (labels['regression']) await api('POST', `/issues/${issue.number}/labels`, { labels: [labels['regression']] });
    if (hasLabel(issue, 'verified-fixed')) await api('DELETE', `/issues/${issue.number}/labels/${labels['verified-fixed']}`);
    await api('POST', `/issues/${issue.number}/comments`, { body:
      `### Regression detected\n${f.cve} is present again on **${f.asset_name}** ` +
      `(${f.pkg} ${f.installed}) in the scan of ${new Date().toISOString()}.\n` +
      `Ticket reopened automatically by the SOAR workflow.` });
    stats.reopened++;
    continue;
  }

  const due = new Date(Date.now() + (SLA_DAYS[f.priority] ?? 30) * 86400000);
  const kev = f.kev ? 'YES - actively exploited in the wild (CISA KEV)' : 'No';
  const epss = f.epss != null ? (f.epss * 100).toFixed(2) + '%' : 'unknown';
  const lines = [
    '## Remediation ticket', '',
    '| Field | Value |', '|---|---|',
    `| CVE | ${f.cve} |`,
    `| Asset | ${f.asset_name} (\`${f.asset_id}\`, ${f.asset_criticality} importance) |`,
    `| Package | ${f.pkg} - installed ${f.installed}, fixed in ${f.fixed || 'no fixed version available'} |`,
    `| Severity | ${f.severity} (CVSS ${f.cvss}) |`,
    `| EPSS exploitation probability | ${epss} |`,
    `| CISA KEV listed | ${kev} |`,
    `| Contextual priority | ${f.priority_score} / 100 - ${f.priority} |`,
    `| SLA deadline | ${due.toISOString().slice(0, 10)} (${SLA_DAYS[f.priority] ?? 30} days) |`,
    '', '> ' + (f.title || ''), '',
    '### Priority formula',
    'P = 0.25*CVSS + 0.30*EPSS + 0.25*KEV + 0.20*Asset importance', '',
    '### Acceptance criteria',
    '- [ ] Apply the fix (upgrade package or rebuild image)',
    '- [ ] Request verification scan (dashboard -> Verify)',
    '- [ ] Ticket is closed ONLY if a new scan proves the finding is gone', '',
    '_Risk acceptance: add the `risk-accepted` label with a written justification comment._',
  ];
  const ids = [labels[f.priority], f.kev ? labels['kev'] : null].filter(Boolean);
  toCreate.push({ json: {
    cve: f.cve, asset: f.asset_name,
    payload: {
      title: `[${f.priority}] Fix ${f.cve} on ${f.asset_name}`,
      body: lines.join('\n'),
      labels: ids,
      due_date: due.toISOString(),
    },
  }});
  stats.created++;
}

console.log('triage stats', JSON.stringify(stats));
return toCreate;
"""

SLA_JS = COMMON_JS + r"""
const WARN_RATIO = 0.75;
const now = Date.now();
const labels = await labelIds();
const actions = [];

const addLabels = (n, names) => api('POST', `/issues/${n}/labels`,
  { labels: names.map(x => labels[x]).filter(Boolean) });
const comment = (n, body) => api('POST', `/issues/${n}/comments`, { body });

for (const issue of await allIssues('open')) {
  const m = issue.title.match(TITLE_RE);
  if (!m || hasLabel(issue, 'risk-accepted')) continue;
  const priority = m[1];
  const created = Date.parse(issue.created_at);

  let due = issue.due_date ? Date.parse(issue.due_date) : null;
  if (!due) {
    // legacy ticket without deadline: derive it from the priority SLA
    due = created + (SLA_DAYS[priority] ?? 30) * 86400000;
    await api('PATCH', `/issues/${issue.number}`, { due_date: new Date(due).toISOString() });
    actions.push({ issue: issue.number, action: 'due-date-set' });
  }

  const ratio = (now - created) / Math.max(due - created, 1);
  const dueStr = new Date(due).toISOString().slice(0, 10);

  if (now > due && !hasLabel(issue, 'sla-breached')) {
    const late = Math.ceil((now - due) / 86400000);
    await addLabels(issue.number, ['sla-breached', 'escalated']);
    await comment(issue.number,
      `### SLA breached - escalated\nDeadline was **${dueStr}** (${priority}, ` +
      `${SLA_DAYS[priority]} days). Overdue by ${late} day(s).\n` +
      `Escalated to the security manager (@vulnadmin). ` +
      `Fix the finding or file a risk-acceptance exception.`);
    actions.push({ issue: issue.number, action: 'escalated', due: dueStr });
  } else if (now <= due && ratio >= WARN_RATIO && !hasLabel(issue, 'sla-warning')) {
    const left = Math.max(0, Math.ceil((due - now) / 86400000));
    await addLabels(issue.number, ['sla-warning']);
    await comment(issue.number,
      `### SLA reminder\n${Math.round(ratio * 100)}% of the SLA elapsed - ` +
      `${left} day(s) left before **${dueStr}**.`);
    actions.push({ issue: issue.number, action: 'reminder', due: dueStr });
  }
}

if (actions.length === 0) actions.push({ action: 'none' });
return actions.map(a => ({ json: a }));
"""


def code_node(name, js, pos):
    return {
        "parameters": {"jsCode": js.strip()},
        "id": name.lower().replace(" ", "-"),
        "name": name,
        "type": "n8n-nodes-base.code",
        "typeVersion": 2,
        "position": pos,
    }


def webhook_node(name, path, pos, response_mode):
    params = {"httpMethod": "POST", "path": path, "responseMode": response_mode, "options": {}}
    return {
        "parameters": params,
        "id": f"webhook-{path}",
        "name": name,
        "type": "n8n-nodes-base.webhook",
        "typeVersion": 2,
        "position": pos,
        "webhookId": f"vulnmgmt-{path}",
    }


def link(*names):
    conns = {}
    for a, b in zip(names, names[1:]):
        conns.setdefault(a, {"main": [[]]})["main"][0].append(
            {"node": b, "type": "main", "index": 0})
    return conns


def findings_to_tickets():
    create = {
        "parameters": {
            "method": "POST",
            "url": "http://gitea:3000/api/v1/repos/vulnadmin/remediation-tickets/issues",
            "sendHeaders": True,
            "headerParameters": {"parameters": [
                {"name": "Authorization", "value": "=token {{ $env.N8N_GITEA_TOKEN }}"},
                {"name": "Accept", "value": "application/json"},
            ]},
            "sendBody": True,
            "specifyBody": "json",
            "jsonBody": "={{ JSON.stringify($json.payload) }}",
            "options": {},
        },
        "id": "create-gitea-ticket",
        "name": "Create Gitea ticket",
        "type": "n8n-nodes-base.httpRequest",
        "typeVersion": 4.2,
        "position": [440, 0],
    }
    nodes = [
        webhook_node("Findings Webhook", "vuln-findings", [0, 0], "onReceived"),
        code_node("Triage: filter, dedupe, reopen", TRIAGE_JS, [220, 0]),
        create,
    ]
    return {
        "id": "r4BdUkFrYaCkz8FQ",
        "name": "Vuln Management - Findings to Tickets",
        "nodes": nodes,
        "connections": link(*[n["name"] for n in nodes]),
        "settings": {"executionOrder": "v1"},
        "active": False,
    }


def sla_escalation():
    schedule = {
        "parameters": {"rule": {"interval": [
            {"field": "cronExpression", "expression": "0 8 * * *"}]}},
        "id": "daily-0800",
        "name": "Daily 08:00",
        "type": "n8n-nodes-base.scheduleTrigger",
        "typeVersion": 1.2,
        "position": [0, -100],
    }
    hook = webhook_node("Manual SLA check", "sla-check", [0, 100], "lastNode")
    check = code_node("Check SLA + escalate", SLA_JS, [240, 0])
    conns = {
        schedule["name"]: {"main": [[{"node": check["name"], "type": "main", "index": 0}]]},
        hook["name"]: {"main": [[{"node": check["name"], "type": "main", "index": 0}]]},
    }
    return {
        "id": "vmSlaEscalation1",
        "name": "Vuln Management - SLA reminders & escalation",
        "nodes": [schedule, hook, check],
        "connections": conns,
        "settings": {"executionOrder": "v1"},
        "active": False,
    }


if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    for fname, wf in [("findings-to-tickets.json", findings_to_tickets()),
                      ("sla-escalation.json", sla_escalation())]:
        (OUT / fname).write_text(json.dumps(wf, indent=2) + "\n")
        print(f"[+] n8n/workflows/{fname}")
