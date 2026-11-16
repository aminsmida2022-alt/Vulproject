import { Head, router, useForm } from '@inertiajs/react';
import { Fragment, useEffect, useRef, useState } from 'react';
import { scan } from '@/routes/vuln';
import { cn } from '@/lib/utils';

type Finding = {
  cve: string;
  asset_id: string;
  asset_name: string;
  pkg: string;
  installed: string;
  fixed?: string | null;
  status?: string;
  severity: string;
  cvss: number;
  epss: number;
  kev: boolean;
  priority_score: number;
  priority: string;
  title: string;
};

type Asset = {
  asset_id: string;
  name: string;
  image: string;
  criticality: string;
  importance: number;
};

type History = {
  asset_id: string;
  findings: number;
  scanned_at: string;
};

type Ticket = {
  number: number;
  title: string;
  url: string;
  state: string;
  created_at: string;
  closed_at?: string | null;
  due_date?: string | null;
  labels: { name: string; color: string }[];
};

type VerifyStatus = {
  state: 'idle' | 'running' | 'done' | 'failed';
  ticket: number | null;
  started_at?: string | null;
  log: string[];
};

type Verification = {
  ticket: number;
  cve: string;
  asset_id: string;
  image: string;
  result: 'fixed' | 'still-present';
  verified_at: string;
  evidence_file: string;
};

type AssetProgress = {
  asset_id: string;
  name: string;
  image: string;
  state: 'pending' | 'scanned' | 'done';
};

type ScanStatus = {
  state: 'idle' | 'running' | 'done' | 'failed';
  started_at?: string | null;
  progress?: AssetProgress[];
  log?: string[];
  errors?: string[];
};

type Stats = {
  total: number;
  kev: number;
  p1: number;
  p2: number;
  p3: number;
  p4: number;
  p5: number;
  assets: number;
  max_score: number;
};

type Props = {
  stats: Stats;
  findings: Finding[];
  inventory: Asset[];
  history: History[];
  scanStatus: ScanStatus;
  tickets: Ticket[];
  closedTickets: Ticket[];
  verifyStatus: VerifyStatus;
  verifications: Verification[];
};

const PAGE_SIZE = 15;
const ticketKey = (cve: string, asset: string) => `${cve}|${asset}`;
const TITLE_RE = /Fix (CVE-\d{4}-\d+) on (.+)$/;

function LabelChip({ name, color }: { name: string; color: string }) {
  return (
    <span
      className="mr-1 inline-block rounded px-1.5 py-0.5 text-[10px] font-semibold text-white"
      style={{ background: color }}
    >
      {name}
    </span>
  );
}

/** Score breakdown for one finding: P = 0.25C + 0.30E + 0.25K + 0.20A */
function FindingDetail({ f, importance, ticket, onClose }: {
  f: Finding;
  importance: number;
  ticket?: Ticket;
  onClose: () => void;
}) {
  const parts = [
    { label: 'CVSS', raw: `${f.cvss?.toFixed(1)} / 10`, pts: 0.25 * Math.min(f.cvss * 10, 100), max: 25, color: '#7f1d1d' },
    { label: 'EPSS', raw: `${((f.epss ?? 0) * 100).toFixed(2)}%`, pts: 0.3 * (f.epss ?? 0) * 100, max: 30, color: '#ea580c' },
    { label: 'KEV', raw: f.kev ? 'listed' : 'not listed', pts: f.kev ? 25 : 0, max: 25, color: '#5319e7' },
    { label: 'Asset', raw: `${importance} / 100`, pts: 0.2 * importance, max: 20, color: '#0284c7' },
  ];

  return (
    <div className="rounded-lg border border-neutral-300 bg-neutral-50 p-4 text-xs dark:border-neutral-700 dark:bg-neutral-900">
      <div className="mb-3 flex items-start justify-between gap-4">
        <div>
          <div className="font-mono text-sm font-bold">{f.cve}</div>
          <div className="mt-0.5 text-neutral-600 dark:text-neutral-300">{f.title}</div>
        </div>
        <button onClick={onClose} className="rounded px-2 py-1 text-neutral-500 hover:bg-neutral-200 dark:hover:bg-neutral-800">
          ✕
        </button>
      </div>
      <div className="grid gap-4 md:grid-cols-2">
        <dl className="grid grid-cols-[110px_1fr] gap-y-1">
          <dt className="text-neutral-500">Asset</dt><dd>{f.asset_name}</dd>
          <dt className="text-neutral-500">Package</dt><dd className="font-mono">{f.pkg} {f.installed}</dd>
          <dt className="text-neutral-500">Fixed in</dt><dd className="font-mono">{f.fixed || 'no fix available'}</dd>
          <dt className="text-neutral-500">Severity</dt><dd>{f.severity}</dd>
          <dt className="text-neutral-500">Ticket</dt>
          <dd>
            {ticket ? (
              <a href={ticket.url} target="_blank" rel="noopener noreferrer" className="text-sky-600 underline">
                #{ticket.number} ({ticket.state})
              </a>
            ) : f.priority_score >= 60 ? 'pending (next n8n run)' : 'not required (below P2)'}
          </dd>
          <dt className="text-neutral-500">NVD</dt>
          <dd>
            <a href={`https://nvd.nist.gov/vuln/detail/${f.cve}`} target="_blank" rel="noopener noreferrer" className="text-sky-600 underline">
              nvd.nist.gov
            </a>
          </dd>
        </dl>
        <div>
          <div className="mb-1 font-semibold">
            Priority score {f.priority_score.toFixed(1)} = sum of weighted factors
          </div>
          {parts.map((p) => (
            <div key={p.label} className="mb-1.5">
              <div className="flex justify-between">
                <span>{p.label} <span className="text-neutral-400">({p.raw})</span></span>
                <span className="tabular-nums font-semibold">{p.pts.toFixed(1)} / {p.max}</span>
              </div>
              <div className="h-1.5 rounded bg-neutral-200 dark:bg-neutral-800">
                <div className="h-1.5 rounded" style={{ width: `${(p.pts / p.max) * 100}%`, background: p.color }} />
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

const P_COLORS: Record<string, string> = {
  'P1-CRITICAL': '#dc2626',
  'P2-HIGH': '#ea580c',
  'P3-MEDIUM': '#d97706',
  'P4-LOW': '#0284c7',
  'P5-INFORMATIONAL': '#94a3b8',
};

/* ---------- charts (pure SVG/CSS, Tableau-style) ---------- */

function HBar({
  label,
  value,
  max,
  color,
}: {
  label: string;
  value: number;
  max: number;
  color: string;
}) {
  const pct = max > 0 ? (value / max) * 100 : 0;
  return (
    <div className="flex items-center gap-3 py-1.5">
      <div className="w-32 shrink-0 text-right text-xs text-neutral-600">{label}</div>
      <div className="flex flex-1 items-center gap-2">
        <div className="h-4 flex-1 rounded-sm bg-neutral-100">
          <div
            className="h-4 rounded-sm transition-all"
            style={{ width: `${Math.max(pct, value > 0 ? 1.5 : 0)}%`, background: color }}
          />
        </div>
        <div className="w-8 text-right text-xs font-semibold tabular-nums text-neutral-800">
          {value}
        </div>
      </div>
    </div>
  );
}

function Donut({
  segments,
  total,
}: {
  segments: { label: string; value: number; color: string }[];
  total: number;
}) {
  const r = 54;
  const c = 2 * Math.PI * r;
  let offset = 0;
  const shown = segments.filter((s) => s.value > 0);

  return (
    <div className="flex items-center justify-center gap-6 py-2">
      <svg viewBox="0 0 140 140" className="size-[140px]">
        <circle cx="70" cy="70" r={r} fill="none" stroke="#f1f5f9" strokeWidth="16" />
        {shown.map((s) => {
          const frac = total ? s.value / total : 0;
          const el = (
            <circle
              key={s.label}
              cx="70"
              cy="70"
              r={r}
              fill="none"
              stroke={s.color}
              strokeWidth="16"
              strokeDasharray={`${frac * c} ${c}`}
              strokeDashoffset={-offset * c}
              transform="rotate(-90 70 70)"
            />
          );
          offset += frac;
          return el;
        })}
        <text x="70" y="66" textAnchor="middle" className="fill-neutral-900 text-[20px] font-semibold">
          {total}
        </text>
        <text x="70" y="84" textAnchor="middle" className="fill-neutral-400 text-[9px]">
          FINDINGS
        </text>
      </svg>
      <div className="space-y-1.5">
        {segments.map((s) => (
          <div key={s.label} className="flex items-center gap-2 text-xs">
            <span className="size-2.5 rounded-sm" style={{ background: s.color }} />
            <span className="text-neutral-600">{s.label}</span>
            <span className="ml-auto pl-3 font-semibold tabular-nums">{s.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function Scatter({ data }: { data: Finding[] }) {
  const W = 340;
  const H = 180;
  const px = (v: number) => (v / 10) * W;
  const py = (v: number) => H - v * H;

  return (
    <div className="px-2 py-3">
      <svg viewBox={`-24 -6 ${W + 30} ${H + 36}`} className="w-full">
        <text x={4} y={8} className="fill-neutral-400 text-[8px]">EPSS %</text>
        {[0, 0.25, 0.5, 0.75, 1].map((g) => (
          <g key={g}>
            <line x1={0} x2={W} y1={H - g * H} y2={H - g * H} stroke="#f1f5f9" strokeWidth="1" />
            <text x={-6} y={H - g * H + 3} textAnchor="end" className="fill-neutral-400 text-[8px]">
              {Math.round(g * 100)}
            </text>
          </g>
        ))}
        {[0, 2, 4, 6, 8, 10].map((t) => (
          <text key={t} x={px(t)} y={H + 12} textAnchor="middle" className="fill-neutral-400 text-[8px]">
            {t}
          </text>
        ))}
        {[...data].sort((a, b) => Number(a.kev) - Number(b.kev)).map((f, i) => (
          <circle
            key={`${f.cve}-${i}`}
            cx={px(f.cvss ?? 0)}
            cy={py(f.epss ?? 0)}
            r={f.kev ? 5 : 2.5}
            fill={f.kev ? '#dc2626' : '#0ea5e9'}
            fillOpacity={f.kev ? 0.9 : 0.35}
            stroke={f.kev ? '#ffffff' : 'none'}
            strokeWidth={f.kev ? 1.5 : 0}
          />
        ))}
        <text x={W / 2} y={H + 26} textAnchor="middle" className="fill-neutral-400 text-[9px]">
          CVSS score →
        </text>
      </svg>
      <div className="mt-1 flex justify-center gap-4 text-xs">
        <span className="flex items-center gap-1.5">
          <span className="size-2 rounded-full bg-sky-500/50" /> standard
        </span>
        <span className="flex items-center gap-1.5">
          <span className="size-2 rounded-full bg-red-600" /> CISA KEV (actively exploited)
        </span>
      </div>
    </div>
  );
}

function Card({ title, subtitle, children, className }: {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn('rounded-lg border bg-white p-4 shadow-xs dark:bg-neutral-950', className)}>
      <div className="mb-3">
        <h3 className="text-sm font-semibold text-neutral-900 dark:text-neutral-100">{title}</h3>
        {subtitle && <p className="text-xs text-neutral-500">{subtitle}</p>}
      </div>
      {children}
    </div>
  );
}

/* ---------- page ---------- */

export default function VulnOverview({
  stats, findings, inventory, history, scanStatus, tickets, closedTickets, verifyStatus, verifications,
}: Props) {
  /* ---------- findings filters + drill-down ---------- */
  const [fPriority, setFPriority] = useState('all');
  const [fAsset, setFAsset] = useState('all');
  const [fKev, setFKev] = useState(false);
  const [query, setQuery] = useState('');
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<string | null>(null);

  const filtered = findings.filter((f) =>
    (fPriority === 'all' || f.priority === fPriority)
    && (fAsset === 'all' || f.asset_id === fAsset)
    && (!fKev || f.kev)
    && (query === '' || `${f.cve} ${f.pkg} ${f.title}`.toLowerCase().includes(query.toLowerCase())));
  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const pageRows = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  const ticketIndex: Record<string, Ticket> = {};
  for (const t of [...closedTickets, ...tickets]) {
    const m = t.title.match(TITLE_RE);
    if (m) ticketIndex[ticketKey(m[1], m[2])] = t;
  }
  const importanceOf = (assetId: string) => inventory.find((a) => a.asset_id === assetId)?.importance ?? 0;

  /* ---------- Phase 8: verification ---------- */
  const [vStatus, setVStatus] = useState<VerifyStatus>(verifyStatus);
  const vPollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const verifying = vStatus.state === 'running';

  const pollVerify = () => {
    if (vPollRef.current) return;
    vPollRef.current = setInterval(async () => {
      try {
        const data: VerifyStatus = await (await fetch('/tickets/verify/status')).json();
        setVStatus(data);
        if (data.state !== 'running') {
          if (vPollRef.current) clearInterval(vPollRef.current);
          vPollRef.current = null;
          router.reload({ only: ['tickets', 'closedTickets', 'verifications', 'verifyStatus', 'history'] });
        }
      } catch {
        /* transient errors ignored */
      }
    }, 2000);
  };

  useEffect(() => {
    if (verifyStatus.state === 'running') pollVerify();
    return () => {
      if (vPollRef.current) clearInterval(vPollRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const runVerify = (ticket: number | null) => {
    router.post('/tickets/verify', ticket === null ? {} : { ticket }, {
      preserveScroll: true,
      onSuccess: () => {
        setVStatus({ state: 'running', ticket, log: [] });
        pollVerify();
      },
    });
  };

  const scanForm = useForm({});
  const [status, setStatus] = useState<ScanStatus>(scanStatus);
  const [polling, setPolling] = useState(false);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (scanStatus.state !== 'idle') setStatus(scanStatus);
  }, [scanStatus]);

  useEffect(() => {
    if (scanStatus.state === 'running' && !polling) startPolling();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const stopPolling = () => {
    if (pollRef.current) clearInterval(pollRef.current);
    pollRef.current = null;
    setPolling(false);
  };

  const startPolling = () => {
    setPolling(true);
    pollRef.current = setInterval(async () => {
      try {
        const res = await fetch('/scan/status');
        const data: ScanStatus = await res.json();
        setStatus(data);
        if (data.state === 'done' || data.state === 'failed') {
          stopPolling();
          router.reload({ only: ['stats', 'findings', 'inventory', 'history', 'tickets', 'closedTickets'] });
        }
      } catch {
        /* transient errors ignored */
      }
    }, 1500);
  };

  const runScan = () => {
    scanForm.post(scan().url, {
      preserveScroll: true,
      onSuccess: () => {
        scanForm.reset();
        startPolling();
      },
    });
  };

  const running = polling && status.state === 'running';

  const prioritySegments = [
    { label: 'P1 Critical', value: stats.p1, color: P_COLORS['P1-CRITICAL'] },
    { label: 'P2 High', value: stats.p2, color: P_COLORS['P2-HIGH'] },
    { label: 'P3 Medium', value: stats.p3, color: P_COLORS['P3-MEDIUM'] },
    { label: 'P4 Low', value: stats.p4, color: P_COLORS['P4-LOW'] },
    { label: 'P5 Info', value: stats.p5, color: P_COLORS['P5-INFORMATIONAL'] },
  ];

  const severitySegments = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'].map((sev, i) => ({
    label: sev.charAt(0) + sev.slice(1).toLowerCase(),
    value: findings.filter((f) => (f.severity ?? '').toUpperCase() === sev).length,
    color: ['#7f1d1d', '#dc2626', '#d97706', '#0284c7', '#94a3b8'][i],
  }));

  const maxPriority = Math.max(stats.p1, stats.p2, stats.p3, stats.p4, stats.p5, 1);

  return (
    <>
      <Head title="Vulnerability Management" />
      <div className="flex h-full flex-1 flex-col gap-4 overflow-y-auto bg-neutral-50 p-6 dark:bg-neutral-900">
        {/* header */}
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h1 className="text-xl font-bold tracking-tight text-neutral-900 dark:text-white">
              Vulnerability Management
            </h1>
            <p className="text-xs text-neutral-500">
              Fix what matters, and prove it · P = 0.25·CVSS + 0.30·EPSS + 0.25·KEV + 0.20·Asset
            </p>
          </div>
          <button
            onClick={runScan}
            disabled={scanForm.processing || running}
            className={cn(
              'flex items-center gap-2 rounded-md px-4 py-2 text-sm font-semibold text-white shadow-sm transition-colors',
              running || scanForm.processing
                ? 'cursor-not-allowed bg-neutral-400'
                : 'bg-neutral-900 hover:bg-neutral-700 dark:bg-white dark:text-neutral-900 dark:hover:bg-neutral-200',
            )}
          >
            {running && (
              <span className="size-2 animate-pulse rounded-full bg-emerald-400" />
            )}
            {running ? 'Scan running…' : 'Start Scan'}
          </button>
        </div>

        {(scanForm.errors as Record<string, string>).scan && (
          <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
            {(scanForm.errors as Record<string, string>).scan}
          </div>
        )}

        {/* live scan progress */}
        {status.state !== 'idle' && (
          <div className="rounded-lg border bg-white p-4 dark:bg-neutral-950">
            <div className="mb-2 flex items-center gap-2 text-sm font-semibold">
              {running && <span className="size-2 animate-pulse rounded-full bg-emerald-500" />}
              {running ? 'Scan in progress' : status.state === 'done' ? 'Last scan completed' : 'Last scan failed'}
              {status.started_at && (
                <span className="text-xs font-normal text-neutral-500">· {status.started_at}</span>
              )}
            </div>
            <div className="flex flex-wrap gap-2">
              {(status.progress ?? []).map((p) => (
                <div
                  key={p.asset_id}
                  className={cn(
                    'flex items-center gap-2 rounded-md border px-3 py-1.5 text-xs',
                    p.state === 'done' && 'border-emerald-200 bg-emerald-50',
                    p.state === 'scanned' && 'border-sky-200 bg-sky-50',
                    p.state === 'pending' && 'opacity-50',
                  )}
                >
                  <span>{p.state === 'done' ? '✅' : p.state === 'scanned' ? '🔍' : '⏳'}</span>
                  <span className="font-medium">{p.name}</span>
                  <span className="font-mono text-neutral-400">{p.image}</span>
                </div>
              ))}
            </div>
            {status.log && status.log.length > 0 && (
              <pre className="mt-2 max-h-28 overflow-auto rounded bg-neutral-950 p-2 font-mono text-[10px] leading-relaxed text-neutral-200">
                {status.log.join('\n')}
              </pre>
            )}
          </div>
        )}

        {/* KPI row */}
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          {[
            { label: 'Total findings', value: stats.total, sub: `${stats.assets} assets scanned` },
            { label: 'KEV exploited', value: stats.kev, sub: 'actively exploited in the wild', red: (stats.kev ?? 0) > 0 },
            { label: 'Needs ticket (P1+P2)', value: (stats.p1 ?? 0) + (stats.p2 ?? 0), sub: 'auto-created in Gitea' },
            { label: 'Max priority score', value: Number(stats.max_score ?? 0).toFixed(1), sub: 'out of 100' },
          ].map((k) => (
            <div key={k.label} className="rounded-lg border bg-white p-4 dark:bg-neutral-950">
              <div className="text-xs font-medium text-neutral-500">{k.label}</div>
              <div className={cn('mt-1 text-3xl font-bold tabular-nums', k.red ? 'text-red-600' : 'text-neutral-900 dark:text-white')}>
                {k.value}
              </div>
              <div className="text-xs text-neutral-400">{k.sub}</div>
            </div>
          ))}
        </div>

        {/* charts row */}
        <div className="grid gap-4 lg:grid-cols-3">
          <Card title="Priority distribution" subtitle="Contextual risk (P1–P5)">
            <div className="pt-1">
              {prioritySegments.map((s) => (
                <HBar key={s.label} label={s.label} value={s.value} max={maxPriority} color={s.color} />
              ))}
            </div>
          </Card>

          <Card title="Severity mix" subtitle="CVSS severity classes">
            <Donut segments={severitySegments} total={stats.total} />
          </Card>

          <Card title="CVSS vs EPSS" subtitle="Does real exploitability match the score?">
            <Scatter data={findings} />
          </Card>
        </div>

        {/* findings explorer with drill-down */}
        <Card title="Findings by contextual priority" subtitle="Ranked by the weighted score, not CVSS alone. Click a row for the score breakdown.">
          <div className="mb-3 flex flex-wrap items-center gap-2 text-xs">
            <input
              value={query}
              onChange={(e) => { setQuery(e.target.value); setPage(0); }}
              placeholder="Search CVE, package, title…"
              className="w-56 rounded border bg-white px-2 py-1 dark:bg-neutral-900"
            />
            <select value={fPriority} onChange={(e) => { setFPriority(e.target.value); setPage(0); }} className="rounded border bg-white px-2 py-1 dark:bg-neutral-900">
              <option value="all">All priorities</option>
              {Object.keys(P_COLORS).map((p) => <option key={p} value={p}>{p}</option>)}
            </select>
            <select value={fAsset} onChange={(e) => { setFAsset(e.target.value); setPage(0); }} className="rounded border bg-white px-2 py-1 dark:bg-neutral-900">
              <option value="all">All assets</option>
              {inventory.map((a) => <option key={a.asset_id} value={a.asset_id}>{a.name}</option>)}
            </select>
            <label className="flex items-center gap-1">
              <input type="checkbox" checked={fKev} onChange={(e) => { setFKev(e.target.checked); setPage(0); }} />
              KEV only
            </label>
            <span className="ml-auto text-neutral-400">{filtered.length} of {findings.length} findings</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b text-left text-neutral-500">
                  <th className="py-2 pr-3 font-medium">Score</th>
                  <th className="py-2 pr-3 font-medium">Priority</th>
                  <th className="py-2 pr-3 font-medium">CVE</th>
                  <th className="py-2 pr-3 font-medium">Asset</th>
                  <th className="py-2 pr-3 font-medium">Package</th>
                  <th className="py-2 pr-3 text-right font-medium">CVSS</th>
                  <th className="py-2 pr-3 text-right font-medium">EPSS</th>
                  <th className="py-2 pr-3 font-medium">KEV</th>
                  <th className="py-2 font-medium">Ticket</th>
                </tr>
              </thead>
              <tbody>
                {pageRows.length === 0 && (
                  <tr>
                    <td colSpan={9} className="py-10 text-center text-neutral-400">
                      {findings.length === 0
                        ? <>No findings yet. Click <strong>Start Scan</strong> to run the first scan.</>
                        : 'No finding matches the filters.'}
                    </td>
                  </tr>
                )}
                {pageRows.map((f) => {
                  const key = `${f.cve}|${f.asset_id}|${f.pkg}`;
                  const ticket = ticketIndex[ticketKey(f.cve, f.asset_name)];
                  return (
                    <Fragment key={key}>
                      <tr
                        onClick={() => setSelected(selected === key ? null : key)}
                        className={cn(
                          'cursor-pointer border-b last:border-0 hover:bg-neutral-50 dark:hover:bg-neutral-900',
                          selected === key && 'bg-neutral-100 dark:bg-neutral-800',
                        )}
                      >
                        <td className="py-2 pr-3 font-bold tabular-nums" style={{ color: P_COLORS[f.priority] ?? '#94a3b8' }}>
                          {f.priority_score.toFixed(1)}
                        </td>
                        <td className="py-2 pr-3">
                          <span className="rounded px-1.5 py-0.5 text-[10px] font-semibold text-white" style={{ background: P_COLORS[f.priority] ?? '#94a3b8' }}>
                            {f.priority}
                          </span>
                        </td>
                        <td className="py-2 pr-3 font-mono">{f.cve}</td>
                        <td className="py-2 pr-3">{f.asset_name}</td>
                        <td className="py-2 pr-3 text-neutral-500">{f.pkg} ({f.installed})</td>
                        <td className="py-2 pr-3 text-right tabular-nums">{f.cvss?.toFixed(1) ?? '—'}</td>
                        <td className="py-2 pr-3 text-right tabular-nums">{f.epss ? `${(f.epss * 100).toFixed(1)}%` : '—'}</td>
                        <td className="py-2 pr-3">
                          {f.kev ? <span className="font-semibold text-red-600">●</span> : <span className="text-neutral-300">—</span>}
                        </td>
                        <td className="py-2 font-mono text-neutral-500">
                          {ticket ? `#${ticket.number}${ticket.state === 'closed' ? ' ✓' : ''}` : '—'}
                        </td>
                      </tr>
                      {selected === key && (
                        <tr>
                          <td colSpan={9} className="py-2">
                            <FindingDetail f={f} importance={importanceOf(f.asset_id)} ticket={ticket} onClose={() => setSelected(null)} />
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
          {pageCount > 1 && (
            <div className="mt-2 flex items-center justify-end gap-2 text-xs">
              <button disabled={page === 0} onClick={() => setPage(page - 1)} className="rounded border px-2 py-0.5 disabled:opacity-40">←</button>
              <span className="tabular-nums text-neutral-500">page {page + 1} / {pageCount}</span>
              <button disabled={page >= pageCount - 1} onClick={() => setPage(page + 1)} className="rounded border px-2 py-0.5 disabled:opacity-40">→</button>
            </div>
          )}
        </Card>

        {/* remediation tickets + verification (Phase 8) */}
        <Card
          title="Remediation tickets"
          subtitle="Created by n8n · closed only when a rescan proves the finding is gone"
        >
          <div className="mb-3 flex flex-wrap items-center gap-2 text-xs">
            <span className="text-neutral-500">{tickets.length} open · {closedTickets.length} recently closed</span>
            <button
              onClick={() => runVerify(null)}
              disabled={verifying || tickets.length === 0}
              className="ml-auto rounded-md bg-neutral-900 px-3 py-1.5 font-semibold text-white disabled:cursor-not-allowed disabled:bg-neutral-400 dark:bg-white dark:text-neutral-900"
            >
              {verifying ? 'Verifying…' : 'Verify all open tickets'}
            </button>
          </div>
          {vStatus.state !== 'idle' && (
            <div className="mb-3 rounded border bg-white p-2 text-xs dark:bg-neutral-950">
              <div className="mb-1 flex items-center gap-2 font-semibold">
                {verifying && <span className="size-2 animate-pulse rounded-full bg-emerald-500" />}
                {verifying ? 'Verification running' : vStatus.state === 'done' ? 'Last verification completed' : 'Last verification failed'}
                <span className="font-normal text-neutral-500">
                  · {vStatus.ticket ? `ticket #${vStatus.ticket}` : 'all open tickets'} · {vStatus.started_at}
                </span>
              </div>
              {vStatus.log.length > 0 && (
                <pre className="max-h-28 overflow-auto rounded bg-neutral-950 p-2 font-mono text-[10px] leading-relaxed text-neutral-200">
                  {vStatus.log.join('\n')}
                </pre>
              )}
            </div>
          )}
          {tickets.length === 0 ? (
            <p className="py-6 text-center text-xs text-neutral-400">No open tickets.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b text-left text-neutral-500">
                    <th className="py-2 pr-3 font-medium">#</th>
                    <th className="py-2 pr-3 font-medium">Ticket</th>
                    <th className="py-2 pr-3 font-medium">Labels</th>
                    <th className="py-2 pr-3 font-medium">SLA due</th>
                    <th className="py-2 text-right font-medium">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {tickets.map((t) => {
                    const overdue = t.due_date ? new Date(t.due_date) < new Date() : false;
                    return (
                      <tr key={t.number} className="border-b last:border-0">
                        <td className="py-2 pr-3 font-mono text-neutral-400">{t.number}</td>
                        <td className="py-2 pr-3">
                          <a href={t.url} target="_blank" rel="noopener noreferrer" className="hover:underline">{t.title}</a>
                        </td>
                        <td className="py-2 pr-3">{t.labels.map((l) => <LabelChip key={l.name} {...l} />)}</td>
                        <td className={cn('py-2 pr-3 tabular-nums', overdue && 'font-semibold text-red-600')}>
                          {t.due_date ?? '—'}
                        </td>
                        <td className="py-2 text-right">
                          <button
                            onClick={() => runVerify(t.number)}
                            disabled={verifying}
                            className="rounded border px-2 py-1 font-medium hover:bg-neutral-100 disabled:cursor-not-allowed disabled:opacity-40 dark:hover:bg-neutral-800"
                          >
                            Verify
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Card>

        {/* bottom row */}
        <div className="grid gap-4 lg:grid-cols-3">
          <Card title="Verification evidence" subtitle="Latest rescans (tickets/verification_log.jsonl)">
            {verifications.length === 0 ? (
              <p className="py-6 text-center text-xs text-neutral-400">No verification yet.</p>
            ) : (
              <div className="space-y-2">
                {verifications.map((v, i) => (
                  <div key={`${v.ticket}-${i}`} className="border-b pb-2 text-xs last:border-0">
                    <div className="flex items-center justify-between">
                      <span>
                        <span className="mr-2 font-mono text-neutral-400">#{v.ticket}</span>
                        <span className="font-mono">{v.cve}</span>
                      </span>
                      <span className={cn('rounded px-1.5 py-0.5 text-[10px] font-semibold text-white', v.result === 'fixed' ? 'bg-emerald-600' : 'bg-red-600')}>
                        {v.result === 'fixed' ? 'FIXED' : 'STILL PRESENT'}
                      </span>
                    </div>
                    <div className="mt-0.5 text-neutral-500">
                      {v.image} · {v.verified_at.replace('T', ' ').slice(0, 16)}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Card>

          <Card title="Asset inventory" subtitle="Isolated lab assets">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b text-left text-neutral-500">
                  <th className="py-2 font-medium">Asset</th>
                  <th className="py-2 font-medium">Image</th>
                  <th className="py-2 text-right font-medium">Importance</th>
                </tr>
              </thead>
              <tbody>
                {inventory.map((a) => (
                  <tr key={a.asset_id} className="border-b last:border-0">
                    <td className="py-2 font-medium">{a.name}</td>
                    <td className="py-2 font-mono text-neutral-500">{a.image}</td>
                    <td className="py-2 text-right font-semibold tabular-nums">{a.importance}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>

          <Card title="Scan history" subtitle="Latest Trivy reports">
            {history.length === 0 ? (
              <p className="py-6 text-center text-xs text-neutral-400">No scans yet.</p>
            ) : (
              <div className="space-y-2">
                {history.map((h) => (
                  <div key={h.asset_id} className="flex items-center justify-between border-b pb-2 text-xs last:border-0">
                    <span className="font-medium">{h.asset_id}</span>
                    <span className="text-neutral-500">
                      {h.findings} findings · {h.scanned_at}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>
      </div>
    </>
  );
}
