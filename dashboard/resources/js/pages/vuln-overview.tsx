import { Head, router, useForm } from '@inertiajs/react';
import { useEffect, useRef, useState } from 'react';
import { scan } from '@/routes/vuln';
import { cn } from '@/lib/utils';

type Finding = {
  cve: string;
  asset_name: string;
  pkg: string;
  installed: string;
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
};

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
      <svg viewBox={`0 0 ${W} ${H + 30}`} className="w-full">
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
        {data.slice(0, 120).map((f, i) => (
          <circle
            key={`${f.cve}-${i}`}
            cx={px(f.cvss ?? 0)}
            cy={py((f.epss ?? 0) * 100)}
            r={f.kev ? 5 : 3}
            fill={f.kev ? '#dc2626' : '#0ea5e9'}
            fillOpacity={f.kev ? 0.9 : 0.45}
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

export default function VulnOverview({ stats, findings, inventory, history, scanStatus, tickets }: Props) {
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
          router.reload({ only: ['stats', 'findings', 'inventory', 'history', 'tickets'] });
        }
      } catch {
        /* transient errors ignored */
      }
    }, 1500);
  };

  const runScan = () => {
    scanForm.post(scan(), {
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
  const top = findings.slice(0, 8);

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

        {scanForm.errors.scan && (
          <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
            {scanForm.errors.scan}
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

        {/* top findings */}
        <Card title="Top findings by contextual priority" subtitle="Ranked by the weighted score — not CVSS alone">
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
                  <th className="py-2 font-medium">KEV</th>
                </tr>
              </thead>
              <tbody>
                {top.length === 0 && (
                  <tr>
                    <td colSpan={8} className="py-10 text-center text-neutral-400">
                      No findings yet — click <strong>Start Scan</strong> to run the first scan.
                    </td>
                  </tr>
                )}
                {top.map((f, i) => (
                  <tr key={`${f.cve}-${i}`} className="border-b last:border-0 hover:bg-neutral-50 dark:hover:bg-neutral-900">
                    <td className="py-2 pr-3 font-bold tabular-nums" style={{ color: P_COLORS[f.priority] ?? '#94a3b8' }}>
                      {f.priority_score.toFixed(1)}
                    </td>
                    <td className="py-2 pr-3">
                      <span
                        className="rounded px-1.5 py-0.5 text-[10px] font-semibold text-white"
                        style={{ background: P_COLORS[f.priority] ?? '#94a3b8' }}
                      >
                        {f.priority}
                      </span>
                    </td>
                    <td className="py-2 pr-3 font-mono">{f.cve}</td>
                    <td className="py-2 pr-3">{f.asset_name}</td>
                    <td className="py-2 pr-3 text-neutral-500">
                      {f.pkg} ({f.installed})
                    </td>
                    <td className="py-2 pr-3 text-right tabular-nums">{f.cvss?.toFixed(1) ?? '—'}</td>
                    <td className="py-2 pr-3 text-right tabular-nums">
                      {f.epss ? `${(f.epss * 100).toFixed(1)}%` : '—'}
                    </td>
                    <td className="py-2">
                      {f.kev ? (
                        <span className="font-semibold text-red-600">●</span>
                      ) : (
                        <span className="text-neutral-300">—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {findings.length > top.length && (
            <p className="mt-2 text-right text-xs text-neutral-400">
              showing 8 of {findings.length} findings
            </p>
          )}
        </Card>

        {/* bottom row */}
        <div className="grid gap-4 lg:grid-cols-3">
          <Card title="Remediation tickets" subtitle="Open Gitea issues created by the n8n workflow">
            {tickets.length === 0 ? (
              <p className="py-6 text-center text-xs text-neutral-400">No open tickets yet.</p>
            ) : (
              <div className="space-y-2">
                {tickets.slice(0, 6).map((t) => (
                  <a
                    key={t.number}
                    href={t.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="block rounded border px-3 py-2 text-xs hover:bg-neutral-50 dark:hover:bg-neutral-900"
                  >
                    <span className="mr-2 font-mono text-neutral-400">#{t.number}</span>
                    {t.title}
                  </a>
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
