import { Head, useForm } from '@inertiajs/react';
import { scan } from '@/routes/vuln';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Spinner } from '@/components/ui/spinner';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { cn } from '@/lib/utils';

type Finding = {
  cve: string;
  asset_name: string;
  pkg: string;
  installed: string;
  fixed: string | null;
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
  owner: string;
};

type History = {
  asset_id: string;
  findings: number;
  scanned_at: string;
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
};

const PRIORITY_STYLES: Record<string, string> = {
  'P1-CRITICAL': 'bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300',
  'P2-HIGH': 'bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-300',
  'P3-MEDIUM': 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300',
  'P4-LOW': 'bg-sky-100 text-sky-800 dark:bg-sky-950 dark:text-sky-300',
  'P5-INFORMATIONAL': 'bg-neutral-100 text-neutral-700 dark:bg-neutral-900 dark:text-neutral-300',
};

function scoreColor(score: number) {
  if (score >= 80) return 'bg-red-500';
  if (score >= 60) return 'bg-orange-500';
  if (score >= 40) return 'bg-amber-500';
  if (score >= 20) return 'bg-sky-500';
  return 'bg-neutral-400';
}

export default function VulnOverview({ stats, findings, inventory, history }: Props) {
  const scanForm = useForm({});

  const runScan = () => {
    scanForm.post(scan(), {
      preserveScroll: true,
      onSuccess: () => scanForm.reset(),
    });
  };

  return (
    <>
      <Head title="Vulnerability Management" />
      <div className="flex h-full flex-1 flex-col gap-4 overflow-x-auto rounded-xl p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">
              Vulnerability Management
            </h1>
            <p className="text-sm text-muted-foreground">
              Fix what matters, and prove it — P = 0.25·CVSS + 0.30·EPSS +
              0.25·KEV + 0.20·Asset
            </p>
          </div>
          <Button onClick={runScan} disabled={scanForm.processing}>
            {scanForm.processing ? (
              <>
                <Spinner className="size-4" />
                Scanning...
              </>
            ) : (
              'Start Scan'
            )}
          </Button>
        </div>

        {scanForm.errors.scan && (
          <div className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700 dark:border-red-900 dark:bg-red-950 dark:text-red-300">
            {scanForm.errors.scan}
          </div>
        )}

        {/* KPI cards */}
        <div className="grid auto-rows-min gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Card>
            <CardHeader className="pb-2">
              <CardDescription>Unique findings</CardDescription>
              <CardTitle className="text-3xl">{stats.total}</CardTitle>
            </CardHeader>
            <CardContent className="text-xs text-muted-foreground">
              across {stats.assets} scanned assets
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardDescription>KEV-listed (actively exploited)</CardDescription>
              <CardTitle className="text-3xl text-red-600">{stats.kev}</CardTitle>
            </CardHeader>
            <CardContent className="text-xs text-muted-foreground">
              CISA Known Exploited Vulnerabilities
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardDescription>P1 + P2 priorities</CardDescription>
              <CardTitle className="text-3xl">{stats.p1 + stats.p2}</CardTitle>
            </CardHeader>
            <CardContent className="text-xs text-muted-foreground">
              require remediation tickets
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardDescription>Highest priority score</CardDescription>
              <CardTitle className="text-3xl">
                {Number(stats.max_score ?? 0).toFixed(1)}
              </CardTitle>
            </CardHeader>
            <CardContent className="text-xs text-muted-foreground">
              out of 100 (contextual risk)
            </CardContent>
          </Card>
        </div>

        {/* Priority distribution */}
        <Card>
          <CardHeader>
            <CardTitle>Priority distribution</CardTitle>
            <CardDescription>
              Contextual risk ranking, not CVSS alone
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {[
              ['P1-CRITICAL', stats.p1],
              ['P2-HIGH', stats.p2],
              ['P3-MEDIUM', stats.p3],
              ['P4-LOW', stats.p4],
              ['P5-INFORMATIONAL', stats.p5],
            ].map(([label, count]) => {
              const key = label as keyof typeof PRIORITY_STYLES;
              const pct = stats.total ? ((count as number) / stats.total) * 100 : 0;
              return (
                <div key={key as string} className="flex items-center gap-3">
                  <Badge className={cn('w-36 justify-center', PRIORITY_STYLES[key])}>
                    {key}
                  </Badge>
                  <div className="h-3 flex-1 overflow-hidden rounded-full bg-neutral-100 dark:bg-neutral-800">
                    <div
                      className={cn('h-full rounded-full', scoreColor(count as number))}
                      style={{ width: `${Math.max(pct, 1)}%` }}
                    />
                  </div>
                  <span className="w-10 text-right text-sm tabular-nums">
                    {count as number}
                  </span>
                </div>
              );
            })}
          </CardContent>
        </Card>

        {/* Findings table */}
        <Card>
          <CardHeader>
            <CardTitle>Findings</CardTitle>
            <CardDescription>
              Ranked by contextual priority score
            </CardDescription>
          </CardHeader>
          <CardContent>
            {findings.length === 0 ? (
              <p className="py-8 text-center text-sm text-muted-foreground">
                No findings yet — click <strong>Start Scan</strong> to run the
                first Trivy scan.
              </p>
            ) : (
              <div className="max-h-[480px] overflow-auto rounded-md border">
                <Table>
                  <TableHeader className="sticky top-0 bg-background">
                    <TableRow>
                      <TableHead className="w-16">Score</TableHead>
                      <TableHead className="w-36">Priority</TableHead>
                      <TableHead>CVE</TableHead>
                      <TableHead>Asset</TableHead>
                      <TableHead>Package</TableHead>
                      <TableHead className="text-right">CVSS</TableHead>
                      <TableHead className="text-right">EPSS</TableHead>
                      <TableHead className="text-center">KEV</TableHead>
                      <TableHead>Fixed in</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {findings.map((f) => (
                      <TableRow key={`${f.cve}-${f.asset_id}-${f.pkg}`}>
                        <TableCell>
                          <span className={cn('font-semibold', scoreColor(f.priority_score).replace('bg-', 'text-'))}>
                            {f.priority_score.toFixed(1)}
                          </span>
                        </TableCell>
                        <TableCell>
                          <Badge
                            className={cn(
                              'justify-center',
                              PRIORITY_STYLES[f.priority] ?? PRIORITY_STYLES['P5-INFORMATIONAL'],
                            )}
                          >
                            {f.priority}
                          </Badge>
                        </TableCell>
                        <TableCell className="font-mono text-xs">{f.cve}</TableCell>
                        <TableCell>{f.asset_name}</TableCell>
                        <TableCell className="text-xs">
                          {f.pkg}
                          <span className="text-muted-foreground"> ({f.installed})</span>
                        </TableCell>
                        <TableCell className="text-right tabular-nums">
                          {f.cvss?.toFixed(1) ?? '—'}
                        </TableCell>
                        <TableCell className="text-right tabular-nums">
                          {f.epss ? `${(f.epss * 100).toFixed(1)}%` : '—'}
                        </TableCell>
                        <TableCell className="text-center">
                          {f.kev ? (
                            <Badge variant="destructive">KEV</Badge>
                          ) : (
                            <span className="text-xs text-muted-foreground">—</span>
                          )}
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          {f.fixed ?? <span className="text-red-500">no fix available</span>}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Assets + scan history */}
        <div className="grid gap-4 lg:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle>Asset inventory</CardTitle>
              <CardDescription>Isolated lab assets and importance</CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Asset</TableHead>
                    <TableHead>Image</TableHead>
                    <TableHead>Criticality</TableHead>
                    <TableHead className="text-right">Importance</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {inventory.map((a) => (
                    <TableRow key={a.asset_id}>
                      <TableCell className="font-medium">{a.name}</TableCell>
                      <TableCell className="font-mono text-xs">{a.image}</TableCell>
                      <TableCell>{a.criticality}</TableCell>
                      <TableCell className="text-right tabular-nums">
                        {a.importance}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Scan history</CardTitle>
              <CardDescription>Latest Trivy reports</CardDescription>
            </CardHeader>
            <CardContent>
              {history.length === 0 ? (
                <p className="py-8 text-center text-sm text-muted-foreground">
                  No scans yet.
                </p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Asset</TableHead>
                      <TableHead className="text-right">Findings</TableHead>
                      <TableHead className="text-right">Scanned at</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {history.map((h) => (
                      <TableRow key={h.asset_id}>
                        <TableCell className="font-medium">{h.asset_id}</TableCell>
                        <TableCell className="text-right tabular-nums">
                          {h.findings}
                        </TableCell>
                        <TableCell className="text-right text-xs text-muted-foreground">
                          {h.scanned_at}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </>
  );
}
