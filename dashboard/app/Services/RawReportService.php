<?php

namespace App\Services;

/**
 * Reads Trivy reports and serves raw (un-enriched) findings to the
 * n8n orchestrator, which performs dedupe, EPSS/KEV enrichment and
 * priority scoring. Also serves asset inventory + KEV set.
 */
class RawReportService
{
    public function __construct(private VulnDataService $data)
    {
    }

    /** All findings from all Trivy reports, normalized, duplicates included. */
    public function rawFindings(): array
    {
        $inventory = collect($this->data->inventory())->keyBy('asset_id');
        $dir = $this->data->path('scanner/reports');
        $out = [];

        foreach (glob($dir.'/*.json') ?: [] as $file) {
            $assetId = basename($file, '.json');
            $asset = $inventory->get($assetId);

            $report = json_decode((string) file_get_contents($file), true) ?: [];

            foreach ($report['Results'] ?? [] as $result) {
                foreach ($result['Vulnerabilities'] ?? [] as $v) {
                    $cve = $v['VulnerabilityID'] ?? '';
                    if (! str_starts_with($cve, 'CVE-')) {
                        continue;
                    }

                    $cvss = $v['CVSS']['nvd']['V3Score']
                        ?? $v['CVSS']['redhat']['V3Score']
                        ?? $v['CVSS']['ghsa']['V3Score']
                        ?? null;

                    $out[] = [
                        'cve' => $cve,
                        'asset_id' => $assetId,
                        'asset_name' => $asset['name'] ?? $assetId,
                        'importance' => $asset['importance'] ?? 50,
                        'asset_criticality' => $asset['criticality'] ?? 'Medium',
                        'pkg' => $v['PkgName'] ?? null,
                        'installed' => $v['InstalledVersion'] ?? null,
                        'fixed' => $v['FixedVersion'] ?? null,
                        'cvss' => $cvss,
                        'severity' => $v['Severity'] ?? 'UNKNOWN',
                        'title' => $v['Title'] ?? Str((string) ($v['Description'] ?? ''))->limit(120),
                        'status' => $v['Status'] ?? 'unknown',
                    ];
                }
            }
        }

        return $out;
    }

    /** CISA KEV CVE set, cached locally, refreshed weekly. */
    public function kevCves(): array
    {
        $cache = $this->data->path('data/vulnerabilities/kev_cache.json');
        $maxAge = 7 * 86400;

        if (is_file($cache) && (time() - filemtime($cache)) < $maxAge) {
            $data = json_decode((string) file_get_contents($cache), true) ?: [];
        } else {
            $ctx = stream_context_create(['http' => ['timeout' => 60]]);
            $raw = @file_get_contents(
                'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
                false,
                $ctx
            );
            if ($raw === false && is_file($cache)) {
                $data = json_decode((string) file_get_contents($cache), true) ?: [];
            } else {
                $data = $raw !== false ? (json_decode($raw, true) ?: []) : [];
                @file_put_contents($cache, json_encode($data));
            }
        }

        return array_values(array_filter(
            array_column($data['vulnerabilities'] ?? [], 'cveID')
        ));
    }

    /** Accepted-risk exceptions (cve => until). Written via agent API. */
    public function exceptions(): array
    {
        $path = $this->data->path('data/vulnerabilities/exceptions.json');

        if (! is_file($path)) {
            return [];
        }

        $list = json_decode((string) file_get_contents($path), true) ?: [];

        // drop expired exceptions on read
        $today = date('Y-m-d');

        return collect($list)->reject(fn ($e) => ($e['until'] ?? '0000-00-00') < $today)->values()->all();
    }

    public function addException(array $exception): array
    {
        $path = $this->data->path('data/vulnerabilities/exceptions.json');
        $list = is_file($path) ? (json_decode((string) file_get_contents($path), true) ?: []) : [];

        $list = collect($list)->reject(fn ($e) => $e['cve'] === $exception['cve'])->all();
        $list[] = [
            'cve' => $exception['cve'],
            'until' => $exception['until'],
            'approver' => $exception['approver'] ?? 'admin',
            'reason' => $exception['reason'] ?? '',
            'created_at' => now()->toDateTimeString(),
        ];
        file_put_contents($path, json_encode(array_values($list), JSON_PRETTY_PRINT));

        return $this->exceptions();
    }
}

use Illuminate\Support\Str;
