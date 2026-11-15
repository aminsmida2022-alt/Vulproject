<?php

namespace App\Services;

use Illuminate\Support\Facades\Cache;

/**
 * Reads the normalized vulnerability dataset produced by the
 * enrichment pipeline (scripts/enrich.py) and the asset inventory.
 */
class VulnDataService
{
    private string $basePath;

    public function __construct(?string $basePath = null)
    {
        $this->basePath = $basePath ?? config('vulnmgmt.project_path');
    }

    /** Enriched + prioritized findings (data/vulnerabilities/findings.json). */
    public function findings(): array
    {
        $path = $this->path('data/vulnerabilities/findings.json');

        if (! is_file($path)) {
            return [];
        }

        $findings = json_decode((string) file_get_contents($path), true) ?: [];

        // invalidate the cached stats when the dataset changes
        Cache::forget('vulnmgmt.stats');

        return $findings;
    }

    /** Asset inventory (data/assets/inventory.json). */
    public function inventory(): array
    {
        $path = $this->path('data/assets/inventory.json');

        if (! is_file($path)) {
            return [];
        }

        return json_decode((string) file_get_contents($path), true) ?: [];
    }

    /** Scan history from scanner/reports/*.json modification times. */
    public function scanHistory(): array
    {
        $dir = $this->path('scanner/reports');

        if (! is_dir($dir)) {
            return [];
        }

        $files = glob($dir.'/*.json') ?: [];
        usort($files, fn ($a, $b) => filemtime($b) <=> filemtime($a));

        return array_map(function ($file) {
            $data = json_decode((string) file_get_contents($file), true) ?: [];
            $count = 0;
            foreach ($data['Results'] ?? [] as $result) {
                $count += count($result['Vulnerabilities'] ?? []);
            }

            return [
                'asset_id' => basename($file, '.json'),
                'findings' => $count,
                'scanned_at' => date('Y-m-d H:i:s', filemtime($file)),
            ];
        }, $files);
    }

    /** Aggregated KPIs for the dashboard overview cards. */
    public function stats(): array
    {
        return Cache::remember('vulnmgmt.stats', now()->addMinutes(5), function () {
            $findings = $this->findings();

            $byPriority = collect($findings)->groupBy('priority')
                ->map->count()
                ->all();

            return [
                'total' => count($findings),
                'kev' => collect($findings)->where('kev', true)->count(),
                'p1' => $byPriority['P1-CRITICAL'] ?? 0,
                'p2' => $byPriority['P2-HIGH'] ?? 0,
                'p3' => $byPriority['P3-MEDIUM'] ?? 0,
                'p4' => $byPriority['P4-LOW'] ?? 0,
                'p5' => $byPriority['P5-INFORMATIONAL'] ?? 0,
                'assets' => collect($findings)->pluck('asset_id')->unique()->count(),
                'max_score' => collect($findings)->max('priority_score') ?? 0,
            ];
        });
    }

    public function path(string $relative): string
    {
        return $this->basePath.DIRECTORY_SEPARATOR.$relative;
    }
}
