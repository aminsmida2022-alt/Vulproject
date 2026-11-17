<?php

namespace App\Services;

use Illuminate\Support\Str;

/**
 * Runs the Trivy scan + enrichment pipeline asynchronously and tracks
 * its progress in storage/app/vulnmgmt so the dashboard can poll it.
 */
class VulnScanService
{
    public function __construct(private VulnDataService $data)
    {
    }

    private function dir(): string
    {
        $dir = storage_path('app/vulnmgmt');
        if (! is_dir($dir)) {
            mkdir($dir, 0775, true);
        }

        return $dir;
    }

    private function statusFile(): string
    {
        return $this->dir().'/scan.json';
    }

    private function logFile(): string
    {
        return $this->dir().'/scan.log';
    }

    /**
     * Launch the scan detached. Returns false if one is already running.
     *
     * Modes:
     *  - "pipeline": Trivy only — n8n orchestrates enrichment afterwards
     *                and POSTs the final findings (state 'enriching' until then).
     *  - "local":    Trivy + enrich.py + notify n8n (legacy fallback).
     */
    public function start(string $mode = 'pipeline'): array
    {
        if ($this->isRunning()) {
            return ['started' => false, 'reason' => 'A scan is already running.'];
        }

        $root = config('vulnmgmt.project_path');
        $log = $this->logFile();
        @touch($log);

        if ($mode === 'local') {
            $pipeline = 'bash '.config('vulnmgmt.scan_script').' && '.
                config('vulnmgmt.enrich_script').' && '.
                'curl -sf -m 30 -X POST -H "Content-Type: application/json" '.
                '--data-binary @data/vulnerabilities/findings.json '.
                config('vulnmgmt.n8n_webhook').' || true';
        } else {
            // n8n handles enrichment + ticketing; we stop after Trivy
            $pipeline = 'bash '.config('vulnmgmt.scan_script');
        }

        $cmd = sprintf(
            'nohup bash -c %s > %s 2>&1 & echo $!',
            escapeshellarg('cd '.escapeshellarg($root).' && '.$pipeline),
            escapeshellarg($log)
        );

        $pid = (int) trim((string) shell_exec($cmd));

        if ($pid <= 0) {
            return ['started' => false, 'reason' => 'Failed to launch the scan process.'];
        }

        $this->writeStatus([
            'pid' => $pid,
            'state' => 'running',
            'mode' => $mode,
            'started_at' => now()->toDateTimeString(),
            'log_file' => $log,
        ]);

        return ['started' => true, 'pid' => $pid, 'mode' => $mode];
    }

    /** Called by the agent API once n8n finishes the enrichment phase. */
    public function markCompleted(string $state = 'done'): void
    {
        $status = $this->readStatus();

        if ($status === null) {
            return;
        }

        $status['state'] = $state;
        $status['finished_at'] = now()->toDateTimeString();
        $this->writeStatus($status);
    }

    /** Current scan state + parsed progress + log tail. */
    public function status(): array
    {
        $status = $this->readStatus();

        if ($status === null) {
            return ['state' => 'idle', 'progress' => [], 'log' => []];
        }

        $pid = $status['pid'] ?? 0;

        if ($status['state'] === 'running' && ! $this->pidAlive($pid)) {
            // process ended since last check — decide the outcome from the log
            $log = file_exists($status['log_file'])
                ? (string) file_get_contents($status['log_file'])
                : '';

            $failed = str_contains($log, 'FATAL') ||
                str_contains($log, 'Traceback (most recent call last)');

            if ($failed) {
                $status['state'] = 'failed';
                $status['finished_at'] = now()->toDateTimeString();
                $this->writeStatus($status);
            } elseif (($status['mode'] ?? 'local') === 'pipeline') {
                // Trivy finished; n8n is now enriching + creating tickets
                $status['state'] = 'enriching';
                $this->writeStatus($status);
            } else {
                $status['state'] = 'done';
                $status['finished_at'] = now()->toDateTimeString();
                $this->writeStatus($status);
            }
        }

        $log = file_exists($status['log_file'])
            ? (string) file_get_contents($status['log_file'])
            : '';

        return [
            'state' => $status['state'],
            'mode' => $status['mode'] ?? 'local',
            'started_at' => $status['started_at'] ?? null,
            'progress' => $this->parseProgress($log),
            'log' => $this->tail($log, 20),
            'errors' => $this->parseErrors($log),
        ];
    }

    public function isRunning(): bool
    {
        $status = $this->readStatus();

        if ($status === null) {
            return false;
        }

        if (in_array($status['state'] ?? '', ['running', 'enriching'], true)) {
            return true;
        }

        return false;
    }

    /** Parse "[*] Scanning <image> -> <reports>/<asset>.json" lines. */
    private function parseProgress(string $log): array
    {
        $inventory = collect($this->data->inventory());

        $scanned = [];
        preg_match_all('/\[\*\] Scanning (\S+) -> \S+\/([a-z0-9-]+)\.json/', $log, $m, PREG_SET_ORDER);
        foreach ($m as $match) {
            $scanned[$match[2]] = true;
        }

        $enriched = str_contains($log, 'enriched findings ->');

        return $inventory->map(function ($asset) use ($scanned, $enriched) {
            $state = 'pending';

            if (isset($scanned[$asset['asset_id']])) {
                $state = 'scanned';
            }

            if ($enriched) {
                $state = 'done';
            }

            return [
                'asset_id' => $asset['asset_id'],
                'name' => $asset['name'],
                'image' => $asset['image'],
                'state' => $state,
            ];
        })->all();
    }

    private function parseErrors(string $log): array
    {
        return collect(explode("\n", $log))
            ->filter(fn ($line) => str_contains($line, 'FATAL')
                || str_contains($line, 'ERROR')
                || str_starts_with($line, 'Traceback'))
            ->take(-5)
            ->values()
            ->all();
    }

    private function tail(string $log, int $lines): array
    {
        $parts = array_values(array_filter(explode("\n", $log), fn ($l) => trim($l) !== ''));

        return array_slice($parts, -$lines);
    }

    private function pidAlive(int $pid): bool
    {
        if ($pid <= 0) {
            return false;
        }

        return @file_exists('/proc/'.(int) $pid);
    }

    private function readStatus(): ?array
    {
        if (! is_file($this->statusFile())) {
            return null;
        }

        $decoded = json_decode((string) file_get_contents($this->statusFile()), true);

        return is_array($decoded) ? $decoded : null;
    }

    private function writeStatus(array $status): void
    {
        file_put_contents($this->statusFile(), json_encode($status, JSON_PRETTY_PRINT));
    }
}
