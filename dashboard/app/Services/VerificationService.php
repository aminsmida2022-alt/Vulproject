<?php

namespace App\Services;

/**
 * Runs the remediation verification (scripts/verify.py) detached:
 * rescan the asset, close the ticket with evidence if the CVE is gone,
 * keep it open with evidence otherwise.
 */
class VerificationService
{
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
        return $this->dir().'/verify.json';
    }

    private function logFile(): string
    {
        return $this->dir().'/verify.log';
    }

    /** @param  int|null  $ticket  null = verify every open ticket */
    public function start(?int $ticket): array
    {
        if ($this->isRunning()) {
            return ['started' => false, 'reason' => 'A verification is already running.'];
        }

        $root = config('vulnmgmt.project_path');
        $target = $ticket === null ? '--all' : '--ticket '.(int) $ticket;

        $inner = 'cd '.escapeshellarg($root).' && '
            .'GITEA_URL='.escapeshellarg(config('vulnmgmt.gitea.url')).' '
            .'GITEA_REPO='.escapeshellarg(config('vulnmgmt.gitea.repo')).' '
            .'GITEA_TOKEN='.escapeshellarg((string) config('vulnmgmt.gitea.token')).' '
            .config('vulnmgmt.verify_script').' '.$target;

        $cmd = sprintf('nohup bash -c %s > %s 2>&1 & echo $!',
            escapeshellarg($inner), escapeshellarg($this->logFile()));

        $pid = (int) trim((string) shell_exec($cmd));

        if ($pid <= 0) {
            return ['started' => false, 'reason' => 'Failed to launch the verification.'];
        }

        file_put_contents($this->statusFile(), json_encode([
            'pid' => $pid,
            'ticket' => $ticket,
            'state' => 'running',
            'started_at' => now()->toDateTimeString(),
        ]));

        return ['started' => true, 'pid' => $pid];
    }

    public function status(): array
    {
        $status = $this->readStatus();

        if ($status === null) {
            return ['state' => 'idle', 'ticket' => null, 'log' => []];
        }

        $log = is_file($this->logFile()) ? (string) file_get_contents($this->logFile()) : '';

        if ($status['state'] === 'running' && ! $this->pidAlive($status['pid'] ?? 0)) {
            $status['state'] = (str_contains($log, 'FATAL') || str_contains($log, 'Traceback'))
                ? 'failed' : 'done';
            file_put_contents($this->statusFile(), json_encode($status));
        }

        $lines = array_values(array_filter(explode("\n", $log), fn ($l) => trim($l) !== ''));

        return [
            'state' => $status['state'],
            'ticket' => $status['ticket'] ?? null,
            'started_at' => $status['started_at'] ?? null,
            'log' => array_slice($lines, -12),
        ];
    }

    public function isRunning(): bool
    {
        $status = $this->readStatus();

        return $status !== null
            && ($status['state'] ?? '') === 'running'
            && $this->pidAlive($status['pid'] ?? 0);
    }

    /** Latest verification results from tickets/verification_log.jsonl. */
    public function history(int $limit = 10): array
    {
        $file = config('vulnmgmt.project_path').'/tickets/verification_log.jsonl';

        if (! is_file($file)) {
            return [];
        }

        $rows = array_filter(array_map(
            fn ($line) => json_decode($line, true),
            file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: []
        ));

        return array_slice(array_reverse(array_values($rows)), 0, $limit);
    }

    private function pidAlive(int $pid): bool
    {
        return $pid > 0 && file_exists('/proc/'.$pid);
    }

    private function readStatus(): ?array
    {
        if (! is_file($this->statusFile())) {
            return null;
        }

        $decoded = json_decode((string) file_get_contents($this->statusFile()), true);

        return is_array($decoded) ? $decoded : null;
    }
}
