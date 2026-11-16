<?php

use App\Services\VulnScanService;
use Illuminate\Foundation\Inspiring;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Schedule;

Artisan::command('inspire', function () {
    $this->comment(Inspiring::quote());
})->purpose('Display an inspiring quote');

// Phase 6: scheduled scan -> enrichment -> n8n tickets, every day
Artisan::command('vuln:scan', function (VulnScanService $scan) {
    $result = $scan->start();
    $this->info($result['started'] ? "Scan started (pid {$result['pid']})" : $result['reason']);
})->purpose('Start the Trivy scan + enrichment + n8n pipeline');

Schedule::command('vuln:scan')->dailyAt(config('vulnmgmt.scheduled_scan_at'));
