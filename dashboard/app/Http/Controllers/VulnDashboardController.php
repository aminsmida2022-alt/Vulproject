<?php

namespace App\Http\Controllers;

use App\Services\VulnDataService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Process;
use Inertia\Inertia;

class VulnDashboardController extends Controller
{
    public function __construct(private VulnDataService $data)
    {
    }

    public function index()
    {
        return Inertia::render('vuln-overview', [
            'stats' => $this->data->stats(),
            'findings' => $this->data->findings(),
            'inventory' => $this->data->inventory(),
            'history' => $this->data->scanHistory(),
        ]);
    }

    /**
     * Runs a full scan + enrichment synchronously (offline Trivy DB makes
     * this fast enough for the local lab).
     */
    public function scan(Request $request)
    {
        $root = config('vulnmgmt.project_path');

        $scan = Process::timeout(600)->run(
            'cd '.escapeshellarg($root).' && bash '.config('vulnmgmt.scan_script')
        );

        if ($scan->failed()) {
            return back()->withErrors([
                'scan' => 'Trivy scan failed: '.mb_substr($scan->errorOutput(), -400),
            ]);
        }

        $enrich = Process::timeout(300)->run(
            'cd '.escapeshellarg($root).' && '.config('vulnmgmt.enrich_script')
        );

        if ($enrich->failed()) {
            return back()->withErrors([
                'scan' => 'Enrichment failed: '.mb_substr($enrich->errorOutput(), -400),
            ]);
        }

        return back()->with('success', 'Scan and enrichment completed.');
    }
}
