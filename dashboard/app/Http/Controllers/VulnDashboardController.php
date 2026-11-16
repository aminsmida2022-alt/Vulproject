<?php

namespace App\Http\Controllers;

use App\Services\VulnDataService;
use App\Services\VulnScanService;
use Illuminate\Http\Request;
use Inertia\Inertia;

class VulnDashboardController extends Controller
{
    public function __construct(
        private VulnDataService $data,
        private VulnScanService $scanService,
    ) {
    }

    public function index()
    {
        return Inertia::render('vuln-overview', [
            'stats' => $this->data->stats(),
            'findings' => $this->data->findings(),
            'inventory' => $this->data->inventory(),
            'history' => $this->data->scanHistory(),
            'scanStatus' => $this->scanService->status(),
        ]);
    }

    /**
     * Starts the scan immediately (detached) and redirects back;
     * the page polls GET /scan/status for live progress.
     */
    public function scan(Request $request)
    {
        $result = $this->scanService->start();

        if (! $result['started']) {
            return back()->with('warning', $result['reason']);
        }

        return back()->with('success', 'Scan started.');
    }

    /** Live scan status for polling. */
    public function scanStatus()
    {
        return response()->json($this->scanService->status());
    }
}
