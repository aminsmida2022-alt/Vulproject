<?php

namespace App\Http\Controllers;

use App\Services\GiteaTicketService;
use App\Services\VerificationService;
use App\Services\VulnDataService;
use App\Services\VulnScanService;
use Illuminate\Http\Request;
use Inertia\Inertia;

class VulnDashboardController extends Controller
{
    public function __construct(
        private VulnDataService $data,
        private VulnScanService $scanService,
        private GiteaTicketService $tickets,
        private VerificationService $verification,
    ) {}

    public function index()
    {
        return Inertia::render('vuln-overview', [
            'stats' => $this->data->stats(),
            'findings' => $this->data->findings(),
            'inventory' => $this->data->inventory(),
            'history' => $this->data->scanHistory(),
            'scanStatus' => $this->scanService->status(),
            'tickets' => $this->tickets->openIssues(),
            'closedTickets' => $this->tickets->closedIssues(),
            'verifyStatus' => $this->verification->status(),
            'verifications' => $this->verification->history(),
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

    /** Phase 8: rescan + close/keep-open one ticket (or all open ones). */
    public function verify(Request $request)
    {
        $validated = $request->validate([
            'ticket' => ['nullable', 'integer', 'min:1'],
        ]);

        $result = $this->verification->start($validated['ticket'] ?? null);

        if (! $result['started']) {
            return back()->with('warning', $result['reason']);
        }

        return back()->with('success', 'Verification started.');
    }

    public function verifyStatus()
    {
        return response()->json($this->verification->status());
    }
}
