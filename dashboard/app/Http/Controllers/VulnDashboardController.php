<?php

namespace App\Http\Controllers;

use App\Services\GiteaTicketService;
use App\Services\RawReportService;
use App\Services\VerificationService;
use App\Services\VulnDataService;
use App\Services\VulnScanService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
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
     * Starts the remediation cycle. When n8n is the orchestrator the whole
     * A-to-Z pipeline (scan -> enrich -> tickets) is triggered through its
     * webhook; otherwise everything runs locally as a fallback.
     */
    public function scan(Request $request)
    {
        if (config('vulnmgmt.orchestrator') === 'n8n') {
            $response = Http::timeout(10)->post(
                config('vulnmgmt.n8n_scan_webhook'),
                ['mode' => 'pipeline', 'source' => 'dashboard']
            );

            if ($response->successful()) {
                return back()->with('success', 'Scan handed over to the n8n pipeline (scan → enrich → tickets).');
            }
        }

        $result = $this->scanService->start('local');

        if (! $result['started']) {
            return back()->with('warning', $result['reason']);
        }

        return back()->with('success', 'Local scan started (n8n unavailable, fallback mode).');
    }

    /** Live scan status for polling. */
    public function scanStatus()
    {
        return response()->json($this->scanService->status());
    }

    /** Phase 8: proof scan for one ticket (or all) — orchestrated by n8n when enabled. */
    public function verify(Request $request)
    {
        $validated = $request->validate([
            'ticket' => ['nullable', 'integer', 'min:1'],
        ]);

        if (config('vulnmgmt.orchestrator') === 'n8n') {
            // the n8n workflow verifies ONE ticket; for "verify all" we fire
            // one request per currently open ticket
            $targets = isset($validated['ticket'])
                ? [$validated['ticket']]
                : collect($this->tickets->openIssues())->pluck('number')->all();

            $ok = true;

            foreach ($targets as $number) {
                $response = Http::timeout(10)->post(
                    config('vulnmgmt.n8n_verify_webhook'),
                    ['ticket' => (int) $number]
                );

                $ok = $ok && $response->successful();
            }

            if ($ok && count($targets) > 0) {
                return back()->with('success', 'Proof scan delegated to the n8n verification workflow.');
            }
        }

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

    /** Accepted risk: dated, approved exception for one CVE. */
    public function acceptRisk(Request $request)
    {
        $validated = $request->validate([
            'cve' => ['required', 'string', 'starts_with:CVE-'],
            'until' => ['required', 'date', 'after:today'],
            'reason' => ['nullable', 'string', 'max:500'],
        ]);

        app(RawReportService::class)->addException([
            'cve' => $validated['cve'],
            'until' => $validated['until'],
            'approver' => auth()->user()?->name ?? 'admin',
            'reason' => $validated['reason'] ?? 'Accepted risk from dashboard',
        ]);

        return back()->with('success', $validated['cve'].' accepted as a risk until '.$validated['until'].'. It is now excluded from the pipeline.');
    }
}
