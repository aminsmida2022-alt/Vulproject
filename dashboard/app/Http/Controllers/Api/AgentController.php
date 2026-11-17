<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Services\GiteaTicketService;
use App\Services\RawReportService;
use App\Services\VulnDataService;
use App\Services\VulnScanService;
use Illuminate\Http\Request;

/**
 * Machine-to-machine API used by the n8n SOAR orchestrator.
 * Every route requires the X-Agent-Token header.
 */
class AgentController extends Controller
{
    public function __construct(
        private VulnDataService $data,
        private RawReportService $reports,
        private VulnScanService $scan,
        private GiteaTicketService $tickets,
    ) {
    }

    private function authorize(Request $request): void
    {
        abort_unless(
            $request->header('X-Agent-Token') === config('vulnmgmt.agent_token'),
            401,
            'Invalid agent token'
        );
    }

    /** POST /api/agent/scan/start — body: {"mode": "pipeline"|"raw"} */
    public function startScan(Request $request)
    {
        $this->authorize($request);

        $mode = $request->input('mode', 'pipeline');

        $result = $this->scan->start($mode);

        return response()->json($result, $result['started'] ? 202 : 409);
    }

    /** GET /api/agent/scan/status */
    public function scanStatus(Request $request)
    {
        $this->authorize($request);

        return response()->json($this->scan->status());
    }

    /** GET /api/agent/reports/raw — un-enriched findings, duplicates included */
    public function rawReports(Request $request)
    {
        $this->authorize($request);

        return response()->json($this->reports->rawFindings());
    }

    /** GET /api/agent/assets — {"assets": [...]} (object so n8n always gets 1 item) */
    public function assets(Request $request)
    {
        $this->authorize($request);

        return response()->json([
            'count' => count($this->data->inventory()),
            'assets' => $this->data->inventory(),
        ]);
    }

    /** GET /api/agent/kev — {"cves": [...]} */
    public function kev(Request $request)
    {
        $this->authorize($request);

        return response()->json([
            'count' => count($this->reports->kevCves()),
            'cves' => $this->reports->kevCves(),
        ]);
    }

    /** GET /api/agent/exceptions — {"exceptions": [...]} (object so n8n always gets 1 item) */
    public function exceptions(Request $request)
    {
        $this->authorize($request);

        $list = $this->reports->exceptions();

        return response()->json([
            'count' => count($list),
            'exceptions' => $list,
        ]);
    }

    /** POST /api/agent/exceptions — {cve, until, approver, reason} */
    public function addException(Request $request)
    {
        $this->authorize($request);

        $request->validate([
            'cve' => ['required', 'string', 'starts_with:CVE-'],
            'until' => ['required', 'date', 'after:today'],
            'reason' => ['nullable', 'string', 'max:500'],
        ]);

        return response()->json([
            'added' => true,
            'exceptions' => $this->reports->addException($request->all()),
        ]);
    }

    /**
     * POST /api/agent/findings — the n8n pipeline posts the final
     * enriched dataset here; we persist it and close the scan cycle.
     */
    public function storeFindings(Request $request)
    {
        $this->authorize($request);

        $findings = $request->input('findings');

        abort_unless(is_array($findings), 422, 'findings array required');

        $path = $this->data->path('data/vulnerabilities/findings.json');
        @mkdir(dirname($path), 0775, true);
        file_put_contents($path, json_encode(array_values($findings), JSON_PRETTY_PRINT));

        // close the scan cycle: pipeline enrichment finished
        $this->scan->markCompleted('done');

        return response()->json(['stored' => count($findings)]);
    }

    /** GET /api/agent/open-tickets — current Gitea tickets (for verification flows) */
    public function openTickets(Request $request)
    {
        $this->authorize($request);

        return response()->json($this->tickets->openIssues());
    }
}
