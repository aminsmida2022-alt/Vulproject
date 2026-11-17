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
    ) {}

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

    /**
     * POST /api/agent/verifications — n8n records a proof-scan result so the
     * dashboard evidence panel and the audit trail include n8n verifications.
     * Body: {ticket, cve, asset, still_present, scanned_at, total_findings_in_scan}
     */
    public function storeVerification(Request $request)
    {
        $this->authorize($request);

        $v = $request->validate([
            'ticket' => ['required', 'integer', 'min:1'],
            'cve' => ['required', 'string', 'regex:/^CVE-\d{4}-\d+$/'],
            'asset' => ['required', 'string', 'max:100'],
            'still_present' => ['required', 'boolean'],
            'scanned_at' => ['nullable', 'string', 'max:40'],
            'total_findings_in_scan' => ['nullable', 'integer', 'min:0'],
        ]);

        $asset = collect($this->data->inventory())->firstWhere('name', $v['asset']) ?? [];
        $root = config('vulnmgmt.project_path');
        $now = now()->utc();
        $evidenceFile = sprintf('tickets/evidence/%d-%s.json', $v['ticket'], $now->format('Ymd\THis\Z'));

        $evidence = [
            'ticket' => $v['ticket'],
            'cve' => $v['cve'],
            'asset_id' => $asset['asset_id'] ?? null,
            'asset_name' => $v['asset'],
            'image' => $asset['image'] ?? null,
            'scanned_at' => $v['scanned_at'] ?? null,
            'scanner' => 'trivy (n8n proof scan)',
            'total_findings' => $v['total_findings_in_scan'] ?? null,
            'verified_at' => $now->toIso8601String(),
            'result' => $v['still_present'] ? 'still-present' : 'fixed',
            'verified_by' => 'n8n Remediation Verification',
        ];

        if (! is_dir($root.'/tickets/evidence')) {
            mkdir($root.'/tickets/evidence', 0775, true);
        }
        file_put_contents($root.'/'.$evidenceFile, json_encode($evidence, JSON_PRETTY_PRINT));

        $logLine = collect($evidence)->only(['ticket', 'cve', 'asset_id', 'image', 'result', 'verified_at'])
            ->put('evidence_file', $evidenceFile)
            ->all();
        file_put_contents($root.'/tickets/verification_log.jsonl', json_encode($logLine)."\n", FILE_APPEND | LOCK_EX);

        return response()->json(['recorded' => true, 'evidence_file' => $evidenceFile], 201);
    }
}
