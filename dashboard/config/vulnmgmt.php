<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Vulnerability Management configuration
    |--------------------------------------------------------------------------
    |
    | Absolute path to the vulnerability-management project root, where the
    | enrichment pipeline writes data/vulnerabilities/findings.json and the
    | Trivy reports live under scanner/reports/.
    |
    */
    'project_path' => env('VULNMGMT_PROJECT_PATH', dirname(__DIR__, 2)),

    /*
    | Pipeline commands, run from the project root by the dashboard.
    */
    'scan_script' => 'scanner/scan_all.sh',
    'enrich_script' => 'python3 scripts/enrich.py',
    'verify_script' => 'python3 scripts/verify.py',

    /*
    | Daily automatic scan (Laravel scheduler, needs `php artisan schedule:work`
    | or a cron entry running `php artisan schedule:run` every minute).
    */
    'scheduled_scan_at' => env('VULNMGMT_SCAN_AT', '02:00'),

    /*
    | SOAR integration: n8n webhook that receives the enriched findings
    | after every scan, and Gitea API for the tickets panel.
    */
    'n8n_webhook' => env('VULNMGMT_N8N_WEBHOOK', 'http://localhost:5678/webhook/vuln-findings'),
    'n8n_scan_webhook' => env('VULNMGMT_N8N_SCAN_WEBHOOK', 'http://localhost:5678/webhook/scan-request'),
    'n8n_verify_webhook' => env('VULNMGMT_N8N_VERIFY_WEBHOOK', 'http://localhost:5678/webhook/verify-request'),

    // 'n8n' = n8n orchestrates the whole pipeline (scan -> enrich -> tickets)
    // 'local' = everything runs locally as a fallback
    'orchestrator' => env('VULNMGMT_ORCHESTRATOR', 'n8n'),

    // shared secret between Laravel and n8n (X-Agent-Token header)
    'agent_token' => env('VULNMGMT_AGENT_TOKEN', '***REMOVED***'),

    'gitea' => [
        'url' => env('VULNMGMT_GITEA_URL', 'http://localhost:3001'),
        'token' => env('VULNMGMT_GITEA_TOKEN', ''),
        'repo' => env('VULNMGMT_GITEA_REPO', 'vulnadmin/remediation-tickets'),
    ],
];
