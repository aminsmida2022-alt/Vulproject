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
];
