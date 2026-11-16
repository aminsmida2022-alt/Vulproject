<?php

namespace App\Services;

use Illuminate\Support\Facades\Http;

/**
 * Reads remediation tickets from the Gitea repository
 * (created by the n8n SOAR workflow).
 */
class GiteaTicketService
{
    public function openIssues(): array
    {
        $cfg = config('vulnmgmt.gitea');
        $base = rtrim($cfg['url'], '/');

        try {
            $response = Http::withToken($cfg['token'], 'token')
                ->timeout(10)
                ->get("{$base}/api/v1/repos/{$cfg['repo']}/issues", [
                    'state' => 'open',
                    'limit' => 50,
                    'type' => 'issues',
                ]);
        } catch (\Throwable) {
            return [];
        }

        if (! $response->successful()) {
            return [];
        }

        return collect($response->json())
            ->filter(fn ($i) => ($i['pull_request'] ?? null) === null)
            ->map(fn ($i) => [
                'number' => $i['number'],
                'title' => $i['title'],
                'url' => $i['html_url'],
                'state' => $i['state'],
                'created_at' => substr($i['created_at'], 0, 16),
                'body' => Str::of($i['body'] ?? '')->stripTags()->limit(0),
            ])
            ->values()
            ->all();
    }

    public function closedIssues(): array
    {
        return [];
    }
}
