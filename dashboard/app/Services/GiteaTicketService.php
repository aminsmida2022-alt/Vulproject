<?php

namespace App\Services;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;

/**
 * Reads remediation tickets from the Gitea repository
 * (created by the n8n SOAR workflow).
 */
class GiteaTicketService
{
    public function openIssues(): array
    {
        return $this->issues('open');
    }

    public function closedIssues(): array
    {
        return $this->issues('closed', 10);
    }

    private function issues(string $state, int $limit = 50): array
    {
        $cfg = config('vulnmgmt.gitea');
        $base = rtrim($cfg['url'], '/');

        try {
            $response = Http::withToken($cfg['token'], 'token')
                ->timeout(10)
                ->get("{$base}/api/v1/repos/{$cfg['repo']}/issues", [
                    'state' => $state,
                    'limit' => $limit,
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
                'closed_at' => isset($i['closed_at']) ? substr($i['closed_at'], 0, 16) : null,
                'due_date' => isset($i['due_date']) ? substr($i['due_date'], 0, 10) : null,
                'labels' => collect($i['labels'] ?? [])->map(fn ($l) => [
                    'name' => $l['name'],
                    'color' => '#'.ltrim($l['color'], '#'),
                ])->all(),
                'body' => Str::of($i['body'] ?? '')->stripTags()->limit(300)->toString(),
            ])
            ->values()
            ->all();
    }
}
