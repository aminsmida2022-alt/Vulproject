<?php

use App\Http\Controllers\Api\AgentController;
use Illuminate\Support\Facades\Route;

/*
| n8n SOAR agent API — token-protected machine routes.
*/
Route::prefix('agent')->group(function () {
    Route::post('scan/start', [AgentController::class, 'startScan']);
    Route::get('scan/status', [AgentController::class, 'scanStatus']);
    Route::get('reports/raw', [AgentController::class, 'rawReports']);
    Route::get('assets', [AgentController::class, 'assets']);
    Route::get('kev', [AgentController::class, 'kev']);
    Route::get('exceptions', [AgentController::class, 'exceptions']);
    Route::post('exceptions', [AgentController::class, 'addException']);
    Route::post('findings', [AgentController::class, 'storeFindings']);
    Route::get('open-tickets', [AgentController::class, 'openTickets']);
    Route::post('verifications', [AgentController::class, 'storeVerification']);
});
