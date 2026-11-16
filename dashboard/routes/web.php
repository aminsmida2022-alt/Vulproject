<?php

use App\Http\Controllers\VulnDashboardController;
use Illuminate\Support\Facades\Route;

Route::get('/', [VulnDashboardController::class, 'index'])->name('home');
Route::post('/scan', [VulnDashboardController::class, 'scan'])
    ->name('vuln.scan');
Route::get('/scan/status', [VulnDashboardController::class, 'scanStatus'])
    ->name('vuln.status');
Route::post('/tickets/verify', [VulnDashboardController::class, 'verify'])
    ->name('vuln.verify');
Route::get('/tickets/verify/status', [VulnDashboardController::class, 'verifyStatus'])
    ->name('vuln.verify.status');

Route::middleware(['auth'])->group(function () {
    Route::inertia('dashboard', 'dashboard')->name('dashboard');
});

require __DIR__.'/settings.php';
