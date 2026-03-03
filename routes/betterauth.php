<?php

declare(strict_types=1);

use BetterAuth\Laravel\Http\Controllers\AuthController;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| BetterAuth Routes
|--------------------------------------------------------------------------
|
| These routes are loaded by the BetterAuthServiceProvider.
| You can customize the prefix and middleware in config/betterauth.php
|
*/

$config = config('betterauth.routes', []);
$prefix = $config['prefix'] ?? 'auth';
$middleware = $config['middleware'] ?? ['api'];
$namePrefix = $config['name_prefix'] ?? 'betterauth.';

Route::prefix($prefix)
    ->middleware($middleware)
    ->name($namePrefix)
    ->group(function (): void {
        // Public routes
        Route::post('/register', [AuthController::class, 'register'])
            ->middleware('throttle:betterauth-register')
            ->name('register');

        Route::post('/login', [AuthController::class, 'login'])
            ->middleware('throttle:betterauth-login')
            ->name('login');

        Route::post('/refresh', [AuthController::class, 'refresh'])
            ->middleware('throttle:betterauth-refresh')
            ->name('refresh');

        // Protected routes
        Route::middleware('auth:betterauth')->group(function (): void {
            Route::get('/me', [AuthController::class, 'me'])
                ->name('me');

            Route::post('/logout', [AuthController::class, 'logout'])
                ->name('logout');

            Route::post('/revoke-all', [AuthController::class, 'revokeAll'])
                ->name('revoke-all');

            Route::put('/password', [AuthController::class, 'updatePassword'])
                ->name('password.update');
        });

        // OAuth routes (when enabled)
        if (config('betterauth.oauth.enabled', false)) {
            Route::get('/oauth/{provider}', [AuthController::class, 'oauthRedirect'])
                ->middleware('throttle:betterauth-oauth')
                ->name('oauth.redirect');

            Route::get('/oauth/{provider}/callback', [AuthController::class, 'oauthCallback'])
                ->middleware('throttle:betterauth-oauth')
                ->name('oauth.callback');
        }

        // Magic Link routes (when enabled)
        if (config('betterauth.magic_links.enabled', false)) {
            Route::post('/magic-link', [\BetterAuth\Laravel\Http\Controllers\MagicLinkController::class, 'send'])
                ->middleware('throttle:betterauth-magic-link-send')
                ->name('magic-link.send');

            Route::match(['get', 'post'], '/magic-link/verify', [\BetterAuth\Laravel\Http\Controllers\MagicLinkController::class, 'verify'])
                ->middleware('throttle:betterauth-magic-link-verify')
                ->name('magic-link.verify');

            Route::post('/magic-link/check', [\BetterAuth\Laravel\Http\Controllers\MagicLinkController::class, 'check'])
                ->middleware('throttle:betterauth-magic-link-check')
                ->name('magic-link.check');
        }

        // 2FA routes (when enabled)
        if (config('betterauth.2fa.enabled', false)) {
            Route::middleware('auth:betterauth')->prefix('2fa')->name('2fa.')->group(function (): void {
                Route::get('/status', [\BetterAuth\Laravel\Http\Controllers\TwoFactorController::class, 'status'])
                    ->name('status');

                Route::post('/setup', [\BetterAuth\Laravel\Http\Controllers\TwoFactorController::class, 'setup'])
                    ->name('setup');

                Route::post('/enable', [\BetterAuth\Laravel\Http\Controllers\TwoFactorController::class, 'enable'])
                    ->name('enable');

                Route::post('/verify', [\BetterAuth\Laravel\Http\Controllers\TwoFactorController::class, 'verify'])
                    ->name('verify');

                Route::post('/recovery', [\BetterAuth\Laravel\Http\Controllers\TwoFactorController::class, 'recovery'])
                    ->name('recovery');

                Route::post('/recovery-codes', [\BetterAuth\Laravel\Http\Controllers\TwoFactorController::class, 'regenerateRecoveryCodes'])
                    ->name('recovery-codes');

                Route::delete('/', [\BetterAuth\Laravel\Http\Controllers\TwoFactorController::class, 'disable'])
                    ->name('disable');
            });
        }
    });
