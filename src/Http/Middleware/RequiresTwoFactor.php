<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Http\Middleware;

use BetterAuth\Laravel\Guards\BetterAuthGuard;
use BetterAuth\Laravel\Services\TwoFactorService;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Ensure the authenticated user has completed 2FA verification.
 *
 * When 2FA is enabled for a user, this middleware checks that the
 * current token includes a valid 2FA verification claim.
 */
final class RequiresTwoFactor
{
    public function __construct(
        private readonly TwoFactorService $twoFactorService,
    ) {}

    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next): Response
    {
        $user = $request->user();

        if ($user === null) {
            return response()->json([
                'message' => 'Unauthenticated.',
                'error' => 'unauthenticated',
            ], 401);
        }

        if (! $this->twoFactorService->isEnabled($user)) {
            return $next($request);
        }

        $guard = auth()->guard('betterauth');

        $twoFactorVerified = $guard instanceof BetterAuthGuard
            ? $guard->getClaim('2fa_verified', false)
            : false;

        if (! $twoFactorVerified) {
            return response()->json([
                'message' => 'Two-factor authentication is required.',
                'error' => 'two_factor_required',
            ], 403);
        }

        return $next($request);
    }
}
