<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

/**
 * Authenticate requests using the BetterAuth guard.
 *
 * Verifies the Paseto V4 token from the Authorization header
 * and rejects unauthenticated requests with a 401 response.
 */
final class Authenticate
{
    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next, string $guard = 'betterauth'): Response
    {
        if (! Auth::guard($guard)->check()) {
            return response()->json([
                'message' => 'Unauthenticated.',
                'error' => 'unauthenticated',
            ], 401);
        }

        return $next($request);
    }
}
