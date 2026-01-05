<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

/**
 * BetterAuth Authentication Middleware.
 *
 * Ensures the request has a valid Paseto V4 token.
 */
final class BetterAuthAuthenticate
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next, string $guard = 'betterauth'): Response
    {
        $user = Auth::guard($guard)->user();

        if ($user === null) {
            return response()->json([
                'message' => 'Unauthenticated',
                'error' => 'token_missing_or_invalid',
            ], 401);
        }

        return $next($request);
    }
}
