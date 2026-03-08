<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Http\Middleware;

use BetterAuth\Core\Interfaces\TokenSignerInterface;
use BetterAuth\Laravel\Services\BetterAuthManager;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Refresh Token Middleware.
 *
 * Automatically refreshes the access token if it's about to expire
 * and includes the new token in the response headers.
 */
final class RefreshToken
{
    /**
     * The threshold in seconds before expiration to trigger refresh.
     */
    private const REFRESH_THRESHOLD = 300; // 5 minutes

    public function __construct(
        private readonly TokenSignerInterface $tokenService,
        private readonly BetterAuthManager $auth,
    ) {}

    /**
     * Handle an incoming request.
     *
     * @param  \Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        // Only process successful responses
        if ($response->getStatusCode() >= 400) {
            return $response;
        }

        $token = $this->getTokenFromRequest($request);

        if ($token === null) {
            return $response;
        }

        try {
            $payload = $this->tokenService->decode($token);

            // Check if token is about to expire
            $exp = $payload['exp'] ?? 0;
            $timeUntilExpiry = $exp - time();

            if ($timeUntilExpiry > 0 && $timeUntilExpiry <= self::REFRESH_THRESHOLD) {
                // Token is about to expire, add header to notify client
                $response->headers->set('X-Token-Expiring', 'true');
                $response->headers->set('X-Token-Expires-In', (string) $timeUntilExpiry);
            }
        } catch (\Throwable) {
            // Ignore decode errors - the auth guard will handle invalid tokens
        }

        return $response;
    }

    /**
     * Get the token from the request.
     */
    private function getTokenFromRequest(Request $request): ?string
    {
        $header = $request->header('Authorization', '');

        if (str_starts_with($header, 'Bearer ')) {
            return substr($header, 7);
        }

        return null;
    }
}
