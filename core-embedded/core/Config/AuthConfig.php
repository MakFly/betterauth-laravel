<?php

declare(strict_types=1);

namespace BetterAuth\Core\Config;

/**
 * Authentication configuration supporting monolith, API, and hybrid modes.
 */
class AuthConfig
{
    public function __construct(
        public readonly AuthMode $mode = AuthMode::MONOLITH,
        public readonly string $secretKey = '',
        public readonly int $sessionLifetime = 604800, // 7 days
        public readonly int $sessionAbsoluteLifetime = 2592000, // 30 days — hard cap regardless of activity
        public readonly int $tokenLifetime = 3600, // 1 hour for API tokens
        public readonly int $refreshTokenLifetime = 2592000, // 30 days
        public readonly bool $enableRefreshTokens = true,
        public readonly string $cookieName = 'better_auth_session',
        public readonly bool $cookieHttpOnly = true,
        public readonly bool $cookieSecure = true,
        public readonly string $cookieSameSite = 'lax',
        public readonly string $tokenHeader = 'Authorization',
        public readonly string $tokenPrefix = 'Bearer',
        public readonly bool $enableRateLimiting = true,
        public readonly int $rateLimitMaxAttempts = 5,
        public readonly int $rateLimitDecaySeconds = 300,
    ) {
    }

    /**
     * Create config for monolith mode.
     */
    public static function forMonolith(string $secretKey, array $overrides = []): self
    {
        $defaults = [
            'mode' => AuthMode::MONOLITH,
            'secretKey' => $secretKey,
            'enableRefreshTokens' => false, // Not needed in monolith
        ];

        $params = array_merge($defaults, $overrides);

        return new self(...$params);
    }

    /**
     * Create config for API mode.
     */
    public static function forApi(string $secretKey, array $overrides = []): self
    {
        $defaults = [
            'mode' => AuthMode::API,
            'secretKey' => $secretKey,
            'sessionLifetime' => 3600, // Shorter for APIs
            'enableRefreshTokens' => true, // Essential for APIs
            'cookieHttpOnly' => false, // APIs don't use cookies
        ];

        $params = array_merge($defaults, $overrides);

        return new self(...$params);
    }

    /**
     * Create config for hybrid mode (both sessions and tokens).
     * Best for apps with web frontend + mobile/SPA clients.
     */
    public static function forHybrid(string $secretKey, array $overrides = []): self
    {
        $defaults = [
            'mode' => AuthMode::HYBRID,
            'secretKey' => $secretKey,
            'sessionLifetime' => 604800, // 7 days for sessions
            'tokenLifetime' => 3600, // 1 hour for API tokens
            'enableRefreshTokens' => true, // Needed for API clients
            'cookieHttpOnly' => true, // Sessions use cookies
            'cookieSecure' => true,
        ];

        $params = array_merge($defaults, $overrides);

        return new self(...$params);
    }

    /**
     * Check if mode is monolith.
     */
    public function isMonolith(): bool
    {
        return $this->mode->isMonolith();
    }

    /**
     * Check if mode is API.
     */
    public function isApi(): bool
    {
        return $this->mode->isApi();
    }

    /**
     * Check if mode is hybrid.
     */
    public function isHybrid(): bool
    {
        return $this->mode->isHybrid();
    }

    /**
     * Check if this mode supports token-based authentication.
     */
    public function supportsTokens(): bool
    {
        return $this->mode->supportsTokens();
    }

    /**
     * Check if this mode supports session-based authentication.
     */
    public function supportsSessions(): bool
    {
        return $this->mode->supportsSessions();
    }
}
