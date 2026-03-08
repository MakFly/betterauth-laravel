<?php

declare(strict_types=1);

namespace BetterAuth\Core\Config;

/**
 * Enum defining authentication modes.
 */
enum AuthMode: string
{
    /**
     * Monolithic mode - Traditional session-based auth with cookies.
     * Best for: Traditional web apps, server-side rendered pages
     */
    case MONOLITH = 'monolith';

    /**
     * Microservice API mode - Stateless JWT/token-based auth.
     * Best for: REST APIs, SPAs, Mobile apps, Microservices
     */
    case API = 'api';

    /**
     * Hybrid mode - Both session-based and token-based auth.
     * Best for: Apps with both web frontend and mobile/SPA clients
     */
    case HYBRID = 'hybrid';

    /**
     * Check if current mode is monolith.
     */
    public function isMonolith(): bool
    {
        return $this === self::MONOLITH;
    }

    /**
     * Check if current mode is API.
     */
    public function isApi(): bool
    {
        return $this === self::API;
    }

    /**
     * Check if current mode is hybrid.
     */
    public function isHybrid(): bool
    {
        return $this === self::HYBRID;
    }

    /**
     * Check if this mode supports token-based authentication.
     * API and HYBRID modes support tokens.
     */
    public function supportsTokens(): bool
    {
        return $this !== self::MONOLITH;
    }

    /**
     * Check if this mode supports session-based authentication.
     * MONOLITH and HYBRID modes support sessions.
     */
    public function supportsSessions(): bool
    {
        return $this !== self::API;
    }
}
