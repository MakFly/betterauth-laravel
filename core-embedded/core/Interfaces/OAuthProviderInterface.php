<?php

declare(strict_types=1);

namespace BetterAuth\Core\Interfaces;

use BetterAuth\Core\Entities\ProviderUser;

/**
 * Interface for OAuth provider implementations.
 */
interface OAuthProviderInterface
{
    /**
     * Get the authorization URL for the OAuth flow.
     *
     * @param string $state CSRF protection state parameter
     * @param array<string, mixed> $options Additional options (scopes, etc.)
     *
     * @return string The authorization URL
     */
    public function getAuthorizationUrl(string $state, array $options = []): string;

    /**
     * Exchange authorization code for access token.
     *
     * @param string $code The authorization code
     * @param string $redirectUri The redirect URI used in the authorization request
     *
     * @return string The access token
     */
    public function getAccessToken(string $code, string $redirectUri): string;

    /**
     * Get user information from the provider.
     *
     * @param string $accessToken The access token
     *
     * @return ProviderUser The provider user information
     */
    public function getUserInfo(string $accessToken): ProviderUser;

    /**
     * Get the provider name.
     *
     * @return string The provider name (e.g., 'google', 'github')
     */
    public function getName(): string;
}
