<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\OAuth;

use Illuminate\Http\RedirectResponse;

/**
 * OAuth Provider Interface.
 *
 * Defines the contract for OAuth authentication providers.
 * Implementations can use Socialite, custom OAuth flows, or mock providers for testing.
 */
interface OAuthProviderInterface
{
    /**
     * Redirect the user to the provider's authentication page.
     */
    public function redirect(): RedirectResponse;

    /**
     * Handle the callback from the OAuth provider.
     *
     * Should return user information including:
     * - provider_user_id: Unique ID from the provider
     * - email: User's email
     * - name: User's display name
     * - avatar: User's avatar URL (optional)
     * - raw: Raw provider data
     *
     * @return array{provider_user_id: string, email: string, name: string, avatar: string|null, raw: array<string, mixed>}
     *
     * @throws \RuntimeException If the callback fails or user cannot be retrieved
     */
    public function callback(): array;

    /**
     * Get the provider name (e.g., 'google', 'github', 'facebook').
     */
    public function getName(): string;
}
