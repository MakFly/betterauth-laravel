<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\OAuth;

use Illuminate\Http\RedirectResponse;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\Two\InvalidStateException;

/**
 * Socialite OAuth Provider.
 *
 * Uses Laravel Socialite to handle OAuth authentication.
 * Supports all providers included in Socialite: Google, GitHub, Facebook, Twitter, LinkedIn, etc.
 */
final class SocialiteOAuthProvider implements OAuthProviderInterface
{
    /**
     * Create a new provider instance.
     *
     * @param  string  $name  Provider name (e.g., 'google', 'github')
     * @param  array<string, mixed>  $config  Provider configuration
     */
    public function __construct(
        private readonly string $name,
        private readonly array $config,
    ) {
        $this->validateConfig();
    }

    /**
     * Redirect to the provider's authentication page.
     */
    public function redirect(): RedirectResponse
    {
        // Additional scopes can be configured per provider
        $scopes = $this->config['scopes'] ?? [];
        $with = $this->config['with'] ?? [];

        $driver = Socialite::driver($this->name);

        if (! empty($scopes)) {
            $driver = $driver->scopes($scopes);
        }

        if (! empty($with)) {
            foreach ($with as $key => $value) {
                $driver = $driver->with([$key => $value]);
            }
        }

        return $driver->redirect();
    }

    /**
     * Handle the callback from the OAuth provider.
     *
     * @return array{provider_user_id: string, email: string, name: string, avatar: string|null, raw: array<string, mixed>}
     *
     * @throws \RuntimeException
     */
    public function callback(): array
    {
        try {
            $socialiteUser = Socialite::driver($this->name)->user();
        } catch (InvalidStateException $e) {
            throw new \RuntimeException('Invalid state parameter. Possible CSRF attack.', 0, $e);
        } catch (\Exception $e) {
            throw new \RuntimeException('OAuth callback failed: '.$e->getMessage(), 0, $e);
        }

        // Normalize user data from different providers
        $email = $socialiteUser->email ?? throw new \RuntimeException('Email is required from OAuth provider.');
        $name = $socialiteUser->name ?? $this->extractNameFromEmail($email);
        $avatar = $socialiteUser->avatar ?? null;

        return [
            'provider_user_id' => (string) $socialiteUser->id,
            'email' => $email,
            'name' => $name,
            'avatar' => $avatar,
            'raw' => $socialiteUser->user ?? [],
        ];
    }

    /**
     * Get the provider name.
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * Validate that required configuration is present.
     *
     * @throws \InvalidArgumentException
     */
    private function validateConfig(): void
    {
        if (! isset($this->config['client_id']) || ! isset($this->config['client_secret'])) {
            throw new \InvalidArgumentException("OAuth provider '{$this->name}' is not configured. Set CLIENT_ID and CLIENT_SECRET.");
        }

        if (! isset($this->config['redirect_uri'])) {
            throw new \InvalidArgumentException("OAuth provider '{$this->name}' missing redirect_uri configuration.");
        }
    }

    /**
     * Extract name from email as fallback.
     */
    private function extractNameFromEmail(string $email): string
    {
        $parts = explode('@', $email);

        return ucfirst(str_replace(['.', '_', '-'], ' ', $parts[0]));
    }
}
