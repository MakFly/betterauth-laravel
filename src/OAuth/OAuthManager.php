<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\OAuth;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\DB;

/**
 * OAuth Manager.
 *
 * Central point for OAuth authentication operations.
 * Manages provider selection and integrates with BetterAuth user management.
 */
final class OAuthManager
{
    /**
     * Create a new OAuth manager instance.
     *
     * @param  array<string, array<string, mixed>>  $providerConfigs
     */
    public function __construct(
        private readonly Application $app,
        private readonly array $providerConfigs,
    ) {}

    /**
     * Get a provider instance by name.
     *
     * @param  string  $name  Provider name (e.g., 'google', 'github')
     *
     * @throws \InvalidArgumentException
     */
    public function getProvider(string $name): OAuthProviderInterface
    {
        $config = $this->providerConfigs[$name] ?? null;

        if ($config === null) {
            throw new \InvalidArgumentException("OAuth provider '{$name}' is not configured.");
        }

        // If Socialite is available, use it
        if (class_exists(\Laravel\Socialite\SocialiteServiceProvider::class)) {
            return new SocialiteOAuthProvider($name, $config);
        }

        throw new \InvalidArgumentException(
            'Laravel Socialite is not installed. '.
            'Run: composer require laravel/socialite',
        );
    }

    /**
     * Redirect to the OAuth provider.
     */
    public function redirect(string $provider): RedirectResponse
    {
        return $this->getProvider($provider)->redirect();
    }

    /**
     * Handle the OAuth callback.
     *
     * This method:
     * 1. Gets user data from the provider
     * 2. Finds or creates the user
     * 3. Links the OAuth account to the user
     * 4. Returns the user with tokens
     *
     * @param  string  $provider  Provider name
     * @return array{user: \Illuminate\Contracts\Auth\Authenticatable, is_new: bool, oauth_account: \stdClass|null}
     *
     * @throws \RuntimeException
     */
    public function handleCallback(string $provider): array
    {
        $oauthProvider = $this->getProvider($provider);
        $userData = $oauthProvider->callback();

        // Check if OAuth account already exists
        $oauthAccount = $this->findOAuthAccount(
            $provider,
            $userData['provider_user_id'],
        );

        if ($oauthAccount !== null) {
            // Existing OAuth account - get the user
            $user = $this->getUserModel($oauthAccount->user_id);

            if ($user === null) {
                throw new \RuntimeException('OAuth account exists but user not found. Data inconsistency.');
            }

            return [
                'user' => $user,
                'is_new' => false,
                'oauth_account' => $oauthAccount,
            ];
        }

        // Check if user with same email exists
        $existingUser = $this->findUserByEmail($userData['email']);

        if ($existingUser !== null) {
            // Link OAuth account to existing user
            $this->linkOAuthAccount($existingUser, $provider, $userData);

            return [
                'user' => $existingUser,
                'is_new' => false,
                'oauth_account' => $this->findOAuthAccount($provider, $userData['provider_user_id']),
            ];
        }

        // Create new user
        $user = $this->createUserFromOAuth($userData);

        // Link OAuth account to new user
        $this->linkOAuthAccount($user, $provider, $userData);

        return [
            'user' => $user,
            'is_new' => true,
            'oauth_account' => $this->findOAuthAccount($provider, $userData['provider_user_id']),
        ];
    }

    /**
     * Find an OAuth account by provider and provider user ID.
     */
    private function findOAuthAccount(string $provider, string $providerUserId): ?\stdClass
    {
        return DB::table('better_auth_oauth_accounts')
            ->where('provider', $provider)
            ->where('provider_user_id', $providerUserId)
            ->first();
    }

    /**
     * Find a user by ID.
     */
    private function getUserModel(string $userId): ?\Illuminate\Contracts\Auth\Authenticatable
    {
        $userModel = config('betterauth.user_model');

        return $userModel::where('id', $userId)->first();
    }

    /**
     * Find a user by email.
     */
    private function findUserByEmail(string $email): ?\Illuminate\Contracts\Auth\Authenticatable
    {
        $userModel = config('betterauth.user_model');

        return $userModel::where('email', $email)->first();
    }

    /**
     * Create a new user from OAuth data.
     *
     * @param  array<string, mixed>  $userData
     */
    private function createUserFromOAuth(array $userData): \Illuminate\Contracts\Auth\Authenticatable
    {
        $userModel = config('betterauth.user_model');
        $user = new $userModel;

        // Generate UUID if configured
        if (config('betterauth.id_strategy') === 'uuid') {
            $user->{$user->getKeyName()} = (string) \Illuminate\Support\Str::uuid7();
        }

        $user->fill([
            'email' => $userData['email'],
            'name' => $userData['name'],
            'avatar' => $userData['avatar'],
            'password' => null, // No password for OAuth-only users
            'email_verified_at' => now(), // OAuth emails are verified
            'roles' => ['ROLE_USER'],
        ]);

        $user->save();

        return $user;
    }

    /**
     * Link an OAuth account to a user.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  array<string, mixed>  $userData
     */
    private function linkOAuthAccount($user, string $provider, array $userData): void
    {
        DB::table('better_auth_oauth_accounts')->insert([
            'user_id' => $user->getAuthIdentifier(),
            'provider' => $provider,
            'provider_user_id' => $userData['provider_user_id'],
            'provider_email' => $userData['email'],
            'access_token' => null, // Socialite doesn't provide access token by default
            'refresh_token' => null,
            'expires_at' => null,
            'raw_data' => json_encode($userData['raw']),
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    /**
     * Check if a provider is available and configured.
     */
    public function isProviderAvailable(string $name): bool
    {
        if (! isset($this->providerConfigs[$name])) {
            return false;
        }

        return class_exists(\Laravel\Socialite\SocialiteServiceProvider::class);
    }

    /**
     * Get list of configured providers.
     *
     * @return array<string>
     */
    public function getAvailableProviders(): array
    {
        if (! class_exists(\Laravel\Socialite\SocialiteServiceProvider::class)) {
            return [];
        }

        return array_keys($this->providerConfigs);
    }
}
