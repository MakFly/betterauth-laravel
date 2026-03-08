<?php

declare(strict_types=1);

namespace BetterAuth\Providers\OAuthProvider;

use BetterAuth\Core\Config\AuthConfig;
use BetterAuth\Core\Entities\Session;
use BetterAuth\Core\Entities\User;
use BetterAuth\Core\Interfaces\OAuthProviderInterface;
use BetterAuth\Core\Interfaces\TokenManagerInterface;
use BetterAuth\Core\Interfaces\UserRepositoryInterface;
use BetterAuth\Core\SessionService;
use BetterAuth\Core\Utils\Crypto;

/**
 * OAuth manager for handling OAuth authentication flow.
 * Supports both session-based (monolith) and token-based (API/hybrid) authentication modes.
 *
 * This manager is final to ensure consistent OAuth behavior.
 */
final class OAuthManager
{
    /** @var array<string, OAuthProviderInterface> */
    private array $providers = [];

    public function __construct(
        private readonly UserRepositoryInterface $userRepository,
        private readonly SessionService $sessionService,
        private readonly ?AuthConfig $authConfig = null,
        private readonly ?TokenManagerInterface $tokenManager = null,
    ) {
    }

    /**
     * Register an OAuth provider.
     */
    public function addProvider(OAuthProviderInterface $provider): void
    {
        $this->providers[$provider->getName()] = $provider;
    }

    /**
     * Get the authorization URL for a provider.
     *
     * @param array<string, mixed> $options
     *
     * @return array{url: string, state: string}
     *
     * @throws \Exception
     */
    public function getAuthorizationUrl(string $providerName, array $options = []): array
    {
        $provider = $this->getProvider($providerName);
        $state = Crypto::randomToken(16);

        $url = $provider->getAuthorizationUrl($state, $options);

        return [
            'url' => $url,
            'state' => $state,
        ];
    }

    /**
     * Handle OAuth callback and create/login user.
     *
     * Returns tokens in API/hybrid mode, session in monolith mode.
     *
     * @return array{user: array<string, mixed>, session?: Session, access_token?: string, refresh_token?: string, expires_in?: int, token_type?: string, isNewUser: bool}
     *
     * @throws \Exception
     */
    public function handleCallback(
        string $providerName,
        string $code,
        string $redirectUri,
        string $ipAddress,
        string $userAgent,
        ?string $state = null,
        ?string $expectedState = null,
    ): array {
        if ($state !== null && $expectedState !== null) {
            if (!hash_equals($expectedState, $state)) {
                throw new \InvalidArgumentException('Invalid OAuth state parameter');
            }
        }

        $provider = $this->getProvider($providerName);

        // Exchange code for access token
        $accessToken = $provider->getAccessToken($code, $redirectUri);

        // Get user info from provider
        $providerUser = $provider->getUserInfo($accessToken);

        // Find existing user by provider
        $user = $this->userRepository->findByProvider($providerName, $providerUser->providerId);

        $isNewUser = false;

        if ($user === null) {
            // Check if user exists with same email
            $user = $this->userRepository->findByEmail($providerUser->email);

            if ($user === null) {
                // Create new user
                $userData = [
                    'email' => $providerUser->email,
                    'password_hash' => null,
                    'name' => $providerUser->name,
                    'avatar' => $providerUser->avatar,
                    'email_verified' => $providerUser->emailVerified,
                    'email_verified_at' => $providerUser->emailVerified ? date('Y-m-d H:i:s') : null,
                    'metadata' => [
                        'oauth_providers' => [
                            $providerName => [
                                'provider_id' => $providerUser->providerId,
                                'connected_at' => date('Y-m-d H:i:s'),
                            ],
                        ],
                    ],
                ];

                // Only set 'id' if repository generates one (UUID/ULID strategy)
                // For auto-increment (INT strategy), repository will let DB handle it
                $generatedId = $this->userRepository->generateId();
                if ($generatedId !== null) {
                    $userData['id'] = $generatedId;
                }

                $user = $this->userRepository->create($userData);

                $isNewUser = true;
            } else {
                // Only auto-link if the OAuth provider confirms the email is verified
                if (!$providerUser->emailVerified) {
                    throw new \RuntimeException(
                        'Cannot link OAuth account: the email address has not been verified by the OAuth provider. ' .
                        'Please verify your email with ' . $providerName . ' first.'
                    );
                }

                // Link provider to existing user
                $metadata = $user->metadata ?? [];
                $metadata['oauth_providers'][$providerName] = [
                    'provider_id' => $providerUser->providerId,
                    'connected_at' => date('Y-m-d H:i:s'),
                ];

                $user = $this->userRepository->update($user->getId(), ['metadata' => $metadata]);
            }
        }

        // API/Hybrid mode: Return JWT tokens
        if ($this->authConfig?->supportsTokens() && $this->tokenManager !== null) {
            $tokens = $this->tokenManager->create($user);

            return [
                'user' => \BetterAuth\Core\DTO\UserDto::fromUser($user)->toArray(),
                'access_token' => $tokens['access_token'],
                'refresh_token' => $tokens['refresh_token'],
                'token_type' => $tokens['token_type'],
                'expires_in' => $tokens['expires_in'],
                'isNewUser' => $isNewUser,
            ];
        }

        // Session mode (default): Create session
        $session = $this->sessionService->create($user, $ipAddress, $userAgent);

        return [
            'user' => \BetterAuth\Core\DTO\UserDto::fromUser($user)->toArray(),
            'session' => $session,
            'isNewUser' => $isNewUser,
        ];
    }

    /**
     * Get list of available (configured) providers.
     *
     * @return string[]
     */
    public function getAvailableProviders(): array
    {
        return array_keys($this->providers);
    }

    /**
     * Check if a provider is available.
     */
    public function hasProvider(string $name): bool
    {
        return isset($this->providers[$name]);
    }

    /**
     * Get a provider by name.
     *
     * @throws \InvalidArgumentException
     */
    private function getProvider(string $name): OAuthProviderInterface
    {
        if (!isset($this->providers[$name])) {
            $available = empty($this->providers)
                ? 'No OAuth providers are configured'
                : 'Available providers: ' . implode(', ', array_keys($this->providers));

            throw new \InvalidArgumentException(
                "OAuth provider '$name' not found. $available. " .
                "Make sure '$name' is configured with 'enabled: true' in config/packages/better_auth.yaml",
            );
        }

        return $this->providers[$name];
    }
}
