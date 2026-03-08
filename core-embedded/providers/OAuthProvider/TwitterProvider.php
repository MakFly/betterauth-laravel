<?php

declare(strict_types=1);

namespace BetterAuth\Providers\OAuthProvider;

use BetterAuth\Core\Entities\ProviderUser;

/**
 * Twitter (X) OAuth provider implementation.
 * Uses OAuth 2.0 with PKCE (Twitter API v2).
 */
final class TwitterProvider extends AbstractOAuthProvider
{
    private ?string $codeVerifier = null;

    public function getName(): string
    {
        return 'twitter';
    }

    public function getAuthorizationUrl(string $state, array $options = []): string
    {
        $scopes = $options['scopes'] ?? $this->getDefaultScopes();

        // Generate PKCE code verifier and challenge
        $this->codeVerifier = bin2hex(random_bytes(32));
        $codeChallenge = $this->generateCodeChallenge($this->codeVerifier);

        $params = [
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'response_type' => 'code',
            'scope' => implode(' ', $scopes),
            'state' => $state,
            'code_challenge' => $codeChallenge,
            'code_challenge_method' => 'S256',
        ];

        return $this->getAuthorizationEndpoint() . '?' . http_build_query($params);
    }

    public function getAccessToken(string $code, string $redirectUri): string
    {
        $response = $this->httpRequest(
            $this->getTokenEndpoint(),
            'POST',
            [
                'client_id' => $this->clientId,
                'code' => $code,
                'redirect_uri' => $redirectUri,
                'grant_type' => 'authorization_code',
                'code_verifier' => $this->codeVerifier,
            ],
        );

        if (!isset($response['access_token'])) {
            throw new \RuntimeException('Failed to obtain access token from Twitter');
        }

        return $response['access_token'];
    }

    public function getUserInfo(string $accessToken): ProviderUser
    {
        $response = $this->httpRequest(
            $this->getUserInfoEndpoint(),
            'GET',
            ['user.fields' => 'id,name,username,profile_image_url,verified'],
            ['Authorization' => "Bearer $accessToken"],
        );

        $userData = $response['data'] ?? [];

        return new ProviderUser(
            providerId: $userData['id'] ?? '',
            email: $userData['email'] ?? '', // Note: Email requires elevated access
            name: $userData['name'] ?? $userData['username'] ?? null,
            avatar: $userData['profile_image_url'] ?? null,
            emailVerified: $userData['verified'] ?? false,
            rawData: $userData,
        );
    }

    protected function getAuthorizationEndpoint(): string
    {
        return 'https://twitter.com/i/oauth2/authorize';
    }

    protected function getTokenEndpoint(): string
    {
        return 'https://api.twitter.com/2/oauth2/token';
    }

    protected function getUserInfoEndpoint(): string
    {
        return 'https://api.twitter.com/2/users/me';
    }

    protected function getDefaultScopes(): array
    {
        return [
            'tweet.read',
            'users.read',
        ];
    }

    /**
     * Generate PKCE code challenge from verifier.
     */
    private function generateCodeChallenge(string $verifier): string
    {
        $hash = hash('sha256', $verifier, true);
        $challenge = base64_encode($hash);

        return rtrim(strtr($challenge, '+/', '-_'), '=');
    }

    /**
     * Set code verifier (useful when reconstructing state).
     */
    public function setCodeVerifier(string $verifier): void
    {
        $this->codeVerifier = $verifier;
    }

    /**
     * Get code verifier for session storage.
     */
    public function getCodeVerifier(): ?string
    {
        return $this->codeVerifier;
    }
}
