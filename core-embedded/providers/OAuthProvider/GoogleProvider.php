<?php

declare(strict_types=1);

namespace BetterAuth\Providers\OAuthProvider;

use BetterAuth\Core\Entities\ProviderUser;

/**
 * Google OAuth provider implementation.
 */
final class GoogleProvider extends AbstractOAuthProvider
{
    public function getName(): string
    {
        return 'google';
    }

    public function getAuthorizationUrl(string $state, array $options = []): string
    {
        $scopes = $options['scopes'] ?? $this->getDefaultScopes();

        $params = [
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'response_type' => 'code',
            'scope' => implode(' ', $scopes),
            'state' => $state,
            'access_type' => 'offline',
            'prompt' => 'consent',
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
                'client_secret' => $this->clientSecret,
                'code' => $code,
                'redirect_uri' => $redirectUri,
                'grant_type' => 'authorization_code',
            ],
        );

        if (!isset($response['access_token'])) {
            throw new \RuntimeException('Failed to obtain access token from Google');
        }

        return $response['access_token'];
    }

    public function getUserInfo(string $accessToken): ProviderUser
    {
        $response = $this->httpRequest(
            $this->getUserInfoEndpoint(),
            'GET',
            [],
            ['Authorization' => "Bearer $accessToken"],
        );

        return new ProviderUser(
            providerId: $response['sub'] ?? $response['id'] ?? '',
            email: $response['email'] ?? '',
            name: $response['name'] ?? null,
            avatar: $response['picture'] ?? null,
            emailVerified: ($response['email_verified'] ?? $response['verified_email'] ?? false) === true,
            rawData: $response,
        );
    }

    protected function getAuthorizationEndpoint(): string
    {
        return 'https://accounts.google.com/o/oauth2/v2/auth';
    }

    protected function getTokenEndpoint(): string
    {
        return 'https://oauth2.googleapis.com/token';
    }

    protected function getUserInfoEndpoint(): string
    {
        return 'https://www.googleapis.com/oauth2/v2/userinfo';
    }

    protected function getDefaultScopes(): array
    {
        return [
            'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/userinfo.profile',
        ];
    }
}
