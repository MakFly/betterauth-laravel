<?php

declare(strict_types=1);

namespace BetterAuth\Providers\OAuthProvider;

use BetterAuth\Core\Entities\ProviderUser;

/**
 * Microsoft OAuth provider implementation.
 * Supports Microsoft Azure AD / Microsoft Account login.
 */
final class MicrosoftProvider extends AbstractOAuthProvider
{
    public function __construct(
        string $clientId,
        string $clientSecret,
        string $redirectUri,
        private readonly string $tenant = 'common',
    ) {
        parent::__construct($clientId, $clientSecret, $redirectUri);
    }

    public function getName(): string
    {
        return 'microsoft';
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
            'response_mode' => 'query',
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
            throw new \RuntimeException('Failed to obtain access token from Microsoft');
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
            providerId: $response['id'] ?? '',
            email: $response['mail'] ?? $response['userPrincipalName'] ?? '',
            name: $response['displayName'] ?? null,
            avatar: null, // Microsoft Graph API doesn't provide avatar URL directly
            emailVerified: true, // Microsoft accounts are always verified
            rawData: $response,
        );
    }

    protected function getAuthorizationEndpoint(): string
    {
        return "https://login.microsoftonline.com/{$this->tenant}/oauth2/v2.0/authorize";
    }

    protected function getTokenEndpoint(): string
    {
        return "https://login.microsoftonline.com/{$this->tenant}/oauth2/v2.0/token";
    }

    protected function getUserInfoEndpoint(): string
    {
        return 'https://graph.microsoft.com/v1.0/me';
    }

    protected function getDefaultScopes(): array
    {
        return [
            'openid',
            'profile',
            'email',
            'User.Read',
        ];
    }
}
