<?php

declare(strict_types=1);

namespace BetterAuth\Providers\OAuthProvider;

use BetterAuth\Core\Entities\ProviderUser;

/**
 * Facebook OAuth provider implementation.
 *
 * @see https://developers.facebook.com/docs/facebook-login/guides/advanced/manual-flow
 */
final class FacebookProvider extends AbstractOAuthProvider
{
    public function getName(): string
    {
        return 'facebook';
    }

    public function getAuthorizationUrl(string $state, array $options = []): string
    {
        $scopes = $options['scopes'] ?? $this->getDefaultScopes();

        $params = [
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'response_type' => 'code',
            'scope' => implode(',', $scopes),
            'state' => $state,
        ];

        return $this->getAuthorizationEndpoint() . '?' . http_build_query($params);
    }

    public function getAccessToken(string $code, string $redirectUri): string
    {
        $response = $this->httpRequest(
            $this->getTokenEndpoint(),
            'GET',
            [
                'client_id' => $this->clientId,
                'client_secret' => $this->clientSecret,
                'code' => $code,
                'redirect_uri' => $redirectUri,
            ],
        );

        if (!isset($response['access_token'])) {
            throw new \RuntimeException('Failed to obtain access token from Facebook');
        }

        return $response['access_token'];
    }

    public function getUserInfo(string $accessToken): ProviderUser
    {
        $response = $this->httpRequest(
            $this->getUserInfoEndpoint(),
            'GET',
            [
                'fields' => 'id,name,email,picture.type(large)',
                'access_token' => $accessToken,
            ],
        );

        return new ProviderUser(
            providerId: $response['id'] ?? '',
            email: $response['email'] ?? '',
            name: $response['name'] ?? null,
            avatar: $response['picture']['data']['url'] ?? null,
            emailVerified: false, // Facebook doesn't provide email verification status
            rawData: $response,
        );
    }

    protected function getAuthorizationEndpoint(): string
    {
        return 'https://www.facebook.com/v18.0/dialog/oauth';
    }

    protected function getTokenEndpoint(): string
    {
        return 'https://graph.facebook.com/v18.0/oauth/access_token';
    }

    protected function getUserInfoEndpoint(): string
    {
        return 'https://graph.facebook.com/v18.0/me';
    }

    protected function getDefaultScopes(): array
    {
        return [
            'email',
            'public_profile',
        ];
    }
}
