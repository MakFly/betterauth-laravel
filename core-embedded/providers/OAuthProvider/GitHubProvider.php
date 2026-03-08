<?php

declare(strict_types=1);

namespace BetterAuth\Providers\OAuthProvider;

use BetterAuth\Core\Entities\ProviderUser;

/**
 * GitHub OAuth provider implementation.
 */
final class GitHubProvider extends AbstractOAuthProvider
{
    public function getName(): string
    {
        return 'github';
    }

    public function getAuthorizationUrl(string $state, array $options = []): string
    {
        $scopes = $options['scopes'] ?? $this->getDefaultScopes();

        $params = [
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'scope' => implode(' ', $scopes),
            'state' => $state,
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
            ],
            ['Accept' => 'application/json'],
        );

        if (!isset($response['access_token'])) {
            throw new \RuntimeException('Failed to obtain access token from GitHub');
        }

        return $response['access_token'];
    }

    public function getUserInfo(string $accessToken): ProviderUser
    {
        $response = $this->httpRequest(
            $this->getUserInfoEndpoint(),
            'GET',
            [],
            [
                'Authorization' => "Bearer $accessToken",
                'Accept' => 'application/json',
            ],
        );

        // GitHub doesn't return email in user endpoint by default, need to fetch separately
        $email = $this->getUserEmail($accessToken);

        return new ProviderUser(
            providerId: (string) $response['id'],
            email: $email,
            name: $response['name'] ?? $response['login'] ?? null,
            avatar: $response['avatar_url'] ?? null,
            emailVerified: true, // GitHub verifies emails
            rawData: $response,
        );
    }

    /**
     * Get user's primary email from GitHub.
     */
    private function getUserEmail(string $accessToken): string
    {
        $emails = $this->httpRequest(
            'https://api.github.com/user/emails',
            'GET',
            [],
            [
                'Authorization' => "Bearer $accessToken",
                'Accept' => 'application/json',
            ],
        );

        foreach ($emails as $email) {
            if ($email['primary'] ?? false) {
                return $email['email'];
            }
        }

        // Return first email if no primary found
        if (count($emails) > 0) {
            $firstEmail = reset($emails);
            if (is_array($firstEmail) && isset($firstEmail['email'])) {
                return $firstEmail['email'];
            }
        }

        return '';
    }

    protected function getAuthorizationEndpoint(): string
    {
        return 'https://github.com/login/oauth/authorize';
    }

    protected function getTokenEndpoint(): string
    {
        return 'https://github.com/login/oauth/access_token';
    }

    protected function getUserInfoEndpoint(): string
    {
        return 'https://api.github.com/user';
    }

    protected function getDefaultScopes(): array
    {
        return ['user:email'];
    }
}
