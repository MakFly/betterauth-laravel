<?php

declare(strict_types=1);

namespace BetterAuth\Providers\OAuthProvider;

use BetterAuth\Core\Entities\ProviderUser;

/**
 * Discord OAuth provider implementation.
 */
final class DiscordProvider extends AbstractOAuthProvider
{
    public function getName(): string
    {
        return 'discord';
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
            throw new \RuntimeException('Failed to obtain access token from Discord');
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

        // Discord user avatar URL construction
        $avatar = null;
        if (isset($response['avatar'], $response['id'])) {
            $avatar = sprintf(
                'https://cdn.discordapp.com/avatars/%s/%s.png',
                $response['id'],
                $response['avatar'],
            );
        }

        return new ProviderUser(
            providerId: $response['id'] ?? '',
            email: $response['email'] ?? '',
            name: $response['username'] ?? ($response['global_name'] ?? null),
            avatar: $avatar,
            emailVerified: $response['verified'] ?? false,
            rawData: $response,
        );
    }

    protected function getAuthorizationEndpoint(): string
    {
        return 'https://discord.com/api/oauth2/authorize';
    }

    protected function getTokenEndpoint(): string
    {
        return 'https://discord.com/api/oauth2/token';
    }

    protected function getUserInfoEndpoint(): string
    {
        return 'https://discord.com/api/users/@me';
    }

    protected function getDefaultScopes(): array
    {
        return [
            'identify',
            'email',
        ];
    }
}
