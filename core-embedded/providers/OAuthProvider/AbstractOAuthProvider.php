<?php

declare(strict_types=1);

namespace BetterAuth\Providers\OAuthProvider;

use BetterAuth\Core\Interfaces\OAuthProviderInterface;

/**
 * Abstract base class for OAuth providers.
 */
abstract class AbstractOAuthProvider implements OAuthProviderInterface
{
    public function __construct(
        protected readonly string $clientId,
        protected readonly string $clientSecret,
        protected readonly string $redirectUri,
    ) {
    }

    /**
     * Make an HTTP request.
     *
     * @param array<string, mixed> $data
     * @param array<string, string> $headers
     *
     * @return array<string, mixed>
     */
    protected function httpRequest(
        string $url,
        string $method = 'GET',
        array $data = [],
        array $headers = [],
    ): array {
        $ch = curl_init();

        $options = [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => $this->buildHeaders($headers),
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_FOLLOWLOCATION => false,
        ];

        if ($method === 'POST') {
            $options[CURLOPT_POST] = true;
            $options[CURLOPT_POSTFIELDS] = http_build_query($data);
        } elseif (!empty($data)) {
            $options[CURLOPT_URL] = $url . '?' . http_build_query($data);
        }

        curl_setopt_array($ch, $options);

        $response = curl_exec($ch);
        $error = curl_error($ch);
        curl_close($ch);

        if ($error) {
            throw new \RuntimeException("HTTP request failed: $error");
        }

        $decoded = json_decode($response, true);

        if (!is_array($decoded)) {
            throw new \RuntimeException('Invalid JSON response from OAuth provider');
        }

        return $decoded;
    }

    /**
     * Build headers array.
     *
     * @param array<string, string> $headers
     *
     * @return string[]
     */
    protected function buildHeaders(array $headers): array
    {
        $result = [];
        foreach ($headers as $key => $value) {
            $result[] = "$key: $value";
        }

        return $result;
    }

    /**
     * Get the authorization endpoint URL.
     */
    abstract protected function getAuthorizationEndpoint(): string;

    /**
     * Get the token endpoint URL.
     */
    abstract protected function getTokenEndpoint(): string;

    /**
     * Get the user info endpoint URL.
     */
    abstract protected function getUserInfoEndpoint(): string;

    /**
     * Get the default scopes.
     *
     * @return string[]
     */
    abstract protected function getDefaultScopes(): array;
}
