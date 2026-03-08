<?php

declare(strict_types=1);

namespace BetterAuth\Providers\OAuthProvider;

use BetterAuth\Core\Entities\ProviderUser;

/**
 * Apple OAuth provider implementation (Sign in with Apple).
 *
 * Note: Apple requires a JWT-based client_secret. You must generate this
 * before using this provider. See documentation for details.
 *
 * @see https://developer.apple.com/documentation/sign_in_with_apple
 */
final class AppleProvider extends AbstractOAuthProvider
{
    public function __construct(
        string $clientId,
        string $clientSecret,
        string $redirectUri,
    ) {
        throw new \RuntimeException(
            'AppleProvider is disabled: JWT signature verification against Apple JWKS is not yet implemented. '
            . 'This is required for secure Sign in with Apple. '
            . 'See https://developer.apple.com/documentation/sign_in_with_apple'
        );
    }

    public function getName(): string
    {
        return 'apple';
    }

    public function getAuthorizationUrl(string $state, array $options = []): string
    {
        $scopes = $options['scopes'] ?? $this->getDefaultScopes();

        $params = [
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'response_type' => 'code',
            'response_mode' => $options['response_mode'] ?? 'form_post',
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
            throw new \RuntimeException('Failed to obtain access token from Apple');
        }

        return $response['access_token'];
    }

    public function getUserInfo(string $accessToken): ProviderUser
    {
        // Apple doesn't provide a traditional userinfo endpoint
        // User info is provided in the ID token during the callback
        // This is a simplified implementation
        // In production, you should decode the id_token JWT

        // For now, we'll need to handle this differently in the callback
        // The user info comes in the initial response
        throw new \RuntimeException(
            'Apple provider requires special handling. Use the id_token from the token response.',
        );
    }

    /**
     * Decode Apple ID Token to get user information.
     *
     * @param string $idToken The JWT ID token from Apple
     */
    public function getUserInfoFromIdToken(string $idToken): ProviderUser
    {
        // Validate JWT structure (must have 3 parts: header.payload.signature)
        $parts = explode('.', $idToken);
        if (count($parts) !== 3) {
            throw new \RuntimeException('Invalid JWT token');
        }

        // Decode and validate header
        $header = json_decode(base64_decode(strtr($parts[0], '-_', '+/')), true);
        if (!is_array($header) || !isset($header['kid']) || !isset($header['alg'])) {
            throw new \RuntimeException('Invalid JWT header: missing kid or alg');
        }

        // @todo Fetch Apple JWKS from https://appleid.apple.com/auth/keys and verify
        // the signature using the public key matching header['kid'].
        // This requires an HTTP client dependency (e.g. symfony/http-client or guzzlehttp/guzzle).

        $payload = json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true);

        if (!is_array($payload)) {
            throw new \RuntimeException('Invalid JWT payload');
        }

        // Validate issuer claim
        if (($payload['iss'] ?? '') !== 'https://appleid.apple.com') {
            throw new \RuntimeException('Invalid JWT issuer');
        }

        // Validate expiration claim
        if (!isset($payload['exp']) || $payload['exp'] < time()) {
            throw new \RuntimeException('JWT token has expired');
        }

        return new ProviderUser(
            providerId: $payload['sub'] ?? '',
            email: $payload['email'] ?? '',
            name: null, // Apple doesn't always provide name in token
            avatar: null,
            emailVerified: ($payload['email_verified'] ?? 'false') === 'true',
            rawData: $payload,
        );
    }

    protected function getAuthorizationEndpoint(): string
    {
        return 'https://appleid.apple.com/auth/authorize';
    }

    protected function getTokenEndpoint(): string
    {
        return 'https://appleid.apple.com/auth/token';
    }

    protected function getUserInfoEndpoint(): string
    {
        // Apple doesn't have a separate userinfo endpoint
        return '';
    }

    protected function getDefaultScopes(): array
    {
        return [
            'name',
            'email',
        ];
    }

    /**
     * Generate client secret JWT for Apple.
     *
     * This is a helper method to generate the required JWT client_secret.
     * You need to call this before instantiating the provider.
     *
     * @param string $teamId Your Apple Team ID
     * @param string $clientId Your Apple Client ID (Service ID)
     * @param string $keyId Your Apple Key ID
     * @param string $privateKey The private key content (ES256)
     * @param int $expiresIn Expiration time in seconds (max 6 months)
     *
     * @return string The JWT client secret
     */
    public static function generateClientSecret(
        string $teamId,
        string $clientId,
        string $keyId,
        string $privateKey,
        int $expiresIn = 86400 * 180, // 6 months
    ): string {
        $header = [
            'alg' => 'ES256',
            'kid' => $keyId,
        ];

        $now = time();
        $payload = [
            'iss' => $teamId,
            'iat' => $now,
            'exp' => $now + $expiresIn,
            'aud' => 'https://appleid.apple.com',
            'sub' => $clientId,
        ];

        $headerEncoded = rtrim(strtr(base64_encode(json_encode($header)), '+/', '-_'), '=');
        $payloadEncoded = rtrim(strtr(base64_encode(json_encode($payload)), '+/', '-_'), '=');

        $signature = '';
        $dataToSign = $headerEncoded . '.' . $payloadEncoded;

        // Sign with ES256 (requires openssl)
        $key = openssl_pkey_get_private($privateKey);
        if ($key === false) {
            throw new \RuntimeException('Invalid private key');
        }

        openssl_sign($dataToSign, $signature, $key, OPENSSL_ALGO_SHA256);

        $signatureEncoded = rtrim(strtr(base64_encode($signature), '+/', '-_'), '=');

        return $dataToSign . '.' . $signatureEncoded;
    }
}
