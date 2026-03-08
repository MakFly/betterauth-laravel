<?php

declare(strict_types=1);

namespace BetterAuth\Providers\OidcProvider;

use BetterAuth\Core\Entities\User;
use BetterAuth\Core\Exceptions\InvalidCredentialsException;
use BetterAuth\Core\Interfaces\AuthorizationCodeRepositoryInterface;
use BetterAuth\Core\Interfaces\OAuthClientRepositoryInterface;
use BetterAuth\Core\Interfaces\RefreshTokenRepositoryInterface;
use BetterAuth\Core\Interfaces\UserRepositoryInterface;
use BetterAuth\Core\TokenService;
use BetterAuth\Core\Utils\Crypto;
use DateTimeImmutable;

/**
 * OpenID Connect Provider - Makes BetterAuth act as an SSO server.
 *
 * This allows other applications to use BetterAuth as their authentication provider.
 */
final class OidcProvider
{
    private const SUPPORTED_SCOPES = ['openid', 'profile', 'email', 'offline_access'];

    public function __construct(
        private readonly OAuthClientRepositoryInterface $clientRepository,
        private readonly AuthorizationCodeRepositoryInterface $codeRepository,
        private readonly UserRepositoryInterface $userRepository,
        private readonly RefreshTokenRepositoryInterface $refreshTokenRepository,
        private readonly TokenService $tokenService,
        private readonly string $issuer,
        private readonly int $authCodeLifetime = 600, // 10 minutes
        private readonly int $accessTokenLifetime = 3600, // 1 hour
        private readonly int $refreshTokenLifetime = 2592000, // 30 days
    ) {
    }

    /**
     * Handle authorization request (Step 1 of OAuth flow).
     *
     * Returns authorization code or error.
     */
    public function authorize(
        string $clientId,
        string $redirectUri,
        string $responseType,
        array $scopes,
        string $state,
        User $authenticatedUser,
        ?string $codeChallenge = null,
        ?string $codeChallengeMethod = null,
    ): array {
        // Validate client
        $client = $this->clientRepository->findById($clientId);
        if ($client === null || !$client->active) {
            throw new InvalidCredentialsException('Invalid client');
        }

        // Validate redirect URI
        if (!$client->isRedirectUriAllowed($redirectUri)) {
            throw new InvalidCredentialsException('Invalid redirect URI');
        }

        // Validate response type
        if ($responseType !== 'code') {
            throw new InvalidCredentialsException('Unsupported response type');
        }

        // Validate scopes
        if (!in_array('openid', $scopes, true)) {
            throw new InvalidCredentialsException('openid scope is required');
        }

        foreach ($scopes as $scope) {
            if (!in_array($scope, self::SUPPORTED_SCOPES, true)) {
                throw new InvalidCredentialsException("Unsupported scope: {$scope}");
            }
            if (!$client->isScopeAllowed($scope)) {
                throw new InvalidCredentialsException("Scope not allowed for client: {$scope}");
            }
        }

        // Generate authorization code
        $code = Crypto::randomToken(32);
        $expiresAt = new DateTimeImmutable("+{$this->authCodeLifetime} seconds");

        $this->codeRepository->create([
            'code' => $code,
            'clientId' => $clientId,
            'userId' => $authenticatedUser->getId(),
            'redirectUri' => $redirectUri,
            'scopes' => $scopes,
            'expiresAt' => $expiresAt->format('Y-m-d H:i:s'),
            'codeChallenge' => $codeChallenge,
            'codeChallengeMethod' => $codeChallengeMethod,
        ]);

        return [
            'code' => $code,
            'state' => $state,
            'redirect_uri' => $redirectUri,
        ];
    }

    /**
     * Exchange authorization code for tokens (Step 2 of OAuth flow).
     */
    public function token(
        string $grantType,
        ?string $code = null,
        ?string $redirectUri = null,
        ?string $clientId = null,
        ?string $clientSecret = null,
        ?string $codeVerifier = null,
        ?string $refreshToken = null,
    ): array {
        if ($grantType === 'authorization_code') {
            return $this->handleAuthorizationCodeGrant(
                $code,
                $redirectUri,
                $clientId,
                $clientSecret,
                $codeVerifier,
            );
        }

        if ($grantType === 'refresh_token') {
            return $this->handleRefreshTokenGrant($refreshToken, $clientId, $clientSecret);
        }

        throw new InvalidCredentialsException('Unsupported grant type');
    }

    /**
     * Get user info endpoint (OIDC standard).
     */
    public function userinfo(string $accessToken): array
    {
        // Verify token
        $payload = $this->tokenService->verify($accessToken);
        if ($payload === null || !isset($payload['sub'])) {
            throw new InvalidCredentialsException('Invalid access token');
        }

        // Get user
        $user = $this->userRepository->findById($payload['sub']);
        if ($user === null) {
            throw new InvalidCredentialsException('User not found');
        }

        // Get scopes from token
        $scopes = $payload['scope'] ?? [];

        // Build response based on scopes
        $userinfo = [
            'sub' => $user->getId(),
        ];

        if (in_array('profile', $scopes, true)) {
            $userinfo['name'] = $user->getUsername();
            $userinfo['picture'] = $user->getAvatar();
        }

        if (in_array('email', $scopes, true)) {
            $userinfo['email'] = $user->getEmail();
            $userinfo['email_verified'] = $user->isEmailVerified();
        }

        return $userinfo;
    }

    /**
     * Get OpenID Discovery configuration.
     */
    public function getDiscoveryConfiguration(): array
    {
        return [
            'issuer' => $this->issuer,
            'authorization_endpoint' => "{$this->issuer}/oauth/authorize",
            'token_endpoint' => "{$this->issuer}/oauth/token",
            'userinfo_endpoint' => "{$this->issuer}/oauth/userinfo",
            'jwks_uri' => "{$this->issuer}/.well-known/jwks.json",
            'response_types_supported' => ['code'],
            'grant_types_supported' => ['authorization_code', 'refresh_token'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['HS256'],
            'scopes_supported' => self::SUPPORTED_SCOPES,
            'token_endpoint_auth_methods_supported' => ['client_secret_post', 'client_secret_basic'],
            'code_challenge_methods_supported' => ['S256', 'plain'],
        ];
    }

    /**
     * Handle authorization code grant.
     */
    private function handleAuthorizationCodeGrant(
        ?string $code,
        ?string $redirectUri,
        ?string $clientId,
        ?string $clientSecret,
        ?string $codeVerifier,
    ): array {
        if ($code === null) {
            throw new InvalidCredentialsException('Missing authorization code');
        }

        // Verify code exists and is valid
        $authCode = $this->codeRepository->findByCode($code);
        if ($authCode === null || !$authCode->isValid()) {
            throw new InvalidCredentialsException('Invalid or expired authorization code');
        }

        // Verify client
        $client = $this->clientRepository->findById($authCode->clientId);
        if ($client === null) {
            throw new InvalidCredentialsException('Invalid client');
        }

        // Verify client credentials (for confidential clients)
        if ($client->type === 'confidential') {
            if ($clientId !== $client->id || !$client->verifySecret($clientSecret ?? '')) {
                throw new InvalidCredentialsException('Invalid client credentials');
            }
        }

        // Verify redirect URI matches
        if ($redirectUri !== $authCode->redirectUri) {
            throw new InvalidCredentialsException('Redirect URI mismatch');
        }

        // Verify PKCE if required
        if ($authCode->codeChallenge !== null) {
            if ($codeVerifier === null || !$authCode->verifyChallenge($codeVerifier)) {
                throw new InvalidCredentialsException('Invalid code verifier');
            }
        }

        // Mark code as used
        $this->codeRepository->markAsUsed($code);

        // Get user
        $user = $this->userRepository->findById($authCode->userId);
        if ($user === null) {
            throw new InvalidCredentialsException('User not found');
        }

        // Generate tokens
        return $this->generateTokens($user, $authCode->scopes, $client->id);
    }

    /**
     * Handle refresh token grant.
     */
    private function handleRefreshTokenGrant(
        ?string $refreshTokenValue,
        ?string $clientId,
        ?string $clientSecret,
    ): array {
        if ($refreshTokenValue === null) {
            throw new InvalidCredentialsException('Missing refresh token');
        }

        $refreshToken = null;
        $consumed = false;

        if (method_exists($this->refreshTokenRepository, 'consume')) {
            /** @var callable $consume */
            $consume = [$this->refreshTokenRepository, 'consume'];
            $refreshToken = $consume($refreshTokenValue, null);
            $consumed = $refreshToken !== null;
        } else {
            $refreshToken = $this->refreshTokenRepository->findByToken($refreshTokenValue);
            if ($refreshToken !== null && $refreshToken->isValid()) {
                $this->refreshTokenRepository->revoke($refreshTokenValue);
                $consumed = true;
            }
        }

        if (!$consumed || $refreshToken === null) {
            throw new InvalidCredentialsException('Invalid or expired refresh token');
        }

        // Verify client
        $client = $this->clientRepository->findById($clientId ?? '');
        if ($client === null || !$client->verifySecret($clientSecret ?? '')) {
            throw new InvalidCredentialsException('Invalid client credentials');
        }

        // Get user
        $user = $this->userRepository->findById($refreshToken->getUserId());
        if ($user === null) {
            throw new InvalidCredentialsException('User not found');
        }

        // Generate new tokens
        return $this->generateTokens($user, ['openid', 'profile', 'email'], $client->id);
    }

    /**
     * Generate access and ID tokens.
     */
    private function generateTokens(User $user, array $scopes, string $clientId): array
    {
        // Generate access token
        $accessToken = $this->tokenService->sign(
            [
                'sub' => $user->getId(),
                'iss' => $this->issuer,
                'aud' => $clientId,
                'type' => 'access_token',
                'scope' => $scopes,
                'email' => $user->getEmail(),
                'username' => $user->getUsername(),
            ],
            $this->accessTokenLifetime,
        );

        // Generate ID token (OIDC)
        $idToken = $this->tokenService->sign(
            [
                'sub' => $user->getId(),
                'iss' => $this->issuer,
                'aud' => $clientId,
                'iat' => time(),
                'exp' => time() + $this->accessTokenLifetime,
                'email' => $user->getEmail(),
                'email_verified' => $user->isEmailVerified(),
                'name' => $user->getUsername(),
                'picture' => $user->getAvatar(),
            ],
            $this->accessTokenLifetime,
        );

        $response = [
            'access_token' => $accessToken,
            'token_type' => 'Bearer',
            'expires_in' => $this->accessTokenLifetime,
            'id_token' => $idToken,
        ];

        // Generate refresh token if offline_access scope requested
        if (in_array('offline_access', $scopes, true)) {
            $refreshTokenValue = Crypto::randomToken(32);
            $expiresAt = new DateTimeImmutable("+{$this->refreshTokenLifetime} seconds");

            $this->refreshTokenRepository->create([
                'token' => $refreshTokenValue,
                'userId' => $user->getId(),
                'expiresAt' => $expiresAt->format('Y-m-d H:i:s'),
            ]);

            $response['refresh_token'] = $refreshTokenValue;
        }

        return $response;
    }
}
