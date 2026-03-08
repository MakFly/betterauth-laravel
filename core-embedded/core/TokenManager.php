<?php

declare(strict_types=1);

namespace BetterAuth\Core;

use BetterAuth\Core\Config\AuthConfig;
use BetterAuth\Core\Entities\User;
use BetterAuth\Core\Interfaces\RefreshTokenRepositoryInterface;
use BetterAuth\Core\Interfaces\TokenManagerInterface;
use BetterAuth\Core\Interfaces\TokenSignerInterface;
use BetterAuth\Core\Interfaces\UserRepositoryInterface;
use BetterAuth\Core\Utils\Crypto;
use DateTimeImmutable;

/**
 * High-level token manager for creating and managing authentication tokens.
 * Similar to Lexik's JWTManager.
 *
 * Use this class in custom controllers to create/decode tokens easily.
 *
 * Example usage in a custom controller:
 * ```php
 * public function __construct(
 *     private TokenManagerInterface $tokenManager,
 * ) {}
 *
 * public function login(Request $request): JsonResponse
 * {
 *     // ... validate credentials ...
 *     $tokens = $this->tokenManager->create($user);
 *     return $this->json($tokens);
 * }
 * ```
 */
final class TokenManager implements TokenManagerInterface
{
    private const USER_ID_CLAIM = 'sub';

    public function __construct(
        private readonly TokenSignerInterface $tokenSigner,
        private readonly UserRepositoryInterface $userRepository,
        private readonly RefreshTokenRepositoryInterface $refreshTokenRepository,
        private readonly AuthConfig $config,
    ) {
    }

    /**
     * {@inheritdoc}
     */
    public function create(User $user): array
    {
        $accessToken = $this->createAccessToken($user);

        $refreshTokenValue = Crypto::randomToken(32);
        $expiresAt = new DateTimeImmutable("+{$this->config->refreshTokenLifetime} seconds");

        $refreshToken = $this->refreshTokenRepository->create([
            'token' => $refreshTokenValue,
            'userId' => $user->getId(),
            'expiresAt' => $expiresAt->format('Y-m-d H:i:s'),
        ]);

        return [
            'access_token' => $accessToken,
            'refresh_token' => $refreshToken->getToken(),
            'token_type' => 'Bearer',
            'expires_in' => $this->config->tokenLifetime,
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function createAccessToken(User $user): string
    {
        return $this->tokenSigner->sign(
            [
                self::USER_ID_CLAIM => $user->getId(),
                'type' => 'access',
                'data' => [
                    'email' => $user->getEmail(),
                    'username' => $user->getUsername(),
                ],
            ],
            $this->config->tokenLifetime,
        );
    }

    /**
     * {@inheritdoc}
     */
    public function parse(string $token): ?array
    {
        return $this->tokenSigner->verify($token);
    }

    /**
     * {@inheritdoc}
     */
    public function decode(string $token): ?array
    {
        return $this->tokenSigner->decode($token);
    }

    /**
     * {@inheritdoc}
     */
    public function getUserFromToken(string $token): ?User
    {
        $payload = $this->parse($token);

        if ($payload === null) {
            return null;
        }

        return $this->userRepository->findById($payload[self::USER_ID_CLAIM]);
    }

    /**
     * {@inheritdoc}
     */
    public function getUserIdClaim(): string
    {
        return self::USER_ID_CLAIM;
    }
}
