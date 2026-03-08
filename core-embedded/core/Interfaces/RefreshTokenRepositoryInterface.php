<?php

declare(strict_types=1);

namespace BetterAuth\Core\Interfaces;

use BetterAuth\Core\Entities\RefreshToken;

/**
 * Repository interface for refresh token persistence (API mode).
 */
interface RefreshTokenRepositoryInterface
{
    /**
     * Find a refresh token by its value.
     */
    public function findByToken(string $token): ?RefreshToken;

    /**
     * Find all refresh tokens for a user.
     */
    public function findByUserId(string $userId): array;

    /**
     * Create a new refresh token.
     */
    public function create(array $data): RefreshToken;

    /**
     * Revoke a refresh token.
     */
    public function revoke(string $token, ?string $replacedBy = null): bool;

    /**
     * Revoke all refresh tokens for a user.
     */
    public function revokeAllForUser(string $userId): int;

    /**
     * Delete expired tokens.
     */
    public function deleteExpired(): int;
}
