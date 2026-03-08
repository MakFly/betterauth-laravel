<?php

declare(strict_types=1);

namespace BetterAuth\Core\Interfaces;

use BetterAuth\Core\Entities\AuthorizationCode;

/**
 * Repository interface for authorization codes.
 */
interface AuthorizationCodeRepositoryInterface
{
    /**
     * Find authorization code.
     */
    public function findByCode(string $code): ?AuthorizationCode;

    /**
     * Create authorization code.
     */
    public function create(array $data): AuthorizationCode;

    /**
     * Mark code as used.
     */
    public function markAsUsed(string $code): void;

    /**
     * Delete expired codes.
     */
    public function deleteExpired(): int;

    /**
     * Delete all codes for a user.
     */
    public function deleteByUserId(string $userId): int;
}
