<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Repositories;

/**
 * Laravel-specific session repository contract.
 */
interface SessionRepository
{
    /**
     * Find a session by ID.
     */
    public function findById(string $id): ?object;

    /**
     * Find all active sessions for a user.
     *
     * @return array<object>
     */
    public function findByUserId(string $userId): array;

    /**
     * Create a new session.
     *
     * @param  array<string, mixed>  $data
     */
    public function create(array $data): object;

    /**
     * Revoke a session.
     */
    public function revoke(string $id): bool;

    /**
     * Revoke all sessions for a user.
     */
    public function revokeAllForUser(string $userId, ?string $exceptId = null): int;

    /**
     * Delete expired sessions.
     */
    public function deleteExpired(): int;
}
