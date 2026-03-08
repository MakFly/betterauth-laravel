<?php

declare(strict_types=1);

namespace BetterAuth\Core\Interfaces;

use BetterAuth\Core\Entities\Session;

/**
 * Repository interface for session persistence operations.
 */
interface SessionRepositoryInterface
{
    /**
     * Find a session by its token.
     *
     * @param string $token The session token
     *
     * @return Session|null The session entity or null if not found
     */
    public function findByToken(string $token): ?Session;

    /**
     * Find all active sessions for a user.
     *
     * @param string $userId The user ID
     *
     * @return Session[] Array of active sessions
     */
    public function findByUserId(string $userId): array;

    /**
     * Create a new session.
     *
     * @param array<string, mixed> $data Session data
     *
     * @return Session The created session entity
     */
    public function create(array $data): Session;

    /**
     * Update an existing session.
     *
     * @param string $token The session token
     * @param array<string, mixed> $data Data to update
     *
     * @return Session The updated session entity
     */
    public function update(string $token, array $data): Session;

    /**
     * Delete a session by its token.
     *
     * @param string $token The session token
     *
     * @return bool True if deleted, false otherwise
     */
    public function delete(string $token): bool;

    /**
     * Delete all sessions for a user.
     *
     * @param string $userId The user ID
     *
     * @return int Number of sessions deleted
     */
    public function deleteByUserId(string $userId): int;

    /**
     * Delete all expired sessions.
     *
     * @return int Number of sessions deleted
     */
    public function deleteExpired(): int;
}
