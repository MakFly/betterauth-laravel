<?php

declare(strict_types=1);

namespace BetterAuth\Core\Interfaces;

use BetterAuth\Core\Entities\MagicLinkToken;

/**
 * Interface for magic link token storage.
 */
interface MagicLinkStorageInterface
{
    /**
     * Store a magic link token.
     *
     * @param string $token The token
     * @param string $email The email address
     * @param int $expiresIn Expiration time in seconds
     *
     * @return MagicLinkToken The stored token
     */
    public function store(string $token, string $email, int $expiresIn): MagicLinkToken;

    /**
     * Find a magic link token by its value.
     *
     * @param string $token The token
     *
     * @return MagicLinkToken|null The token or null if not found
     */
    public function findByToken(string $token): ?MagicLinkToken;

    /**
     * Mark a token as used.
     *
     * @param string $token The token
     *
     * @return bool True if marked as used, false otherwise
     */
    public function markAsUsed(string $token): bool;

    /**
     * Delete a token.
     *
     * @param string $token The token
     *
     * @return bool True if deleted, false otherwise
     */
    public function delete(string $token): bool;

    /**
     * Delete all expired tokens.
     *
     * @return int Number of tokens deleted
     */
    public function deleteExpired(): int;
}
