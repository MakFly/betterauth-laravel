<?php

declare(strict_types=1);

namespace BetterAuth\Core\Interfaces;

use BetterAuth\Core\Entities\PasswordResetToken;

/**
 * Interface for password reset token storage.
 */
interface PasswordResetStorageInterface
{
    /**
     * Store a password reset token.
     *
     * @param string $token The reset token
     * @param string $email The user email
     * @param int $expiresIn Expiration time in seconds
     *
     * @return PasswordResetToken The stored token
     */
    public function store(string $token, string $email, int $expiresIn): PasswordResetToken;

    /**
     * Find a password reset token by its value.
     *
     * @param string $token The token
     *
     * @return PasswordResetToken|null The token or null if not found
     */
    public function findByToken(string $token): ?PasswordResetToken;

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
     * Delete all tokens for an email.
     *
     * @param string $email The email address
     *
     * @return int Number of tokens deleted
     */
    public function deleteByEmail(string $email): int;

    /**
     * Delete all expired tokens.
     *
     * @return int Number of tokens deleted
     */
    public function deleteExpired(): int;
}
