<?php

declare(strict_types=1);

namespace BetterAuth\Core\Interfaces;

use BetterAuth\Core\Entities\EmailVerificationToken;

/**
 * Interface for email verification token storage.
 */
interface EmailVerificationStorageInterface
{
    /**
     * Store an email verification token.
     *
     * @param string $token The verification token
     * @param string $email The user email
     * @param int $expiresIn Expiration time in seconds
     *
     * @return EmailVerificationToken The stored token
     */
    public function store(string $token, string $email, int $expiresIn): EmailVerificationToken;

    /**
     * Find an email verification token by its value.
     *
     * @param string $token The token
     *
     * @return EmailVerificationToken|null The token or null if not found
     */
    public function findByToken(string $token): ?EmailVerificationToken;

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
