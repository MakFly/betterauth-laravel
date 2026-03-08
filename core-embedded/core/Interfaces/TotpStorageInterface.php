<?php

declare(strict_types=1);

namespace BetterAuth\Core\Interfaces;

/**
 * Interface for TOTP (Time-based One-Time Password) storage.
 */
interface TotpStorageInterface
{
    /**
     * Store a TOTP secret for a user.
     *
     * @param string $userId The user ID
     * @param string $secret The TOTP secret
     * @param array<string, mixed> $metadata Additional metadata (backup codes, etc.)
     *
     * @return bool True if stored successfully, false otherwise
     */
    public function store(string $userId, string $secret, array $metadata = []): bool;

    /**
     * Get the TOTP secret for a user.
     *
     * @param string $userId The user ID
     *
     * @return array<string, mixed>|null The TOTP data or null if not found
     */
    public function findByUserId(string $userId): ?array;

    /**
     * Verify if TOTP is enabled for a user.
     *
     * @param string $userId The user ID
     *
     * @return bool True if enabled, false otherwise
     */
    public function isEnabled(string $userId): bool;

    /**
     * Enable TOTP for a user.
     *
     * @param string $userId The user ID
     *
     * @return bool True if enabled successfully, false otherwise
     */
    public function enable(string $userId): bool;

    /**
     * Disable TOTP for a user.
     *
     * @param string $userId The user ID
     *
     * @return bool True if disabled successfully, false otherwise
     */
    public function disable(string $userId): bool;

    /**
     * Delete TOTP data for a user.
     *
     * @param string $userId The user ID
     *
     * @return bool True if deleted, false otherwise
     */
    public function delete(string $userId): bool;

    /**
     * Use a backup code.
     *
     * @param string $userId The user ID
     * @param string $code The backup code
     *
     * @return bool True if valid and used, false otherwise
     */
    public function useBackupCode(string $userId, string $code): bool;

    /**
     * Update the last 2FA verification timestamp.
     *
     * @param string $userId The user ID
     *
     * @return bool True if updated successfully, false otherwise
     */
    public function updateLast2faVerifiedAt(string $userId): bool;
}
