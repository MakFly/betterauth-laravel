<?php

declare(strict_types=1);

namespace BetterAuth\Core;

/**
 * Password hashing service using Argon2id.
 *
 * This service is final to prevent extension and ensure consistent security behavior.
 */
final class PasswordHasher
{
    private const ALGORITHM = PASSWORD_ARGON2ID;

    public function __construct(
        private readonly int $memoryCost = PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
        private readonly int $timeCost = PASSWORD_ARGON2_DEFAULT_TIME_COST,
        private readonly int $threads = PASSWORD_ARGON2_DEFAULT_THREADS,
    ) {
    }

    /**
     * Hash a password using Argon2id.
     *
     * @param string $password The password to hash
     *
     * @return string The hashed password
     */
    public function hash(string $password): string
    {
        return password_hash($password, self::ALGORITHM, [
            'memory_cost' => $this->memoryCost,
            'time_cost' => $this->timeCost,
            'threads' => $this->threads,
        ]);
    }

    /**
     * Verify a password against a hash.
     *
     * @param string $password The password to verify
     * @param string $hash The hash to verify against
     *
     * @return bool True if password matches, false otherwise
     */
    public function verify(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    /**
     * Check if a hash needs to be rehashed.
     *
     * @param string $hash The hash to check
     *
     * @return bool True if rehashing is needed, false otherwise
     */
    public function needsRehash(string $hash): bool
    {
        return password_needs_rehash($hash, self::ALGORITHM, [
            'memory_cost' => $this->memoryCost,
            'time_cost' => $this->timeCost,
            'threads' => $this->threads,
        ]);
    }
}
