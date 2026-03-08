<?php

declare(strict_types=1);

namespace BetterAuth\Core\Interfaces;

/**
 * Interface for rate limiting operations.
 */
interface RateLimiterInterface
{
    /**
     * Check if a key has exceeded the rate limit.
     *
     * @param string $key The rate limit key (e.g., email, IP)
     * @param int $maxAttempts Maximum number of attempts
     * @param int $decaySeconds Time window in seconds
     *
     * @return bool True if rate limit exceeded, false otherwise
     */
    public function tooManyAttempts(string $key, int $maxAttempts, int $decaySeconds): bool;

    /**
     * Increment the attempt counter for a key.
     *
     * @param string $key The rate limit key
     * @param int $decaySeconds Time window in seconds
     *
     * @return int The current number of attempts
     */
    public function hit(string $key, int $decaySeconds): int;

    /**
     * Get the number of attempts for a key.
     *
     * @param string $key The rate limit key
     *
     * @return int The number of attempts
     */
    public function attempts(string $key): int;

    /**
     * Clear the attempts for a key.
     *
     * @param string $key The rate limit key
     *
     * @return bool True if cleared, false otherwise
     */
    public function clear(string $key): bool;

    /**
     * Get the number of seconds until the rate limit resets.
     *
     * @param string $key The rate limit key
     *
     * @return int Seconds until reset
     */
    public function availableIn(string $key): int;
}
