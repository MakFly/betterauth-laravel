<?php

declare(strict_types=1);

namespace BetterAuth\Core\Interfaces;

/**
 * Interface for token signing and verification (Paseto V4).
 */
interface TokenSignerInterface
{
    /**
     * Sign a payload and create a token.
     *
     * @param array<string, mixed> $payload The payload to sign
     * @param int $expiresIn Expiration time in seconds
     *
     * @return string The signed token
     */
    public function sign(array $payload, int $expiresIn): string;

    /**
     * Verify and parse a token.
     *
     * @param string $token The token to verify
     *
     * @return array<string, mixed>|null The payload if valid, null otherwise
     */
    public function verify(string $token): ?array;

    /**
     * Extract payload without verification (use with caution).
     *
     * @param string $token The token
     *
     * @return array<string, mixed>|null The payload if parseable, null otherwise
     */
    public function decode(string $token): ?array;
}
