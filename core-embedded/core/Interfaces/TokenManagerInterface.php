<?php

declare(strict_types=1);

namespace BetterAuth\Core\Interfaces;

use BetterAuth\Core\Entities\User;

/**
 * High-level interface for token management.
 * Similar to Lexik's JWTTokenManagerInterface.
 *
 * Use this interface in custom controllers to create/decode tokens.
 */
interface TokenManagerInterface
{
    /**
     * Create access + refresh tokens for a user.
     *
     * @return array{access_token: string, refresh_token: string, token_type: string, expires_in: int}
     */
    public function create(User $user): array;

    /**
     * Create only an access token (no refresh token).
     */
    public function createAccessToken(User $user): string;

    /**
     * Decode a token and return the payload (with validation).
     * Similar to Lexik's JWTTokenManagerInterface::parse().
     *
     * @return array{sub: int|string, type: string, data: array|null, exp: int, iat: int}|null
     */
    public function parse(string $token): ?array;

    /**
     * Decode without validation (inspection only).
     * WARNING: Do not trust the data from this method for authentication!
     * Similar to Lexik's JWTTokenManagerInterface::decode().
     *
     * @return array{sub: int|string, type: string, data: array|null, exp: int|null, iat: int|null}|null
     */
    public function decode(string $token): ?array;

    /**
     * Get user from token.
     * Validates the token and retrieves the associated user.
     */
    public function getUserFromToken(string $token): ?User;

    /**
     * Get the claim name used to store the user ID.
     * Default is 'sub' (subject) per JWT/Paseto standards.
     */
    public function getUserIdClaim(): string;
}
