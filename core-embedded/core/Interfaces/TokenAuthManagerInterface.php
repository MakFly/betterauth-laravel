<?php

declare(strict_types=1);

namespace BetterAuth\Core\Interfaces;

use BetterAuth\Core\Entities\User;

/**
 * Interface for token-based authentication managers.
 *
 * Allows mocking in tests while keeping TokenAuthManager as a final class.
 */
interface TokenAuthManagerInterface
{
    /**
     * Authenticate and return access + refresh tokens.
     *
     * @return array{user: array<string, mixed>, access_token: string, refresh_token: string, token_type: string, expires_in: int}
     */
    public function signIn(string $email, string $password): array;

    /**
     * Refresh access token using refresh token.
     *
     * @return array{user: array<string, mixed>, access_token: string, refresh_token: string, token_type: string, expires_in: int}
     */
    public function refresh(string $refreshTokenValue): array;

    /**
     * Verify access token and return user.
     */
    public function verify(string $accessToken): User;

    /**
     * Revoke all tokens for a user (logout from all devices).
     */
    public function revokeAllTokens(string $userId): int;

    /**
     * Create tokens for an existing user without password verification.
     * Useful for OAuth, magic links, or automatic login after registration.
     *
     * @return array{user: array<string, mixed>, access_token: string, refresh_token: string, token_type: string, expires_in: int}
     */
    public function createTokensForUser(User $user): array;

    /**
     * Update user password.
     */
    public function updatePassword(string $userId, string $newPassword): User;
}
