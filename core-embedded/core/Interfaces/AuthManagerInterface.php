<?php

declare(strict_types=1);

namespace BetterAuth\Core\Interfaces;

use BetterAuth\Core\Entities\User;

/**
 * Façade interface for authentication operations.
 *
 * This is the main interface to use in controllers.
 * It automatically delegates to the appropriate manager based on the configured mode.
 */
interface AuthManagerInterface
{
    /**
     * Authenticate a user with email and password.
     * Returns session or tokens based on configured mode.
     *
     * @return array Session mode returns {user, session}, API mode returns {user, access_token, refresh_token, ...}
     *
     * @throws \BetterAuth\Core\Exceptions\InvalidCredentialsException
     * @throws \BetterAuth\Core\Exceptions\RateLimitException
     */
    public function signIn(string $email, string $password, string $ipAddress, string $userAgent): array;

    /**
     * Register a new user with email and password.
     *
     * @param array<string, mixed> $additionalData Additional user data (name, avatar, etc.)
     *
     * @throws \InvalidArgumentException If user already exists
     */
    public function signUp(string $email, string $password, array $additionalData = []): User;

    /**
     * Sign out a user by invalidating their session/tokens.
     *
     * @return bool True if signed out successfully
     */
    public function signOut(string $token): bool;

    /**
     * Get the currently authenticated user from a token or session.
     */
    public function getCurrentUser(string $token): ?User;
}
