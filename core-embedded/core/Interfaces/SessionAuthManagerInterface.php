<?php

declare(strict_types=1);

namespace BetterAuth\Core\Interfaces;

use BetterAuth\Core\Entities\User;

/**
 * Interface for session-based authentication managers.
 *
 * Allows mocking in tests and custom implementations.
 */
interface SessionAuthManagerInterface
{
    /**
     * Register a new user with email and password.
     *
     * @param array<string, mixed> $additionalData Additional user data (name, avatar, etc.)
     *
     * @throws \InvalidArgumentException If user already exists
     */
    public function signUp(string $email, string $password, array $additionalData = []): User;

    /**
     * Authenticate a user with email and password.
     *
     * @return array{user: array<string, mixed>, session: \BetterAuth\Core\Entities\Session}
     *
     * @throws \BetterAuth\Core\Exceptions\InvalidCredentialsException
     * @throws \BetterAuth\Core\Exceptions\RateLimitException
     */
    public function signIn(string $email, string $password, string $ipAddress, string $userAgent): array;

    /**
     * Sign out a user by invalidating their session.
     *
     * @return bool True if signed out successfully
     */
    public function signOut(string $sessionToken): bool;

    /**
     * Get the currently authenticated user from a session token.
     */
    public function getCurrentUser(string $sessionToken): ?User;
}
