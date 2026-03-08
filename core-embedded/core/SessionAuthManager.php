<?php

declare(strict_types=1);

namespace BetterAuth\Core;

use BetterAuth\Core\Entities\Session;
use BetterAuth\Core\Entities\User;
use BetterAuth\Core\Exceptions\InvalidCredentialsException;
use BetterAuth\Core\Exceptions\RateLimitException;
use BetterAuth\Core\Exceptions\UserNotFoundException;
use BetterAuth\Core\Interfaces\RateLimiterInterface;
use BetterAuth\Core\Interfaces\SessionAuthManagerInterface;
use BetterAuth\Core\Interfaces\UserRepositoryInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Session-based authentication manager for stateful applications.
 *
 * Uses SessionService to create and manage database-backed sessions.
 * Perfect for traditional web applications with cookies.
 *
 * For stateless API authentication with JWT/Paseto tokens, use TokenAuthManager instead.
 *
 * This class is final to ensure consistent session authentication behavior.
 */
final class SessionAuthManager implements SessionAuthManagerInterface
{
    private readonly LoggerInterface $logger;

    public function __construct(
        private readonly UserRepositoryInterface $userRepository,
        private readonly SessionService $sessionService,
        private readonly PasswordHasher $passwordHasher,
        private readonly ?RateLimiterInterface $rateLimiter = null,
        ?LoggerInterface $logger = null,
    ) {
        $this->logger = $logger ?? new NullLogger();
    }

    /**
     * Sign up a new user with email and password.
     *
     * @param string $email The user's email
     * @param string $password The user's password
     * @param array<string, mixed> $additionalData Additional user data
     *
     * @return User The created user
     *
     * @throws \Exception
     */
    public function signUp(string $email, string $password, array $additionalData = []): User
    {
        $this->logger->info('Sign up attempt', ['email' => $email]);

        // Check if user already exists
        $existingUser = $this->userRepository->findByEmail($email);
        if ($existingUser !== null) {
            $this->logger->warning('Sign up failed: User already exists', ['email' => $email]);

            throw new \InvalidArgumentException('User with this email already exists');
        }

        try {
            $passwordHash = $this->passwordHasher->hash($password);

            $userData = [
                'email' => $email,
                'password' => $passwordHash,
                'name' => $additionalData['name'] ?? null,
                'avatar' => $additionalData['avatar'] ?? null,
                'email_verified' => false,
                'metadata' => $additionalData['metadata'] ?? null,
            ];

            // Only set 'id' if repository generates one (UUID/ULID strategy)
            // For auto-increment (INT strategy), repository will let DB handle it
            $generatedId = $this->userRepository->generateId();
            if ($generatedId !== null) {
                $userData['id'] = $generatedId;
            }

            $user = $this->userRepository->create($userData);

            $this->logger->info('Sign up successful', [
                'email' => $email,
                'user_id' => $user->getId(),
            ]);

            return $user;
        } catch (\Exception $e) {
            $this->logger->error('Sign up failed with exception', [
                'email' => $email,
                'error' => $e->getMessage(),
            ]);

            throw $e;
        }
    }

    /**
     * Sign in a user with email and password.
     *
     * @param string $email The user's email
     * @param string $password The user's password
     * @param string $ipAddress The user's IP address
     * @param string $userAgent The user's user agent
     *
     * @return array{user: array<string, mixed>, session: Session} The user DTO array and session
     *
     * @throws InvalidCredentialsException
     * @throws RateLimitException
     * @throws \Exception
     */
    public function signIn(string $email, string $password, string $ipAddress, string $userAgent): array
    {
        $this->logger->info('Sign in attempt', ['email' => $email, 'ip_address' => $ipAddress]);

        // Rate limiting
        $rateLimitKey = "login:$email";
        if ($this->rateLimiter?->tooManyAttempts($rateLimitKey, 5, 300)) {
            $retryAfter = $this->rateLimiter->availableIn($rateLimitKey);

            $this->logger->warning('Sign in rate limited', [
                'email' => $email,
                'ip_address' => $ipAddress,
                'retry_after' => $retryAfter,
            ]);

            throw new RateLimitException(retryAfter: $retryAfter);
        }

        $user = $this->userRepository->findByEmail($email);

        if ($user === null || !$user->hasPassword()) {
            $this->rateLimiter?->hit($rateLimitKey, 300);

            $this->logger->warning('Sign in failed: Invalid credentials', [
                'email' => $email,
                'ip_address' => $ipAddress,
                'reason' => $user === null ? 'user_not_found' : 'no_password',
            ]);

            throw new InvalidCredentialsException();
        }

        // After hasPassword() check, password is guaranteed to be non-null
        $passwordHash = $user->getPassword();
        assert($passwordHash !== null);

        if (!$this->passwordHasher->verify($password, $passwordHash)) {
            $this->rateLimiter?->hit($rateLimitKey, 300);

            $this->logger->warning('Sign in failed: Invalid password', [
                'email' => $email,
                'ip_address' => $ipAddress,
                'user_id' => $user->getId(),
            ]);

            throw new InvalidCredentialsException();
        }

        // Clear rate limit on successful login
        $this->rateLimiter?->clear($rateLimitKey);

        try {
            // Check if password needs rehashing
            if ($this->passwordHasher->needsRehash($passwordHash)) {
                $this->logger->debug('Password needs rehashing', ['user_id' => $user->getId()]);
                $newHash = $this->passwordHasher->hash($password);
                $user = $this->userRepository->update($user->getId(), ['password_hash' => $newHash]);
            }

            $session = $this->sessionService->create($user, $ipAddress, $userAgent);

            $this->logger->info('Sign in successful', [
                'email' => $email,
                'user_id' => $user->getId(),
                'session_token' => substr($session->getToken(), 0, 10) . '...',
                'ip_address' => $ipAddress,
            ]);

            return [
                'user' => \BetterAuth\Core\DTO\UserDto::fromUser($user)->toArray(),
                'session' => $session,
            ];
        } catch (\Exception $e) {
            $this->logger->error('Sign in failed with exception', [
                'email' => $email,
                'user_id' => $user->getId(),
                'ip_address' => $ipAddress,
                'error' => $e->getMessage(),
            ]);

            throw $e;
        }
    }

    /**
     * Sign out a user by deleting their session.
     *
     * @param string $sessionToken The session token
     *
     * @return bool True if signed out, false otherwise
     */
    public function signOut(string $sessionToken): bool
    {
        $this->logger->info('Sign out attempt', [
            'session_token' => substr($sessionToken, 0, 10) . '...',
        ]);

        $result = $this->sessionService->delete($sessionToken);

        if ($result) {
            $this->logger->info('Sign out successful', [
                'session_token' => substr($sessionToken, 0, 10) . '...',
            ]);
        } else {
            $this->logger->warning('Sign out failed: Session not found', [
                'session_token' => substr($sessionToken, 0, 10) . '...',
            ]);
        }

        return $result;
    }

    /**
     * Get the current user from a session token.
     *
     * @param string $sessionToken The session token
     *
     * @return User|null The user or null if not found
     */
    public function getCurrentUser(string $sessionToken): ?User
    {
        try {
            $session = $this->sessionService->validate($sessionToken);

            $user = $this->userRepository->findById($session->getUserId());

            if ($user === null) {
                $this->logger->warning('Get current user failed: User not found', [
                    'session_token' => substr($sessionToken, 0, 10) . '...',
                    'user_id' => $session->getUserId(),
                ]);
            }

            return $user;
        } catch (\Exception $e) {
            $this->logger->debug('Get current user failed: Invalid session', [
                'session_token' => substr($sessionToken, 0, 10) . '...',
                'error' => $e->getMessage(),
            ]);

            return null;
        }
    }

    /**
     * Verify a user's email.
     *
     * @param string $userId The user ID
     *
     * @return bool True if verified, false otherwise
     */
    public function verifyEmail(string $userId): bool
    {
        $this->logger->info('Email verification attempt', ['user_id' => $userId]);

        $result = $this->userRepository->verifyEmail($userId);

        if ($result) {
            $this->logger->info('Email verified successfully', ['user_id' => $userId]);
        } else {
            $this->logger->warning('Email verification failed', ['user_id' => $userId]);
        }

        return $result;
    }

    /**
     * Update user password.
     *
     * @param string $userId The user ID
     * @param string $newPassword The new password
     *
     * @return User The updated user
     *
     * @throws UserNotFoundException
     */
    public function updatePassword(string $userId, string $newPassword): User
    {
        $this->logger->info('Password update attempt', ['user_id' => $userId]);

        $user = $this->userRepository->findById($userId);

        if ($user === null) {
            $this->logger->error('Password update failed: User not found', ['user_id' => $userId]);

            throw new UserNotFoundException();
        }

        try {
            $passwordHash = $this->passwordHasher->hash($newPassword);

            $updatedUser = $this->userRepository->update($userId, ['password_hash' => $passwordHash]);

            $this->logger->info('Password updated successfully', ['user_id' => $userId]);

            return $updatedUser;
        } catch (\Exception $e) {
            $this->logger->error('Password update failed with exception', [
                'user_id' => $userId,
                'error' => $e->getMessage(),
            ]);

            throw $e;
        }
    }

    /**
     * Validate a session and refresh it if needed.
     *
     * @param string $sessionToken The session token
     *
     * @return Session The validated/refreshed session
     */
    public function validateSession(string $sessionToken): Session
    {
        return $this->sessionService->validate($sessionToken);
    }

    /**
     * Get all sessions for a user.
     *
     * @param string $userId The user ID
     *
     * @return Session[] Array of sessions
     */
    public function getUserSessions(string $userId): array
    {
        $this->logger->debug('Getting all sessions for user', ['user_id' => $userId]);

        $sessions = $this->sessionService->getAllForUser($userId);

        $this->logger->debug('Retrieved user sessions', [
            'user_id' => $userId,
            'session_count' => count($sessions),
        ]);

        return $sessions;
    }

    /**
     * Revoke a specific session for a user.
     *
     * @param string $userId The user ID
     * @param string $sessionId The session token to revoke
     *
     * @return bool True if revoked, false otherwise
     */
    public function revokeSession(string $userId, string $sessionId): bool
    {
        $this->logger->info('Session revocation attempt', [
            'user_id' => $userId,
            'session_token' => substr($sessionId, 0, 10) . '...',
        ]);

        try {
            // Verify that the session belongs to the user
            $session = $this->sessionService->validate($sessionId);
            if ($session->getUserId() !== $userId) {
                $this->logger->warning('Session revocation failed: Session does not belong to user', [
                    'user_id' => $userId,
                    'session_user_id' => $session->getUserId(),
                    'session_token' => substr($sessionId, 0, 10) . '...',
                ]);

                throw new \InvalidArgumentException('Session does not belong to user');
            }

            $result = $this->sessionService->delete($sessionId);

            $this->logger->info('Session revoked successfully', [
                'user_id' => $userId,
                'session_token' => substr($sessionId, 0, 10) . '...',
            ]);

            return $result;
        } catch (\Exception $e) {
            $this->logger->error('Session revocation failed with exception', [
                'user_id' => $userId,
                'session_token' => substr($sessionId, 0, 10) . '...',
                'error' => $e->getMessage(),
            ]);

            throw $e;
        }
    }

    /**
     * Get the user repository.
     *
     * @internal Used by AuthManager for two-factor authentication
     */
    public function getUserRepository(): UserRepositoryInterface
    {
        return $this->userRepository;
    }

    /**
     * Get the session service.
     *
     * @internal Used by AuthManager for two-factor authentication
     */
    public function getSessionService(): SessionService
    {
        return $this->sessionService;
    }
}
