<?php

declare(strict_types=1);

namespace BetterAuth\Core;

use BetterAuth\Core\Entities\Session;
use BetterAuth\Core\Entities\User;
use BetterAuth\Core\Exceptions\SessionExpiredException;
use BetterAuth\Core\Interfaces\SessionRepositoryInterface;
use BetterAuth\Core\Utils\Crypto;
use DateTimeImmutable;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Service for managing user sessions.
 *
 * This service is final to ensure consistent session management behavior.
 */
final class SessionService
{
    private readonly LoggerInterface $logger;

    public function __construct(
        private readonly SessionRepositoryInterface $sessionRepository,
        private readonly int $sessionLifetime = 86400 * 7, // 7 days default
        private readonly int $absoluteLifetime = 86400 * 30, // 30 days hard cap
        ?LoggerInterface $logger = null,
    ) {
        $this->logger = $logger ?? new NullLogger();
    }

    /**
     * Create a new session for a user.
     *
     * @param User $user The user to create a session for
     * @param string $ipAddress The user's IP address
     * @param string $userAgent The user's user agent
     * @param array<string, mixed> $metadata Additional session metadata
     *
     * @return Session The created session
     *
     * @throws \Exception
     */
    public function create(
        User $user,
        string $ipAddress,
        string $userAgent,
        array $metadata = [],
    ): Session {
        $this->logger->info('Creating new session', [
            'user_id' => $user->getId(),
            'ip_address' => $ipAddress,
        ]);

        try {
            $token = Crypto::randomToken(32);
            $expiresAt = new DateTimeImmutable("+{$this->sessionLifetime} seconds");

            $session = $this->sessionRepository->create([
                'token' => $token,
                'user_id' => $user->getId(),
                'expires_at' => $expiresAt->format('Y-m-d H:i:s'),
                'ip_address' => $ipAddress,
                'user_agent' => $userAgent,
                'metadata' => $metadata,
            ]);

            $this->logger->info('Session created successfully', [
                'user_id' => $user->getId(),
                'session_token' => substr($token, 0, 10) . '...',
                'expires_at' => $expiresAt->format('Y-m-d H:i:s'),
            ]);

            return $session;
        } catch (\Exception $e) {
            $this->logger->error('Failed to create session', [
                'user_id' => $user->getId(),
                'ip_address' => $ipAddress,
                'error' => $e->getMessage(),
            ]);

            throw $e;
        }
    }

    /**
     * Validate and retrieve a session by token.
     *
     * @param string $token The session token
     *
     * @return Session The valid session
     *
     * @throws SessionExpiredException
     */
    public function validate(string $token): Session
    {
        $this->logger->debug('Validating session', [
            'session_token' => substr($token, 0, 10) . '...',
        ]);

        $session = $this->sessionRepository->findByToken($token);

        if ($session === null) {
            $this->logger->warning('Session validation failed: Session not found', [
                'session_token' => substr($token, 0, 10) . '...',
            ]);

            throw new SessionExpiredException('Session not found');
        }

        if ($session->isExpired()) {
            $this->logger->warning('Session validation failed: Session expired', [
                'session_token' => substr($token, 0, 10) . '...',
                'user_id' => $session->getUserId(),
                'expired_at' => $session->getExpiresAt()->format('Y-m-d H:i:s'),
            ]);

            $this->sessionRepository->delete($token);

            throw new SessionExpiredException();
        }

        // Absolute lifetime check: expire the session regardless of last activity
        $absoluteDeadline = $session->getCreatedAt()->modify("+{$this->absoluteLifetime} seconds");
        if ($absoluteDeadline < new DateTimeImmutable()) {
            $this->logger->warning('Session validation failed: Absolute lifetime exceeded', [
                'session_token' => substr($token, 0, 10) . '...',
                'user_id' => $session->getUserId(),
                'created_at' => $session->getCreatedAt()->format('Y-m-d H:i:s'),
                'absolute_deadline' => $absoluteDeadline->format('Y-m-d H:i:s'),
            ]);

            $this->sessionRepository->delete($token);

            throw new SessionExpiredException('Session absolute lifetime exceeded');
        }

        $this->logger->debug('Session validated successfully', [
            'session_token' => substr($token, 0, 10) . '...',
            'user_id' => $session->getUserId(),
        ]);

        return $session;
    }

    /**
     * Refresh a session's expiration time.
     *
     * @param string $token The session token
     *
     * @return Session The refreshed session
     *
     * @throws SessionExpiredException
     */
    public function refresh(string $token): Session
    {
        $this->logger->debug('Refreshing session', [
            'session_token' => substr($token, 0, 10) . '...',
        ]);

        try {
            $session = $this->validate($token);

            $expiresAt = new DateTimeImmutable("+{$this->sessionLifetime} seconds");

            $refreshedSession = $this->sessionRepository->update($token, [
                'expires_at' => $expiresAt->format('Y-m-d H:i:s'),
            ]);

            $this->logger->info('Session refreshed successfully', [
                'session_token' => substr($token, 0, 10) . '...',
                'user_id' => $session->getUserId(),
                'new_expires_at' => $expiresAt->format('Y-m-d H:i:s'),
            ]);

            return $refreshedSession;
        } catch (SessionExpiredException $e) {
            throw $e;
        } catch (\Exception $e) {
            $this->logger->error('Failed to refresh session', [
                'session_token' => substr($token, 0, 10) . '...',
                'error' => $e->getMessage(),
            ]);

            throw $e;
        }
    }

    /**
     * Delete a session.
     *
     * @param string $token The session token
     *
     * @return bool True if deleted, false otherwise
     */
    public function delete(string $token): bool
    {
        $this->logger->info('Deleting session', [
            'session_token' => substr($token, 0, 10) . '...',
        ]);

        $result = $this->sessionRepository->delete($token);

        if ($result) {
            $this->logger->info('Session deleted successfully', [
                'session_token' => substr($token, 0, 10) . '...',
            ]);
        } else {
            $this->logger->warning('Session deletion failed: Session not found', [
                'session_token' => substr($token, 0, 10) . '...',
            ]);
        }

        return $result;
    }

    /**
     * Delete all sessions for a user.
     *
     * @param string $userId The user ID
     *
     * @return int Number of sessions deleted
     */
    public function deleteAllForUser(string $userId): int
    {
        $this->logger->info('Deleting all sessions for user', ['user_id' => $userId]);

        $deletedCount = $this->sessionRepository->deleteByUserId($userId);

        $this->logger->info('All user sessions deleted', [
            'user_id' => $userId,
            'deleted_count' => $deletedCount,
        ]);

        return $deletedCount;
    }

    /**
     * Get all active sessions for a user.
     *
     * @param string $userId The user ID
     *
     * @return Session[] Array of active sessions
     */
    public function getAllForUser(string $userId): array
    {
        $this->logger->debug('Getting all sessions for user', ['user_id' => $userId]);

        $sessions = $this->sessionRepository->findByUserId($userId);

        $this->logger->debug('Retrieved sessions for user', [
            'user_id' => $userId,
            'session_count' => count($sessions),
        ]);

        return $sessions;
    }

    /**
     * Clean up expired sessions.
     *
     * @return int Number of sessions deleted
     */
    public function cleanupExpired(): int
    {
        $this->logger->info('Cleaning up expired sessions');

        $deletedCount = $this->sessionRepository->deleteExpired();

        $this->logger->info('Expired sessions cleaned up', [
            'deleted_count' => $deletedCount,
        ]);

        return $deletedCount;
    }
}
