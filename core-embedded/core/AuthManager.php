<?php

declare(strict_types=1);

namespace BetterAuth\Core;

use BetterAuth\Core\Config\AuthConfig;
use BetterAuth\Core\Config\AuthMode;
use BetterAuth\Core\Entities\Session;
use BetterAuth\Core\Entities\User;
use BetterAuth\Core\Interfaces\AuthManagerInterface;

/**
 * Unified Authentication Manager - Facade pattern.
 *
 * Automatically delegates to SessionAuthManager or TokenAuthManager
 * based on your configuration mode.
 *
 * This provides a unified API while maintaining separation of concerns:
 * - Use SessionAuthManager directly for explicit session-based auth
 * - Use TokenAuthManager directly for explicit token-based auth
 * - Use AuthManager for automatic mode detection and delegation
 *
 * Supports three modes:
 * - MONOLITH: Session-based auth with cookies
 * - API: Token-based stateless auth (Paseto V4)
 * - HYBRID: Both session and token auth (web + mobile/SPA)
 *
 * This class is final as it's a facade that should not be extended.
 * Extend the underlying managers if you need custom behavior.
 *
 * @example
 * ```php
 * // Automatic mode detection
 * $auth = new AuthManager($config, $sessionAuth, $tokenAuth);
 * $result = $auth->signIn($email, $password, $ip, $userAgent);
 * ```
 */
final class AuthManager implements AuthManagerInterface
{
    private readonly AuthMode $mode;

    public function __construct(
        AuthConfig $config,
        private readonly ?SessionAuthManager $sessionAuthManager = null,
        private readonly ?TokenAuthManager $tokenAuthManager = null,
    ) {
        $this->mode = $config->mode;

        if ($this->mode->isMonolith() && $this->sessionAuthManager === null) {
            throw new \InvalidArgumentException('SessionAuthManager is required for session mode');
        }

        if ($this->mode->isApi() && $this->tokenAuthManager === null) {
            throw new \InvalidArgumentException('TokenAuthManager is required for API mode');
        }

        // Hybrid mode requires both managers
        if ($this->mode->isHybrid()) {
            if ($this->sessionAuthManager === null) {
                throw new \InvalidArgumentException('SessionAuthManager is required for hybrid mode');
            }
            if ($this->tokenAuthManager === null) {
                throw new \InvalidArgumentException('TokenAuthManager is required for hybrid mode');
            }
        }
    }

    /**
     * Sign in a user - delegates to appropriate manager based on mode.
     *
     * @return array Session mode returns {user, session}, API/Hybrid mode returns {user, access_token, refresh_token}
     */
    public function signIn(string $email, string $password, string $ipAddress, string $userAgent): array
    {
        // API and Hybrid modes use token-based auth
        if ($this->mode->supportsTokens()) {
            return $this->tokenAuthManager->signIn($email, $password);
        }

        // Monolith mode uses session-based auth
        return $this->sessionAuthManager->signIn($email, $password, $ipAddress, $userAgent);
    }

    /**
     * Sign up a new user.
     */
    public function signUp(string $email, string $password, array $additionalData = []): User
    {
        if ($this->mode->isMonolith()) {
            return $this->sessionAuthManager->signUp($email, $password, $additionalData);
        }

        // For API mode, we need to create user through token manager
        // Note: TokenAuthManager doesn't have signUp, so we delegate to session manager
        // This is a design decision - user creation is the same regardless of auth mode
        if ($this->sessionAuthManager) {
            return $this->sessionAuthManager->signUp($email, $password, $additionalData);
        }

        throw new \BadMethodCallException('signUp requires SessionAuthManager');
    }

    /**
     * Sign out a user.
     *
     * @param string $token Session token or access token depending on mode
     */
    public function signOut(string $token): bool
    {
        // Session-based modes can sign out
        if ($this->mode->supportsSessions() && $this->sessionAuthManager !== null) {
            return $this->sessionAuthManager->signOut($token);
        }

        // Token-based auth is stateless, no server-side logout needed
        // For full logout in API mode, use revokeAllTokens() to invalidate refresh tokens
        return false;
    }

    /**
     * Get current user from token.
     */
    public function getCurrentUser(string $token): ?User
    {
        // Token-based modes (API, Hybrid) verify the Paseto token
        if ($this->mode->supportsTokens() && $this->tokenAuthManager !== null) {
            try {
                return $this->tokenAuthManager->verify($token);
            } catch (\Exception) {
                // If token verification fails in hybrid mode, try session
                if (!$this->mode->isHybrid()) {
                    return null;
                }
            }
        }

        // Session-based modes (Monolith, Hybrid) check the session
        if ($this->mode->supportsSessions() && $this->sessionAuthManager !== null) {
            return $this->sessionAuthManager->getCurrentUser($token);
        }

        return null;
    }

    /**
     * Verify email.
     */
    public function verifyEmail(string $userId): bool
    {
        return $this->sessionAuthManager
            ? $this->sessionAuthManager->verifyEmail($userId)
            : false;
    }

    /**
     * Update password.
     */
    public function updatePassword(string $userId, string $newPassword): User
    {
        if ($this->sessionAuthManager) {
            return $this->sessionAuthManager->updatePassword($userId, $newPassword);
        }

        return $this->tokenAuthManager->updatePassword($userId, $newPassword);
    }

    /**
     * Validate session (session/hybrid mode).
     */
    public function validateSession(string $sessionToken): Session
    {
        if (!$this->mode->supportsSessions()) {
            throw new \BadMethodCallException('validateSession is only available in session/hybrid mode');
        }

        return $this->sessionAuthManager->validateSession($sessionToken);
    }

    /**
     * Refresh token (API/hybrid mode).
     */
    public function refresh(string $refreshToken): array
    {
        if (!$this->mode->supportsTokens()) {
            throw new \BadMethodCallException('refresh is only available in API/hybrid mode');
        }

        return $this->tokenAuthManager->refresh($refreshToken);
    }

    /**
     * Revoke all tokens for a user (API/hybrid mode).
     */
    public function revokeAllTokens(string $userId): int
    {
        if (!$this->mode->supportsTokens()) {
            throw new \BadMethodCallException('revokeAllTokens is only available in API/hybrid mode');
        }

        return $this->tokenAuthManager->revokeAllTokens($userId);
    }

    /**
     * Get all sessions for a user (session/hybrid mode).
     *
     * @return Session[]
     */
    public function getUserSessions(string $userId): array
    {
        if (!$this->mode->supportsSessions()) {
            throw new \BadMethodCallException('getUserSessions is only available in session/hybrid mode');
        }

        return $this->sessionAuthManager->getUserSessions($userId);
    }

    /**
     * Revoke a specific session for a user (session/hybrid mode).
     */
    public function revokeSession(string $userId, string $sessionId): bool
    {
        if (!$this->mode->supportsSessions()) {
            throw new \BadMethodCallException('revokeSession is only available in session/hybrid mode');
        }

        return $this->sessionAuthManager->revokeSession($userId, $sessionId);
    }

    /**
     * Get the underlying session manager (if available).
     */
    public function session(): SessionAuthManager
    {
        if (!$this->sessionAuthManager) {
            throw new \BadMethodCallException('SessionAuthManager not available');
        }

        return $this->sessionAuthManager;
    }

    /**
     * Get the underlying token manager (if available).
     */
    public function token(): TokenAuthManager
    {
        if (!$this->tokenAuthManager) {
            throw new \BadMethodCallException('TokenAuthManager not available');
        }

        return $this->tokenAuthManager;
    }

    /**
     * Get current mode.
     */
    public function getMode(): string
    {
        return $this->mode->value;
    }

    /**
     * Check if in session mode (monolith).
     */
    public function isSessionMode(): bool
    {
        return $this->mode->isMonolith();
    }

    /**
     * Check if in API mode.
     */
    public function isApiMode(): bool
    {
        return $this->mode->isApi();
    }

    /**
     * Check if in hybrid mode.
     */
    public function isHybridMode(): bool
    {
        return $this->mode->isHybrid();
    }

    /**
     * Check if this mode supports token-based authentication.
     */
    public function supportsTokens(): bool
    {
        return $this->mode->supportsTokens();
    }

    /**
     * Check if this mode supports session-based authentication.
     */
    public function supportsSessions(): bool
    {
        return $this->mode->supportsSessions();
    }

    /**
     * Complete two-factor authentication login after validating TOTP code.
     *
     * @param string $email The user's email
     * @param string $ipAddress The user's IP address
     * @param string $userAgent The user's user agent
     *
     * @return array Authentication result (tokens or session depending on mode)
     */
    public function completeTwoFactorLogin(string $email, string $ipAddress, string $userAgent): array
    {
        if ($this->mode->isMonolith() && $this->sessionAuthManager) {
            // For session mode, find user and create session
            $userRepo = $this->sessionAuthManager->getUserRepository();
            $user = $userRepo->findByEmail($email);

            if ($user === null) {
                throw new \RuntimeException('User not found');
            }

            $sessionService = $this->sessionAuthManager->getSessionService();
            $session = $sessionService->create($user, $ipAddress, $userAgent);

            return [
                'user' => \BetterAuth\Core\DTO\UserDto::fromUser($user)->toArray(),
                'session' => $session,
                'sessionToken' => $session->getToken(),
            ];
        }

        throw new \BadMethodCallException('completeTwoFactorLogin is not implemented for API mode yet');
    }
}
