<?php

declare(strict_types=1);

namespace BetterAuth\Providers\PasswordResetProvider;

use BetterAuth\Core\AuthManager;
use BetterAuth\Core\Exceptions\RateLimitException;
use BetterAuth\Core\Interfaces\EmailSenderInterface;
use BetterAuth\Core\Interfaces\PasswordResetStorageInterface;
use BetterAuth\Core\Interfaces\RateLimiterInterface;
use BetterAuth\Core\Interfaces\UserRepositoryInterface;
use BetterAuth\Core\Utils\Crypto;

/**
 * Password reset provider for handling password reset flows.
 */
final class PasswordResetProvider
{
    private const TOKEN_EXPIRY = 3600; // 1 hour

    public function __construct(
        private readonly UserRepositoryInterface $userRepository,
        private readonly PasswordResetStorageInterface $passwordResetStorage,
        private readonly EmailSenderInterface $emailSender,
        private readonly AuthManager $authManager,
        private readonly ?RateLimiterInterface $rateLimiter = null,
    ) {
    }

    /**
     * Send a password reset email.
     *
     * @param string $email The user's email
     * @param string|null $callbackUrl Optional callback URL (token will be appended)
     *
     * @return array{success: bool} Result of the request
     *
     * @throws RateLimitException
     * @throws \Exception
     */
    public function sendResetEmail(string $email, ?string $callbackUrl = null): array
    {
        // Rate limiting
        $rateLimitKey = "password_reset:$email";
        if ($this->rateLimiter?->tooManyAttempts($rateLimitKey, 3, 3600)) {
            $retryAfter = $this->rateLimiter->availableIn($rateLimitKey);

            throw new RateLimitException(
                message: 'Too many password reset attempts. Please try again later.',
                retryAfter: $retryAfter,
            );
        }

        // Check if user exists
        $user = $this->userRepository->findByEmail($email);

        // Don't reveal if user exists or not (security best practice)
        // Always return success but only send email if user exists
        if ($user === null) {
            $this->rateLimiter?->hit($rateLimitKey, 3600);

            return ['success' => true];
        }

        $this->rateLimiter?->hit($rateLimitKey, 3600);

        // Invalidate any existing reset tokens for this email
        $this->passwordResetStorage->deleteByEmail($email);

        // Generate new token
        $token = Crypto::randomToken(32);

        // Store token
        $this->passwordResetStorage->store($token, $email, self::TOKEN_EXPIRY);

        if ($callbackUrl !== null) {
            // Build reset link URL
            $separator = str_contains($callbackUrl, '?') ? '&' : '?';
            $resetLink = $callbackUrl . $separator . 'token=' . urlencode($token);

            // Send email
            $this->emailSender->sendPasswordReset($email, $resetLink);
        }

        return ['success' => true];
    }

    /**
     * Alias for sendResetEmail for backward compatibility.
     *
     * @deprecated Use sendResetEmail() instead
     */
    public function requestReset(string $email, string $callbackUrl): bool
    {
        $result = $this->sendResetEmail($email, $callbackUrl);

        return $result['success'];
    }

    /**
     * Verify a password reset token.
     *
     * @param string $token The reset token
     *
     * @return array{valid: bool, email?: string} Result of verification
     */
    public function verifyResetToken(string $token): array
    {
        $resetToken = $this->passwordResetStorage->findByToken($token);

        if ($resetToken !== null && $resetToken->isValid()) {
            return ['valid' => true, 'email' => $resetToken->getEmail()];
        }

        return ['valid' => false];
    }

    /**
     * Alias for verifyResetToken for backward compatibility.
     *
     * @deprecated Use verifyResetToken() instead
     */
    public function verifyToken(string $token): bool
    {
        $result = $this->verifyResetToken($token);

        return $result['valid'];
    }

    /**
     * Reset password using a valid token.
     *
     * @param string $token The reset token
     * @param string $newPassword The new password
     *
     * @return array{success: bool, error?: string} Result of password reset
     */
    public function resetPassword(string $token, string $newPassword): array
    {
        // Validate password strength
        if (strlen($newPassword) < 8) {
            return ['success' => false, 'error' => 'Password must be at least 8 characters long'];
        }

        // Find and validate token
        $resetToken = $this->passwordResetStorage->findByToken($token);

        if ($resetToken === null || !$resetToken->isValid()) {
            return ['success' => false, 'error' => 'Invalid or expired password reset token'];
        }

        // Find user
        $user = $this->userRepository->findByEmail($resetToken->getEmail());

        if ($user === null) {
            return ['success' => false, 'error' => 'User not found'];
        }

        // Update password
        $this->authManager->updatePassword($user->getId(), $newPassword);

        // Mark token as used
        $this->passwordResetStorage->markAsUsed($token);

        // Delete all other reset tokens for this email
        $this->passwordResetStorage->deleteByEmail($resetToken->getEmail());

        // Clear rate limit
        $this->rateLimiter?->clear("password_reset:{$resetToken->getEmail()}");

        return ['success' => true];
    }

    /**
     * Cancel a password reset by deleting the token.
     *
     * @param string $token The reset token
     *
     * @return bool True if cancelled, false otherwise
     */
    public function cancelReset(string $token): bool
    {
        return $this->passwordResetStorage->delete($token);
    }
}
