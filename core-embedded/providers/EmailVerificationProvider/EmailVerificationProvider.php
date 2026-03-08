<?php

declare(strict_types=1);

namespace BetterAuth\Providers\EmailVerificationProvider;

use BetterAuth\Core\Exceptions\RateLimitException;
use BetterAuth\Core\Exceptions\UserNotFoundException;
use BetterAuth\Core\Interfaces\EmailSenderInterface;
use BetterAuth\Core\Interfaces\EmailVerificationStorageInterface;
use BetterAuth\Core\Interfaces\RateLimiterInterface;
use BetterAuth\Core\Interfaces\UserRepositoryInterface;
use BetterAuth\Core\Utils\Crypto;

final class EmailVerificationProvider
{
    private const TOKEN_EXPIRY = 86400; // 24 hours

    public function __construct(
        private readonly UserRepositoryInterface $userRepository,
        private readonly EmailVerificationStorageInterface $verificationStorage,
        private readonly EmailSenderInterface $emailSender,
        private readonly ?RateLimiterInterface $rateLimiter = null,
    ) {
    }

    /**
     * Send a verification email to a user.
     *
     * @param string $userId The user ID
     * @param string $email The user's email address
     * @param string|null $callbackUrl Optional callback URL for the verification link
     *
     * @return array{success: bool, expiresIn: int} Result with expiration time
     *
     * @throws RateLimitException
     * @throws UserNotFoundException
     */
    public function sendVerificationEmail(string $userId, string $email, ?string $callbackUrl = null): array
    {
        $rateLimitKey = "email_verification:$email";
        if ($this->rateLimiter?->tooManyAttempts($rateLimitKey, 3, 3600)) {
            throw new RateLimitException(retryAfter: $this->rateLimiter->availableIn($rateLimitKey));
        }

        $user = $this->userRepository->findById($userId);
        if ($user === null) {
            throw new UserNotFoundException();
        }

        if ($user->isEmailVerified()) {
            return ['success' => true, 'expiresIn' => self::TOKEN_EXPIRY];
        }

        $this->rateLimiter?->hit($rateLimitKey, 3600);
        $this->verificationStorage->deleteByEmail($email);

        $token = Crypto::randomToken(32);
        $this->verificationStorage->store($token, $email, self::TOKEN_EXPIRY);

        // Always send email - construct verification link
        if ($callbackUrl === null) {
            // If no callbackUrl provided, throw exception - it should always be provided
            // This prevents hardcoded URLs that won't work in Docker or different environments
            throw new \InvalidArgumentException('callbackUrl is required for email verification. Please provide it when calling sendVerificationEmail.');
        }

        $separator = str_contains($callbackUrl, '?') ? '&' : '?';
        $verificationLink = $callbackUrl . $separator . 'token=' . urlencode($token);

        $this->emailSender->sendVerificationEmail($email, $verificationLink);

        return ['success' => true, 'expiresIn' => self::TOKEN_EXPIRY];
    }

    /**
     * Verify an email using a verification token.
     *
     * @param string $token The verification token
     *
     * @return array{success: bool, error?: string} Result of verification
     */
    public function verifyEmail(string $token): array
    {
        $verificationToken = $this->verificationStorage->findByToken($token);

        if ($verificationToken === null || !$verificationToken->isValid()) {
            return ['success' => false, 'error' => 'Invalid or expired verification token'];
        }

        $user = $this->userRepository->findByEmail($verificationToken->getEmail());
        if ($user === null) {
            return ['success' => false, 'error' => 'User not found'];
        }

        $this->userRepository->verifyEmail($user->getId());
        $this->verificationStorage->markAsUsed($token);
        $this->verificationStorage->deleteByEmail($verificationToken->getEmail());
        $this->rateLimiter?->clear("email_verification:{$verificationToken->getEmail()}");

        return ['success' => true];
    }

    /**
     * Resend verification email by email address.
     *
     * @param string $email The email address
     * @param string|null $callbackUrl Optional callback URL for the verification link
     *
     * @return array{success: bool, expiresIn?: int} Result with expiration time
     */
    public function resendVerificationEmail(string $email, ?string $callbackUrl = null): array
    {
        $user = $this->userRepository->findByEmail($email);

        // Don't reveal if user exists (security best practice)
        if ($user === null || $user->isEmailVerified()) {
            return ['success' => true];
        }

        return $this->sendVerificationEmail($user->getId(), $email, $callbackUrl);
    }
}
