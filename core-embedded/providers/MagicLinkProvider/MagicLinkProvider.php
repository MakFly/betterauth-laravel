<?php

declare(strict_types=1);

namespace BetterAuth\Providers\MagicLinkProvider;

use BetterAuth\Core\Config\AuthConfig;
use BetterAuth\Core\Entities\Session;
use BetterAuth\Core\Entities\User;
use BetterAuth\Core\Exceptions\RateLimitException;
use BetterAuth\Core\Interfaces\EmailSenderInterface;
use BetterAuth\Core\Interfaces\MagicLinkStorageInterface;
use BetterAuth\Core\Interfaces\RateLimiterInterface;
use BetterAuth\Core\Interfaces\TokenManagerInterface;
use BetterAuth\Core\Interfaces\UserRepositoryInterface;
use BetterAuth\Core\SessionService;
use BetterAuth\Core\Utils\Crypto;
use BetterAuth\Core\Utils\IdGenerator;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Magic link (passwordless) authentication provider.
 * Supports both session-based (monolith) and token-based (API/hybrid) authentication modes.
 */
final class MagicLinkProvider
{
    private const TOKEN_EXPIRY = 600; // 10 minutes
    private readonly LoggerInterface $logger;

    public function __construct(
        private readonly UserRepositoryInterface $userRepository,
        private readonly MagicLinkStorageInterface $magicLinkStorage,
        private readonly EmailSenderInterface $emailSender,
        private readonly SessionService $sessionService,
        private readonly AuthConfig $authConfig,
        private readonly ?TokenManagerInterface $tokenManager = null,
        private readonly ?RateLimiterInterface $rateLimiter = null,
        ?LoggerInterface $logger = null,
        private readonly bool $allowUserCreation = false,
    ) {
        $this->logger = $logger ?? new NullLogger();
    }

    /**
     * Send a magic link to the user's email.
     *
     * @param string $email The user's email
     * @param string $ipAddress The user's IP address
     * @param string $userAgent The user's user agent
     * @param string|null $callbackUrl Optional callback URL (magic link will be appended)
     *
     * @return array{success: bool, expiresIn: int} Result with expiration time
     *
     * @throws RateLimitException
     * @throws \Exception
     */
    public function sendMagicLink(string $email, string $ipAddress, string $userAgent, ?string $callbackUrl = null): array
    {
        $this->logger->info('Magic link send attempt', [
            'email' => $email,
            'ip_address' => $ipAddress,
        ]);

        // Rate limiting
        $rateLimitKey = "magic_link:$email";
        if ($this->rateLimiter?->tooManyAttempts($rateLimitKey, 3, 300)) {
            $retryAfter = $this->rateLimiter->availableIn($rateLimitKey);

            $this->logger->warning('Magic link send rate limited', [
                'email' => $email,
                'ip_address' => $ipAddress,
                'retry_after' => $retryAfter,
            ]);

            throw new RateLimitException(retryAfter: $retryAfter);
        }

        $this->rateLimiter?->hit($rateLimitKey, 300);

        try {
            if (!$this->allowUserCreation && $this->userRepository->findByEmail($email) === null) {
                $this->logger->info('Magic link request ignored for unknown user', [
                    'email' => $email,
                    'ip_address' => $ipAddress,
                ]);

                return ['success' => true, 'expiresIn' => self::TOKEN_EXPIRY];
            }

            // Generate token
            $token = Crypto::randomToken(32);

            // Store token
            $this->magicLinkStorage->store($token, $email, self::TOKEN_EXPIRY);

            if ($callbackUrl !== null) {
                // Build magic link URL
                $separator = str_contains($callbackUrl, '?') ? '&' : '?';
                $magicLink = $callbackUrl . $separator . 'token=' . urlencode($token);

                // Send email
                $this->emailSender->sendMagicLink($email, $magicLink);

                $this->logger->info('Magic link sent successfully', [
                    'email' => $email,
                    'callback_url' => $callbackUrl,
                    'expires_in' => self::TOKEN_EXPIRY,
                ]);
            } else {
                $this->logger->info('Magic link created (no callback URL)', [
                    'email' => $email,
                    'expires_in' => self::TOKEN_EXPIRY,
                ]);
            }

            return ['success' => true, 'expiresIn' => self::TOKEN_EXPIRY];
        } catch (\Exception $e) {
            $this->logger->error('Failed to send magic link', [
                'email' => $email,
                'ip_address' => $ipAddress,
                'error' => $e->getMessage(),
            ]);

            throw $e;
        }
    }

    /**
     * Verify a magic link token and create a session.
     *
     * @param string $token The magic link token
     * @param string $ipAddress The user's IP address
     * @param string $userAgent The user's user agent
     *
     * @return array{success: bool, error?: string, access_token?: string, refresh_token?: string, expires_in?: int, user?: array<string, mixed>} Result of verification
     *
     * @throws \Exception
     */
    public function verifyMagicLink(string $token, string $ipAddress, string $userAgent): array
    {
        $this->logger->info('Magic link verification attempt', [
            'token' => substr($token, 0, 10) . '...',
            'ip_address' => $ipAddress,
        ]);

        try {
            // Find token
            $magicLinkToken = $this->magicLinkStorage->findByToken($token);

            if ($magicLinkToken === null || !$magicLinkToken->isValid()) {
                $this->logger->warning('Magic link verification failed: Invalid or expired token', [
                    'token' => substr($token, 0, 10) . '...',
                    'ip_address' => $ipAddress,
                    'found' => $magicLinkToken !== null,
                ]);

                return ['success' => false, 'error' => 'Invalid or expired magic link'];
            }

            $email = $magicLinkToken->getEmail();

            // Find or create user
            $user = $this->userRepository->findByEmail($email);

            if ($user === null) {
                if (!$this->allowUserCreation) {
                    $this->logger->warning('Magic link verification failed: User not found', [
                        'email' => $email,
                        'ip_address' => $ipAddress,
                    ]);
                    $this->magicLinkStorage->markAsUsed($token);

                    return ['success' => false, 'error' => 'Account not found'];
                }

                $this->logger->info('Creating new user via magic link', ['email' => $email]);

                // Auto-create user for magic link
                $user = $this->userRepository->create([
                    'id' => IdGenerator::ulid(),
                    'email' => $email,
                    'password_hash' => null,
                    'email_verified' => true, // Magic link confirms email ownership
                    'email_verified_at' => date('Y-m-d H:i:s'),
                ]);

                $this->logger->info('User created successfully via magic link', [
                    'user_id' => $user->getId(),
                    'email' => $email,
                ]);
            } else {
                $this->logger->debug('Existing user found for magic link', [
                    'user_id' => $user->getId(),
                    'email' => $email,
                ]);

                // Verify email if not already verified
                if (!$user->isEmailVerified()) {
                    $this->logger->info('Verifying email for user', ['user_id' => $user->getId()]);
                    $this->userRepository->verifyEmail($user->getId());
                    $updatedUser = $this->userRepository->findById($user->getId());
                    if ($updatedUser !== null) {
                        $user = $updatedUser;
                    }
                }
            }

            // Create authentication tokens/session based on mode
            if ($this->authConfig->supportsTokens() && $this->tokenManager !== null) {
                // API/Hybrid mode: Create JWT tokens (stateless)
                $this->logger->debug('Magic link: Creating JWT tokens (API/Hybrid mode)', [
                    'user_id' => $user->getId(),
                ]);

                $tokens = $this->tokenManager->create($user);

                // Mark token as used AFTER successful token creation
                $this->magicLinkStorage->markAsUsed($token);

                $this->logger->info('Magic link verification successful (API/Hybrid mode)', [
                    'user_id' => $user->getId(),
                    'email' => $email,
                    'ip_address' => $ipAddress,
                ]);

                return [
                    'success' => true,
                    'access_token' => $tokens['access_token'],
                    'refresh_token' => $tokens['refresh_token'],
                    'expires_in' => $tokens['expires_in'],
                    'token_type' => $tokens['token_type'],
                    'user' => \BetterAuth\Core\DTO\UserDto::fromUser($user)->toArray(),
                ];
            } else {
                // Session mode: Create database session (stateful)
                $this->logger->debug('Magic link: Creating session (Session mode)', [
                    'user_id' => $user->getId(),
                ]);

                $session = $this->sessionService->create($user, $ipAddress, $userAgent);

                // Mark token as used AFTER successful session creation
                $this->magicLinkStorage->markAsUsed($token);

                $this->logger->info('Magic link verification successful (Session mode)', [
                    'user_id' => $user->getId(),
                    'email' => $email,
                    'ip_address' => $ipAddress,
                ]);

                return [
                    'success' => true,
                    'access_token' => $session->getToken(),
                    'refresh_token' => $session->getToken(), // Using session token as both
                    'expires_in' => 604800, // 7 days default
                    'user' => \BetterAuth\Core\DTO\UserDto::fromUser($user)->toArray(),
                ];
            }
        } catch (\Exception $e) {
            $this->logger->error('Magic link verification failed with exception', [
                'token' => substr($token, 0, 10) . '...',
                'ip_address' => $ipAddress,
                'error' => $e->getMessage(),
            ]);

            throw $e;
        }
    }

    /**
     * Check if a magic link token is valid without consuming it.
     *
     * @param string $token The magic link token
     *
     * @return array{valid: bool, email?: string, expires_at?: int} Token status
     */
    public function checkToken(string $token): array
    {
        $magicLinkToken = $this->magicLinkStorage->findByToken($token);

        if ($magicLinkToken === null || !$magicLinkToken->isValid()) {
            return ['valid' => false];
        }

        return [
            'valid' => true,
            'email' => $magicLinkToken->getEmail(),
            'expires_at' => $magicLinkToken->getExpiresAt()->getTimestamp(),
        ];
    }
}
