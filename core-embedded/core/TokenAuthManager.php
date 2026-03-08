<?php

declare(strict_types=1);

namespace BetterAuth\Core;

use BetterAuth\Core\Config\AuthConfig;
use BetterAuth\Core\DTO\UserDto;
use BetterAuth\Core\Entities\User;
use BetterAuth\Core\Exceptions\InvalidCredentialsException;
use BetterAuth\Core\Exceptions\InvalidTokenException;
use BetterAuth\Core\Interfaces\RefreshTokenRepositoryInterface;
use BetterAuth\Core\Interfaces\TokenAuthManagerInterface;
use BetterAuth\Core\Interfaces\TokenSignerInterface;
use BetterAuth\Core\Interfaces\UserRepositoryInterface;
use BetterAuth\Core\Utils\Crypto;
use DateTimeImmutable;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Token-based authentication manager for stateless APIs and microservices.
 *
 * Uses TokenService (Paseto V4) to create and verify JWT-like access/refresh tokens.
 * Perfect for REST APIs, SPAs, mobile apps, and microservices.
 *
 * For session-based authentication with cookies, use SessionAuthManager instead.
 *
 * This class is final to ensure consistent token authentication behavior.
 */
final class TokenAuthManager implements TokenAuthManagerInterface
{
    private readonly LoggerInterface $logger;

    public function __construct(
        private readonly UserRepositoryInterface $userRepository,
        private readonly RefreshTokenRepositoryInterface $refreshTokenRepository,
        private readonly TokenSignerInterface $tokenService,
        private readonly PasswordHasher $passwordHasher,
        private readonly AuthConfig $config,
        ?LoggerInterface $logger = null,
    ) {
        $this->logger = $logger ?? new NullLogger();
    }

    /**
     * Authenticate and return access + refresh tokens.
     */
    public function signIn(string $email, string $password): array
    {
        $this->logger->info('Token sign in attempt', ['email' => $email]);

        $user = $this->userRepository->findByEmail($email);

        if ($user === null || !$user->hasPassword()) {
            $this->logger->warning('Token sign in failed: Invalid credentials', [
                'email' => $email,
                'reason' => $user === null ? 'user_not_found' : 'no_password',
            ]);

            // Prevent timing-based user enumeration by performing a dummy hash comparison
            password_verify($password, '$argon2id$v=19$m=65536,t=4,p=1$c29tZXNhbHQ$WDyus6py/G3sCiNFKHKiRyjFbVkOrCE/P+SpEPmPCnc');

            throw new InvalidCredentialsException();
        }

        // After hasPassword() check, password is guaranteed to be non-null
        $passwordHash = $user->getPassword();
        assert($passwordHash !== null);

        if (!$this->passwordHasher->verify($password, $passwordHash)) {
            $this->logger->warning('Token sign in failed: Invalid password', [
                'email' => $email,
                'user_id' => $user->getId(),
            ]);

            throw new InvalidCredentialsException();
        }

        try {
            $tokens = $this->createTokenPair($user);

            $this->logger->info('Token sign in successful', [
                'email' => $email,
                'user_id' => $user->getId(),
            ]);

            return $tokens;
        } catch (\Exception $e) {
            $this->logger->error('Token sign in failed with exception', [
                'email' => $email,
                'user_id' => $user->getId(),
                'error' => $e->getMessage(),
            ]);

            throw $e;
        }
    }

    /**
     * Refresh access token using refresh token.
     */
    public function refresh(string $refreshTokenValue): array
    {
        $this->logger->debug('Token refresh attempt', [
            'refresh_token' => substr($refreshTokenValue, 0, 10) . '...',
        ]);

        $newRefreshTokenValue = Crypto::randomToken(32);
        $refreshToken = null;
        $consumed = false;

        if (method_exists($this->refreshTokenRepository, 'consume')) {
            /** @var callable $consume */
            $consume = [$this->refreshTokenRepository, 'consume'];
            $refreshToken = $consume($refreshTokenValue, $newRefreshTokenValue);
            $consumed = $refreshToken !== null;
        } else {
            $refreshToken = $this->refreshTokenRepository->findByToken($refreshTokenValue);
            if ($refreshToken !== null && $refreshToken->isValid()) {
                $this->refreshTokenRepository->revoke($refreshTokenValue, $newRefreshTokenValue);
                $consumed = true;
            }
        }

        if (!$consumed || $refreshToken === null) {
            $this->logger->warning('Token refresh failed: Invalid or expired refresh token', [
                'refresh_token' => substr($refreshTokenValue, 0, 10) . '...',
            ]);

            throw new InvalidTokenException('Invalid or expired refresh token');
        }

        $user = $this->userRepository->findById($refreshToken->getUserId());
        if ($user === null) {
            $this->logger->error('Token refresh failed: User not found', [
                'refresh_token' => substr($refreshTokenValue, 0, 10) . '...',
                'user_id' => $refreshToken->getUserId(),
            ]);

            throw new InvalidTokenException('User not found');
        }

        try {
            // Create new token pair
            $tokens = $this->createTokenPair($user, $newRefreshTokenValue);

            $this->logger->info('Token refresh successful', [
                'user_id' => $user->getId(),
                'old_token' => substr($refreshTokenValue, 0, 10) . '...',
            ]);

            return $tokens;
        } catch (\Exception $e) {
            $this->logger->error('Token refresh failed with exception', [
                'user_id' => $user->getId(),
                'refresh_token' => substr($refreshTokenValue, 0, 10) . '...',
                'error' => $e->getMessage(),
            ]);

            throw $e;
        }
    }

    /**
     * Verify access token and return user.
     */
    public function verify(string $accessToken): User
    {
        try {
            $payload = $this->tokenService->verify($accessToken);

            if ($payload === null || !isset($payload['sub'])) {
                $this->logger->debug('Token verification failed: Invalid payload', [
                    'token' => substr($accessToken, 0, 20) . '...',
                ]);

                throw new InvalidTokenException();
            }

            $user = $this->userRepository->findById($payload['sub']);
            if ($user === null) {
                $this->logger->warning('Token verification failed: User not found', [
                    'user_id' => $payload['sub'],
                ]);

                throw new InvalidTokenException('User not found');
            }

            return $user;
        } catch (InvalidTokenException $e) {
            throw $e;
        } catch (\Exception $e) {
            $this->logger->error('Token verification failed with exception', [
                'token' => substr($accessToken, 0, 20) . '...',
                'error' => $e->getMessage(),
            ]);

            throw new InvalidTokenException('Token verification failed');
        }
    }

    /**
     * Revoke all tokens for a user (logout from all devices).
     */
    public function revokeAllTokens(string $userId): int
    {
        $this->logger->info('Revoking all tokens for user', ['user_id' => $userId]);

        $revokedCount = $this->refreshTokenRepository->revokeAllForUser($userId);

        $this->logger->info('All tokens revoked', [
            'user_id' => $userId,
            'revoked_count' => $revokedCount,
        ]);

        return $revokedCount;
    }

    /**
     * Create tokens for an existing user without password verification.
     * Useful for OAuth, magic links, or automatic login after registration.
     */
    public function createTokensForUser(User $user): array
    {
        $this->logger->info('Creating tokens for user without password', [
            'user_id' => $user->getId(),
            'email' => $user->getEmail(),
        ]);

        try {
            $tokens = $this->createTokenPair($user);

            $this->logger->info('Tokens created successfully for user', [
                'user_id' => $user->getId(),
            ]);

            return $tokens;
        } catch (\Exception $e) {
            $this->logger->error('Failed to create tokens for user', [
                'user_id' => $user->getId(),
                'error' => $e->getMessage(),
            ]);

            throw $e;
        }
    }

    /**
     * Update user password.
     */
    public function updatePassword(string $userId, string $newPassword): User
    {
        $this->logger->info('Password update attempt', ['user_id' => $userId]);

        $user = $this->userRepository->findById($userId);

        if ($user === null) {
            $this->logger->error('Password update failed: User not found', ['user_id' => $userId]);

            throw new \RuntimeException('User not found');
        }

        try {
            $passwordHash = $this->passwordHasher->hash($newPassword);

            $updatedUser = $this->userRepository->update($userId, ['password_hash' => $passwordHash]);

            $this->logger->info('Password updated successfully', ['user_id' => $userId]);

            // Revoke all refresh tokens after password change for security
            $this->refreshTokenRepository->revokeAllForUser($userId);

            return $updatedUser;
        } catch (\Exception $e) {
            $this->logger->error('Password update failed', [
                'user_id' => $userId,
                'error' => $e->getMessage(),
            ]);

            throw $e;
        }
    }

    /**
     * Create access and refresh token pair.
     */
    private function createTokenPair(User $user, ?string $refreshTokenValue = null): array
    {
        $this->logger->debug('Creating token pair', ['user_id' => $user->getId()]);

        try {
            // Create access token
            $accessToken = $this->tokenService->sign(
                [
                    'sub' => $user->getId(),
                    'type' => 'access',
                    'data' => [
                        'email' => $user->getEmail(),
                        'username' => $user->getUsername(),
                    ],
                ],
                $this->config->tokenLifetime,
            );

            // Create refresh token
            if ($refreshTokenValue === null) {
                $refreshTokenValue = Crypto::randomToken(32);
            }

            $expiresAt = new DateTimeImmutable("+{$this->config->refreshTokenLifetime} seconds");

            $refreshToken = $this->refreshTokenRepository->create([
                'token' => $refreshTokenValue,
                'userId' => $user->getId(),
                'expiresAt' => $expiresAt->format('Y-m-d H:i:s'),
            ]);

            $this->logger->debug('Token pair created successfully', [
                'user_id' => $user->getId(),
                'expires_in' => $this->config->tokenLifetime,
            ]);

            return [
                'user' => UserDto::fromUser($user)->toArray(),
                'access_token' => $accessToken,
                'refresh_token' => $refreshToken->getToken(),
                'token_type' => 'Bearer',
                'expires_in' => $this->config->tokenLifetime,
            ];
        } catch (\Exception $e) {
            $this->logger->error('Failed to create token pair', [
                'user_id' => $user->getId(),
                'error' => $e->getMessage(),
            ]);

            throw $e;
        }
    }
}
