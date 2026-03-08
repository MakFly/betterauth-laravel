<?php

declare(strict_types=1);

namespace BetterAuth\Providers\EmailProvider;

use BetterAuth\Core\AuthManager;
use BetterAuth\Core\Entities\Session;
use BetterAuth\Core\Entities\User;
use BetterAuth\Core\Security\PasswordStrengthValidator;

/**
 * Email/Password authentication provider.
 */
final class EmailPasswordProvider
{
    private readonly PasswordStrengthValidator $passwordValidator;

    public function __construct(
        private readonly AuthManager $authManager,
        ?PasswordStrengthValidator $passwordValidator = null,
    ) {
        $this->passwordValidator = $passwordValidator ?? new PasswordStrengthValidator();
    }

    /**
     * Register a new user with email and password.
     *
     * @param array<string, mixed> $additionalData
     *
     * @throws \Exception
     */
    public function signUp(string $email, string $password, array $additionalData = []): User
    {
        $this->validateEmail($email);
        $this->validatePassword($password);

        return $this->authManager->signUp($email, $password, $additionalData);
    }

    /**
     * Sign in with email and password.
     *
     * @return array{user: array<string, mixed>, session: Session}
     *
     * @throws \Exception
     */
    public function signIn(string $email, string $password, string $ipAddress, string $userAgent): array
    {
        $this->validateEmail($email);

        return $this->authManager->signIn($email, $password, $ipAddress, $userAgent);
    }

    /**
     * Validate email format.
     *
     * @throws \InvalidArgumentException
     */
    private function validateEmail(string $email): void
    {
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            throw new \InvalidArgumentException('Invalid email address');
        }
    }

    /**
     * Validate password strength using entropy-based scoring.
     *
     * Requirements:
     * - Minimum 10 characters
     * - Score >= 3 (Strong) on 0-4 scale
     * - Mix of character classes recommended
     *
     * @throws \InvalidArgumentException with detailed feedback
     */
    private function validatePassword(string $password): void
    {
        $result = $this->passwordValidator->validate($password);

        if (!$result['valid']) {
            $feedback = implode('. ', $result['feedback']);
            $strengthLabel = $this->passwordValidator->getStrengthLabel($result['score']);

            throw new \InvalidArgumentException(
                sprintf('Password too weak (%s). %s', $strengthLabel, $feedback)
            );
        }
    }

    /**
     * Get password strength analysis without throwing.
     *
     * @return array{valid: bool, score: int, label: string, feedback: array<string>}
     */
    public function analyzePasswordStrength(string $password): array
    {
        $result = $this->passwordValidator->validate($password);

        return [
            'valid' => $result['valid'],
            'score' => $result['score'],
            'label' => $this->passwordValidator->getStrengthLabel($result['score']),
            'feedback' => $result['feedback'],
        ];
    }
}
