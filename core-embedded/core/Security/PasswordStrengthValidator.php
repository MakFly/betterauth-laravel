<?php

declare(strict_types=1);

namespace BetterAuth\Core\Security;

/**
 * Password strength validator using entropy-based scoring.
 *
 * Inspired by zxcvbn algorithm - checks for:
 * - Character class variety (upper, lower, digits, special)
 * - Common password patterns
 * - Sequential characters
 * - Repeated characters
 * - Dictionary words
 * - Keyboard patterns
 *
 * Score: 0 (very weak) to 4 (very strong)
 */
final class PasswordStrengthValidator
{
    /**
     * Minimum score required (0-4 scale).
     */
    public const MIN_SCORE = 3;

    /**
     * Minimum length for any password.
     */
    public const MIN_LENGTH = 10;

    /**
     * Common weak passwords (top 100 most used).
     *
     * @var array<string>
     */
    private const COMMON_PASSWORDS = [
        'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', 'master',
        'dragon', '111111', 'baseball', 'iloveyou', 'trustno1', 'sunshine',
        'princess', 'welcome', 'shadow', 'superman', 'michael', 'football',
        'password1', 'password123', 'batman', 'letmein', 'login', 'admin',
        'administrator', 'passw0rd', 'starwars', 'hello', 'freedom', 'whatever',
        'qazwsx', 'ninja', 'mustang', 'password!', '000000', 'access', 'flower',
        'hottie', 'loveme', 'zaq1zaq1', 'god', 'secret', 'money', 'power',
    ];

    /**
     * Keyboard sequences to detect.
     *
     * @var array<string>
     */
    private const KEYBOARD_SEQUENCES = [
        'qwerty', 'qwertz', 'azerty', 'qweasd', 'asdfgh', 'zxcvbn',
        '123456', '654321', '098765', '012345', 'abcdef', 'fedcba',
    ];

    /**
     * Validate password strength.
     *
     * @return array{valid: bool, score: int, feedback: array<string>}
     */
    public function validate(string $password): array
    {
        $feedback = [];
        $score = 0;

        // Length check
        $length = mb_strlen($password);
        if ($length < self::MIN_LENGTH) {
            $feedback[] = sprintf('Password must be at least %d characters long', self::MIN_LENGTH);
        } elseif ($length >= 12) {
            $score++;
            if ($length >= 16) {
                $score++;
            }
        }

        // Character class variety
        $hasLower = preg_match('/[a-z]/', $password) === 1;
        $hasUpper = preg_match('/[A-Z]/', $password) === 1;
        $hasDigit = preg_match('/\d/', $password) === 1;
        $hasSpecial = preg_match('/[^a-zA-Z0-9]/', $password) === 1;

        $charClassCount = (int) $hasLower + (int) $hasUpper + (int) $hasDigit + (int) $hasSpecial;

        if ($charClassCount < 3) {
            $feedback[] = 'Use a mix of uppercase, lowercase, numbers, and special characters';
        } else {
            $score++;
            if ($charClassCount === 4) {
                $score++;
            }
        }

        // Common password check
        $lowercasePassword = strtolower($password);
        foreach (self::COMMON_PASSWORDS as $common) {
            if (str_contains($lowercasePassword, $common)) {
                $score = max(0, $score - 2);
                $feedback[] = 'Avoid common passwords or patterns';
                break;
            }
        }

        // Keyboard sequence check
        foreach (self::KEYBOARD_SEQUENCES as $sequence) {
            if (str_contains($lowercasePassword, $sequence)) {
                $score = max(0, $score - 1);
                $feedback[] = 'Avoid keyboard patterns like "qwerty" or "123456"';
                break;
            }
        }

        // Repeated characters check
        if (preg_match('/(.)\1{2,}/', $password) === 1) {
            $score = max(0, $score - 1);
            $feedback[] = 'Avoid repeating characters (e.g., "aaa")';
        }

        // Sequential characters check
        if ($this->hasSequentialChars($password)) {
            $score = max(0, $score - 1);
            $feedback[] = 'Avoid sequential characters (e.g., "abc", "123")';
        }

        // Entropy calculation bonus
        $entropy = $this->calculateEntropy($password);
        if ($entropy >= 60) {
            $score++;
        }

        // Clamp score to 0-4
        $score = max(0, min(4, $score));

        $isValid = $score >= self::MIN_SCORE && $length >= self::MIN_LENGTH;

        if ($isValid && empty($feedback)) {
            $feedback[] = 'Strong password';
        }

        return [
            'valid' => $isValid,
            'score' => $score,
            'feedback' => $feedback,
        ];
    }

    /**
     * Quick validation - just returns bool.
     */
    public function isValid(string $password): bool
    {
        return $this->validate($password)['valid'];
    }

    /**
     * Get human-readable strength label.
     */
    public function getStrengthLabel(int $score): string
    {
        return match ($score) {
            0 => 'Very Weak',
            1 => 'Weak',
            2 => 'Fair',
            3 => 'Strong',
            4 => 'Very Strong',
            default => 'Unknown',
        };
    }

    /**
     * Check for sequential characters (abc, 123, etc.).
     */
    private function hasSequentialChars(string $password, int $minSequence = 3): bool
    {
        $chars = str_split(strtolower($password));
        $sequential = 1;

        for ($i = 1, $len = count($chars); $i < $len; $i++) {
            $current = ord($chars[$i]);
            $previous = ord($chars[$i - 1]);

            if ($current === $previous + 1 || $current === $previous - 1) {
                $sequential++;
                if ($sequential >= $minSequence) {
                    return true;
                }
            } else {
                $sequential = 1;
            }
        }

        return false;
    }

    /**
     * Calculate password entropy (bits).
     */
    private function calculateEntropy(string $password): float
    {
        $charsetSize = 0;

        if (preg_match('/[a-z]/', $password)) {
            $charsetSize += 26;
        }
        if (preg_match('/[A-Z]/', $password)) {
            $charsetSize += 26;
        }
        if (preg_match('/\d/', $password)) {
            $charsetSize += 10;
        }
        if (preg_match('/[^a-zA-Z0-9]/', $password)) {
            $charsetSize += 32;
        }

        if ($charsetSize === 0) {
            return 0.0;
        }

        return mb_strlen($password) * log($charsetSize, 2);
    }
}
