<?php

declare(strict_types=1);

namespace BetterAuth\Core\Utils;

use Exception;

/**
 * Cryptographic utilities for secure random generation.
 *
 * This utility class is final to ensure consistent cryptographic behavior.
 */
final class Crypto
{
    /**
     * Generate a cryptographically secure random string.
     *
     * @param int $length The length of the string
     *
     * @return string The random string (hex encoded)
     *
     * @throws Exception
     */
    public static function randomString(int $length = 32): string
    {
        return bin2hex(random_bytes($length));
    }

    /**
     * Generate a cryptographically secure random token.
     *
     * @param int $bytes Number of random bytes
     *
     * @return string The random token (base64url encoded)
     *
     * @throws Exception
     */
    public static function randomToken(int $bytes = 32): string
    {
        return self::base64UrlEncode(random_bytes($bytes));
    }

    /**
     * Generate a secure random integer.
     *
     * @param int $min Minimum value
     * @param int $max Maximum value
     *
     * @return int The random integer
     *
     * @throws Exception
     */
    public static function randomInt(int $min, int $max): int
    {
        return random_int($min, $max);
    }

    /**
     * Base64url encode a string.
     *
     * @param string $data The data to encode
     *
     * @return string The base64url encoded string
     */
    public static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Base64url decode a string.
     *
     * @param string $data The data to decode
     *
     * @return false|string The decoded string or false on failure
     */
    public static function base64UrlDecode(string $data): string|false
    {
        return base64_decode(strtr($data, '-_', '+/'));
    }

    /**
     * Hash a value using a secure algorithm.
     *
     * @param string $value The value to hash
     * @param string $algorithm The hash algorithm (default: sha256)
     *
     * @return string The hashed value
     */
    public static function hash(string $value, string $algorithm = 'sha256'): string
    {
        return hash($algorithm, $value);
    }

    /**
     * Constant-time string comparison.
     *
     * @param string $known The known string
     * @param string $user The user-supplied string
     *
     * @return bool True if strings are equal, false otherwise
     */
    public static function timingSafeEquals(string $known, string $user): bool
    {
        return hash_equals($known, $user);
    }

    /**
     * Derive an encryption key from a secret using HKDF.
     *
     * Uses a zero-length salt (RFC 5869 §3.1) with domain-separation via the $info parameter.
     *
     * @param string $secret The master secret
     * @param int $length Output key length in bytes
     * @param string $info Context/application-specific info for domain separation
     */
    public static function deriveKey(string $secret, int $length = 32, string $info = 'betterauth-token-key'): string
    {
        return hash_hkdf('sha256', $secret, $length, $info);
    }
}
