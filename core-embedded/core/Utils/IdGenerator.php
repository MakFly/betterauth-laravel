<?php

declare(strict_types=1);

namespace BetterAuth\Core\Utils;

use Exception;

/**
 * ID generation utilities.
 *
 * This utility class is final to ensure consistent ID generation behavior.
 */
final class IdGenerator
{
    /**
     * Generate a UUID v4.
     *
     * @return string The UUID
     *
     * @throws Exception
     */
    public static function uuid(): string
    {
        $data = random_bytes(16);

        // Set version to 0100
        $data[6] = chr(ord($data[6]) & 0x0f | 0x40);
        // Set bits 6-7 to 10
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80);

        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }

    /**
     * Generate a short unique ID (nanoid style).
     *
     * @param int $length The length of the ID
     *
     * @return string The ID
     *
     * @throws Exception
     */
    public static function nanoid(int $length = 21): string
    {
        $alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
        $alphabetLength = strlen($alphabet);
        $id = '';

        for ($i = 0; $i < $length; $i++) {
            $id .= $alphabet[random_int(0, $alphabetLength - 1)];
        }

        return $id;
    }

    /**
     * Generate a ULID (Universally Unique Lexicographically Sortable Identifier).
     *
     * @return string The ULID
     *
     * @throws Exception
     */
    public static function ulid(): string
    {
        $time = (int) (microtime(true) * 1000);
        $timeBytes = [];

        for ($i = 5; $i >= 0; $i--) {
            $timeBytes[] = ($time >> ($i * 8)) & 0xFF;
        }

        $randomBytes = random_bytes(10);
        $bytes = array_merge($timeBytes, unpack('C*', $randomBytes));

        return self::encodeBase32($bytes);
    }

    /**
     * Encode bytes to Crockford's Base32.
     *
     * @param array<int> $bytes
     */
    private static function encodeBase32(array $bytes): string
    {
        $alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
        $encoded = '';
        $bits = 0;
        $value = 0;

        foreach ($bytes as $byte) {
            $value = ($value << 8) | $byte;
            $bits += 8;

            while ($bits >= 5) {
                $encoded .= $alphabet[($value >> ($bits - 5)) & 31];
                $bits -= 5;
            }
        }

        if ($bits > 0) {
            $encoded .= $alphabet[($value << (5 - $bits)) & 31];
        }

        return $encoded;
    }
}
