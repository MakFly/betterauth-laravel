<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Services;

use BetterAuth\Laravel\Events\TwoFactorDisabled;
use BetterAuth\Laravel\Events\TwoFactorEnabled;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;

/**
 * TOTP-based Two-Factor Authentication Service.
 *
 * Provides setup, verification, and recovery code management for 2FA.
 */
final class TwoFactorService
{
    private const SECRET_LENGTH = 20;
    private const RECOVERY_CODE_COUNT = 8;
    private const RECOVERY_CODE_LENGTH = 10;

    public function __construct(
        private readonly string $table = 'better_auth_totp_secrets',
    ) {}

    /**
     * Generate a new 2FA secret for a user.
     *
     * @return array{secret: string, uri: string, qr_code_url: string}
     */
    public function generateSecret(Authenticatable $user): array
    {
        $secret = $this->generateRandomSecret();
        $issuer = config('betterauth.2fa.issuer', config('app.name', 'BetterAuth'));
        $email = $user->getAttribute('email');

        // Store pending secret (not enabled until verified)
        DB::table($this->table)->updateOrInsert(
            ['user_id' => $user->getAuthIdentifier()],
            [
                'id' => (string) Str::uuid7(),
                'secret' => $this->encryptSecret($secret),
                'enabled' => false,
                'recovery_codes' => null,
                'verified_at' => null,
                'created_at' => now(),
                'updated_at' => now(),
            ]
        );

        $uri = $this->buildTotpUri($secret, $email, $issuer);

        return [
            'secret' => $secret,
            'uri' => $uri,
            'qr_code_url' => $this->buildQrCodeUrl($uri),
        ];
    }

    /**
     * Verify a TOTP code and enable 2FA.
     *
     * @return array{enabled: bool, recovery_codes: array<string>}|null
     */
    public function verifyAndEnable(Authenticatable $user, string $code): ?array
    {
        $record = $this->getSecretRecord($user);

        if ($record === null) {
            return null;
        }

        $secret = $this->decryptSecret($record->secret);

        if (! $this->verifyCode($secret, $code)) {
            return null;
        }

        // Generate recovery codes
        $recoveryCodes = $this->generateRecoveryCodes();

        // Enable 2FA
        DB::table($this->table)
            ->where('user_id', $user->getAuthIdentifier())
            ->update([
                'enabled' => true,
                'recovery_codes' => json_encode($this->hashRecoveryCodes($recoveryCodes)),
                'verified_at' => now(),
                'updated_at' => now(),
            ]);

        Event::dispatch(new TwoFactorEnabled($user));

        return [
            'enabled' => true,
            'recovery_codes' => $recoveryCodes,
        ];
    }

    /**
     * Verify a TOTP code for an enabled 2FA.
     */
    public function verify(Authenticatable $user, string $code): bool
    {
        $record = $this->getSecretRecord($user);

        if ($record === null || ! $record->enabled) {
            return false;
        }

        $secret = $this->decryptSecret($record->secret);

        return $this->verifyCode($secret, $code);
    }

    /**
     * Verify a recovery code and consume it.
     */
    public function verifyRecoveryCode(Authenticatable $user, string $code): bool
    {
        $record = $this->getSecretRecord($user);

        if ($record === null || ! $record->enabled) {
            return false;
        }

        $recoveryCodes = json_decode($record->recovery_codes ?? '[]', true);

        foreach ($recoveryCodes as $index => $hashedCode) {
            if (hash_equals($hashedCode, hash('sha256', $code))) {
                // Remove used code
                unset($recoveryCodes[$index]);

                DB::table($this->table)
                    ->where('user_id', $user->getAuthIdentifier())
                    ->update([
                        'recovery_codes' => json_encode(array_values($recoveryCodes)),
                        'updated_at' => now(),
                    ]);

                return true;
            }
        }

        return false;
    }

    /**
     * Disable 2FA for a user.
     */
    public function disable(Authenticatable $user): bool
    {
        $deleted = DB::table($this->table)
            ->where('user_id', $user->getAuthIdentifier())
            ->delete();

        if ($deleted > 0) {
            Event::dispatch(new TwoFactorDisabled($user));
        }

        return $deleted > 0;
    }

    /**
     * Check if 2FA is enabled for a user.
     */
    public function isEnabled(Authenticatable $user): bool
    {
        $record = $this->getSecretRecord($user);

        return $record !== null && $record->enabled;
    }

    /**
     * Regenerate recovery codes.
     *
     * @return array<string>
     */
    public function regenerateRecoveryCodes(Authenticatable $user): array
    {
        $recoveryCodes = $this->generateRecoveryCodes();

        DB::table($this->table)
            ->where('user_id', $user->getAuthIdentifier())
            ->update([
                'recovery_codes' => json_encode($this->hashRecoveryCodes($recoveryCodes)),
                'updated_at' => now(),
            ]);

        return $recoveryCodes;
    }

    /**
     * Get the secret record for a user.
     */
    private function getSecretRecord(Authenticatable $user): ?object
    {
        return DB::table($this->table)
            ->where('user_id', $user->getAuthIdentifier())
            ->first();
    }

    /**
     * Generate a random base32 secret.
     */
    private function generateRandomSecret(): string
    {
        $bytes = random_bytes(self::SECRET_LENGTH);
        $base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

        $secret = '';
        foreach (str_split($bytes) as $byte) {
            $secret .= $base32Chars[ord($byte) % 32];
        }

        return substr($secret, 0, 32);
    }

    /**
     * Build the TOTP URI for QR code generation.
     */
    private function buildTotpUri(string $secret, string $email, string $issuer): string
    {
        $params = http_build_query([
            'secret' => $secret,
            'issuer' => $issuer,
            'algorithm' => 'SHA1',
            'digits' => 6,
            'period' => 30,
        ]);

        $label = rawurlencode("{$issuer}:{$email}");

        return "otpauth://totp/{$label}?{$params}";
    }

    /**
     * Build a QR code URL using Google Charts API.
     */
    private function buildQrCodeUrl(string $uri): string
    {
        return 'https://chart.googleapis.com/chart?'.http_build_query([
            'chs' => '200x200',
            'cht' => 'qr',
            'chl' => $uri,
        ]);
    }

    /**
     * Verify a TOTP code against a secret.
     */
    private function verifyCode(string $secret, string $code): bool
    {
        // Allow for time drift (±1 interval)
        $timestamp = time();
        $period = 30;

        for ($offset = -1; $offset <= 1; $offset++) {
            $timeSlice = floor(($timestamp + ($offset * $period)) / $period);
            $expectedCode = $this->generateTotpCode($secret, $timeSlice);

            if (hash_equals($expectedCode, $code)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Generate a TOTP code for a given time slice.
     */
    private function generateTotpCode(string $secret, int $timeSlice): string
    {
        // Decode base32 secret
        $key = $this->base32Decode($secret);

        // Pack time slice as 64-bit big-endian
        $time = pack('N*', 0, $timeSlice);

        // Calculate HMAC-SHA1
        $hmac = hash_hmac('sha1', $time, $key, true);

        // Dynamic truncation
        $offset = ord(substr($hmac, -1)) & 0x0F;
        $binary = (ord($hmac[$offset]) & 0x7F) << 24
            | (ord($hmac[$offset + 1]) & 0xFF) << 16
            | (ord($hmac[$offset + 2]) & 0xFF) << 8
            | (ord($hmac[$offset + 3]) & 0xFF);

        $otp = $binary % 1000000;

        return str_pad((string) $otp, 6, '0', STR_PAD_LEFT);
    }

    /**
     * Decode a base32 string.
     */
    private function base32Decode(string $input): string
    {
        $map = array_flip(str_split('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'));
        $input = strtoupper($input);
        $input = str_replace('=', '', $input);

        $buffer = 0;
        $length = 0;
        $result = '';

        foreach (str_split($input) as $char) {
            if (! isset($map[$char])) {
                continue;
            }

            $buffer = ($buffer << 5) | $map[$char];
            $length += 5;

            if ($length >= 8) {
                $length -= 8;
                $result .= chr(($buffer >> $length) & 0xFF);
            }
        }

        return $result;
    }

    /**
     * Generate recovery codes.
     *
     * @return array<string>
     */
    private function generateRecoveryCodes(): array
    {
        $codes = [];

        for ($i = 0; $i < self::RECOVERY_CODE_COUNT; $i++) {
            $codes[] = strtoupper(bin2hex(random_bytes(self::RECOVERY_CODE_LENGTH / 2)));
        }

        return $codes;
    }

    /**
     * Hash recovery codes for storage.
     *
     * @param  array<string>  $codes
     * @return array<string>
     */
    private function hashRecoveryCodes(array $codes): array
    {
        return array_map(fn ($code) => hash('sha256', $code), $codes);
    }

    /**
     * Encrypt the secret for storage.
     */
    private function encryptSecret(string $secret): string
    {
        return encrypt($secret);
    }

    /**
     * Decrypt the stored secret.
     */
    private function decryptSecret(string $encrypted): string
    {
        return decrypt($encrypted);
    }
}
