<?php

declare(strict_types=1);

namespace BetterAuth\Providers\TotpProvider;

use BetterAuth\Core\Interfaces\TotpStorageInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * TOTP (Time-based One-Time Password) provider for two-factor authentication.
 *
 * Supports dual-algorithm mode for SHA-1 → SHA-256 migration:
 * - New secrets use SHA-256 (more secure)
 * - Existing SHA-1 secrets are migrated lazily on next use
 * - Both algorithms accepted during transition period
 *
 * Note: This is a simplified implementation. For production use,
 * consider using a library like spomky-labs/otphp.
 */
final class TotpProvider
{
    private const PERIOD = 30; // 30 seconds
    private const DIGITS = 6;
    private const BACKUP_CODES_COUNT = 10;

    /**
     * Current preferred algorithm for new secrets.
     */
    public const ALGORITHM_SHA256 = 'sha256';

    /**
     * Legacy algorithm for backward compatibility.
     */
    public const ALGORITHM_SHA1 = 'sha1';

    /**
     * Default algorithm for new secrets.
     */
    private const DEFAULT_ALGORITHM = self::ALGORITHM_SHA256;

    /**
     * Supported algorithms for verification (order = preference).
     */
    private const SUPPORTED_ALGORITHMS = [self::ALGORITHM_SHA256, self::ALGORITHM_SHA1];

    private readonly LoggerInterface $logger;

    /**
     * @param TotpStorageInterface $totpStorage Storage implementation (PDO or Doctrine)
     * @param string $issuer Issuer name for TOTP QR codes
     * @param LoggerInterface|null $logger Optional logger
     */
    public function __construct(
        private readonly TotpStorageInterface $totpStorage,
        private readonly string $issuer = 'BetterAuth',
        ?LoggerInterface $logger = null,
    ) {
        $this->logger = $logger ?? new NullLogger();
    }

    /**
     * Generate a new TOTP secret for a user.
     *
     * @param string $userId The user ID for storage
     * @param string|null $displayIdentifier The identifier to display in QR code (email or user ID). If null, uses $userId
     *
     * @return array{secret: string, qrCode: string, qrCodeUrl?: string, manualEntryKey?: string, backupCodes: array<string>}
     *
     * @throws \Exception
     */
    public function generateSecret(string $userId, ?string $displayIdentifier = null): array
    {
        $this->logger->info('Generating TOTP secret', ['user_id' => $userId]);

        try {
            // Generate a random secret (base32 encoded)
            $secret = $this->generateBase32Secret();

            // Generate backup codes
            $backupCodes = $this->generateBackupCodes();

            // Store the secret with algorithm version (always use userId for storage)
            $this->totpStorage->store($userId, $secret, [
                'backup_codes' => array_map(fn ($code) => password_hash($code, PASSWORD_DEFAULT), $backupCodes),
                'enabled' => false,
                'algorithm' => self::DEFAULT_ALGORITHM,
            ]);

            // Generate QR code URL (otpauth:// URI) - use displayIdentifier (email) or fallback to userId
            $qrCodeIdentifier = $displayIdentifier ?? $userId;
            $qrCodeUrl = $this->getQrCodeUrl($qrCodeIdentifier, $secret);

            $this->logger->info('TOTP secret generated successfully', [
                'user_id' => $userId,
                'backup_codes_count' => count($backupCodes),
            ]);

            return [
                'secret' => $secret,
                'qrCode' => $qrCodeUrl, // Controller expects 'qrCode' key
                'qrCodeUrl' => $qrCodeUrl,
                'manualEntryKey' => $secret,
                'backupCodes' => $backupCodes,
            ];
        } catch (\Exception $e) {
            $this->logger->error('Failed to generate TOTP secret', [
                'user_id' => $userId,
                'error' => $e->getMessage(),
            ]);

            throw $e;
        }
    }

    /**
     * Verify a TOTP code and enable 2FA.
     *
     * @return bool True if verified and enabled
     */
    public function verifyAndEnable(string $userId, string $code): bool
    {
        $this->logger->info('TOTP verify and enable attempt', ['user_id' => $userId]);

        $totpData = $this->totpStorage->findByUserId($userId);

        if ($totpData === null) {
            $this->logger->warning('TOTP verify and enable failed: TOTP not configured', [
                'user_id' => $userId,
            ]);

            return false;
        }

        if ($this->verifyCode($totpData['secret'], $code)) {
            $this->totpStorage->enable($userId);

            $this->logger->info('TOTP enabled successfully', ['user_id' => $userId]);

            return true;
        }

        $this->logger->warning('TOTP verify and enable failed: Invalid code', [
            'user_id' => $userId,
        ]);

        return false;
    }

    /**
     * Verify a TOTP code for an enabled user.
     *
     * @return bool True if code is valid
     */
    public function verify(string $userId, string $code): bool
    {
        $this->logger->debug('TOTP verification attempt', ['user_id' => $userId]);

        $totpData = $this->totpStorage->findByUserId($userId);

        if ($totpData === null || !$totpData['enabled']) {
            $this->logger->warning('TOTP verification failed: TOTP not configured or not enabled', [
                'user_id' => $userId,
                'found' => $totpData !== null,
                'enabled' => $totpData['enabled'] ?? false,
            ]);

            return false;
        }

        // Try verifying as TOTP code
        if ($this->verifyCode($totpData['secret'], $code)) {
            $this->logger->info('TOTP code verified successfully', ['user_id' => $userId]);
            // Update last verification timestamp
            $this->totpStorage->updateLast2faVerifiedAt($userId);

            return true;
        }

        // Try verifying as backup code
        $backupCodeValid = $this->totpStorage->useBackupCode($userId, $code);

        if ($backupCodeValid) {
            $this->logger->info('TOTP backup code used successfully', ['user_id' => $userId]);
            $this->totpStorage->updateLast2faVerifiedAt($userId);

            // Warn when backup codes are nearly depleted
            $remainingData = $this->totpStorage->findByUserId($userId);
            $backupCodesCount = count($remainingData['backup_codes'] ?? []);
            if ($backupCodesCount <= 1) {
                $this->logger->warning('TOTP: Last backup code used or nearly depleted', [
                    'user_id' => $userId,
                    'remaining' => $backupCodesCount,
                ]);
            }
        } else {
            $this->logger->warning('TOTP verification failed: Invalid code', ['user_id' => $userId]);
        }

        return $backupCodeValid;
    }

    /**
     * Disable TOTP for a user.
     * Requires a backup code to disable (not a TOTP code).
     *
     * @param string $backupCode Backup code required to disable
     */
    public function disable(string $userId, string $backupCode): bool
    {
        $this->logger->info('TOTP disable attempt', ['user_id' => $userId]);

        $totpData = $this->totpStorage->findByUserId($userId);

        if ($totpData === null || !$totpData['enabled']) {
            $this->logger->warning('TOTP disable failed: TOTP not configured or not enabled', [
                'user_id' => $userId,
            ]);

            return false;
        }

        // Verify backup code before disabling
        if (!$this->totpStorage->useBackupCode($userId, $backupCode)) {
            $this->logger->warning('TOTP disable failed: Invalid backup code', ['user_id' => $userId]);

            return false;
        }

        $result = $this->totpStorage->disable($userId);

        if ($result) {
            $this->logger->info('TOTP disabled successfully', ['user_id' => $userId]);
        }

        return $result;
    }

    /**
     * Regenerate backup codes.
     *
     * @param string $code Verification code required
     *
     * @return array{success: bool, backupCodes?: array<string>, error?: string} Result with new backup codes
     *
     * @throws \Exception
     */
    public function regenerateBackupCodes(string $userId, string $code): array
    {
        $totpData = $this->totpStorage->findByUserId($userId);

        if ($totpData === null) {
            return ['success' => false, 'error' => 'TOTP not configured for user'];
        }

        // Verify code before regenerating
        if (!$this->verifyCode($totpData['secret'], $code)) {
            return ['success' => false, 'error' => 'Invalid verification code'];
        }

        $backupCodes = $this->generateBackupCodes();

        $this->totpStorage->store($userId, $totpData['secret'], [
            'backup_codes' => array_map(fn ($code) => password_hash($code, PASSWORD_DEFAULT), $backupCodes),
            'enabled' => $totpData['enabled'],
        ]);

        return ['success' => true, 'backupCodes' => $backupCodes];
    }

    /**
     * Validate a TOTP or backup code during login.
     *
     * @param string $email The user's email
     * @param string $code The TOTP or backup code
     * @param bool $isBackupCode Whether the code is a backup code
     *
     * @return array{valid: bool, userId?: string} Result of validation
     *
     * @throws \LogicException Always — use verify($userId, $code) instead
     *
     * @deprecated Use TotpProvider::verify($userId, $code) directly.
     *             This method cannot resolve email to userId without a UserRepository dependency.
     */
    public function validateCode(string $email, string $code, bool $isBackupCode = false): array
    {
        throw new \LogicException(
            'TotpProvider::validateCode() cannot resolve email to userId. ' .
            'Use TotpProvider::verify($userId, $code) instead.'
        );
    }

    /**
     * Get TOTP status for a user.
     *
     * @return array{enabled: bool, backupCodesRemaining?: int, requires2fa?: bool, last2faVerifiedAt?: string|null}
     */
    public function getStatus(string $userId): array
    {
        $totpData = $this->totpStorage->findByUserId($userId);

        if ($totpData === null) {
            return ['enabled' => false];
        }

        $lastVerified = $totpData['last_2fa_verified_at'] ?? null;
        $requires2fa = false;

        if ($totpData['enabled'] && $lastVerified) {
            // Check if last verification was more than 24 hours ago
            $lastVerifiedDate = \DateTimeImmutable::createFromFormat('Y-m-d H:i:s', $lastVerified);
            if ($lastVerifiedDate) {
                $now = new \DateTimeImmutable();
                $diff = $now->diff($lastVerifiedDate);
                // If more than 24 hours have passed, 2FA is required
                $requires2fa = ($diff->days > 0 || ($diff->days === 0 && $diff->h >= 24));
            }
        } elseif ($totpData['enabled'] && !$lastVerified) {
            // If 2FA is enabled but never verified, require it
            $requires2fa = true;
        }

        return [
            'enabled' => $totpData['enabled'],
            'backupCodesRemaining' => count($totpData['backup_codes'] ?? []),
            'requires2fa' => $requires2fa,
            'last2faVerifiedAt' => $lastVerified,
        ];
    }

    /**
     * Check if 2FA is required for a user (once per day).
     *
     * @return bool True if 2FA is required
     */
    public function requires2fa(string $userId): bool
    {
        $status = $this->getStatus($userId);

        return $status['requires2fa'] ?? false;
    }

    /**
     * Reset 2FA with a backup code (when 2FA is broken).
     * This will generate a new secret and backup codes.
     *
     * @param string $userId The user ID for storage
     * @param string $backupCode The backup code to verify
     * @param string|null $displayIdentifier The identifier to display in QR code (email or user ID). If null, uses $userId
     *
     * @return array{success: bool, secret?: string, qrCode?: string, manualEntryKey?: string, backupCodes?: array<string>, error?: string}
     *
     * @throws \Exception
     */
    public function resetWithBackupCode(string $userId, string $backupCode, ?string $displayIdentifier = null): array
    {
        $this->logger->info('TOTP reset with backup code attempt', ['user_id' => $userId]);

        $totpData = $this->totpStorage->findByUserId($userId);

        if ($totpData === null || !$totpData['enabled']) {
            return ['success' => false, 'error' => 'TOTP not configured or not enabled'];
        }

        // Verify backup code
        if (!$this->totpStorage->useBackupCode($userId, $backupCode)) {
            $this->logger->warning('TOTP reset failed: Invalid backup code', ['user_id' => $userId]);

            return ['success' => false, 'error' => 'Invalid backup code'];
        }

        // Generate new secret and backup codes
        $secret = $this->generateBase32Secret();
        $backupCodes = $this->generateBackupCodes();

        // Store new secret with SHA-256 algorithm (disabled until validated)
        $this->totpStorage->store($userId, $secret, [
            'backup_codes' => array_map(fn ($code) => password_hash($code, PASSWORD_DEFAULT), $backupCodes),
            'enabled' => false,
            'algorithm' => self::DEFAULT_ALGORITHM,
        ]);

        // Generate QR code - use displayIdentifier (email) or fallback to userId
        $qrCodeIdentifier = $displayIdentifier ?? $userId;
        $qrCodeUrl = $this->getQrCodeUrl($qrCodeIdentifier, $secret, self::DEFAULT_ALGORITHM);

        $this->logger->info('TOTP reset successfully', [
            'user_id' => $userId,
            'algorithm' => self::DEFAULT_ALGORITHM,
        ]);

        return [
            'success' => true,
            'secret' => $secret,
            'qrCode' => $qrCodeUrl,
            'manualEntryKey' => $secret,
            'backupCodes' => $backupCodes,
            'algorithm' => self::DEFAULT_ALGORITHM,
        ];
    }

    /**
     * Verify a TOTP code against a secret using dual-algorithm support.
     *
     * Tries SHA-256 first (preferred), then SHA-1 (legacy) for migration.
     *
     * @param string $secret The TOTP secret
     * @param string $code The code to verify
     * @param string|null $algorithm Force a specific algorithm (null = try both)
     *
     * @return array{valid: bool, algorithm: string|null} Verification result with matched algorithm
     */
    private function verifyCodeWithAlgorithm(string $secret, string $code, ?string $algorithm = null): array
    {
        $timestamp = time();
        $algorithmsToTry = $algorithm !== null ? [$algorithm] : self::SUPPORTED_ALGORITHMS;

        foreach ($algorithmsToTry as $algo) {
            // Check current time window and ±1 windows for clock skew
            for ($i = -1; $i <= 1; $i++) {
                $testTime = $timestamp + ($i * self::PERIOD);
                $expectedCode = $this->generateCodeWithAlgorithm($secret, $testTime, $algo);

                if (hash_equals($expectedCode, $code)) {
                    return ['valid' => true, 'algorithm' => $algo];
                }
            }
        }

        return ['valid' => false, 'algorithm' => null];
    }

    /**
     * Verify a TOTP code against a secret (backward compatible wrapper).
     */
    private function verifyCode(string $secret, string $code): bool
    {
        return $this->verifyCodeWithAlgorithm($secret, $code)['valid'];
    }

    /**
     * Generate a TOTP code for a given timestamp with specified algorithm.
     */
    private function generateCodeWithAlgorithm(string $secret, int $timestamp, string $algorithm): string
    {
        $time = pack('N*', 0) . pack('N*', floor($timestamp / self::PERIOD));
        $hash = hash_hmac($algorithm, $time, $this->base32Decode($secret), true);

        $offset = ord($hash[strlen($hash) - 1]) & 0x0F;
        $value = (
            ((ord($hash[$offset]) & 0x7F) << 24) |
            ((ord($hash[$offset + 1]) & 0xFF) << 16) |
            ((ord($hash[$offset + 2]) & 0xFF) << 8) |
            (ord($hash[$offset + 3]) & 0xFF)
        );

        $code = $value % (10 ** self::DIGITS);

        return str_pad((string) $code, self::DIGITS, '0', STR_PAD_LEFT);
    }

    /**
     * Generate a TOTP code using the default algorithm (backward compatible).
     *
     * @phpstan-ignore-next-line This method exists for backward compatibility and future use.
     */
    private function generateCode(string $secret, int $timestamp): string
    {
        return $this->generateCodeWithAlgorithm($secret, $timestamp, self::DEFAULT_ALGORITHM);
    }

    /**
     * Generate a random base32-encoded secret.
     *
     * @throws \Exception
     */
    private function generateBase32Secret(): string
    {
        $bytes = random_bytes(20);

        return $this->base32Encode($bytes);
    }

    /**
     * Generate backup codes.
     *
     * @return array<string>
     *
     * @throws \Exception
     */
    private function generateBackupCodes(): array
    {
        $codes = [];
        for ($i = 0; $i < self::BACKUP_CODES_COUNT; $i++) {
            $codes[] = substr(str_replace(['/', '+', '='], '', base64_encode(random_bytes(8))), 0, 10);
        }

        return $codes;
    }

    /**
     * Get the QR code URL for TOTP setup.
     *
     * @param string $identifier The identifier to display (email or user ID)
     * @param string $algorithm The HMAC algorithm to use (sha256 or sha1)
     */
    private function getQrCodeUrl(string $identifier, string $secret, string $algorithm = self::DEFAULT_ALGORITHM): string
    {
        $params = http_build_query([
            'secret' => $secret,
            'issuer' => $this->issuer,
            'algorithm' => strtoupper($algorithm),
            'digits' => self::DIGITS,
            'period' => self::PERIOD,
        ]);

        return sprintf(
            'otpauth://totp/%s:%s?%s',
            urlencode($this->issuer),
            urlencode($identifier),
            $params,
        );
    }

    /**
     * Get the algorithm used for a user's TOTP.
     *
     * @return string The algorithm (sha256 or sha1)
     */
    public function getUserAlgorithm(string $userId): string
    {
        $totpData = $this->totpStorage->findByUserId($userId);

        if ($totpData === null) {
            return self::DEFAULT_ALGORITHM;
        }

        // Check stored algorithm, default to sha1 for legacy secrets
        return $totpData['algorithm'] ?? self::ALGORITHM_SHA1;
    }

    /**
     * Check if user needs TOTP algorithm migration.
     */
    public function needsAlgorithmMigration(string $userId): bool
    {
        return $this->getUserAlgorithm($userId) === self::ALGORITHM_SHA1;
    }

    /**
     * Base32 encode.
     */
    private function base32Encode(string $data): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $encoded = '';
        $bits = 0;
        $value = 0;

        foreach (str_split($data) as $char) {
            $value = ($value << 8) | ord($char);
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

    /**
     * Base32 decode.
     */
    private function base32Decode(string $data): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $data = strtoupper($data);
        $decoded = '';
        $bits = 0;
        $value = 0;

        foreach (str_split($data) as $char) {
            if (($pos = strpos($alphabet, $char)) === false) {
                continue;
            }

            $value = ($value << 5) | $pos;
            $bits += 5;

            if ($bits >= 8) {
                $decoded .= chr(($value >> ($bits - 8)) & 255);
                $bits -= 8;
            }
        }

        return $decoded;
    }
}
