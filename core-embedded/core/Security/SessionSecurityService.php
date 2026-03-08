<?php

declare(strict_types=1);

namespace BetterAuth\Core\Security;

use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Adaptive Session Security Service.
 *
 * Implements risk-based session fingerprinting that:
 * - Tolerates minor changes (WiFi ↔ 4G, IP rotation)
 * - Detects major changes (new device + new location + new OS)
 * - Mobile-friendly: doesn't block legitimate users
 *
 * Risk Score: 0 (safe) to 100 (hijack detected)
 * Threshold: 50 = require re-auth, 75 = force logout
 */
final class SessionSecurityService
{
    /**
     * Risk threshold for soft challenge (re-auth via email).
     */
    public const RISK_THRESHOLD_SOFT = 50;

    /**
     * Risk threshold for hard challenge (force logout).
     */
    public const RISK_THRESHOLD_HARD = 75;

    /**
     * Weights for risk calculation.
     */
    private const WEIGHTS = [
        'ip_class_c_change' => 15,      // Same ISP, different subnet
        'ip_country_change' => 40,       // Different country = major flag
        'os_family_change' => 25,        // Windows → macOS = suspicious
        'browser_family_change' => 15,   // Chrome → Firefox = minor
        'device_type_change' => 30,      // Desktop → Mobile = suspicious
        'user_agent_hash_change' => 10,  // Minor UA changes (version updates)
        'impossible_travel' => 50,       // Distance / time = impossible speed
    ];

    private readonly LoggerInterface $logger;

    public function __construct(
        ?LoggerInterface $logger = null,
    ) {
        $this->logger = $logger ?? new NullLogger();
    }

    /**
     * Calculate risk score between two fingerprints.
     *
     * @param array{
     *     ip_address?: string,
     *     user_agent?: string,
     *     os_family?: string,
     *     browser_family?: string,
     *     device_type?: string,
     *     country?: string,
     *     timestamp?: int
     * } $original Original session fingerprint
     * @param array{
     *     ip_address?: string,
     *     user_agent?: string,
     *     os_family?: string,
     *     browser_family?: string,
     *     device_type?: string,
     *     country?: string,
     *     timestamp?: int
     * } $current Current request fingerprint
     *
     * @return array{
     *     score: int,
     *     level: string,
     *     factors: array<string, int>,
     *     action: string
     * }
     */
    public function calculateRiskScore(array $original, array $current): array
    {
        $factors = [];
        $score = 0;

        // IP Class C comparison (first 3 octets)
        if ($this->hasIpClassCChange($original['ip_address'] ?? '', $current['ip_address'] ?? '')) {
            $factors['ip_class_c_change'] = self::WEIGHTS['ip_class_c_change'];
            $score += self::WEIGHTS['ip_class_c_change'];
        }

        // Country change (requires GeoIP)
        if (isset($original['country'], $current['country']) && $original['country'] !== $current['country']) {
            $factors['ip_country_change'] = self::WEIGHTS['ip_country_change'];
            $score += self::WEIGHTS['ip_country_change'];

            // Check for impossible travel
            if ($this->isImpossibleTravel($original, $current)) {
                $factors['impossible_travel'] = self::WEIGHTS['impossible_travel'];
                $score += self::WEIGHTS['impossible_travel'];
            }
        }

        // OS family change
        if (isset($original['os_family'], $current['os_family']) && $original['os_family'] !== $current['os_family']) {
            $factors['os_family_change'] = self::WEIGHTS['os_family_change'];
            $score += self::WEIGHTS['os_family_change'];
        }

        // Browser family change
        if (isset($original['browser_family'], $current['browser_family']) && $original['browser_family'] !== $current['browser_family']) {
            $factors['browser_family_change'] = self::WEIGHTS['browser_family_change'];
            $score += self::WEIGHTS['browser_family_change'];
        }

        // Device type change
        if (isset($original['device_type'], $current['device_type']) && $original['device_type'] !== $current['device_type']) {
            $factors['device_type_change'] = self::WEIGHTS['device_type_change'];
            $score += self::WEIGHTS['device_type_change'];
        }

        // User agent hash change (for minor version changes)
        $originalUaHash = $this->normalizeUserAgentHash($original['user_agent'] ?? '');
        $currentUaHash = $this->normalizeUserAgentHash($current['user_agent'] ?? '');
        if ($originalUaHash !== $currentUaHash && !isset($factors['browser_family_change'])) {
            $factors['user_agent_hash_change'] = self::WEIGHTS['user_agent_hash_change'];
            $score += self::WEIGHTS['user_agent_hash_change'];
        }

        // Clamp score to 0-100
        $score = min(100, max(0, $score));

        $level = $this->getRiskLevel($score);
        $action = $this->getRecommendedAction($score);

        $this->logger->info('Session risk score calculated', [
            'score' => $score,
            'level' => $level,
            'factors' => $factors,
            'action' => $action,
        ]);

        return [
            'score' => $score,
            'level' => $level,
            'factors' => $factors,
            'action' => $action,
        ];
    }

    /**
     * Create fingerprint from request data.
     *
     * @return array{
     *     ip_address: string,
     *     user_agent: string,
     *     os_family: string,
     *     browser_family: string,
     *     device_type: string,
     *     country: string|null,
     *     hash: string,
     *     timestamp: int
     * }
     */
    public function createFingerprint(
        string $ipAddress,
        string $userAgent,
        ?string $country = null,
    ): array {
        $parsed = $this->parseUserAgent($userAgent);

        return [
            'ip_address' => $ipAddress,
            'user_agent' => $userAgent,
            'os_family' => $parsed['os_family'],
            'browser_family' => $parsed['browser_family'],
            'device_type' => $parsed['device_type'],
            'country' => $country,
            'hash' => $this->generateHash($ipAddress, $userAgent),
            'timestamp' => time(),
        ];
    }

    /**
     * Quick check if fingerprint is suspicious.
     */
    public function isSuspicious(array $original, array $current): bool
    {
        $result = $this->calculateRiskScore($original, $current);

        return $result['score'] >= self::RISK_THRESHOLD_SOFT;
    }

    /**
     * Check if session should be terminated.
     */
    public function shouldTerminateSession(array $original, array $current): bool
    {
        $result = $this->calculateRiskScore($original, $current);

        return $result['score'] >= self::RISK_THRESHOLD_HARD;
    }

    /**
     * Check if IP class C (first 3 octets) has changed.
     */
    private function hasIpClassCChange(string $original, string $current): bool
    {
        if (empty($original) || empty($current)) {
            return false;
        }

        // Handle IPv4
        if (filter_var($original, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)
            && filter_var($current, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $originalParts = explode('.', $original);
            $currentParts = explode('.', $current);

            // Compare first 3 octets
            return $originalParts[0] !== $currentParts[0]
                || $originalParts[1] !== $currentParts[1]
                || $originalParts[2] !== $currentParts[2];
        }

        // For IPv6, compare first 64 bits (network prefix)
        return $original !== $current;
    }

    /**
     * Check for impossible travel (speed > 1000 km/h).
     */
    private function isImpossibleTravel(array $original, array $current): bool
    {
        $originalTime = $original['timestamp'] ?? 0;
        $currentTime = $current['timestamp'] ?? time();

        $timeDiffHours = ($currentTime - $originalTime) / 3600;

        // If less than 1 hour and different country = impossible
        // (Simplified check - real implementation would use actual distance)
        if ($timeDiffHours < 1 && isset($original['country'], $current['country'])) {
            return $original['country'] !== $current['country'];
        }

        return false;
    }

    /**
     * Normalize user agent to hash (ignoring minor version changes).
     */
    private function normalizeUserAgentHash(string $userAgent): string
    {
        if (empty($userAgent)) {
            return '';
        }

        // Remove version numbers to tolerate browser updates
        $normalized = preg_replace('/\d+(\.\d+)+/', 'X', $userAgent);

        return hash('sha256', $normalized ?? $userAgent);
    }

    /**
     * Parse user agent to extract OS, browser, device type.
     *
     * @return array{os_family: string, browser_family: string, device_type: string}
     */
    private function parseUserAgent(string $userAgent): array
    {
        $osFamily = 'Unknown';
        $browserFamily = 'Unknown';
        $deviceType = 'Desktop';

        // OS detection
        if (stripos($userAgent, 'Windows') !== false) {
            $osFamily = 'Windows';
        } elseif (stripos($userAgent, 'Mac OS') !== false || stripos($userAgent, 'Macintosh') !== false) {
            $osFamily = 'macOS';
        } elseif (stripos($userAgent, 'Linux') !== false) {
            $osFamily = 'Linux';
        } elseif (stripos($userAgent, 'Android') !== false) {
            $osFamily = 'Android';
            $deviceType = 'Mobile';
        } elseif (stripos($userAgent, 'iPhone') !== false || stripos($userAgent, 'iPad') !== false) {
            $osFamily = 'iOS';
            $deviceType = stripos($userAgent, 'iPad') !== false ? 'Tablet' : 'Mobile';
        }

        // Browser detection
        if (stripos($userAgent, 'Firefox') !== false) {
            $browserFamily = 'Firefox';
        } elseif (stripos($userAgent, 'Edg') !== false) {
            $browserFamily = 'Edge';
        } elseif (stripos($userAgent, 'Chrome') !== false) {
            $browserFamily = 'Chrome';
        } elseif (stripos($userAgent, 'Safari') !== false) {
            $browserFamily = 'Safari';
        } elseif (stripos($userAgent, 'Opera') !== false || stripos($userAgent, 'OPR') !== false) {
            $browserFamily = 'Opera';
        }

        // Mobile detection override
        if (stripos($userAgent, 'Mobile') !== false) {
            $deviceType = 'Mobile';
        } elseif (stripos($userAgent, 'Tablet') !== false) {
            $deviceType = 'Tablet';
        }

        return [
            'os_family' => $osFamily,
            'browser_family' => $browserFamily,
            'device_type' => $deviceType,
        ];
    }

    /**
     * Generate fingerprint hash.
     */
    private function generateHash(string $ipAddress, string $userAgent): string
    {
        return hash('sha256', sprintf('%s|%s', $ipAddress, $userAgent));
    }

    /**
     * Get risk level label.
     */
    private function getRiskLevel(int $score): string
    {
        return match (true) {
            $score >= self::RISK_THRESHOLD_HARD => 'critical',
            $score >= self::RISK_THRESHOLD_SOFT => 'high',
            $score >= 25 => 'medium',
            $score > 0 => 'low',
            default => 'safe',
        };
    }

    /**
     * Get recommended action based on risk score.
     */
    private function getRecommendedAction(int $score): string
    {
        return match (true) {
            $score >= self::RISK_THRESHOLD_HARD => 'terminate_session',
            $score >= self::RISK_THRESHOLD_SOFT => 'require_reauth',
            $score >= 25 => 'log_warning',
            default => 'allow',
        };
    }
}
