<?php

declare(strict_types=1);

namespace BetterAuth\Providers\DeviceManagementProvider;

use BetterAuth\Core\Security\SessionSecurityService;

/**
 * Device fingerprinting service with adaptive risk scoring.
 *
 * Generates device fingerprints and compares them to detect suspicious activity.
 * Uses SessionSecurityService for risk-based analysis that tolerates legitimate
 * changes (WiFi ↔ 4G, browser updates) while detecting hijacking attempts.
 *
 * Note: This class is not final to allow mocking in tests.
 */
class DeviceFingerprintService
{
    private readonly SessionSecurityService $securityService;

    public function __construct(
        ?SessionSecurityService $securityService = null,
    ) {
        $this->securityService = $securityService ?? new SessionSecurityService();
    }

    /**
     * Generate a simple fingerprint hash.
     */
    public function generate(?string $userAgent, ?string $ipAddress, ?array $additionalData = null): string
    {
        $parts = [
            $userAgent ?? 'unknown',
            $ipAddress ?? 'unknown',
        ];

        if ($additionalData !== null) {
            ksort($additionalData);
            $parts[] = json_encode($additionalData);
        }

        return hash('sha256', implode('|', $parts));
    }

    /**
     * Create a detailed fingerprint with parsed metadata.
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
    public function createDetailedFingerprint(
        string $ipAddress,
        string $userAgent,
        ?string $country = null,
    ): array {
        return $this->securityService->createFingerprint($ipAddress, $userAgent, $country);
    }

    /**
     * Compare two fingerprints and calculate risk score.
     *
     * @param array<string, mixed> $original Original session fingerprint
     * @param array<string, mixed> $current Current request fingerprint
     *
     * @return array{
     *     score: int,
     *     level: string,
     *     factors: array<string, int>,
     *     action: string
     * }
     */
    public function compareFingerprints(array $original, array $current): array
    {
        return $this->securityService->calculateRiskScore($original, $current);
    }

    /**
     * Quick check if session fingerprint is suspicious.
     */
    public function isSuspicious(array $original, array $current): bool
    {
        return $this->securityService->isSuspicious($original, $current);
    }

    /**
     * Check if session should be terminated due to hijacking risk.
     */
    public function shouldTerminateSession(array $original, array $current): bool
    {
        return $this->securityService->shouldTerminateSession($original, $current);
    }

    /**
     * Validate current request against stored session fingerprint.
     *
     * @return array{
     *     valid: bool,
     *     risk_score: int,
     *     risk_level: string,
     *     action: string,
     *     factors: array<string, int>
     * }
     */
    public function validateRequest(
        array $storedFingerprint,
        string $currentIp,
        string $currentUserAgent,
        ?string $currentCountry = null,
    ): array {
        $currentFingerprint = $this->createDetailedFingerprint(
            $currentIp,
            $currentUserAgent,
            $currentCountry,
        );

        $riskAnalysis = $this->compareFingerprints($storedFingerprint, $currentFingerprint);

        return [
            'valid' => $riskAnalysis['action'] === 'allow',
            'risk_score' => $riskAnalysis['score'],
            'risk_level' => $riskAnalysis['level'],
            'action' => $riskAnalysis['action'],
            'factors' => $riskAnalysis['factors'],
        ];
    }
}
