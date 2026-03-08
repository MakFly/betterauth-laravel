<?php

declare(strict_types=1);

namespace BetterAuth\Providers\SecurityProvider;

use BetterAuth\Core\Entities\SuspiciousActivity;
use BetterAuth\Core\Interfaces\DeviceInfoRepositoryInterface;
use BetterAuth\Core\Interfaces\SuspiciousActivityRepositoryInterface;
use BetterAuth\Core\Utils\IdGenerator;
use BetterAuth\Providers\DeviceManagementProvider\DeviceFingerprintService;
use BetterAuth\Providers\DeviceManagementProvider\GeolocationService;
use DateTimeImmutable;

final class ThreatDetector
{
    public function __construct(
        private SuspiciousActivityRepositoryInterface $suspiciousActivityRepository,
        private DeviceInfoRepositoryInterface $deviceInfoRepository,
        private GeolocationService $geolocationService,
        private DeviceFingerprintService $fingerprintService,
    ) {
    }

    public function detectSuspiciousActivity(
        string $userId,
        string $activityType,
        ?string $ipAddress = null,
        ?string $userAgent = null,
        ?array $details = null,
    ): ?SuspiciousActivity {
        $riskLevel = $this->assessRiskLevel($userId, $ipAddress, $userAgent);

        if ($riskLevel === 'low') {
            return null;
        }

        $id = $this->suspiciousActivityRepository->generateId() ?? IdGenerator::ulid();
        $location = $this->geolocationService->getLocation($ipAddress);

        return $this->suspiciousActivityRepository->create([
            'id' => $id,
            'user_id' => $userId,
            'activity_type' => $activityType,
            'risk_level' => $riskLevel,
            'ip_address' => $ipAddress,
            'user_agent' => $userAgent,
            'location' => $location,
            'detected_at' => (new DateTimeImmutable())->format('Y-m-d H:i:s'),
            'status' => 'pending',
            'details' => $details,
        ]);
    }

    public function resolveActivity(string $activityId): SuspiciousActivity
    {
        return $this->suspiciousActivityRepository->update($activityId, [
            'status' => 'resolved',
            'resolved_at' => (new DateTimeImmutable())->format('Y-m-d H:i:s'),
        ]);
    }

    public function getUserSuspiciousActivities(string $userId, int $limit = 100): array
    {
        return $this->suspiciousActivityRepository->findByUserId($userId, $limit);
    }

    public function getPendingActivities(int $limit = 100): array
    {
        return $this->suspiciousActivityRepository->findByStatus('pending', $limit);
    }

    private function assessRiskLevel(string $userId, ?string $ipAddress, ?string $userAgent): string
    {
        $fingerprint = $this->fingerprintService->generate($userAgent, $ipAddress);
        $knownDevice = $this->deviceInfoRepository->findByFingerprint($userId, $fingerprint);

        if ($knownDevice === null) {
            // Unknown device — check if user has any known devices
            $knownDevices = $this->deviceInfoRepository->findByUserId($userId);
            if (count($knownDevices) > 0) {
                // User has known devices but this is a new one → high risk
                return 'high';
            }
            // First device for this user → medium risk
            return 'medium';
        }

        if ($knownDevice->isTrusted) {
            return 'low';
        }

        // Known but untrusted device
        return 'medium';
    }
}
