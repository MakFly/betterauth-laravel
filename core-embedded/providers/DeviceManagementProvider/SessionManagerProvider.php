<?php

declare(strict_types=1);

namespace BetterAuth\Providers\DeviceManagementProvider;

use BetterAuth\Core\Entities\DeviceInfo;
use BetterAuth\Core\Entities\SessionActivity;
use BetterAuth\Core\Interfaces\DeviceInfoRepositoryInterface;
use BetterAuth\Core\Interfaces\SessionActivityRepositoryInterface;
use BetterAuth\Core\Utils\IdGenerator;
use DateTimeImmutable;

final readonly class SessionManagerProvider
{
    public function __construct(
        private DeviceInfoRepositoryInterface $deviceInfoRepository,
        private SessionActivityRepositoryInterface $sessionActivityRepository,
        private DeviceDetector $deviceDetector,
        private GeolocationService $geolocationService,
        private DeviceFingerprintService $fingerprintService,
    ) {
    }

    public function trackDevice(
        string $userId,
        ?string $userAgent,
        ?string $ipAddress,
        ?array $metadata = null,
    ): DeviceInfo {
        $fingerprint = $this->fingerprintService->generate($userAgent, $ipAddress);
        $existingDevice = $this->deviceInfoRepository->findByFingerprint($userId, $fingerprint);

        if ($existingDevice !== null) {
            return $this->deviceInfoRepository->update($existingDevice->id, [
                'last_seen_at' => (new DateTimeImmutable())->format('Y-m-d H:i:s'),
                'ip_address' => $ipAddress,
            ]);
        }

        $deviceInfo = $this->deviceDetector->detect($userAgent);
        $location = $this->geolocationService->getLocation($ipAddress);
        $id = $this->deviceInfoRepository->generateId() ?? IdGenerator::ulid();
        $now = (new DateTimeImmutable())->format('Y-m-d H:i:s');

        return $this->deviceInfoRepository->create([
            'id' => $id,
            'user_id' => $userId,
            'fingerprint' => $fingerprint,
            'device_type' => $deviceInfo['device_type'],
            'browser' => $deviceInfo['browser'],
            'browser_version' => $deviceInfo['browser_version'],
            'os' => $deviceInfo['os'],
            'os_version' => $deviceInfo['os_version'],
            'ip_address' => $ipAddress,
            'location' => $location,
            'is_trusted' => false,
            'first_seen_at' => $now,
            'last_seen_at' => $now,
            'metadata' => $metadata,
        ]);
    }

    public function logActivity(
        string $sessionId,
        string $action,
        ?string $ipAddress = null,
        ?string $userAgent = null,
        ?array $metadata = null,
    ): SessionActivity {
        $id = $this->sessionActivityRepository->generateId() ?? IdGenerator::ulid();
        $location = $this->geolocationService->getLocation($ipAddress);

        return $this->sessionActivityRepository->create([
            'id' => $id,
            'session_id' => $sessionId,
            'action' => $action,
            'ip_address' => $ipAddress,
            'user_agent' => $userAgent,
            'location' => $location,
            'created_at' => (new DateTimeImmutable())->format('Y-m-d H:i:s'),
            'metadata' => $metadata,
        ]);
    }

    public function getUserDevices(string $userId): array
    {
        return $this->deviceInfoRepository->findByUserId($userId);
    }

    public function getSessionActivity(string $sessionId, int $limit = 50): array
    {
        return $this->sessionActivityRepository->findBySessionId($sessionId, $limit);
    }

    public function trustDevice(string $deviceId): DeviceInfo
    {
        return $this->deviceInfoRepository->update($deviceId, ['is_trusted' => true]);
    }

    public function revokeDevice(string $deviceId): bool
    {
        return $this->deviceInfoRepository->delete($deviceId);
    }
}
