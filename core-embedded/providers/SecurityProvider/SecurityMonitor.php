<?php

declare(strict_types=1);

namespace BetterAuth\Providers\SecurityProvider;

use BetterAuth\Core\Entities\SecurityEvent;
use BetterAuth\Core\Interfaces\SecurityEventRepositoryInterface;
use BetterAuth\Core\Utils\IdGenerator;
use BetterAuth\Providers\DeviceManagementProvider\GeolocationService;
use DateTimeImmutable;

final readonly class SecurityMonitor
{
    public function __construct(
        private SecurityEventRepositoryInterface $securityEventRepository,
        private GeolocationService $geolocationService,
    ) {
    }

    public function logEvent(
        string $userId,
        string $eventType,
        string $severity,
        ?string $ipAddress = null,
        ?string $userAgent = null,
        ?array $details = null,
    ): SecurityEvent {
        $id = $this->securityEventRepository->generateId() ?? IdGenerator::ulid();
        $location = $this->geolocationService->getLocation($ipAddress);

        return $this->securityEventRepository->create([
            'id' => $id,
            'user_id' => $userId,
            'event_type' => $eventType,
            'severity' => $severity,
            'ip_address' => $ipAddress,
            'user_agent' => $userAgent,
            'location' => $location,
            'created_at' => (new DateTimeImmutable())->format('Y-m-d H:i:s'),
            'details' => $details,
        ]);
    }

    public function getUserEvents(string $userId, int $limit = 100): array
    {
        return $this->securityEventRepository->findByUserId($userId, $limit);
    }

    public function getCriticalEvents(int $limit = 100): array
    {
        return $this->securityEventRepository->findBySeverity('critical', $limit);
    }
}
