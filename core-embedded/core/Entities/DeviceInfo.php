<?php

declare(strict_types=1);

namespace BetterAuth\Core\Entities;

final readonly class DeviceInfo
{
    public function __construct(
        public string $id,
        public string $userId,
        public string $fingerprint,
        public ?string $deviceType,
        public ?string $browser,
        public ?string $browserVersion,
        public ?string $os,
        public ?string $osVersion,
        public ?string $ipAddress,
        public ?string $location,
        public bool $isTrusted,
        public string $firstSeenAt,
        public string $lastSeenAt,
        public ?array $metadata = null,
    ) {
    }

    public static function fromArray(array $data): self
    {
        return new self(
            id: $data['id'],
            userId: $data['user_id'],
            fingerprint: $data['fingerprint'],
            deviceType: $data['device_type'] ?? null,
            browser: $data['browser'] ?? null,
            browserVersion: $data['browser_version'] ?? null,
            os: $data['os'] ?? null,
            osVersion: $data['os_version'] ?? null,
            ipAddress: $data['ip_address'] ?? null,
            location: $data['location'] ?? null,
            isTrusted: $data['is_trusted'] ?? false,
            firstSeenAt: $data['first_seen_at'],
            lastSeenAt: $data['last_seen_at'],
            metadata: $data['metadata'] ?? null,
        );
    }

    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'user_id' => $this->userId,
            'fingerprint' => $this->fingerprint,
            'device_type' => $this->deviceType,
            'browser' => $this->browser,
            'browser_version' => $this->browserVersion,
            'os' => $this->os,
            'os_version' => $this->osVersion,
            'ip_address' => $this->ipAddress,
            'location' => $this->location,
            'is_trusted' => $this->isTrusted,
            'first_seen_at' => $this->firstSeenAt,
            'last_seen_at' => $this->lastSeenAt,
            'metadata' => $this->metadata,
        ];
    }
}
