<?php

declare(strict_types=1);

namespace BetterAuth\Core\Entities;

final readonly class SecurityEvent
{
    public function __construct(
        public string $id,
        public string $userId,
        public string $eventType,
        public string $severity,
        public ?string $ipAddress,
        public ?string $userAgent,
        public ?string $location,
        public string $createdAt,
        public ?array $details = null,
    ) {
    }

    public static function fromArray(array $data): self
    {
        return new self(
            id: $data['id'],
            userId: $data['user_id'],
            eventType: $data['event_type'],
            severity: $data['severity'],
            ipAddress: $data['ip_address'] ?? null,
            userAgent: $data['user_agent'] ?? null,
            location: $data['location'] ?? null,
            createdAt: $data['created_at'],
            details: $data['details'] ?? null,
        );
    }

    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'user_id' => $this->userId,
            'event_type' => $this->eventType,
            'severity' => $this->severity,
            'ip_address' => $this->ipAddress,
            'user_agent' => $this->userAgent,
            'location' => $this->location,
            'created_at' => $this->createdAt,
            'details' => $this->details,
        ];
    }
}
