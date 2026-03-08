<?php

declare(strict_types=1);

namespace BetterAuth\Core\Entities;

final readonly class SessionActivity
{
    public function __construct(
        public string $id,
        public string $sessionId,
        public string $action,
        public ?string $ipAddress,
        public ?string $userAgent,
        public ?string $location,
        public string $createdAt,
        public ?array $metadata = null,
    ) {
    }

    public static function fromArray(array $data): self
    {
        return new self(
            id: $data['id'],
            sessionId: $data['session_id'],
            action: $data['action'],
            ipAddress: $data['ip_address'] ?? null,
            userAgent: $data['user_agent'] ?? null,
            location: $data['location'] ?? null,
            createdAt: $data['created_at'],
            metadata: $data['metadata'] ?? null,
        );
    }

    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'session_id' => $this->sessionId,
            'action' => $this->action,
            'ip_address' => $this->ipAddress,
            'user_agent' => $this->userAgent,
            'location' => $this->location,
            'created_at' => $this->createdAt,
            'metadata' => $this->metadata,
        ];
    }
}
