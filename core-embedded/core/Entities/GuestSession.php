<?php

declare(strict_types=1);

namespace BetterAuth\Core\Entities;

final readonly class GuestSession
{
    public function __construct(
        public string $id,
        public string $token,
        public ?string $deviceInfo,
        public ?string $ipAddress,
        public string $createdAt,
        public string $expiresAt,
        public ?array $metadata = null,
    ) {
    }

    public static function fromArray(array $data): self
    {
        return new self(
            id: $data['id'],
            token: $data['token'],
            deviceInfo: $data['device_info'] ?? null,
            ipAddress: $data['ip_address'] ?? null,
            createdAt: $data['created_at'],
            expiresAt: $data['expires_at'],
            metadata: $data['metadata'] ?? null,
        );
    }

    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'token' => $this->token,
            'device_info' => $this->deviceInfo,
            'ip_address' => $this->ipAddress,
            'created_at' => $this->createdAt,
            'expires_at' => $this->expiresAt,
            'metadata' => $this->metadata,
        ];
    }
}
