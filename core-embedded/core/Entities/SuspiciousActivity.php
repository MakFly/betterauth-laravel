<?php

declare(strict_types=1);

namespace BetterAuth\Core\Entities;

final readonly class SuspiciousActivity
{
    public function __construct(
        public string $id,
        public string $userId,
        public string $activityType,
        public string $riskLevel,
        public ?string $ipAddress,
        public ?string $userAgent,
        public ?string $location,
        public string $detectedAt,
        public string $status,
        public ?string $resolvedAt = null,
        public ?array $details = null,
    ) {
    }

    public static function fromArray(array $data): self
    {
        return new self(
            id: $data['id'],
            userId: $data['user_id'],
            activityType: $data['activity_type'],
            riskLevel: $data['risk_level'],
            ipAddress: $data['ip_address'] ?? null,
            userAgent: $data['user_agent'] ?? null,
            location: $data['location'] ?? null,
            detectedAt: $data['detected_at'],
            status: $data['status'],
            resolvedAt: $data['resolved_at'] ?? null,
            details: $data['details'] ?? null,
        );
    }

    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'user_id' => $this->userId,
            'activity_type' => $this->activityType,
            'risk_level' => $this->riskLevel,
            'ip_address' => $this->ipAddress,
            'user_agent' => $this->userAgent,
            'location' => $this->location,
            'detected_at' => $this->detectedAt,
            'status' => $this->status,
            'resolved_at' => $this->resolvedAt,
            'details' => $this->details,
        ];
    }
}
