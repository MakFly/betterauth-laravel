<?php

declare(strict_types=1);

namespace BetterAuth\Core\Entities;

use DateTimeImmutable;

/**
 * TeamMember entity representing member-team relationship.
 * Links organization members to specific teams within the organization.
 */
class TeamMember
{
    public function __construct(
        public readonly string $id,
        public readonly string $teamId,
        public readonly string $memberId,
        public readonly ?string $role = null,
        public readonly ?DateTimeImmutable $createdAt = null,
    ) {
    }

    /**
     * Create a TeamMember entity from an array of data.
     *
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            id: $data['id'] ?? '',
            teamId: $data['teamId'] ?? $data['team_id'] ?? '',
            memberId: $data['memberId'] ?? $data['member_id'] ?? '',
            role: $data['role'] ?? null,
            createdAt: isset($data['createdAt'])
                ? ($data['createdAt'] instanceof DateTimeImmutable
                    ? $data['createdAt']
                    : new DateTimeImmutable($data['createdAt']))
                : (isset($data['created_at'])
                    ? ($data['created_at'] instanceof DateTimeImmutable
                        ? $data['created_at']
                        : new DateTimeImmutable($data['created_at']))
                    : null),
        );
    }

    /**
     * Convert the entity to an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'teamId' => $this->teamId,
            'memberId' => $this->memberId,
            'role' => $this->role,
            'createdAt' => $this->createdAt?->format('Y-m-d H:i:s'),
        ];
    }
}
