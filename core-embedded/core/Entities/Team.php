<?php

declare(strict_types=1);

namespace BetterAuth\Core\Entities;

use DateTimeImmutable;

/**
 * Team entity for organization sub-groups.
 * Enables team subdivision within organizations for granular permissions.
 */
class Team
{
    public function __construct(
        public readonly string $id,
        public readonly string $organizationId,
        public readonly string $name,
        public readonly ?string $slug = null,
        public readonly ?array $metadata = null,
        public readonly ?DateTimeImmutable $createdAt = null,
    ) {
    }

    /**
     * Create a Team entity from an array of data.
     *
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            id: $data['id'] ?? '',
            organizationId: $data['organizationId'] ?? $data['organization_id'] ?? '',
            name: $data['name'] ?? '',
            slug: $data['slug'] ?? null,
            metadata: $data['metadata'] ?? null,
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
            'organizationId' => $this->organizationId,
            'name' => $this->name,
            'slug' => $this->slug,
            'metadata' => $this->metadata,
            'createdAt' => $this->createdAt?->format('Y-m-d H:i:s'),
        ];
    }
}
