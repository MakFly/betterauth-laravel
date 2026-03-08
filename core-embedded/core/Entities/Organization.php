<?php

declare(strict_types=1);

namespace BetterAuth\Core\Entities;

use DateTimeImmutable;

/**
 * Organization entity for multi-tenant support.
 * Represents a tenant/organization that can have multiple members.
 */
class Organization
{
    public function __construct(
        public readonly string $id,
        public readonly string $name,
        public readonly string $slug,
        public readonly ?string $logo = null,
        public readonly ?array $metadata = null,
        public readonly ?DateTimeImmutable $createdAt = null,
    ) {
    }

    /**
     * Create an Organization entity from an array of data.
     *
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            id: $data['id'] ?? '',
            name: $data['name'] ?? '',
            slug: $data['slug'] ?? '',
            logo: $data['logo'] ?? null,
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
            'name' => $this->name,
            'slug' => $this->slug,
            'logo' => $this->logo,
            'metadata' => $this->metadata,
            'createdAt' => $this->createdAt?->format('Y-m-d H:i:s'),
        ];
    }

    /**
     * Check if slug is valid (lowercase alphanumeric with hyphens).
     */
    public function isValidSlug(): bool
    {
        return preg_match('/^[a-z0-9]+(?:-[a-z0-9]+)*$/', $this->slug) === 1;
    }
}
