<?php

declare(strict_types=1);

namespace BetterAuth\Core\Entities;

use DateTimeImmutable;

/**
 * Member entity representing user-organization relationship.
 * Links users to organizations with role-based access control.
 */
class Member
{
    public function __construct(
        public readonly string $id,
        public readonly string $organizationId,
        public readonly string $userId,
        public readonly string $role,
        public readonly ?DateTimeImmutable $createdAt = null,
    ) {
    }

    /**
     * Create a Member entity from an array of data.
     *
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            id: $data['id'] ?? '',
            organizationId: $data['organizationId'] ?? $data['organization_id'] ?? '',
            userId: $data['userId'] ?? $data['user_id'] ?? '',
            role: $data['role'] ?? 'member',
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
            'userId' => $this->userId,
            'role' => $this->role,
            'createdAt' => $this->createdAt?->format('Y-m-d H:i:s'),
        ];
    }

    /**
     * Check if member has specific role.
     */
    public function hasRole(string $role): bool
    {
        // Support comma-separated multiple roles
        $roles = array_map('trim', explode(',', $this->role));

        return in_array($role, $roles, true);
    }

    /**
     * Check if member is owner.
     */
    public function isOwner(): bool
    {
        return $this->hasRole('owner');
    }

    /**
     * Check if member is admin.
     */
    public function isAdmin(): bool
    {
        return $this->hasRole('admin');
    }

    /**
     * Check if member has admin or owner privileges.
     */
    public function canManageOrganization(): bool
    {
        return $this->isOwner() || $this->isAdmin();
    }
}
