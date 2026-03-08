<?php

declare(strict_types=1);

namespace BetterAuth\Core\Interfaces;

use BetterAuth\Core\Entities\Member;

/**
 * Interface for member repository implementations.
 * Defines methods for managing organization members.
 */
interface MemberRepositoryInterface
{
    /**
     * Find a member by ID.
     */
    public function findById(string $id): ?Member;

    /**
     * Find a member by user ID and organization ID.
     */
    public function findByUserAndOrganization(string $userId, string $organizationId): ?Member;

    /**
     * Get all members of an organization.
     *
     * @return array<Member>
     */
    public function findByOrganization(string $organizationId): array;

    /**
     * Get all organizations a user is a member of.
     *
     * @return array<Member>
     */
    public function findByUser(string $userId): array;

    /**
     * Create a new member.
     *
     * @param array<string, mixed> $data
     */
    public function create(array $data): Member;

    /**
     * Update a member's role.
     */
    public function updateRole(string $id, string $role): Member;

    /**
     * Delete a member.
     */
    public function delete(string $id): bool;

    /**
     * Delete all members of an organization.
     *
     * @return int Number of deleted members
     */
    public function deleteByOrganization(string $organizationId): int;
}
