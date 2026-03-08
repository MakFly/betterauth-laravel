<?php

declare(strict_types=1);

namespace BetterAuth\Core\Interfaces;

use BetterAuth\Core\Entities\TeamMember;

/**
 * Interface for team member repository implementations.
 * Defines methods for managing team membership.
 */
interface TeamMemberRepositoryInterface
{
    /**
     * Find a team member by ID.
     */
    public function findById(string $id): ?TeamMember;

    /**
     * Find a team member by member ID and team ID.
     */
    public function findByMemberAndTeam(string $memberId, string $teamId): ?TeamMember;

    /**
     * Get all team members of a team.
     *
     * @return array<TeamMember>
     */
    public function findByTeam(string $teamId): array;

    /**
     * Get all teams a member belongs to.
     *
     * @return array<TeamMember>
     */
    public function findByMember(string $memberId): array;

    /**
     * Create a new team member.
     *
     * @param array<string, mixed> $data
     */
    public function create(array $data): TeamMember;

    /**
     * Update team member role.
     */
    public function updateRole(string $id, ?string $role): TeamMember;

    /**
     * Delete a team member.
     */
    public function delete(string $id): bool;

    /**
     * Delete all team members of a team.
     *
     * @return int Number of deleted team members
     */
    public function deleteByTeam(string $teamId): int;

    /**
     * Delete all team memberships for a member.
     *
     * @return int Number of deleted team members
     */
    public function deleteByMember(string $memberId): int;
}
