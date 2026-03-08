<?php

declare(strict_types=1);

namespace BetterAuth\Core\Interfaces;

use BetterAuth\Core\Entities\Team;

/**
 * Interface for team repository implementations.
 * Defines methods for managing teams within organizations.
 */
interface TeamRepositoryInterface
{
    /**
     * Find a team by ID.
     */
    public function findById(string $id): ?Team;

    /**
     * Find a team by slug within an organization.
     */
    public function findBySlug(string $slug, string $organizationId): ?Team;

    /**
     * Get all teams for an organization.
     *
     * @return array<Team>
     */
    public function findByOrganization(string $organizationId): array;

    /**
     * Create a new team.
     *
     * @param array<string, mixed> $data
     */
    public function create(array $data): Team;

    /**
     * Update a team.
     *
     * @param array<string, mixed> $data
     */
    public function update(string $id, array $data): Team;

    /**
     * Delete a team.
     */
    public function delete(string $id): bool;

    /**
     * Delete all teams for an organization.
     *
     * @return int Number of deleted teams
     */
    public function deleteByOrganization(string $organizationId): int;
}
