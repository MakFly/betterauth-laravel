<?php

declare(strict_types=1);

namespace BetterAuth\Core\Interfaces;

use BetterAuth\Core\Entities\Organization;

/**
 * Interface for organization repository implementations.
 * Defines methods for managing organizations in the system.
 */
interface OrganizationRepositoryInterface
{
    /**
     * Find an organization by ID.
     */
    public function findById(string $id): ?Organization;

    /**
     * Find an organization by slug.
     */
    public function findBySlug(string $slug): ?Organization;

    /**
     * Get all organizations for a specific user.
     *
     * @return array<Organization>
     */
    public function findByUserId(string $userId): array;

    /**
     * Create a new organization.
     *
     * @param array<string, mixed> $data
     */
    public function create(array $data): Organization;

    /**
     * Update an existing organization.
     *
     * @param array<string, mixed> $data
     */
    public function update(string $id, array $data): Organization;

    /**
     * Delete an organization.
     */
    public function delete(string $id): bool;

    /**
     * Check if a slug is available.
     *
     * @param string|null $excludeId Organization ID to exclude from check
     */
    public function isSlugAvailable(string $slug, ?string $excludeId = null): bool;
}
