<?php

declare(strict_types=1);

namespace BetterAuth\Core\Interfaces;

use BetterAuth\Core\Entities\User;

/**
 * Repository interface for user persistence operations.
 */
interface UserRepositoryInterface
{
    /**
     * Find a user by their unique identifier.
     *
     * @param string $id The user ID
     *
     * @return User|null The user entity or null if not found
     */
    public function findById(string $id): ?User;

    /**
     * Find a user by their email address.
     *
     * @param string $email The user email
     *
     * @return User|null The user entity or null if not found
     */
    public function findByEmail(string $email): ?User;

    /**
     * Find a user by provider and provider user ID.
     *
     * @param string $provider The OAuth provider name (e.g., 'google', 'github')
     * @param string $providerId The provider's user ID
     *
     * @return User|null The user entity or null if not found
     */
    public function findByProvider(string $provider, string $providerId): ?User;

    /**
     * Create a new user.
     *
     * @param array<string, mixed> $data User data
     *
     * @return User The created user entity
     */
    public function create(array $data): User;

    /**
     * Update an existing user.
     *
     * @param string $id The user ID
     * @param array<string, mixed> $data Data to update
     *
     * @return User The updated user entity
     */
    public function update(string $id, array $data): User;

    /**
     * Delete a user by ID.
     *
     * @param string $id The user ID
     *
     * @return bool True if deleted, false otherwise
     */
    public function delete(string $id): bool;

    /**
     * Verify a user's email.
     *
     * @param string $id The user ID
     *
     * @return bool True if verified, false otherwise
     */
    public function verifyEmail(string $id): bool;

    /**
     * Generate a new ID for user creation.
     *
     * Returns null if the storage system uses auto-increment IDs (e.g., INT primary key with auto-increment).
     * Returns a string UUID/ULID if the storage system requires pre-generated IDs (e.g., UUID string primary key).
     *
     * @return string|null The generated ID (UUID/ULID) or null for auto-increment
     */
    public function generateId(): ?string;
}
