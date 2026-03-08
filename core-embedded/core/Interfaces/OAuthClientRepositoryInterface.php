<?php

declare(strict_types=1);

namespace BetterAuth\Core\Interfaces;

use BetterAuth\Core\Entities\OAuthClient;

/**
 * Repository interface for OAuth clients.
 */
interface OAuthClientRepositoryInterface
{
    /**
     * Find client by ID.
     */
    public function findById(string $clientId): ?OAuthClient;

    /**
     * Create a new OAuth client.
     */
    public function create(array $data): OAuthClient;

    /**
     * Update client.
     */
    public function update(string $clientId, array $data): OAuthClient;

    /**
     * Delete client.
     */
    public function delete(string $clientId): bool;

    /**
     * List all clients.
     */
    public function findAll(): array;
}
