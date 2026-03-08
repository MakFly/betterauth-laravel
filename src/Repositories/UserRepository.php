<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Repositories;

use BetterAuth\Core\Interfaces\UserRepositoryInterface;

/**
 * Laravel-specific user repository contract.
 *
 * Extends the core interface with Laravel-specific methods.
 */
interface UserRepository extends UserRepositoryInterface
{
    /**
     * Verify a user's email address.
     */
    public function verifyEmail(string $id): bool;
}
