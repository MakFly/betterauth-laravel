<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Repositories;

use BetterAuth\Core\Interfaces\RefreshTokenRepositoryInterface;

/**
 * Laravel-specific refresh token repository contract.
 *
 * Extends the core interface with Laravel-specific methods.
 */
interface RefreshTokenRepository extends RefreshTokenRepositoryInterface
{
    /**
     * Delete all expired tokens.
     */
    public function deleteExpired(): int;
}
