<?php

declare(strict_types=1);

namespace BetterAuth\Contracts;

/**
 * Interface for users that store a hashed password.
 *
 * Replaces Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface
 * in the core library.
 */
interface PasswordHolderInterface
{
    /**
     * Returns the hashed password for this user.
     *
     * Returns null for passwordless users (e.g. magic link, OAuth-only users).
     */
    public function getPassword(): ?string;
}
