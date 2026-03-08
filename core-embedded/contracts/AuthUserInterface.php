<?php

declare(strict_types=1);

namespace BetterAuth\Contracts;

/**
 * Framework-agnostic interface for an authenticated user.
 *
 * Replaces Symfony\Component\Security\Core\User\UserInterface in the core library,
 * allowing betterauth-core to remain framework-independent.
 */
interface AuthUserInterface
{
    /**
     * Returns the identifier used to authenticate this user (e.g. email, username).
     */
    public function getUserIdentifier(): string;

    /**
     * Returns the roles granted to this user.
     *
     * @return string[]
     */
    public function getRoles(): array;

    /**
     * Erases sensitive data stored on the user (e.g. plain-text passwords).
     *
     * Called after serialization or at the end of a request.
     */
    public function eraseCredentials(): void;
}
