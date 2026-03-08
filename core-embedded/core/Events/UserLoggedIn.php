<?php

declare(strict_types=1);

namespace BetterAuth\Core\Events;

use BetterAuth\Core\Entities\Session;

/**
 * Event fired when a user logs in.
 */
class UserLoggedIn extends AuthEvent
{
    public function __construct(
        public readonly \BetterAuth\Core\Entities\User $user,
        public readonly Session $session,
        array $metadata = [],
    ) {
        parent::__construct($user, $metadata);
    }
}
