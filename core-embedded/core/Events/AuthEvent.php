<?php

declare(strict_types=1);

namespace BetterAuth\Core\Events;

use BetterAuth\Core\Entities\User;

/**
 * Base authentication event.
 */
abstract class AuthEvent
{
    public function __construct(
        public readonly User $user,
        public readonly array $metadata = [],
    ) {
    }
}
