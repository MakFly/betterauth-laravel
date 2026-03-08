<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Events;

use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

/**
 * Event fired when a user logs out.
 */
final class UserLoggedOut
{
    use Dispatchable, InteractsWithSockets, SerializesModels;

    public function __construct(
        public readonly string|int|null $userId,
    ) {}
}
