<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Events;

use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

/**
 * Event fired when a new user registers.
 */
final class UserRegistered
{
    use Dispatchable, InteractsWithSockets, SerializesModels;

    /**
     * @param  array<string, mixed>  $user  The registered user data
     * @param  array<string, mixed>  $tokens  The authentication tokens
     */
    public function __construct(
        public readonly array $user,
        public readonly array $tokens,
    ) {}
}
