<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Events;

use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

/**
 * Event fired when a token is successfully authenticated.
 */
final class TokenAuthenticated
{
    use Dispatchable, InteractsWithSockets, SerializesModels;

    /**
     * @param  array<string, mixed>  $payload  The decoded token payload
     */
    public function __construct(
        public readonly Authenticatable $user,
        public readonly array $payload,
    ) {}
}
