<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Events;

use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

/**
 * Event fired when a refresh token is used to generate new tokens.
 */
final class TokenRefreshed
{
    use Dispatchable, InteractsWithSockets, SerializesModels;

    /**
     * @param  string  $userId  The user ID
     * @param  array<string, mixed>  $tokens  The new tokens
     */
    public function __construct(
        public readonly string $userId,
        public readonly array $tokens,
    ) {}
}
