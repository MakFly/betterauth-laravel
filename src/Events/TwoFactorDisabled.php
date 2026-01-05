<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

final class TwoFactorDisabled
{
    use Dispatchable, SerializesModels;

    public function __construct(
        public readonly Authenticatable $user,
    ) {}
}
