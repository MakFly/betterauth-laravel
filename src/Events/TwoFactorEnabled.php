<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

final class TwoFactorEnabled
{
    use Dispatchable, SerializesModels;

    /**
     * @param  array<int, string>  $recoveryCodes
     */
    public function __construct(
        public readonly Authenticatable $user,
        public readonly array $recoveryCodes,
    ) {}
}
