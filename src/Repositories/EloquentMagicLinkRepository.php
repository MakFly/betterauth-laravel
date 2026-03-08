<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Repositories;

use BetterAuth\Core\Entities\MagicLinkToken;
use BetterAuth\Core\Interfaces\MagicLinkStorageInterface;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/**
 * Eloquent implementation of MagicLinkStorageInterface.
 */
final class EloquentMagicLinkRepository implements MagicLinkStorageInterface
{
    public function __construct(
        private readonly string $table = 'better_auth_magic_links',
    ) {}

    public function store(string $token, string $email, int $expiresIn): MagicLinkToken
    {
        $hashedToken = hash('sha256', $token);
        $now = now();
        $expiresAt = $now->copy()->addSeconds($expiresIn);

        DB::table($this->table)->insert([
            'id' => (string) Str::uuid7(),
            'token' => $hashedToken,
            'email' => $email,
            'expires_at' => $expiresAt,
            'used_at' => null,
            'created_at' => $now,
        ]);

        return MagicLinkToken::fromArray([
            'token' => $hashedToken,
            'email' => $email,
            'expires_at' => $expiresAt->toDateTimeString(),
            'created_at' => $now->toDateTimeString(),
            'used' => false,
        ]);
    }

    public function findByToken(string $token): ?MagicLinkToken
    {
        $hashedToken = hash('sha256', $token);

        $record = DB::table($this->table)
            ->where('token', $hashedToken)
            ->where('expires_at', '>', now())
            ->whereNull('used_at')
            ->first();

        if ($record === null) {
            return null;
        }

        return MagicLinkToken::fromArray([
            'token' => $record->token,
            'email' => $record->email,
            'expires_at' => $record->expires_at,
            'created_at' => $record->created_at,
            'used' => $record->used_at !== null,
        ]);
    }

    public function markAsUsed(string $token): bool
    {
        $hashedToken = hash('sha256', $token);

        return DB::table($this->table)
            ->where('token', $hashedToken)
            ->whereNull('used_at')
            ->update(['used_at' => now()]) > 0;
    }

    public function delete(string $token): bool
    {
        $hashedToken = hash('sha256', $token);

        return DB::table($this->table)
            ->where('token', $hashedToken)
            ->delete() > 0;
    }

    public function deleteExpired(): int
    {
        return DB::table($this->table)
            ->where('expires_at', '<', now())
            ->delete();
    }
}
