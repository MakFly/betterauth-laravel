<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Repositories;

use BetterAuth\Core\Interfaces\TotpStorageInterface;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/**
 * Eloquent implementation of TotpStorageInterface.
 */
final class EloquentTwoFactorRepository implements TotpStorageInterface
{
    public function __construct(
        private readonly string $table = 'better_auth_totp_secrets',
    ) {
    }

    public function store(string $userId, string $secret, array $metadata = []): bool
    {
        return DB::table($this->table)->updateOrInsert(
            ['user_id' => $userId],
            [
                'id' => (string) Str::uuid7(),
                'secret' => encrypt($secret),
                'enabled' => false,
                'recovery_codes' => isset($metadata['recovery_codes'])
                    ? json_encode($metadata['recovery_codes'])
                    : null,
                'verified_at' => null,
                'created_at' => now(),
                'updated_at' => now(),
            ],
        );
    }

    public function findByUserId(string $userId): ?array
    {
        $record = DB::table($this->table)
            ->where('user_id', $userId)
            ->first();

        if ($record === null) {
            return null;
        }

        return [
            'user_id' => $record->user_id,
            'secret' => decrypt($record->secret),
            'enabled' => (bool) $record->enabled,
            'recovery_codes' => json_decode($record->recovery_codes ?? '[]', true),
            'verified_at' => $record->verified_at,
            'created_at' => $record->created_at,
        ];
    }

    public function isEnabled(string $userId): bool
    {
        return DB::table($this->table)
            ->where('user_id', $userId)
            ->where('enabled', true)
            ->exists();
    }

    public function enable(string $userId): bool
    {
        return DB::table($this->table)
            ->where('user_id', $userId)
            ->update([
                'enabled' => true,
                'verified_at' => now(),
                'updated_at' => now(),
            ]) > 0;
    }

    public function disable(string $userId): bool
    {
        return DB::table($this->table)
            ->where('user_id', $userId)
            ->update([
                'enabled' => false,
                'updated_at' => now(),
            ]) > 0;
    }

    public function delete(string $userId): bool
    {
        return DB::table($this->table)
            ->where('user_id', $userId)
            ->delete() > 0;
    }

    public function useBackupCode(string $userId, string $code): bool
    {
        $record = DB::table($this->table)
            ->where('user_id', $userId)
            ->where('enabled', true)
            ->first();

        if ($record === null) {
            return false;
        }

        $recoveryCodes = json_decode($record->recovery_codes ?? '[]', true);

        foreach ($recoveryCodes as $index => $hashedCode) {
            if (hash_equals($hashedCode, hash('sha256', $code))) {
                unset($recoveryCodes[$index]);

                DB::table($this->table)
                    ->where('user_id', $userId)
                    ->update([
                        'recovery_codes' => json_encode(array_values($recoveryCodes)),
                        'updated_at' => now(),
                    ]);

                return true;
            }
        }

        return false;
    }

    public function updateLast2faVerifiedAt(string $userId): bool
    {
        return DB::table($this->table)
            ->where('user_id', $userId)
            ->update([
                'verified_at' => now(),
                'updated_at' => now(),
            ]) > 0;
    }
}
