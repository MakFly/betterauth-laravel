<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Repositories;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/**
 * Eloquent implementation for session storage.
 *
 * Handles user sessions with device tracking and activity logging.
 */
final class EloquentSessionRepository
{
    public function __construct(
        private readonly string $table = 'better_auth_sessions',
    ) {}

    /**
     * Find a session by ID.
     *
     * @return object|null
     */
    public function findById(string $id): ?object
    {
        return DB::table($this->table)
            ->where('id', $id)
            ->where('expires_at', '>', now())
            ->first();
    }

    /**
     * Find all active sessions for a user.
     *
     * @return array<object>
     */
    public function findByUserId(string $userId): array
    {
        return DB::table($this->table)
            ->where('user_id', $userId)
            ->where('expires_at', '>', now())
            ->orderBy('last_activity_at', 'desc')
            ->get()
            ->all();
    }

    /**
     * Create a new session.
     *
     * @param  array<string, mixed>  $data
     */
    public function create(array $data): object
    {
        $id = $data['id'] ?? (string) Str::uuid7();

        $record = [
            'id' => $id,
            'user_id' => $data['user_id'],
            'ip_address' => $data['ip_address'] ?? null,
            'user_agent' => $data['user_agent'] ?? null,
            'device_type' => $data['device_type'] ?? null,
            'device_name' => $data['device_name'] ?? null,
            'location' => $data['location'] ?? null,
            'expires_at' => $data['expires_at'] ?? now()->addDays(30),
            'last_activity_at' => now(),
            'created_at' => now(),
        ];

        DB::table($this->table)->insert($record);

        return (object) $record;
    }

    /**
     * Update session last activity.
     */
    public function touch(string $id): bool
    {
        return DB::table($this->table)
            ->where('id', $id)
            ->update(['last_activity_at' => now()]) > 0;
    }

    /**
     * Revoke a session.
     */
    public function revoke(string $id): bool
    {
        return DB::table($this->table)
            ->where('id', $id)
            ->delete() > 0;
    }

    /**
     * Revoke all sessions for a user.
     */
    public function revokeAllForUser(string $userId, ?string $exceptId = null): int
    {
        $query = DB::table($this->table)->where('user_id', $userId);

        if ($exceptId !== null) {
            $query->where('id', '!=', $exceptId);
        }

        return $query->delete();
    }

    /**
     * Delete expired sessions.
     */
    public function deleteExpired(): int
    {
        return DB::table($this->table)
            ->where('expires_at', '<', now())
            ->delete();
    }

    /**
     * Count active sessions for a user.
     */
    public function countActiveForUser(string $userId): int
    {
        return DB::table($this->table)
            ->where('user_id', $userId)
            ->where('expires_at', '>', now())
            ->count();
    }
}
