<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Repositories;

use BetterAuth\Core\Entities\RefreshToken;
use BetterAuth\Core\Interfaces\RefreshTokenRepositoryInterface;
use DateTimeImmutable;
use Illuminate\Support\Facades\DB;

/**
 * Eloquent implementation of RefreshTokenRepositoryInterface.
 *
 * Uses Query Builder directly for the refresh_tokens table since
 * this is a simple key-value storage without complex relationships.
 */
final class EloquentRefreshTokenRepository implements RefreshTokenRepositoryInterface
{
    public function __construct(
        private readonly string $table = 'better_auth_refresh_tokens',
    ) {}

    public function findByToken(string $token): ?RefreshToken
    {
        // Hash the token for lookup (tokens are stored hashed)
        $hashedToken = hash('sha256', $token);

        $record = DB::table($this->table)
            ->where('token', $hashedToken)
            ->where('revoked', false)
            ->where('expires_at', '>', now())
            ->first();

        return $record ? $this->toEntity($record) : null;
    }

    /**
     * @return RefreshToken[]
     */
    public function findByUserId(string $userId): array
    {
        $records = DB::table($this->table)
            ->where('user_id', $userId)
            ->where('revoked', false)
            ->where('expires_at', '>', now())
            ->get();

        return $records->map(fn ($record) => $this->toEntity($record))->all();
    }

    public function create(array $data): RefreshToken
    {
        $record = [
            'token' => $data['token'],
            'user_id' => $data['user_id'],
            'expires_at' => $data['expires_at'],
            'created_at' => $data['created_at'] ?? now(),
            'revoked' => false,
            'replaced_by' => null,
        ];

        DB::table($this->table)->insert($record);

        return $this->toEntity((object) $record);
    }

    public function revoke(string $token, ?string $replacedBy = null): bool
    {
        $hashedToken = hash('sha256', $token);

        $updated = DB::table($this->table)
            ->where('token', $hashedToken)
            ->update([
                'revoked' => true,
                'replaced_by' => $replacedBy,
            ]);

        return $updated > 0;
    }

    public function revokeAllForUser(string $userId): int
    {
        return DB::table($this->table)
            ->where('user_id', $userId)
            ->where('revoked', false)
            ->update(['revoked' => true]);
    }

    public function deleteExpired(): int
    {
        return DB::table($this->table)
            ->where('expires_at', '<', now())
            ->delete();
    }

    /**
     * Atomic consume operation for refresh token rotation.
     *
     * Marks the token as revoked and returns it only if it wasn't already revoked.
     * This prevents race conditions in token rotation.
     */
    public function consume(string $token): ?RefreshToken
    {
        $hashedToken = hash('sha256', $token);

        return DB::transaction(function () use ($hashedToken, $token) {
            $record = DB::table($this->table)
                ->where('token', $hashedToken)
                ->where('revoked', false)
                ->where('expires_at', '>', now())
                ->lockForUpdate()
                ->first();

            if (! $record) {
                return null;
            }

            DB::table($this->table)
                ->where('token', $hashedToken)
                ->update(['revoked' => true]);

            return $this->toEntity($record);
        });
    }

    /**
     * Convert database record to RefreshToken entity.
     */
    private function toEntity(object $record): RefreshToken
    {
        return new class($record) extends RefreshToken {
            private object $record;

            public function __construct(object $record)
            {
                parent::__construct();
                $this->record = $record;

                $this->token = $record->token;
                $this->expiresAt = $record->expires_at instanceof DateTimeImmutable
                    ? $record->expires_at
                    : new DateTimeImmutable($record->expires_at);
                $this->createdAt = $record->created_at instanceof DateTimeImmutable
                    ? $record->created_at
                    : new DateTimeImmutable($record->created_at);
                $this->revoked = (bool) $record->revoked;
                $this->replacedBy = $record->replaced_by ?? null;
            }

            public function getUserId(): string|int
            {
                return $this->record->user_id;
            }

            public function setUserId(string|int $userId): static
            {
                $this->record->user_id = $userId;

                return $this;
            }
        };
    }
}
