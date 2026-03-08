<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * Eloquent model for BetterAuth refresh tokens.
 *
 * @property string $id
 * @property string $token
 * @property string $user_id
 * @property \Illuminate\Support\Carbon $expires_at
 * @property bool $revoked
 * @property string|null $replaced_by
 * @property \Illuminate\Support\Carbon $created_at
 */
final class RefreshToken extends Model
{
    use HasUuids;

    public $timestamps = false;

    protected $table = 'better_auth_refresh_tokens';

    protected $fillable = [
        'token',
        'user_id',
        'expires_at',
        'revoked',
        'replaced_by',
    ];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'expires_at' => 'datetime',
            'created_at' => 'datetime',
            'revoked' => 'boolean',
        ];
    }

    /**
     * @return BelongsTo<Model, $this>
     */
    public function user(): BelongsTo
    {
        $userModel = config('betterauth.user_model', 'App\\Models\\User');

        return $this->belongsTo($userModel);
    }

    /**
     * Scope to active (non-revoked, non-expired) tokens.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<RefreshToken>  $query
     * @return \Illuminate\Database\Eloquent\Builder<RefreshToken>
     */
    public function scopeActive($query)
    {
        return $query->where('revoked', false)
            ->where('expires_at', '>', now());
    }
}
