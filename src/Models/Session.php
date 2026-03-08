<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * Eloquent model for BetterAuth sessions.
 *
 * @property string $id
 * @property string $user_id
 * @property string|null $ip_address
 * @property string|null $user_agent
 * @property string|null $device_type
 * @property string|null $device_name
 * @property string|null $location
 * @property \Illuminate\Support\Carbon $expires_at
 * @property \Illuminate\Support\Carbon $last_activity_at
 * @property \Illuminate\Support\Carbon $created_at
 */
final class Session extends Model
{
    use HasUuids;

    public $timestamps = false;

    protected $table = 'better_auth_sessions';

    protected $fillable = [
        'user_id',
        'ip_address',
        'user_agent',
        'device_type',
        'device_name',
        'location',
        'expires_at',
        'last_activity_at',
    ];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'expires_at' => 'datetime',
            'last_activity_at' => 'datetime',
            'created_at' => 'datetime',
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
     * Scope to active (non-expired) sessions.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<Session>  $query
     * @return \Illuminate\Database\Eloquent\Builder<Session>
     */
    public function scopeActive($query)
    {
        return $query->where('expires_at', '>', now());
    }
}
