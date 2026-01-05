<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Models\Traits;

use BetterAuth\Laravel\Facades\BetterAuth;
use Illuminate\Database\Eloquent\Casts\Attribute;
use Illuminate\Support\Str;

/**
 * Trait for User models using BetterAuth.
 *
 * Adds authentication helpers and proper casts.
 */
trait HasBetterAuth
{
    /**
     * Boot the trait.
     */
    public static function bootHasBetterAuth(): void
    {
        static::creating(function ($model): void {
            // Generate UUID if using UUID strategy and no ID set
            if (empty($model->{$model->getKeyName()}) && static::usesBetterAuthUuid()) {
                $model->{$model->getKeyName()} = (string) Str::uuid7();
            }
        });
    }

    /**
     * Initialize the trait.
     */
    public function initializeHasBetterAuth(): void
    {
        // Add default casts
        $this->mergeCasts([
            'roles' => 'array',
            'metadata' => 'array',
            'email_verified_at' => 'datetime',
        ]);

        // Add default hidden attributes
        $this->makeHidden(['password', 'remember_token']);
    }

    /**
     * Check if the model uses UUID primary keys.
     */
    public static function usesBetterAuthUuid(): bool
    {
        $strategy = config('betterauth.id_strategy', 'uuid');

        return in_array($strategy, ['uuid', 'ulid'], true);
    }

    /**
     * Get the user's roles.
     *
     * @return array<string>
     */
    public function getRoles(): array
    {
        $roles = $this->roles ?? ['ROLE_USER'];

        // Ensure ROLE_USER is always present
        if (! in_array('ROLE_USER', $roles, true)) {
            $roles[] = 'ROLE_USER';
        }

        return array_unique($roles);
    }

    /**
     * Check if user has a specific role.
     */
    public function hasRole(string $role): bool
    {
        return in_array($role, $this->getRoles(), true);
    }

    /**
     * Add a role to the user.
     */
    public function addRole(string $role): static
    {
        $roles = $this->getRoles();

        if (! in_array($role, $roles, true)) {
            $roles[] = $role;
            $this->roles = $roles;
        }

        return $this;
    }

    /**
     * Remove a role from the user.
     */
    public function removeRole(string $role): static
    {
        if ($role === 'ROLE_USER') {
            return $this; // Cannot remove base role
        }

        $this->roles = array_values(array_filter(
            $this->getRoles(),
            fn ($r) => $r !== $role,
        ));

        return $this;
    }

    /**
     * Check if user's email is verified.
     */
    public function isEmailVerified(): bool
    {
        return $this->email_verified_at !== null;
    }

    /**
     * Mark email as verified.
     */
    public function markEmailAsVerified(): bool
    {
        return $this->forceFill([
            'email_verified_at' => now(),
        ])->save();
    }

    /**
     * Check if user has a password set.
     */
    public function hasPassword(): bool
    {
        return $this->password !== null && $this->password !== '';
    }

    /**
     * Get metadata value.
     */
    public function getMeta(string $key, mixed $default = null): mixed
    {
        return data_get($this->metadata, $key, $default);
    }

    /**
     * Set metadata value.
     */
    public function setMeta(string $key, mixed $value): static
    {
        $metadata = $this->metadata ?? [];
        data_set($metadata, $key, $value);
        $this->metadata = $metadata;

        return $this;
    }

    /**
     * Create tokens for this user.
     *
     * @return array{access_token: string, refresh_token: string, token_type: string, expires_in: int}
     */
    public function createTokens(): array
    {
        return BetterAuth::getTokenAuthManager()->createTokensForUser([
            'id' => $this->getKey(),
            'email' => $this->email,
        ]);
    }

    /**
     * Revoke all tokens for this user.
     */
    public function revokeAllTokens(): void
    {
        BetterAuth::revokeAll((string) $this->getKey());
    }

    /**
     * Get the key type for route model binding.
     */
    public function getKeyType(): string
    {
        return static::usesBetterAuthUuid() ? 'string' : 'int';
    }

    /**
     * Get the auto-incrementing status.
     */
    public function getIncrementing(): bool
    {
        return ! static::usesBetterAuthUuid();
    }

    /**
     * Avatar URL accessor with Gravatar fallback.
     */
    protected function avatarUrl(): Attribute
    {
        return Attribute::make(
            get: function (): string {
                if ($this->avatar) {
                    return $this->avatar;
                }

                // Gravatar fallback
                $hash = md5(strtolower(trim($this->email)));

                return "https://www.gravatar.com/avatar/{$hash}?d=mp&s=200";
            },
        );
    }
}
