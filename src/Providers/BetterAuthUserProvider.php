<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Providers;

use BetterAuth\Core\PasswordHasher;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Database\Eloquent\Model;

/**
 * BetterAuth User Provider for Laravel's authentication system.
 *
 * Uses Argon2id password hashing from BetterAuth Core instead of
 * Laravel's default bcrypt.
 */
final class BetterAuthUserProvider implements UserProvider
{
    /** @var class-string<Model&Authenticatable> */
    private string $model;

    /**
     * @param  class-string<Model&Authenticatable>  $model
     */
    public function __construct(
        string $model,
        private readonly PasswordHasher $hasher,
    ) {
        $this->model = $model;
    }

    /**
     * Retrieve a user by their unique identifier.
     */
    public function retrieveById(mixed $identifier): ?Authenticatable
    {
        $model = $this->createModel();

        return $model->newQuery()
            ->where($model->getAuthIdentifierName(), $identifier)
            ->first();
    }

    /**
     * Retrieve a user by their unique identifier and "remember me" token.
     */
    public function retrieveByToken($identifier, $token): ?Authenticatable
    {
        $model = $this->createModel();

        $retrievedModel = $model->newQuery()
            ->where($model->getAuthIdentifierName(), $identifier)
            ->first();

        if (! $retrievedModel) {
            return null;
        }

        $rememberToken = $retrievedModel->getRememberToken();

        return $rememberToken && hash_equals($rememberToken, $token)
            ? $retrievedModel
            : null;
    }

    /**
     * Update the "remember me" token for the given user in storage.
     */
    public function updateRememberToken(Authenticatable $user, $token): void
    {
        /** @var Model&Authenticatable $user */
        $user->setRememberToken($token);
        $user->save();
    }

    /**
     * Retrieve a user by the given credentials.
     *
     * @param  array<string, mixed>  $credentials
     */
    public function retrieveByCredentials(array $credentials): ?Authenticatable
    {
        $query = $this->createModel()->newQuery();

        foreach ($credentials as $key => $value) {
            if ($key === 'password') {
                continue;
            }

            if (is_array($value)) {
                $query->whereIn($key, $value);
            } else {
                $query->where($key, $value);
            }
        }

        return $query->first();
    }

    /**
     * Validate a user against the given credentials.
     *
     * @param  array<string, mixed>  $credentials
     */
    public function validateCredentials(Authenticatable $user, array $credentials): bool
    {
        $password = $credentials['password'] ?? null;

        if ($password === null) {
            return false;
        }

        $hashedPassword = $user->getAuthPassword();

        if ($hashedPassword === null || $hashedPassword === '') {
            return false;
        }

        return $this->hasher->verify($password, $hashedPassword);
    }

    /**
     * Rehash the user's password if required and supported.
     *
     * @param  array<string, mixed>  $credentials
     */
    public function rehashPasswordIfRequired(Authenticatable $user, array $credentials, bool $force = false): void
    {
        $password = $credentials['password'] ?? null;

        if ($password === null) {
            return;
        }

        $hashedPassword = $user->getAuthPassword();

        if ($hashedPassword === null || $hashedPassword === '') {
            return;
        }

        if (! $force && ! $this->hasher->needsRehash($hashedPassword)) {
            return;
        }

        /** @var Model&Authenticatable $user */
        $user->forceFill([
            'password' => $this->hasher->hash($password),
        ])->save();
    }

    /**
     * Create a new instance of the model.
     *
     * @return Model&Authenticatable
     */
    private function createModel(): Model
    {
        $class = $this->model;

        return new $class();
    }

    /**
     * Get the model class name.
     *
     * @return class-string<Model&Authenticatable>
     */
    public function getModel(): string
    {
        return $this->model;
    }
}
