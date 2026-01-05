<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Repositories;

use BetterAuth\Core\Entities\User;
use BetterAuth\Core\Interfaces\UserRepositoryInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;

/**
 * Eloquent implementation of UserRepositoryInterface.
 *
 * Adapts Laravel's Eloquent ORM to the BetterAuth Core interface.
 */
final class EloquentUserRepository implements UserRepositoryInterface
{
    /** @var class-string<Model> */
    private string $modelClass;

    /**
     * @param  class-string<Model>  $modelClass
     */
    public function __construct(string $modelClass)
    {
        $this->modelClass = $modelClass;
    }

    public function findById(string $id): ?User
    {
        $model = $this->query()->find($id);

        return $model ? $this->toEntity($model) : null;
    }

    public function findByEmail(string $email): ?User
    {
        $model = $this->query()->where('email', $email)->first();

        return $model ? $this->toEntity($model) : null;
    }

    public function findByProvider(string $provider, string $providerId): ?User
    {
        // This requires a join with account_links table
        // For now, we'll use a simple approach assuming the model has the relationship
        $model = $this->query()
            ->whereHas('accountLinks', function ($query) use ($provider, $providerId) {
                $query->where('provider', $provider)
                    ->where('provider_user_id', $providerId);
            })
            ->first();

        return $model ? $this->toEntity($model) : null;
    }

    public function create(array $data): User
    {
        $model = new $this->modelClass();

        // Generate ID if using UUID strategy
        if (! isset($data['id']) && $this->usesUuid()) {
            $data['id'] = (string) Str::uuid7();
        }

        $model->fill($this->mapDataToModel($data));
        $model->save();

        return $this->toEntity($model);
    }

    public function update(string $id, array $data): User
    {
        $model = $this->query()->findOrFail($id);
        $model->update($this->mapDataToModel($data));
        $model->refresh();

        return $this->toEntity($model);
    }

    public function delete(string $id): bool
    {
        return (bool) $this->query()->where('id', $id)->delete();
    }

    public function verifyEmail(string $id): bool
    {
        return (bool) $this->query()->where('id', $id)->update([
            'email_verified_at' => now(),
        ]);
    }

    public function generateId(): ?string
    {
        if ($this->usesUuid()) {
            return (string) Str::uuid7();
        }

        return null; // Auto-increment
    }

    /**
     * Convert Eloquent model to Core User entity.
     */
    private function toEntity(Model $model): User
    {
        // Create anonymous User implementation since the Core User is abstract
        return new class($model) extends User {
            private Model $model;

            public function __construct(Model $model)
            {
                parent::__construct();
                $this->model = $model;

                // Map Eloquent attributes to entity properties
                $this->email = $model->email;
                $this->password = $model->password ?? null;
                $this->roles = $model->roles ?? ['ROLE_USER'];
                $this->username = $model->name ?? $model->username ?? null;
                $this->avatar = $model->avatar ?? null;
                $this->emailVerified = $model->email_verified_at !== null;
                $this->emailVerifiedAt = $model->email_verified_at
                    ? new \DateTimeImmutable($model->email_verified_at->toDateTimeString())
                    : null;
                $this->createdAt = new \DateTimeImmutable($model->created_at->toDateTimeString());
                $this->updatedAt = new \DateTimeImmutable($model->updated_at->toDateTimeString());
                $this->metadata = $model->metadata ?? null;
            }

            public function getId(): string|int|null
            {
                return $this->model->id;
            }

            public function setId(string|int $id): static
            {
                $this->model->id = $id;

                return $this;
            }

            public function getModel(): Model
            {
                return $this->model;
            }
        };
    }

    /**
     * Map data array to Eloquent model attributes.
     *
     * @param  array<string, mixed>  $data
     * @return array<string, mixed>
     */
    private function mapDataToModel(array $data): array
    {
        $mapped = [];

        $mapping = [
            'id' => 'id',
            'email' => 'email',
            'password' => 'password',
            'name' => 'name',
            'username' => 'name', // Fallback
            'avatar' => 'avatar',
            'roles' => 'roles',
            'email_verified_at' => 'email_verified_at',
            'metadata' => 'metadata',
        ];

        foreach ($data as $key => $value) {
            $modelKey = $mapping[$key] ?? $key;
            $mapped[$modelKey] = $value;
        }

        return $mapped;
    }

    /**
     * Check if the model uses UUID strategy.
     */
    private function usesUuid(): bool
    {
        $strategy = config('betterauth.id_strategy', 'uuid');

        return in_array($strategy, ['uuid', 'ulid'], true);
    }

    /**
     * Get the query builder instance.
     *
     * @return \Illuminate\Database\Eloquent\Builder<Model>
     */
    private function query(): \Illuminate\Database\Eloquent\Builder
    {
        return $this->modelClass::query();
    }
}
