<?php

declare(strict_types=1);

use BetterAuth\Core\Entities\User;
use BetterAuth\Laravel\Repositories\EloquentUserRepository;
use BetterAuth\Laravel\Tests\Fixtures\User as UserModel;

beforeEach(function (): void {
    $this->artisan('migrate', ['--database' => 'testing']);
    $this->repository = new EloquentUserRepository(UserModel::class);
});

describe('EloquentUserRepository - findById', function (): void {
    it('returns null when user not found', function (): void {
        expect($this->repository->findById('nonexistent-id'))->toBeNull();
    });

    it('returns User entity when found', function (): void {
        $model = UserModel::create([
            'id' => (string) \Illuminate\Support\Str::uuid7(),
            'email' => 'find@example.com',
            'password' => password_hash('password', PASSWORD_ARGON2ID),
            'roles' => ['ROLE_USER'],
        ]);

        $user = $this->repository->findById((string) $model->id);

        expect($user)->toBeInstanceOf(User::class);
        expect($user->getEmail())->toBe('find@example.com');
    });
});

describe('EloquentUserRepository - findByEmail', function (): void {
    it('returns null when email not found', function (): void {
        expect($this->repository->findByEmail('nobody@example.com'))->toBeNull();
    });

    it('returns User entity when email found', function (): void {
        UserModel::create([
            'id' => (string) \Illuminate\Support\Str::uuid7(),
            'email' => 'byemail@example.com',
            'password' => password_hash('password', PASSWORD_ARGON2ID),
            'roles' => ['ROLE_USER'],
        ]);

        $user = $this->repository->findByEmail('byemail@example.com');

        expect($user)->toBeInstanceOf(User::class);
        expect($user->getEmail())->toBe('byemail@example.com');
    });
});

describe('EloquentUserRepository - create', function (): void {
    it('creates and returns a User entity', function (): void {
        $user = $this->repository->create([
            'email' => 'created@example.com',
            'password' => password_hash('pass', PASSWORD_ARGON2ID),
        ]);

        expect($user)->toBeInstanceOf(User::class);
        expect($user->getEmail())->toBe('created@example.com');
        expect(UserModel::where('email', 'created@example.com')->exists())->toBeTrue();
    });

    it('generates uuid id automatically when using uuid strategy', function (): void {
        $user = $this->repository->create([
            'email' => 'uuid@example.com',
            'password' => password_hash('pass', PASSWORD_ARGON2ID),
        ]);

        expect($user->getId())->toBeString()->not->toBeEmpty();
    });
});

describe('EloquentUserRepository - update', function (): void {
    it('updates an existing user', function (): void {
        $model = UserModel::create([
            'id' => (string) \Illuminate\Support\Str::uuid7(),
            'email' => 'before@example.com',
            'password' => password_hash('pass', PASSWORD_ARGON2ID),
            'roles' => ['ROLE_USER'],
        ]);

        $user = $this->repository->update((string) $model->id, ['name' => 'Updated Name']);

        expect($user)->toBeInstanceOf(User::class);
        expect($user->getUsername())->toBe('Updated Name');
    });
});

describe('EloquentUserRepository - delete', function (): void {
    it('deletes an existing user and returns true', function (): void {
        $model = UserModel::create([
            'id' => (string) \Illuminate\Support\Str::uuid7(),
            'email' => 'delete@example.com',
            'password' => password_hash('pass', PASSWORD_ARGON2ID),
            'roles' => ['ROLE_USER'],
        ]);

        $result = $this->repository->delete((string) $model->id);

        expect($result)->toBeTrue();
        expect(UserModel::find($model->id))->toBeNull();
    });

    it('returns false when user not found', function (): void {
        expect($this->repository->delete('nonexistent'))->toBeFalse();
    });
});

describe('EloquentUserRepository - verifyEmail', function (): void {
    it('sets email_verified_at and returns true', function (): void {
        $model = UserModel::create([
            'id' => (string) \Illuminate\Support\Str::uuid7(),
            'email' => 'unverified@example.com',
            'password' => password_hash('pass', PASSWORD_ARGON2ID),
            'roles' => ['ROLE_USER'],
        ]);

        $result = $this->repository->verifyEmail((string) $model->id);

        expect($result)->toBeTrue();

        $model->refresh();
        expect($model->email_verified_at)->not->toBeNull();
    });

    it('returns false when user not found', function (): void {
        expect($this->repository->verifyEmail('nonexistent'))->toBeFalse();
    });
});

describe('EloquentUserRepository - generateId', function (): void {
    it('generates a string UUID when using uuid strategy', function (): void {
        config(['betterauth.id_strategy' => 'uuid']);

        $id = $this->repository->generateId();

        expect($id)->toBeString()->not->toBeEmpty();
    });

    it('returns null for auto-increment strategy', function (): void {
        config(['betterauth.id_strategy' => 'int']);

        expect($this->repository->generateId())->toBeNull();
    });
});
