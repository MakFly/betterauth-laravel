<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Tests;

use BetterAuth\Laravel\BetterAuthServiceProvider;
use Illuminate\Database\Eloquent\Factories\Factory;
use Orchestra\Testbench\TestCase as OrchestraTestCase;

abstract class TestCase extends OrchestraTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Factory::guessFactoryNamesUsing(
            fn (string $modelName) => 'BetterAuth\\Laravel\\Database\\Factories\\'.class_basename($modelName).'Factory',
        );
    }

    protected function getPackageProviders($app): array
    {
        return [
            BetterAuthServiceProvider::class,
        ];
    }

    protected function defineEnvironment($app): void
    {
        // Setup default database to use sqlite in-memory
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);

        // Setup BetterAuth configuration
        $app['config']->set('betterauth.secret', str_repeat('a', 64));
        $app['config']->set('betterauth.mode', 'api');
        $app['config']->set('betterauth.id_strategy', 'uuid');
        $app['config']->set('betterauth.tokens.access.lifetime', 3600);
        $app['config']->set('betterauth.tokens.refresh.lifetime', 2592000);

        // Enable Magic Link and OAuth for testing
        $app['config']->set('betterauth.magic_links.enabled', true);
        $app['config']->set('betterauth.oauth.enabled', true);

        // Setup auth configuration
        $app['config']->set('auth.guards.betterauth', [
            'driver' => 'betterauth',
            'provider' => 'betterauth',
        ]);

        $app['config']->set('auth.providers.betterauth', [
            'driver' => 'betterauth',
            'model' => \BetterAuth\Laravel\Tests\Fixtures\User::class,
        ]);

        $app['config']->set('betterauth.user_model', \BetterAuth\Laravel\Tests\Fixtures\User::class);
    }

    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(__DIR__.'/database/migrations');
    }

    /**
     * Create a user for testing.
     *
     * @param  array<string, mixed>  $attributes
     */
    protected function createTestUser(array $attributes = []): \BetterAuth\Laravel\Tests\Fixtures\User
    {
        return \BetterAuth\Laravel\Tests\Fixtures\User::create(array_merge([
            'id' => (string) \Illuminate\Support\Str::uuid7(),
            'email' => 'test@example.com',
            'password' => password_hash('password123', PASSWORD_ARGON2ID),
            'name' => 'Test User',
            'roles' => ['ROLE_USER'],
            'email_verified_at' => now(),
        ], $attributes));
    }
}
