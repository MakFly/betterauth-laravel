<?php

declare(strict_types=1);

namespace BetterAuth\Laravel;

use BetterAuth\Core\Config\AuthConfig;
use BetterAuth\Core\Interfaces\TokenSignerInterface;
use BetterAuth\Core\PasswordHasher;
use BetterAuth\Core\TokenService;
use BetterAuth\Laravel\Commands\CleanupCommand;
use BetterAuth\Laravel\Commands\InstallCommand;
use BetterAuth\Laravel\Commands\SecretCommand;
use BetterAuth\Laravel\Guards\BetterAuthGuard;
use BetterAuth\Laravel\Guards\BetterAuthSessionGuard;
use BetterAuth\Laravel\OAuth\OAuthManager;
use BetterAuth\Laravel\Providers\BetterAuthUserProvider;
use BetterAuth\Laravel\Services\BetterAuthManager;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;

final class BetterAuthServiceProvider extends ServiceProvider
{
    private Filesystem $files;

    public function __construct($app)
    {
        parent::__construct($app);
        $this->files = new Filesystem();
    }
    /**
     * Register any application services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/betterauth.php', 'betterauth');

        $this->registerCoreServices();
        $this->registerAuthManager();
        $this->registerOAuthManager();
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        $this->bootPublishes();
        $this->bootCommands();
        $this->bootGuards();
        $this->bootRoutes();

        // Auto-install on first package installation
        if ($this->app->runningInConsole() && $this->shouldAutoInstall()) {
            $this->autoInstall();
        }
    }

    /**
     * Register core BetterAuth services.
     */
    private function registerCoreServices(): void
    {
        // AuthConfig - Core configuration object
        $this->app->singleton(AuthConfig::class, function (Application $app): AuthConfig {
            $config = $app['config']['betterauth'];
            $secret = $config['secret'] ?? '';
            $mode = $config['mode'] ?? 'api';

            $overrides = [
                'tokenLifetime' => $config['tokens']['access']['lifetime'] ?? 3600,
                'refreshTokenLifetime' => $config['tokens']['refresh']['lifetime'] ?? 2592000,
            ];

            return match ($mode) {
                'session' => AuthConfig::forMonolith($secret, $overrides),
                'hybrid' => AuthConfig::forHybrid($secret, $overrides),
                default => AuthConfig::forApi($secret, $overrides),
            };
        });

        // PasswordHasher - Argon2id password hashing
        $this->app->singleton(PasswordHasher::class, function (Application $app): PasswordHasher {
            $config = $app['config']['betterauth.password.options'] ?? [];

            return new PasswordHasher(
                memoryCost: $config['memory_cost'] ?? PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
                timeCost: $config['time_cost'] ?? PASSWORD_ARGON2_DEFAULT_TIME_COST,
                threads: $config['threads'] ?? PASSWORD_ARGON2_DEFAULT_THREADS,
            );
        });

        // TokenService / TokenSigner - Paseto V4 implementation
        $this->app->singleton(TokenSignerInterface::class, function (Application $app): TokenSignerInterface {
            $config = $app->make(AuthConfig::class);
            $appName = $app['config']['app.name'] ?? 'betterauth';

            return new TokenService($config->secretKey, $appName);
        });

        // Alias for convenience
        $this->app->alias(TokenSignerInterface::class, TokenService::class);
    }

    /**
     * Register the BetterAuth manager.
     */
    private function registerAuthManager(): void
    {
        // BetterAuthManager - Pure Laravel implementation using Eloquent
        $this->app->singleton(BetterAuthManager::class, function (Application $app): BetterAuthManager {
            return new BetterAuthManager(
                tokenService: $app->make(TokenSignerInterface::class),
                passwordHasher: $app->make(PasswordHasher::class),
                config: $app['config']['betterauth'],
            );
        });

        // Bind 'betterauth' for Facade resolution
        $this->app->alias(BetterAuthManager::class, 'betterauth');
    }

    /**
     * Register the OAuth manager.
     */
    private function registerOAuthManager(): void
    {
        $this->app->singleton(OAuthManager::class, function (Application $app): OAuthManager {
            $providers = $app['config']['betterauth']['oauth']['providers'] ?? [];

            // Build provider configurations
            $providerConfigs = [];
            foreach ($providers as $name => $settings) {
                $providerConfigs[$name] = [
                    'client_id' => env("OAUTH_{$name}_CLIENT_ID") ?? $settings['client_id'] ?? null,
                    'client_secret' => env("OAUTH_{$name}_CLIENT_SECRET") ?? $settings['client_secret'] ?? null,
                    'redirect_uri' => $settings['redirect_uri'] ?? null,
                    'scopes' => $settings['scopes'] ?? [],
                    'with' => $settings['with'] ?? [],
                ];
            }

            return new OAuthManager($app, $providerConfigs);
        });

        // Bind 'oauth' for Facade resolution
        $this->app->alias(OAuthManager::class, 'betterauth.oauth');
    }

    /**
     * Boot publishable assets.
     */
    private function bootPublishes(): void
    {
        if (! $this->app->runningInConsole()) {
            return;
        }

        // Config
        $this->publishes([
            __DIR__.'/../config/betterauth.php' => config_path('betterauth.php'),
        ], 'betterauth-config');

        // Migrations
        $this->publishes([
            __DIR__.'/../database/migrations' => database_path('migrations'),
        ], 'betterauth-migrations');

        // Controllers
        $this->publishes([
            __DIR__.'/../stubs/controllers/AuthController.php.stub' => app_path('Http/Controllers/Auth/AuthController.php'),
        ], 'betterauth-controllers');

        // Tests
        $this->publishes([
            __DIR__.'/../stubs/tests/Feature/BetterAuthTest.php.stub' => base_path('tests/Feature/BetterAuthTest.php'),
            __DIR__.'/../stubs/tests/Feature/BetterAuthTest.pest.stub' => base_path('tests/Feature/BetterAuthTest.pest.php'),
        ], 'betterauth-tests');

        // Auto-installation tag (triggers full installation)
        $this->publishes([
            __DIR__.'/../config/betterauth.php' => config_path('betterauth.php'),
        ], 'betterauth-auto');

        // All assets
        $this->publishes([
            __DIR__.'/../config/betterauth.php' => config_path('betterauth.php'),
            __DIR__.'/../database/migrations' => database_path('migrations'),
            __DIR__.'/../stubs/controllers/AuthController.php.stub' => app_path('Http/Controllers/Auth/AuthController.php'),
        ], 'betterauth');
    }

    /**
     * Boot console commands.
     */
    private function bootCommands(): void
    {
        if (! $this->app->runningInConsole()) {
            return;
        }

        $this->commands([
            InstallCommand::class,
            SecretCommand::class,
            CleanupCommand::class,
        ]);
    }

    /**
     * Boot authentication guards.
     */
    private function bootGuards(): void
    {
        // Register API guard driver (token-based)
        Auth::extend('betterauth', function (Application $app, string $name, array $config) {
            $provider = Auth::createUserProvider($config['provider'] ?? null);

            return new BetterAuthGuard(
                name: $name,
                provider: $provider,
                request: $app['request'],
                tokenService: $app->make(TokenSignerInterface::class),
                authManager: $app->make(BetterAuthManager::class),
                events: $app['events'],
            );
        });

        // Register Session guard driver (session-based with enhanced tracking)
        Auth::extend('betterauth.session', function (Application $app, string $name, array $config) {
            $provider = Auth::createUserProvider($config['provider'] ?? null);

            return new BetterAuthSessionGuard(
                name: $name,
                provider: $provider,
                session: $app->make('session.store'),
                authManager: $app->make(BetterAuthManager::class),
            );
        });

        // Register custom user provider driver
        Auth::provider('betterauth', function (Application $app, array $config) {
            return new BetterAuthUserProvider(
                model: $config['model'] ?? $app['config']['betterauth.user_model'],
                hasher: $app->make(PasswordHasher::class),
            );
        });
    }

    /**
     * Boot routes.
     */
    private function bootRoutes(): void
    {
        $config = $this->app['config']['betterauth.routes'];

        if (! ($config['enabled'] ?? true)) {
            return;
        }

        $this->loadRoutesFrom(__DIR__.'/../routes/betterauth.php');
    }

    /**
     * Check if auto-installation should be triggered.
     */
    private function shouldAutoInstall(): bool
    {
        // Only auto-install if config doesn't exist (first installation)
        return ! $this->files->exists(config_path('betterauth.php'));
    }

    /**
     * Trigger automatic installation.
     */
    private function autoInstall(): void
    {
        if (defined('BETTERAUTH_AUTO_INSTALL_DISABLED')) {
            return;
        }

        try {
            $this->app->make('command.betterauth.install')->call('--yes', '--skip-checks');
        } catch (\Exception $e) {
            // Silent fail - auto-install is optional
        }
    }

    /**
     * Get the services provided by the provider.
     *
     * @return array<class-string|string>
     */
    public function provides(): array
    {
        return [
            AuthConfig::class,
            PasswordHasher::class,
            TokenSignerInterface::class,
            TokenService::class,
            BetterAuthManager::class,
            'betterauth',
        ];
    }
}
