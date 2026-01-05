<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Commands;

use BetterAuth\Laravel\Services\ConfigurationBuilder;
use Illuminate\Console\Command;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Facades\File;

/**
 * Cleanup Command - Rollback BetterAuth installation.
 *
 * This command allows users to rollback changes made by BetterAuth installation.
 * Use with caution as it will delete files and modifications.
 */
final class CleanupCommand extends Command
{
    protected $signature = 'betterauth:cleanup
        {--all : Remove all BetterAuth files and configuration}
        {--config : Remove only configuration files}
        {--routes : Remove BetterAuth routes configuration}
        {--controllers : Remove generated controllers}
        {--migrations : Remove BetterAuth migrations}
        {--tests : Remove generated test files}';

    protected $description = 'Rollback BetterAuth installation changes';

    private Filesystem $files;

    private ConfigurationBuilder $configBuilder;

    public function __construct(Filesystem $files, ConfigurationBuilder $configBuilder)
    {
        parent::__construct();
        $this->files = $files;
        $this->configBuilder = $configBuilder;
    }

    public function handle(): int
    {
        // Warn user before proceeding
        if (! $this->confirm('This will remove BetterAuth files and modifications. Continue?', true)) {
            $this->components->warn('Cleanup cancelled.');

            return self::SUCCESS;
        }

        $this->components->warn('Rolling back BetterAuth installation...');

        if ($this->option('all') || $this->option('config')) {
            $this->cleanupConfig();
        }

        if ($this->option('all') || $this->option('routes')) {
            $this->cleanupRoutes();
        }

        if ($this->option('all') || $this->option('controllers')) {
            $this->cleanupControllers();
        }

        if ($this->option('all') || $this->option('migrations')) {
            $this->cleanupMigrations();
        }

        if ($this->option('all') || $this->option('tests')) {
            $this->cleanupTests();
        }

        $this->newLine();
        $this->components->info('BetterAuth cleanup completed.');
        $this->components->info('To reinstall, run: <fg=yellow>php artisan betterauth:install</>');

        return self::SUCCESS;
    }

    /**
     * Remove configuration files.
     */
    private function cleanupConfig(): void
    {
        $this->components->task('Removing configuration', function (): void {
            // Remove config file
            $configPath = config_path('betterauth.php');
            if ($this->files->exists($configPath)) {
                $this->files->delete($configPath);
            }

            // Remove from auth.php
            $this->removeFromAuthConfig();

            // Remove BETTER_AUTH_SECRET from .env
            $this->removeFromEnv('BETTER_AUTH_SECRET');
        });
    }

    /**
     * Remove routes configuration.
     */
    private function cleanupRoutes(): void
    {
        $this->components->task('Removing routes configuration', function (): void {
            $laravelVersion = $this->configBuilder->detectLaravelVersion();

            // Remove API routes from bootstrap/app.php (Laravel 12)
            if ($laravelVersion === 12) {
                $this->removeApiFromBootstrap();
            }

            // Remove BetterAuth route imports from routes/api.php
            $this->removeBetterAuthFromApiRoutes();
        });
    }

    /**
     * Remove generated controllers.
     */
    private function cleanupControllers(): void
    {
        $this->components->task('Removing generated controllers', function (): void {
            $controllers = [
                app_path('Http/Controllers/Auth/AuthController.php'),
            ];

            foreach ($controllers as $controller) {
                if ($this->files->exists($controller)) {
                    // Backup before deleting
                    $backupPath = $controller.'.betterauth.bak';
                    $this->files->copy($controller, $backupPath);
                    $this->files->delete($controller);
                }
            }
        });
    }

    /**
     * Remove migrations.
     */
    private function cleanupMigrations(): void
    {
        $this->components->task('Removing migrations', function (): void {
            $migrations = glob(database_path('migrations/*_better_auth_*'));

            if (is_array($migrations)) {
                foreach ($migrations as $migration) {
                    if ($this->files->exists($migration)) {
                        $this->files->delete($migration);
                    }
                }
            }
        });
    }

    /**
     * Remove generated test files.
     */
    private function cleanupTests(): void
    {
        $this->components->task('Removing test files', function (): void {
            $testFiles = [
                base_path('tests/Feature/BetterAuthTest.php'),
            ];

            foreach ($testFiles as $testFile) {
                if ($this->files->exists($testFile)) {
                    $this->files->delete($testFile);
                }
            }
        });
    }

    /**
     * Remove BetterAuth configuration from auth.php.
     */
    private function removeFromAuthConfig(): void
    {
        $authConfig = config_path('auth.php');

        if (! $this->files->exists($authConfig)) {
            return;
        }

        $content = $this->files->get($authConfig);

        // Remove betterauth guard
        $content = preg_replace(
            "/\s*'betterauth'\s*=>\s*\[[^\]]*\],?\n?/",
            '',
            $content,
            1,
        );

        // Remove betterauth provider
        $content = preg_replace(
            "/\s*'betterauth'\s*=>\s*\[[^\]]*\],?\n?/",
            '',
            $content,
            1,
        );

        $this->files->put($authConfig, $content);
    }

    /**
     * Remove API routes from bootstrap/app.php (Laravel 12).
     */
    private function removeApiFromBootstrap(): void
    {
        $bootstrapPath = base_path('bootstrap/app.php');

        if (! $this->files->exists($bootstrapPath)) {
            return;
        }

        $content = $this->files->get($bootstrapPath);

        // Check if we added the API routes (look for our pattern)
        if (str_contains($content, "__DIR__.'/../routes/api.php'")) {
            // Remove the API parameter line we added
            $content = preg_replace(
                "/\s*api:\s*__DIR__\.'\/\.\.\/routes\/api\.php',?\n?/",
                '',
                $content,
                1,
            );

            $this->files->put($bootstrapPath, $content);
        }
    }

    /**
     * Remove BetterAuth route imports from routes/api.php.
     */
    private function removeBetterAuthFromApiRoutes(): void
    {
        $apiPath = base_path('routes/api.php');

        if (! $this->files->exists($apiPath)) {
            return;
        }

        $content = $this->files->get($apiPath);

        // Remove BetterAuth route requirement
        $content = preg_replace(
            '/\/\/ BetterAuth routes.*?\n.*?require.*?betterauth.*?\.php\;?\n\n?/s',
            '',
            $content,
            1,
        );

        $this->files->put($apiPath, $content);
    }

    /**
     * Remove a variable from .env file.
     */
    private function removeFromEnv(string $key): void
    {
        $envPath = base_path('.env');

        if (! $this->files->exists($envPath)) {
            return;
        }

        $content = $this->files->get($envPath);

        // Remove the key=value line
        $content = preg_replace("/^{$key}=.*\n?/m", '', $content);

        $this->files->put($envPath, $content);
    }
}
