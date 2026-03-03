<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Commands;

use ApiPlatform\OpenApi\Factory\OpenApiFactoryInterface;
use Illuminate\Console\Command;
use Illuminate\Filesystem\Filesystem;

final class OpenApiInstallCommand extends Command
{
    protected $signature = 'betterauth:openapi-install
        {--force : Overwrite existing files}
        {--yes : Skip interactive confirmations}';

    protected $description = 'Install BetterAuth OpenAPI integration for API Platform';

    public function __construct(private readonly Filesystem $files)
    {
        parent::__construct();
    }

    public function handle(): int
    {
        $this->components->info('Installing BetterAuth OpenAPI integration...');

        if (! interface_exists(OpenApiFactoryInterface::class)) {
            $this->components->error('API Platform is not installed. Run: composer require api-platform/laravel');

            return self::FAILURE;
        }

        $this->publishOpenApiFactory();
        $this->publishOpenApiConfig();
        $this->publishServiceProvider();
        $this->registerServiceProvider();

        $this->newLine();
        $this->components->info('BetterAuth OpenAPI integration installed successfully.');
        $this->components->bulletList([
            'OpenAPI decorator: app/OpenApi/BetterAuthOpenApiFactory.php',
            'Service provider: app/Providers/BetterAuthOpenApiServiceProvider.php',
            'Configuration: config/betterauth_openapi.php',
            'Check docs: GET /api/docs.jsonopenapi',
        ]);

        return self::SUCCESS;
    }

    private function publishOpenApiFactory(): void
    {
        $target = app_path('OpenApi/BetterAuthOpenApiFactory.php');
        $stub = dirname(__DIR__, 2).'/stubs/openapi/BetterAuthOpenApiFactory.php.stub';

        $this->components->task('Publishing OpenAPI decorator', function () use ($target, $stub): void {
            $this->files->ensureDirectoryExists(dirname($target));

            if ($this->files->exists($target) && ! $this->option('force')) {
                $this->components->warn('BetterAuthOpenApiFactory already exists. Use --force to overwrite.');

                return;
            }

            $this->files->copy($stub, $target);
        });
    }

    private function publishOpenApiConfig(): void
    {
        $target = config_path('betterauth_openapi.php');
        $stub = dirname(__DIR__, 2).'/stubs/config/betterauth_openapi.php.stub';

        $this->components->task('Publishing OpenAPI config', function () use ($target, $stub): void {
            if ($this->files->exists($target) && ! $this->option('force')) {
                $this->components->warn('betterauth_openapi.php already exists. Use --force to overwrite.');

                return;
            }

            $this->files->copy($stub, $target);
        });
    }

    private function publishServiceProvider(): void
    {
        $target = app_path('Providers/BetterAuthOpenApiServiceProvider.php');
        $stub = dirname(__DIR__, 2).'/stubs/providers/BetterAuthOpenApiServiceProvider.php.stub';

        $this->components->task('Publishing service provider', function () use ($target, $stub): void {
            $this->files->ensureDirectoryExists(dirname($target));

            if ($this->files->exists($target) && ! $this->option('force')) {
                $this->components->warn('BetterAuthOpenApiServiceProvider already exists. Use --force to overwrite.');

                return;
            }

            $this->files->copy($stub, $target);
        });
    }

    private function registerServiceProvider(): void
    {
        $providersPath = base_path('bootstrap/providers.php');
        $providerClass = 'App\\Providers\\BetterAuthOpenApiServiceProvider::class';

        if (! $this->files->exists($providersPath)) {
            $this->components->warn('bootstrap/providers.php not found. Register App\\Providers\\BetterAuthOpenApiServiceProvider manually.');

            return;
        }

        $this->components->task('Registering service provider', function () use ($providersPath, $providerClass): void {
            $content = $this->files->get($providersPath);

            if (str_contains($content, $providerClass)) {
                $this->components->info('Service provider already registered in bootstrap/providers.php');

                return;
            }

            if (! $this->option('yes') && ! $this->confirm('Add BetterAuthOpenApiServiceProvider to bootstrap/providers.php?', true)) {
                $this->components->warn('Skipping provider registration. Register it manually if needed.');

                return;
            }

            $updated = preg_replace(
                '/return\s*\[\s*/',
                "return [\n    {$providerClass},\n    ",
                $content,
                1,
            );

            if (! is_string($updated)) {
                $this->components->warn('Unable to patch bootstrap/providers.php automatically. Register provider manually.');

                return;
            }

            $this->files->put($providersPath, $updated);
        });
    }
}
