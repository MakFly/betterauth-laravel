<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Services;

use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Facades\File;

/**
 * Configuration Builder - Detects Laravel version and validates configuration.
 *
 * This service handles the detection of the Laravel version and provides
 * validation for the auto-configuration system.
 */
final class ConfigurationBuilder
{
    private Filesystem $files;

    private array $configuration = [];

    public function __construct(Filesystem $files)
    {
        $this->files = $files;
    }

    /**
     * Detect the Laravel version from composer.json.
     *
     * @return int The Laravel major version (10, 11, or 12)
     */
    public function detectLaravelVersion(): int
    {
        $composerPath = base_path('composer.json');

        if (! $this->files->exists($composerPath)) {
            return 10; // Default to Laravel 10
        }

        $composer = json_decode($this->files->get($composerPath), true);
        $require = $composer['require'] ?? [];
        $laravelVersion = $require['laravel/framework'] ?? $require['illuminate/support'] ?? '^10.0';

        if (str_contains($laravelVersion, '^12.') || str_contains($laravelVersion, '^12')) {
            return 12;
        }

        if (str_contains($laravelVersion, '^11.') || str_contains($laravelVersion, '^11')) {
            return 11;
        }

        return 10;
    }

    /**
     * Check if the bootstrap/app.php file can be safely modified.
     *
     * @return bool True if the file can be modified
     */
    public function canModifyBootstrapFile(): bool
    {
        $bootstrapPath = base_path('bootstrap/app.php');

        if (! $this->files->exists($bootstrapPath)) {
            return false;
        }

        $content = $this->files->get($bootstrapPath);

        // Check if it uses the new Laravel 12 structure
        if (! str_contains($content, '->withRouting(')) {
            return false;
        }

        // Check if already configured
        if (str_contains($content, "'api'")) {
            return false; // Already has API routes configured
        }

        return true;
    }

    /**
     * Build the routing configuration based on Laravel version.
     *
     * @param  int  $laravelVersion  The detected Laravel version
     * @return array The routing configuration
     */
    public function buildRoutingConfiguration(int $laravelVersion): array
    {
        $this->configuration['laravel_version'] = $laravelVersion;
        $this->configuration['use_new_routing'] = $laravelVersion === 12;

        if ($laravelVersion === 12) {
            $this->configuration['routing_modification'] = [
                'method' => 'withRouting',
                'api_file' => 'routes/api.php',
                'needs_api_parameter' => true,
                'can_modify' => $this->canModifyBootstrapFile(),
            ];
        } else {
            $this->configuration['routing_modification'] = [
                'method' => 'loadRoutesFrom',
                'route_file' => 'routes/betterauth.php',
                'needs_api_parameter' => false,
                'can_modify' => true,
            ];
        }

        return $this->configuration;
    }

    /**
     * Validate the current configuration.
     *
     * @return array{errors: array<string>, warnings: array<string>, valid: bool}
     */
    public function validateConfiguration(): array
    {
        $errors = [];
        $warnings = [];

        // Check for required files
        if (! $this->files->exists(base_path('.env'))) {
            $errors[] = '.env file not found. Please create it first.';
        }

        // Check for existing API routes
        $apiPath = base_path('routes/api.php');
        if ($this->files->exists($apiPath)) {
            $apiContent = $this->files->get($apiPath);
            if (str_contains($apiContent, '/auth/') || str_contains($apiContent, 'betterauth')) {
                $warnings[] = 'API routes file already contains authentication endpoints. Review for conflicts.';
            }
        }

        // Check for existing User model
        $userModelPath = app_path('Models/User.php');
        if (! $this->files->exists($userModelPath)) {
            $warnings[] = 'User model not found at app/Models/User.php. Some features may not work as expected.';
        }

        // Check for existing Auth controller
        $authControllerPath = app_path('Http/Controllers/Auth/AuthController.php');
        if ($this->files->exists($authControllerPath)) {
            $warnings[] = 'Auth controller already exists. It will be backed up before publishing.';
        }

        return [
            'errors' => $errors,
            'warnings' => $warnings,
            'valid' => empty($errors),
        ];
    }

    /**
     * Get the configuration array.
     *
     * @return array<string, mixed>
     */
    public function getConfiguration(): array
    {
        return $this->configuration;
    }
}
