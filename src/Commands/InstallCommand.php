<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Commands;

use BetterAuth\Laravel\Services\ConfigurationBuilder;
use Illuminate\Console\Command;
use Illuminate\Filesystem\Filesystem;

use function Laravel\Prompts\confirm;
use function Laravel\Prompts\multiselect;
use function Laravel\Prompts\select;

/**
 * BetterAuth Installation Command.
 *
 * Scaffolds all necessary files for BetterAuth integration:
 * - Configuration file
 * - Database migrations
 * - User model modifications
 * - Auth config updates
 */
final class InstallCommand extends Command
{
    /**
     * The name and signature of the console command.
     */
    protected $signature = 'betterauth:install
        {--api : Install API-only authentication (default)}
        {--session : Install session-based authentication}
        {--hybrid : Install both API and session authentication}
        {--uuid : Use UUID for primary keys (default)}
        {--ulid : Use ULID for primary keys}
        {--int : Use auto-increment integers for primary keys}
        {--minimal : Skip optional fields (name, avatar)}
        {--force : Overwrite existing files}
        {--skip-tests : Skip test generation}
        {--skip-checks : Skip post-install validation}
        {--skip-controllers : Skip controller generation}
        {--yes : Auto-confirm all prompts}';

    /**
     * The console command description.
     */
    protected $description = 'Install BetterAuth scaffolding';

    private Filesystem $files;

    private ConfigurationBuilder $configBuilder;

    public function __construct(Filesystem $files, ConfigurationBuilder $configBuilder)
    {
        parent::__construct();
        $this->files = $files;
        $this->configBuilder = $configBuilder;
    }

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $this->components->info('Installing BetterAuth...');
        $this->newLine();

        // Determine installation mode
        $mode = $this->determineMode();
        $idStrategy = $this->determineIdStrategy();
        $includeOptionalFields = ! $this->option('minimal') && $this->confirmOptionalFields();
        $features = $this->selectFeatures();

        $this->components->info('Configuration:');
        $this->components->bulletList([
            "Mode: {$mode}",
            "ID Strategy: {$idStrategy}",
            'Optional Fields: '.($includeOptionalFields ? 'Yes' : 'No'),
            'Features: '.implode(', ', $features ?: ['Basic Auth']),
        ]);
        $this->newLine();

        // Build configuration
        $laravelVersion = $this->configBuilder->detectLaravelVersion();
        $config = $this->configBuilder->buildRoutingConfiguration($laravelVersion);

        // Step 1: Publish configuration
        $this->publishConfig();

        // Step 2: Generate migrations
        $this->generateMigrations($idStrategy, $includeOptionalFields);

        // Step 3: Update User model
        $this->updateUserModel($idStrategy, $includeOptionalFields);

        // Step 4: Update auth.php config
        $this->updateAuthConfig();

        // Step 5: Generate secret if not exists
        $this->generateSecret();

        // Step 6: Auto-configure Laravel 12 routing
        $this->autoConfigureLaravel12Routing($config);

        // Step 7: Ensure API routes file exists
        $this->ensureApiRoutesFile();

        // Step 8: Publish controllers
        if (! $this->option('skip-controllers')) {
            $this->publishControllers();
        }

        // Step 9: Generate tests
        if (! $this->option('skip-tests')) {
            $this->generateTests();
        }

        // Step 10: Run post-install validation
        if (! $this->option('skip-checks')) {
            $this->runPostInstallChecks();
        }

        // Step 11: Display next steps
        $this->displayNextSteps();

        return self::SUCCESS;
    }

    private function determineMode(): string
    {
        if ($this->option('session')) {
            return 'session';
        }

        if ($this->option('hybrid')) {
            return 'hybrid';
        }

        if ($this->option('api')) {
            return 'api';
        }

        return select(
            label: 'Which authentication mode do you want to use?',
            options: [
                'api' => 'API (Stateless Paseto V4 tokens) - Recommended for APIs',
                'session' => 'Session (Traditional session-based auth)',
                'hybrid' => 'Hybrid (Both API and session)',
            ],
            default: 'api',
        );
    }

    private function determineIdStrategy(): string
    {
        if ($this->option('uuid')) {
            return 'uuid';
        }

        if ($this->option('ulid')) {
            return 'ulid';
        }

        if ($this->option('int')) {
            return 'int';
        }

        return select(
            label: 'Which ID strategy do you want to use?',
            options: [
                'uuid' => 'UUID v7 (Recommended for distributed systems)',
                'ulid' => 'ULID (Sortable, URL-safe)',
                'int' => 'Auto-increment Integer (Legacy compatibility)',
            ],
            default: 'uuid',
        );
    }

    private function confirmOptionalFields(): bool
    {
        return confirm(
            label: 'Include optional user fields (name, avatar)?',
            default: true,
        );
    }

    /**
     * @return array<string>
     */
    private function selectFeatures(): array
    {
        return multiselect(
            label: 'Which additional features do you want to enable?',
            options: [
                'oauth' => 'OAuth (Google, GitHub, etc.)',
                '2fa' => 'Two-Factor Authentication (TOTP)',
                'magic_links' => 'Magic Links (Passwordless)',
                'passkeys' => 'Passkeys (WebAuthn/FIDO2)',
                'device_tracking' => 'Device Tracking',
                'security_events' => 'Security Event Logging',
            ],
            default: [],
            hint: 'Press space to select, enter to confirm',
        );
    }

    private function publishConfig(): void
    {
        $this->components->task('Publishing configuration', function (): void {
            $this->call('vendor:publish', [
                '--tag' => 'betterauth-config',
                '--force' => $this->option('force'),
            ]);
        });
    }

    private function generateMigrations(string $idStrategy, bool $includeOptionalFields): void
    {
        $this->components->task('Generating migrations', function () use ($idStrategy, $includeOptionalFields): void {
            $timestamp = date('Y_m_d_His');

            // Only generate users migration if not using default Laravel users table
            // Check if the default Laravel migration still exists (unmodified)
            $defaultUsersMigration = database_path('migrations/0001_01_01_000000_create_users_table.php');
            if (! $this->files->exists($defaultUsersMigration)) {
                // No default users migration, generate our own
                $this->generateMigration(
                    'create_better_auth_users_table',
                    $this->getUsersMigrationContent($idStrategy, $includeOptionalFields),
                    $timestamp,
                );
            } else {
                // Modify the existing default migration to add BetterAuth fields
                $this->modifyDefaultUsersMigration($defaultUsersMigration, $includeOptionalFields);
            }

            // Refresh tokens migration
            $this->generateMigration(
                'create_better_auth_refresh_tokens_table',
                $this->getRefreshTokensMigrationContent($idStrategy),
                date('Y_m_d_His', strtotime('+1 second')),
            );

            // Sessions migration
            $this->generateMigration(
                'create_better_auth_sessions_table',
                $this->getSessionsMigrationContent($idStrategy),
                date('Y_m_d_His', strtotime('+2 seconds')),
            );
        });
    }

    private function generateMigration(string $name, string $content, string $timestamp): void
    {
        $filename = "{$timestamp}_{$name}.php";
        $path = database_path("migrations/{$filename}");

        if (! $this->option('force') && $this->files->exists($path)) {
            return;
        }

        $this->files->put($path, $content);
    }

    private function modifyDefaultUsersMigration(string $migrationPath, bool $includeOptionalFields): void
    {
        $content = $this->files->get($migrationPath);

        // Check if already modified
        if (str_contains($content, 'better_auth')) {
            return;
        }

        // 1. Change id() to uuid('id')->primary()
        $content = str_replace(
            '$table->id();',
            "\$table->uuid('id')->primary();",
            $content,
        );

        $content = str_replace(
            "->table('users', function (Blueprint \$table) {\n                \$table->id();",
            "->table('users', function (Blueprint \$table) {\n                \$table->uuid('id')->primary();",
            $content,
        );

        // 2. Make name nullable (if it exists in default Laravel migration)
        $content = preg_replace(
            "/\$table->string\('name'\);/",
            "\$table->string('name')->nullable();",
            $content,
        );

        // 3. Add BetterAuth fields after email_verified_at
        $avatarField = $includeOptionalFields ? "\n            \$table->string('avatar', 500)->nullable();" : '';

        $content = preg_replace(
            '/(\$table->timestamp\(\'email_verified_at\'\)->nullable\(\);)/',
            "$1\n            \$table->json('roles')->default('[\"ROLE_USER\"]');\n            \$table->json('metadata')->nullable();{$avatarField}",
            $content,
        );

        $this->files->put($migrationPath, $content);
    }

    private function getUsersMigrationContent(string $idStrategy, bool $includeOptionalFields): string
    {
        $idColumn = match ($idStrategy) {
            'uuid' => "\$table->uuid('id')->primary();",
            'ulid' => "\$table->ulid('id')->primary();",
            default => '$table->id();',
        };

        $optionalFields = $includeOptionalFields ? "
            \$table->string('name')->nullable();
            \$table->string('avatar', 500)->nullable();" : '';

        return <<<PHP
<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('users', function (Blueprint \$table) {
            {$idColumn}
            \$table->string('email')->unique();
            \$table->string('password')->nullable();{$optionalFields}
            \$table->json('roles')->default('["ROLE_USER"]');
            \$table->timestamp('email_verified_at')->nullable();
            \$table->rememberToken();
            \$table->json('metadata')->nullable();
            \$table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('users');
    }
};
PHP;
    }

    private function getRefreshTokensMigrationContent(string $idStrategy): string
    {
        $userIdColumn = match ($idStrategy) {
            'uuid' => "\$table->uuid('user_id');",
            'ulid' => "\$table->ulid('user_id');",
            default => "\$table->unsignedBigInteger('user_id');",
        };

        return <<<PHP
<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('better_auth_refresh_tokens', function (Blueprint \$table) {
            \$table->string('token', 64)->primary();
            {$userIdColumn}
            \$table->timestamp('expires_at');
            \$table->boolean('revoked')->default(false);
            \$table->string('replaced_by', 64)->nullable();
            \$table->timestamp('created_at');

            \$table->index('user_id');
            \$table->index(['user_id', 'revoked']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('better_auth_refresh_tokens');
    }
};
PHP;
    }

    private function getSessionsMigrationContent(string $idStrategy): string
    {
        $idColumn = match ($idStrategy) {
            'uuid' => "\$table->uuid('id')->primary();",
            'ulid' => "\$table->ulid('id')->primary();",
            default => '$table->id();',
        };

        $userIdColumn = match ($idStrategy) {
            'uuid' => "\$table->uuid('user_id');",
            'ulid' => "\$table->ulid('user_id');",
            default => "\$table->unsignedBigInteger('user_id');",
        };

        return <<<PHP
<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('better_auth_sessions', function (Blueprint \$table) {
            {$idColumn}
            {$userIdColumn}
            \$table->string('ip_address', 45)->nullable();
            \$table->text('user_agent')->nullable();
            \$table->string('device_type', 50)->nullable();
            \$table->string('device_name', 255)->nullable();
            \$table->string('location', 255)->nullable();
            \$table->timestamp('expires_at');
            \$table->timestamp('last_activity_at');
            \$table->timestamp('created_at');

            \$table->index('user_id');
            \$table->index(['user_id', 'expires_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('better_auth_sessions');
    }
};
PHP;
    }

    private function updateUserModel(string $idStrategy, bool $includeOptionalFields): void
    {
        $userModelPath = app_path('Models/User.php');

        if (! $this->files->exists($userModelPath)) {
            $this->components->warn('User model not found. Skipping User model update.');

            return;
        }

        $this->components->task('Updating User model', function () use ($userModelPath, $includeOptionalFields): void {
            $content = $this->files->get($userModelPath);

            // Add HasBetterAuth trait if not present
            if (! str_contains($content, 'HasBetterAuth')) {
                // Add use statement
                $content = str_replace(
                    'use Illuminate\Foundation\Auth\User as Authenticatable;',
                    "use Illuminate\\Foundation\\Auth\\User as Authenticatable;\nuse BetterAuth\\Laravel\\Models\\Traits\\HasBetterAuth;",
                    $content,
                );

                // Add trait usage
                $content = preg_replace(
                    '/(class User extends Authenticatable\s*\{)/s',
                    "$1\n    use HasBetterAuth;\n",
                    $content,
                );

                $this->files->put($userModelPath, $content);
            }

            // Update fillable if needed
            $fillable = $includeOptionalFields
                ? "['name', 'email', 'password', 'avatar', 'roles', 'metadata']"
                : "['email', 'password', 'roles', 'metadata']";

            if (! str_contains($content, "'roles'")) {
                $content = preg_replace(
                    '/protected \$fillable = \[[^\]]*\];/',
                    "protected \$fillable = {$fillable};",
                    $content,
                );
            }

            // Remove 'password' => 'hashed' from casts if present (we use Argon2id via BetterAuth)
            if (str_contains($content, "'password' => 'hashed'")) {
                $content = preg_replace(
                    "/'password'\s*=>\s*'hashed',?\s*/",
                    '',
                    $content,
                );
            }

            $this->files->put($userModelPath, $content);
        });
    }

    private function updateAuthConfig(): void
    {
        $authConfigPath = config_path('auth.php');

        if (! $this->files->exists($authConfigPath)) {
            return;
        }

        $this->components->task('Updating auth configuration', function () use ($authConfigPath): void {
            $content = $this->files->get($authConfigPath);

            // Add betterauth guard if not present
            if (! str_contains($content, "'betterauth'")) {
                // Find the guards array and add betterauth guard
                $guardConfig = <<<'PHP'

        'betterauth' => [
            'driver' => 'betterauth',
            'provider' => 'betterauth',
        ],
PHP;

                $content = preg_replace(
                    "/'guards'\s*=>\s*\[\s*'web'\s*=>\s*\[/",
                    "'guards' => [\n{$guardConfig}\n\n        'web' => [",
                    $content,
                );

                // Add betterauth provider if not present
                $providerConfig = <<<'PHP'

        'betterauth' => [
            'driver' => 'betterauth',
            'model' => App\Models\User::class,
        ],
PHP;

                $content = preg_replace(
                    "/'providers'\s*=>\s*\[\s*'users'\s*=>\s*\[/",
                    "'providers' => [\n{$providerConfig}\n\n        'users' => [",
                    $content,
                );

                $this->files->put($authConfigPath, $content);
            }
        });
    }

    private function generateSecret(): void
    {
        $envPath = base_path('.env');

        if (! $this->files->exists($envPath)) {
            return;
        }

        $content = $this->files->get($envPath);

        // Check if BetterAuth is already configured
        if (str_contains($content, 'BETTER_AUTH_SECRET=')) {
            $this->components->info('BetterAuth environment variables already configured');

            return;
        }

        $this->components->task('Configuring BetterAuth environment variables', function () use ($envPath, $content): void {
            $secret = bin2hex(random_bytes(32));

            // Add BetterAuth configuration to .env
            $envConfig = <<<'ENV'

# =============================================================================
# BETTERAUTH CONFIGURATION
# =============================================================================
BETTER_AUTH_SECRET=%s

# Authentication Mode: "api" or "session"
# - api: Paseto V4 tokens for SPAs, Mobile apps, APIs (default)
# - session: Server-side sessions for web apps (Blade, Livewire)
#
# ⚠️  "hybrid" mode is NOT AVAILABLE for Laravel
# BETTER_AUTH_MODE=api

# Token Lifetime (in seconds) - API mode only
# BETTER_AUTH_ACCESS_TOKEN_LIFETIME=3600
# BETTER_AUTH_REFRESH_TOKEN_LIFETIME=2592000

# Magic Link Authentication
# BETTER_AUTH_MAGIC_LINKS_ENABLED=false

# OAuth Providers (Google, GitHub, Facebook, etc.)
# BETTER_AUTH_OAUTH_ENABLED=false
# BETTER_AUTH_GOOGLE_CLIENT_ID=
# BETTER_AUTH_GOOGLE_CLIENT_SECRET=
# BETTER_AUTH_GOOGLE_REDIRECT_URI=

# Two-Factor Authentication (2FA)
# BETTER_AUTH_2FA_ENABLED=false

# Passkeys / WebAuthn (NOT YET IMPLEMENTED - Coming Soon)
# =============================================================================

ENV;

            $content .= sprintf($envConfig, $secret);
            $this->files->put($envPath, $content);
        });
    }

    private function displayNextSteps(): void
    {
        $this->newLine();
        $this->components->info('BetterAuth installed successfully!');
        $this->newLine();

        $this->components->info('Next steps:');
        $this->components->bulletList([
            'Run migrations: <fg=yellow>php artisan migrate</>',
            'Review config: <fg=yellow>config/betterauth.php</>',
            'Test registration: <fg=yellow>POST /auth/register</>',
            'Test login: <fg=yellow>POST /auth/login</>',
        ]);

        $this->newLine();
        $this->components->info('Available endpoints:');
        $this->table(
            ['Method', 'URI', 'Description'],
            [
                ['POST', '/auth/register', 'Register a new user'],
                ['POST', '/auth/login', 'Authenticate user'],
                ['GET', '/auth/me', 'Get current user (protected)'],
                ['POST', '/auth/refresh', 'Refresh access token'],
                ['POST', '/auth/logout', 'Logout (protected)'],
                ['POST', '/auth/revoke-all', 'Revoke all tokens (protected)'],
            ],
        );
    }

    private function autoConfigureLaravel12Routing(array $config): void
    {
        $laravelVersion = $this->configBuilder->detectLaravelVersion();

        if ($laravelVersion < 12) {
            $this->components->info('Laravel '.$laravelVersion.' detected - skipping bootstrap/app.php configuration');

            return;
        }

        $bootstrapPath = base_path('bootstrap/app.php');

        if (! $this->files->exists($bootstrapPath)) {
            $this->components->warn('bootstrap/app.php not found - skipping routing configuration');

            return;
        }

        $content = $this->files->get($bootstrapPath);

        // Check if API routes are already configured
        if (str_contains($content, "'api'")) {
            $this->components->info('API routes already configured in bootstrap/app.php');

            return;
        }

        // Ask for confirmation (unless --yes flag)
        if (! $this->option('yes')) {
            $this->newLine();
            $this->components->warn('Laravel 12 detected: BetterAuth needs to configure API routes in bootstrap/app.php');
            if (! $this->confirm('Modify bootstrap/app.php to add API routes?', true)) {
                $this->components->warn('Skipping bootstrap/app.php modification. You will need to manually configure API routes.');

                return;
            }
        }

        $this->components->task('Configuring bootstrap/app.php', function () use ($bootstrapPath, $content): void {
            // Create backup
            $backupPath = $bootstrapPath.'.betterauth.bak';
            $this->files->copy($bootstrapPath, $backupPath);

            // Add API routes configuration
            $content = str_replace(
                '->withRouting(',
                "->withRouting(\n            api: __DIR__.'/../routes/api.php',",
                $content,
            );

            $this->files->put($bootstrapPath, $content);
        });
    }

    private function ensureApiRoutesFile(): void
    {
        $apiPath = base_path('routes/api.php');

        if ($this->files->exists($apiPath)) {
            $content = $this->files->get($apiPath);

            if (str_contains($content, 'BetterAuth\\\\Laravel\\\\Http\\\\Controllers\\\\AuthController')) {
                $this->components->info('routes/api.php already contains BetterAuth routes');

                return;
            }

            $this->components->task('Adding BetterAuth to routes/api.php', function () use ($apiPath, $content): void {
                // Add BetterAuth routes at the beginning
                $betterauthRoutes = $this->getBetterAuthRoutes();

                $this->files->put($apiPath, '<?php

use Illuminate\Support\Facades\Route;

'.$betterauthRoutes.$content);
            });
        } else {
            $this->components->task('Creating routes/api.php', function () use ($apiPath): void {
                $betterauthRoutes = $this->getBetterAuthRoutes();
                $stub = <<<PHP
<?php

use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
*/

{$betterauthRoutes}
// Your custom routes below
Route::get('/', function () {
    return response()->json(['message' => 'API OK']);
});
PHP;
                $this->files->put($apiPath, $stub);
            });
        }
    }

    private function getBetterAuthRoutes(): string
    {
        return <<<PHP
// BetterAuth routes
Route::prefix('auth')->group(function () {
    // Public routes
    Route::post('/register', [\BetterAuth\Laravel\Http\Controllers\AuthController::class, 'register']);
    Route::post('/login', [\BetterAuth\Laravel\Http\Controllers\AuthController::class, 'login']);
    Route::post('/refresh', [\BetterAuth\Laravel\Http\Controllers\AuthController::class, 'refresh']);

    // Protected routes
    Route::middleware('auth:betterauth')->group(function () {
        Route::get('/me', [\BetterAuth\Laravel\Http\Controllers\AuthController::class, 'me']);
        Route::post('/logout', [\BetterAuth\Laravel\Http\Controllers\AuthController::class, 'logout']);
        Route::post('/revoke-all', [\BetterAuth\Laravel\Http\Controllers\AuthController::class, 'revokeAll']);
        Route::put('/password', [\BetterAuth\Laravel\Http\Controllers\AuthController::class, 'updatePassword']);
    });

    // Magic Link routes (always included - activated via config)
    Route::post('/magic-link', [\BetterAuth\Laravel\Http\Controllers\MagicLinkController::class, 'send']);
    Route::get('/magic-link/verify', [\BetterAuth\Laravel\Http\Controllers\MagicLinkController::class, 'verify']);
    Route::post('/magic-link/check', [\BetterAuth\Laravel\Http\Controllers\MagicLinkController::class, 'check']);

    // OAuth routes (always included - activated via config)
    Route::get('/oauth/{provider}', [\BetterAuth\Laravel\Http\Controllers\AuthController::class, 'oauthRedirect']);
    Route::get('/oauth/{provider}/callback', [\BetterAuth\Laravel\Http\Controllers\AuthController::class, 'oauthCallback']);
});

PHP;
    }

    private function publishControllers(): void
    {
        $this->components->task('Publishing controllers', function (): void {
            $stubPath = dirname(__DIR__, 2).'/stubs/controllers/AuthController.php.stub';
            $targetPath = app_path('Http/Controllers/Auth/AuthController.php');

            // Create directory if it doesn't exist
            $this->files->ensureDirectoryExists(app_path('Http/Controllers/Auth'));

            // Copy the stub
            if ($this->files->exists($targetPath) && ! $this->option('force')) {
                $this->components->warn('AuthController already exists. Use --force to overwrite.');

                return;
            }

            $this->files->copy($stubPath, $targetPath);
        });
    }

    private function generateTests(): void
    {
        $this->components->task('Generating tests', function (): void {
            // Detect test framework (Pest or PHPUnit)
            $composerPath = base_path('composer.json');
            $usesPest = false;

            if ($this->files->exists($composerPath)) {
                $composer = json_decode($this->files->get($composerPath), true);
                $requireDev = $composer['require-dev'] ?? [];
                $usesPest = isset($requireDev['pestphp/pest']);
            }

            $stubFile = $usesPest ? 'BetterAuthTest.pest.stub' : 'BetterAuthTest.php.stub';
            $stubPath = dirname(__DIR__, 2)."/stubs/tests/Feature/{$stubFile}";
            $targetPath = base_path('tests/Feature/BetterAuthTest.php');

            // Copy the stub
            if ($this->files->exists($targetPath) && ! $this->option('force')) {
                $this->components->warn('BetterAuthTest already exists. Use --force to overwrite.');

                return;
            }

            if ($this->files->exists($stubPath)) {
                $this->files->copy($stubPath, $targetPath);
            } else {
                $this->components->warn("Test stub not found: {$stubFile}");
            }
        });
    }

    private function runPostInstallChecks(): void
    {
        $this->newLine();
        $this->components->info('Running post-install validation checks...');

        $errors = [];
        $warnings = [];

        // Check 1: Config file exists
        if (! $this->files->exists(config_path('betterauth.php'))) {
            $errors[] = 'config/betterauth.php not found';
        }

        // Check 2: Secret in .env
        $envPath = base_path('.env');
        if ($this->files->exists($envPath)) {
            $envContent = $this->files->get($envPath);
            if (! str_contains($envContent, 'BETTER_AUTH_SECRET=')) {
                $warnings[] = 'BETTER_AUTH_SECRET not found in .env';
            }
        } else {
            $warnings[] = '.env file not found';
        }

        // Check 3: Migrations exist
        $migrations = glob(database_path('migrations/*_better_auth_*'));
        if ($migrations === false || count($migrations) < 3) {
            $warnings[] = 'Some BetterAuth migrations may be missing';
        }

        // Check 4: API routes file exists
        if (! $this->files->exists(base_path('routes/api.php'))) {
            $errors[] = 'routes/api.php not found';
        }

        // Check 5: Controller exists
        if (! $this->files->exists(app_path('Http/Controllers/Auth/AuthController.php'))) {
            $warnings[] = 'AuthController not found in app/Http/Controllers/Auth/';
        }

        // Check 6: Tests exist
        if (! $this->files->exists(base_path('tests/Feature/BetterAuthTest.php'))) {
            $warnings[] = 'BetterAuthTest not found in tests/Feature/';
        }

        // Display results
        if (empty($errors) && empty($warnings)) {
            $this->components->info('✓ All validation checks passed!');
        } else {
            if (! empty($errors)) {
                $this->components->error('Errors found:');
                foreach ($errors as $error) {
                    $this->components->bulletList(["<fg=red>✗ {$error}"]);
                }
            }

            if (! empty($warnings)) {
                $this->components->warn('Warnings:');
                foreach ($warnings as $warning) {
                    $this->components->bulletList(["<fg=yellow>⚠ {$warning}"]);
                }
            }
        }
    }
}
