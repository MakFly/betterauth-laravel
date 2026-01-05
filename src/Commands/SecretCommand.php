<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Commands;

use Illuminate\Console\Command;
use Illuminate\Filesystem\Filesystem;

/**
 * Generate a new BetterAuth secret.
 */
final class SecretCommand extends Command
{
    protected $signature = 'betterauth:secret
                            {--show : Display the secret instead of modifying files}
                            {--force : Force overwrite existing secret}';

    protected $description = 'Generate a new BetterAuth secret key';

    public function __construct(
        private readonly Filesystem $files,
    ) {
        parent::__construct();
    }

    public function handle(): int
    {
        $secret = bin2hex(random_bytes(32));

        if ($this->option('show')) {
            $this->components->info("BetterAuth Secret: {$secret}");
            $this->newLine();
            $this->line('Add this to your .env file:');
            $this->line("<fg=yellow>BETTER_AUTH_SECRET={$secret}</>");

            return self::SUCCESS;
        }

        $envPath = base_path('.env');

        if (! $this->files->exists($envPath)) {
            $this->components->error('.env file not found');

            return self::FAILURE;
        }

        $content = $this->files->get($envPath);

        if (str_contains($content, 'BETTER_AUTH_SECRET=') && ! $this->option('force')) {
            $this->components->warn('BETTER_AUTH_SECRET already exists. Use --force to overwrite.');

            return self::FAILURE;
        }

        if (str_contains($content, 'BETTER_AUTH_SECRET=')) {
            // Replace existing
            $content = preg_replace(
                '/BETTER_AUTH_SECRET=.*/',
                "BETTER_AUTH_SECRET={$secret}",
                $content,
            );
        } else {
            // Append new
            $content .= "\nBETTER_AUTH_SECRET={$secret}\n";
        }

        $this->files->put($envPath, $content);

        $this->components->info('BetterAuth secret generated successfully.');

        return self::SUCCESS;
    }
}
