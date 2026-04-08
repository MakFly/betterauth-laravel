<?php

declare(strict_types=1);

use BetterAuth\Laravel\Commands\SecretCommand;
use Illuminate\Filesystem\Filesystem;

describe('SecretCommand', function (): void {
    it('generates secret and displays it with --show option', function (): void {
        $this->artisan('betterauth:secret', ['--show' => true])
            ->expectsOutputToContain('BetterAuth Secret:')
            ->assertSuccessful();
    });

    it('generates secret without --show writes to .env file', function (): void {
        $tmpDir = sys_get_temp_dir() . '/ba_secret_write_' . uniqid();
        mkdir($tmpDir);
        file_put_contents($tmpDir . '/.env', "APP_ENV=testing\n");

        app()->setBasePath($tmpDir);

        $this->artisan('betterauth:secret')
            ->assertSuccessful();

        $content = file_get_contents($tmpDir . '/.env');
        expect($content)->toContain('BETTER_AUTH_SECRET=');

        unlink($tmpDir . '/.env');
        rmdir($tmpDir);
    });

    it('warns when secret already exists without --force', function (): void {
        $tmpDir = sys_get_temp_dir() . '/ba_secret_' . uniqid();
        mkdir($tmpDir);
        file_put_contents($tmpDir . '/.env', "BETTER_AUTH_SECRET=existingsecret\n");

        app()->setBasePath($tmpDir);

        $this->artisan('betterauth:secret')
            ->assertFailed();

        unlink($tmpDir . '/.env');
        rmdir($tmpDir);
    });

    it('overwrites secret when --force is used', function (): void {
        $tmpDir = sys_get_temp_dir() . '/ba_secret_force_' . uniqid();
        mkdir($tmpDir);
        file_put_contents($tmpDir . '/.env', "BETTER_AUTH_SECRET=oldsecret\n");

        app()->setBasePath($tmpDir);

        $this->artisan('betterauth:secret', ['--force' => true])
            ->assertSuccessful();

        $content = file_get_contents($tmpDir . '/.env');
        expect($content)->not->toContain('oldsecret');
        expect($content)->toContain('BETTER_AUTH_SECRET=');

        unlink($tmpDir . '/.env');
        rmdir($tmpDir);
    });

    it('fails when .env file does not exist', function (): void {
        $tmpDir = sys_get_temp_dir() . '/ba_secret_noenv_' . uniqid();
        mkdir($tmpDir);

        app()->setBasePath($tmpDir);

        $this->artisan('betterauth:secret')
            ->assertFailed()
            ->expectsOutputToContain('.env file not found');

        rmdir($tmpDir);
    });
});

describe('SecretCommand unit', function (): void {
    it('generates a 64-character hex secret', function (): void {
        $secret = bin2hex(random_bytes(32));
        expect(strlen($secret))->toBe(64);
        expect(ctype_xdigit($secret))->toBeTrue();
    });
});
