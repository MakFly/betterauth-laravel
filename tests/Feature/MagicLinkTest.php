<?php

declare(strict_types=1);

use BetterAuth\Laravel\Facades\BetterAuth;
use BetterAuth\Laravel\Events\MagicLinkSent;
use BetterAuth\Laravel\Events\MagicLinkVerified;
use BetterAuth\Laravel\Services\MagicLinkService;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Mail;

describe('Magic Link', function () {
    it('sends magic link to existing user', function () {
        Event::fake([MagicLinkSent::class]);
        Mail::fake();

        // Create user first
        $this->createTestUser(['email' => 'magic@example.com']);

        $response = $this->postJson('/auth/magic-link', [
            'email' => 'magic@example.com',
        ]);

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'If an account exists with this email, you will receive a magic link shortly.',
            ]);

        // Verify token was created
        $token = DB::table('better_auth_magic_links')
            ->where('email', 'magic@example.com')
            ->whereNull('used_at')
            ->first();

        expect($token)->not->toBeNull();

        Event::assertDispatched(MagicLinkSent::class);
    });

    it('sends magic link to non-existing user (prevents enumeration)', function () {
        Event::fake([MagicLinkSent::class]);
        Mail::fake();

        $response = $this->postJson('/auth/magic-link', [
            'email' => 'nonexistent@example.com',
        ]);

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'If an account exists with this email, you will receive a magic link shortly.',
            ]);

        // Token should still be created for security
        $token = DB::table('better_auth_magic_links')
            ->where('email', 'nonexistent@example.com')
            ->whereNull('used_at')
            ->first();

        expect($token)->not->toBeNull();
    });

    it('validates email format', function () {
        $response = $this->postJson('/auth/magic-link', [
            'email' => 'not-an-email',
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['email']);
    });

    it('verifies magic link and authenticates existing user', function () {
        Event::fake([MagicLinkVerified::class]);

        // Create user
        $this->createTestUser(['email' => 'verify@example.com']);

        // Generate magic link token directly
        $token = bin2hex(random_bytes(32));
        $hashedToken = hash('sha256', $token);

        DB::table('better_auth_magic_links')->insert([
            'id' => (string) \Illuminate\Support\Str::uuid7(),
            'email' => 'verify@example.com',
            'token' => $hashedToken,
            'expires_at' => now()->addMinutes(15),
            'used_at' => null,
            'created_at' => now(),
        ]);

        $response = $this->getJson('/auth/magic-link/verify?token=' . $token);

        $response->assertStatus(200)
            ->assertJsonStructure([
                'message',
                'user' => ['id', 'email'],
                'access_token',
                'refresh_token',
                'token_type',
                'expires_in',
            ])
            ->assertJson([
                'message' => 'Authenticated successfully',
                'token_type' => 'Bearer',
            ]);

        expect($response->json('access_token'))->toBeValidToken();

        // Token should be marked as used
        $magicLink = DB::table('better_auth_magic_links')
            ->where('email', 'verify@example.com')
            ->first();

        expect($magicLink->used_at)->not->toBeNull();

        Event::assertDispatched(MagicLinkVerified::class);
    });

    it('auto-registers new user on magic link verification', function () {
        Event::fake([MagicLinkVerified::class]);

        // Generate magic link token for non-existing user
        $token = bin2hex(random_bytes(32));
        $hashedToken = hash('sha256', $token);

        DB::table('better_auth_magic_links')->insert([
            'id' => (string) \Illuminate\Support\Str::uuid7(),
            'email' => 'newuser@example.com',
            'token' => $hashedToken,
            'expires_at' => now()->addMinutes(15),
            'used_at' => null,
            'created_at' => now(),
        ]);

        $response = $this->getJson('/auth/magic-link/verify?token=' . $token);

        $response->assertStatus(201)
            ->assertJson([
                'message' => 'Account created and authenticated',
            ]);

        // User should exist now
        $user = DB::table('users')->where('email', 'newuser@example.com')->first();
        expect($user)->not->toBeNull();
    });

    it('fails verification with expired token', function () {
        $token = bin2hex(random_bytes(32));
        $hashedToken = hash('sha256', $token);

        DB::table('better_auth_magic_links')->insert([
            'id' => (string) \Illuminate\Support\Str::uuid7(),
            'email' => 'expired@example.com',
            'token' => $hashedToken,
            'expires_at' => now()->subMinutes(1), // Expired
            'used_at' => null,
            'created_at' => now(),
        ]);

        $response = $this->getJson('/auth/magic-link/verify?token=' . $token);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['token']);
    });

    it('fails verification with already used token', function () {
        $token = bin2hex(random_bytes(32));
        $hashedToken = hash('sha256', $token);

        DB::table('better_auth_magic_links')->insert([
            'id' => (string) \Illuminate\Support\Str::uuid7(),
            'email' => 'used@example.com',
            'token' => $hashedToken,
            'expires_at' => now()->addMinutes(15),
            'used_at' => now()->subMinute(), // Already used
            'created_at' => now(),
        ]);

        $response = $this->getJson('/auth/magic-link/verify?token=' . $token);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['token']);
    });

    it('fails verification with invalid token', function () {
        $response = $this->getJson('/auth/magic-link/verify?token=invalidtoken123');

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['token']);
    });

    it('checks magic link validity', function () {
        $token = bin2hex(random_bytes(32));
        $hashedToken = hash('sha256', $token);

        DB::table('better_auth_magic_links')->insert([
            'id' => (string) \Illuminate\Support\Str::uuid7(),
            'email' => 'check@example.com',
            'token' => $hashedToken,
            'expires_at' => now()->addMinutes(15),
            'used_at' => null,
            'created_at' => now(),
        ]);

        $response = $this->postJson('/auth/magic-link/check', [
            'token' => $token,
            'email' => 'check@example.com',
        ]);

        $response->assertStatus(200)
            ->assertJson([
                'valid' => true,
            ]);
    });

    it('revokes old tokens when sending new magic link', function () {
        // Send first magic link
        $this->postJson('/auth/magic-link', [
            'email' => 'revoke@example.com',
        ]);

        $firstToken = DB::table('better_auth_magic_links')
            ->where('email', 'revoke@example.com')
            ->first();

        expect($firstToken)->not->toBeNull();

        // Send second magic link
        $this->postJson('/auth/magic-link', [
            'email' => 'revoke@example.com',
        ]);

        // First token should be revoked (deleted)
        $oldTokens = DB::table('better_auth_magic_links')
            ->where('id', $firstToken->id)
            ->count();

        expect($oldTokens)->toBe(0);

        // Only new token should exist
        $activeTokens = DB::table('better_auth_magic_links')
            ->where('email', 'revoke@example.com')
            ->whereNull('used_at')
            ->count();

        expect($activeTokens)->toBe(1);
    });

    it('allows email parameter in verify for backward compatibility', function () {
        $this->createTestUser(['email' => 'compat@example.com']);

        $token = bin2hex(random_bytes(32));
        $hashedToken = hash('sha256', $token);

        DB::table('better_auth_magic_links')->insert([
            'id' => (string) \Illuminate\Support\Str::uuid7(),
            'email' => 'compat@example.com',
            'token' => $hashedToken,
            'expires_at' => now()->addMinutes(15),
            'used_at' => null,
            'created_at' => now(),
        ]);

        // Verify with both token and email
        $response = $this->getJson('/auth/magic-link/verify?token=' . $token . '&email=compat@example.com');

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'Authenticated successfully',
            ]);
    });
});

describe('Magic Link Service', function () {
    it('generates secure tokens', function () {
        $service = app(MagicLinkService::class);

        $reflection = new \ReflectionClass($service);
        $method = $reflection->getMethod('generateToken');
        $method->setAccessible(true);

        $token = $method->invoke($service);

        expect($token)->toHaveLength(64); // 32 bytes = 64 hex chars
        expect(ctype_xdigit($token))->toBeTrue();
    });

    it('correctly hashes tokens', function () {
        $rawToken = bin2hex(random_bytes(32));
        $hashedToken = hash('sha256', $rawToken);

        expect($hashedToken)->toHaveLength(64);
        expect($hashedToken)->not->toBe($rawToken);
    });

    it('gets email from token', function () {
        $service = app(MagicLinkService::class);

        $rawToken = bin2hex(random_bytes(32));
        $hashedToken = hash('sha256', $rawToken);

        DB::table('better_auth_magic_links')->insert([
            'id' => (string) \Illuminate\Support\Str::uuid7(),
            'email' => 'getemail@example.com',
            'token' => $hashedToken,
            'expires_at' => now()->addMinutes(15),
            'used_at' => null,
            'created_at' => now(),
        ]);

        $email = $service->getEmailFromToken($rawToken);

        expect($email)->toBe('getemail@example.com');
    });

    it('returns null for non-existent token', function () {
        $service = app(MagicLinkService::class);

        $email = $service->getEmailFromToken('nonexistenttoken');

        expect($email)->toBeNull();
    });
});
