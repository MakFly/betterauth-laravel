<?php

declare(strict_types=1);

use BetterAuth\Laravel\Facades\BetterAuth;
use BetterAuth\Laravel\Services\BetterAuthManager;

beforeEach(function (): void {
    $this->artisan('migrate', ['--database' => 'testing']);
});

describe('BetterAuth Facade', function (): void {
    it('resolves the manager instance', function (): void {
        $manager = app(BetterAuthManager::class);

        expect($manager)->toBeInstanceOf(BetterAuthManager::class);
    });

    it('signs up a user', function (): void {
        $result = BetterAuth::signUp([
            'email' => 'facade@example.com',
            'password' => 'securepassword123',
            'name' => 'Facade Test',
        ]);

        expect($result)
            ->toBeArray()
            ->toHaveKeys(['user', 'access_token', 'refresh_token', 'token_type', 'expires_in']);

        expect($result['user']['email'])->toBe('facade@example.com');
        expect($result['token_type'])->toBe('Bearer');
        expect($result['expires_in'])->toBe(3600);
    });

    it('signs in a user', function (): void {
        BetterAuth::signUp([
            'email' => 'signin@example.com',
            'password' => 'password123',
        ]);

        $result = BetterAuth::signIn('signin@example.com', 'password123');

        expect($result)
            ->toBeArray()
            ->toHaveKeys(['user', 'access_token', 'refresh_token']);
    });

    it('verifies a valid token', function (): void {
        $result = BetterAuth::signUp([
            'email' => 'verify@example.com',
            'password' => 'password123',
        ]);

        $payload = BetterAuth::verify($result['access_token']);

        expect($payload)
            ->toBeArray()
            ->toHaveKey('sub')
            ->toHaveKey('email');

        expect($payload['email'])->toBe('verify@example.com');
    });

    it('fails verification for invalid token', function (): void {
        $threw = false;
        try {
            BetterAuth::verify('invalid.token.here');
        } catch (\Throwable) {
            $threw = true;
        }
        expect($threw)->toBeTrue();
    });

    it('checks email existence', function (): void {
        expect(BetterAuth::emailExists('notexist@example.com'))->toBeFalse();

        BetterAuth::signUp([
            'email' => 'exists@example.com',
            'password' => 'password123',
        ]);

        expect(BetterAuth::emailExists('exists@example.com'))->toBeTrue();
    });

    it('gets user by id', function (): void {
        $result = BetterAuth::signUp([
            'email' => 'byid@example.com',
            'password' => 'password123',
        ]);

        $userId = $result['user']['id'];
        $user = BetterAuth::getUserById($userId);

        expect($user)->not->toBeNull();
        expect($user['email'])->toBe('byid@example.com');
    });

    it('gets user by email', function (): void {
        BetterAuth::signUp([
            'email' => 'byemail@example.com',
            'password' => 'password123',
        ]);

        $user = BetterAuth::getUserByEmail('byemail@example.com');

        expect($user)->not->toBeNull();
        expect($user['email'])->toBe('byemail@example.com');
    });

    it('returns null for non-existent user', function (): void {
        expect(BetterAuth::getUserByEmail('nonexistent@example.com'))->toBeNull();
        expect(BetterAuth::getUserById('nonexistent-id'))->toBeNull();
    });
});

describe('Password Hashing', function (): void {
    it('hashes password with argon2id', function (): void {
        $hash = BetterAuth::hashPassword('mypassword');

        expect($hash)
            ->toBeString()
            ->toStartWith('$argon2id$');
    });

    it('verifies correct password', function (): void {
        $hash = BetterAuth::hashPassword('mypassword');

        expect(BetterAuth::verifyPassword('mypassword', $hash))->toBeTrue();
        expect(BetterAuth::verifyPassword('wrongpassword', $hash))->toBeFalse();
    });
});

describe('Token Refresh', function (): void {
    it('refreshes tokens', function (): void {
        $result = BetterAuth::signUp([
            'email' => 'refreshtest@example.com',
            'password' => 'password123',
        ]);

        $newTokens = BetterAuth::refresh($result['refresh_token']);

        expect($newTokens)
            ->toBeArray()
            ->toHaveKeys(['access_token', 'refresh_token', 'token_type', 'expires_in']);

        // Old refresh token should be consumed (one-time use)
        expect(fn () => BetterAuth::refresh($result['refresh_token']))
            ->toThrow(\BetterAuth\Core\Exceptions\InvalidTokenException::class);
    });

    it('signs out and revokes token', function (): void {
        $result = BetterAuth::signUp([
            'email' => 'signout@example.com',
            'password' => 'password123',
        ]);

        BetterAuth::signOut($result['refresh_token']);

        // Token should be revoked
        expect(fn () => BetterAuth::refresh($result['refresh_token']))
            ->toThrow(\BetterAuth\Core\Exceptions\InvalidTokenException::class);
    });
});

describe('Config Access', function (): void {
    it('returns configuration array', function (): void {
        $config = BetterAuth::getConfig();

        expect($config)
            ->toBeArray()
            ->toHaveKey('mode')
            ->toHaveKey('secret');
    });

    it('returns token service', function (): void {
        $tokenService = BetterAuth::getTokenService();

        expect($tokenService)->toBeInstanceOf(\BetterAuth\Core\Interfaces\TokenSignerInterface::class);
    });
});
