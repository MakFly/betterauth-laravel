<?php

declare(strict_types=1);

use BetterAuth\Laravel\Events\EmailVerified;
use BetterAuth\Laravel\Events\MagicLinkSent;
use BetterAuth\Laravel\Events\MagicLinkVerified;
use BetterAuth\Laravel\Events\PasswordChanged;
use BetterAuth\Laravel\Events\TokenAuthenticated;
use BetterAuth\Laravel\Events\TokenExpired;
use BetterAuth\Laravel\Events\TokenInvalid;
use BetterAuth\Laravel\Events\TokenRefreshed;
use BetterAuth\Laravel\Events\TwoFactorDisabled;
use BetterAuth\Laravel\Events\TwoFactorEnabled;
use BetterAuth\Laravel\Events\UserLoggedIn;
use BetterAuth\Laravel\Events\UserLoggedOut;
use BetterAuth\Laravel\Events\UserRegistered;
use BetterAuth\Laravel\Facades\BetterAuth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Mail;

beforeEach(function (): void {
    $this->artisan('migrate', ['--database' => 'testing']);
});

// ---------------------------------------------------------------------------
// UserRegistered
// ---------------------------------------------------------------------------

describe('UserRegistered event', function (): void {
    it('is dispatched on successful registration', function (): void {
        Event::fake([UserRegistered::class]);

        BetterAuth::signUp([
            'email' => 'ev-register@example.com',
            'password' => 'password123',
            'name' => 'Event User',
        ]);

        Event::assertDispatched(UserRegistered::class, function (UserRegistered $event) {
            return $event->user['email'] === 'ev-register@example.com'
                && isset($event->tokens['access_token'])
                && isset($event->tokens['refresh_token']);
        });
    });

    it('is dispatched via HTTP register endpoint', function (): void {
        Event::fake([UserRegistered::class]);

        $this->postJson('/auth/register', [
            'email' => 'ev-register-http@example.com',
            'password' => 'password123',
        ])->assertStatus(201);

        Event::assertDispatched(UserRegistered::class);
    });

    it('holds correct user data in payload', function (): void {
        $capturedEvent = null;

        Event::listen(UserRegistered::class, function (UserRegistered $event) use (&$capturedEvent) {
            $capturedEvent = $event;
        });

        BetterAuth::signUp([
            'email' => 'ev-payload@example.com',
            'password' => 'password123',
            'name' => 'Payload User',
        ]);

        expect($capturedEvent)->not->toBeNull();
        expect($capturedEvent->user['email'])->toBe('ev-payload@example.com');
        expect($capturedEvent->user)->not->toHaveKey('password');
        expect($capturedEvent->tokens['token_type'])->toBe('Bearer');
        expect($capturedEvent->tokens['expires_in'])->toBe(3600);
    });
});

// ---------------------------------------------------------------------------
// UserLoggedIn
// ---------------------------------------------------------------------------

describe('UserLoggedIn event', function (): void {
    it('is dispatched on successful login', function (): void {
        Event::fake([UserLoggedIn::class]);

        BetterAuth::signUp([
            'email' => 'ev-login@example.com',
            'password' => 'password123',
        ]);

        BetterAuth::signIn('ev-login@example.com', 'password123');

        Event::assertDispatched(UserLoggedIn::class, function (UserLoggedIn $event) {
            return $event->user['email'] === 'ev-login@example.com';
        });
    });

    it('is dispatched via HTTP login endpoint', function (): void {
        Event::fake([UserLoggedIn::class]);

        $this->createTestUser([
            'email' => 'ev-login-http@example.com',
            'password' => password_hash('password123', PASSWORD_ARGON2ID),
        ]);

        $this->postJson('/auth/login', [
            'email' => 'ev-login-http@example.com',
            'password' => 'password123',
        ])->assertStatus(200);

        Event::assertDispatched(UserLoggedIn::class);
    });

    it('is not dispatched on failed login', function (): void {
        Event::fake([UserLoggedIn::class]);

        $this->createTestUser([
            'email' => 'ev-login-fail@example.com',
            'password' => password_hash('correctpassword', PASSWORD_ARGON2ID),
        ]);

        $this->postJson('/auth/login', [
            'email' => 'ev-login-fail@example.com',
            'password' => 'wrongpassword',
        ])->assertStatus(422);

        Event::assertNotDispatched(UserLoggedIn::class);
    });
});

// ---------------------------------------------------------------------------
// UserLoggedOut
// ---------------------------------------------------------------------------

describe('UserLoggedOut event', function (): void {
    it('is dispatched on sign out', function (): void {
        Event::fake([UserLoggedOut::class]);

        $result = BetterAuth::signUp([
            'email' => 'ev-logout@example.com',
            'password' => 'password123',
        ]);

        BetterAuth::signOut($result['refresh_token']);

        Event::assertDispatched(UserLoggedOut::class);
    });

    it('is dispatched via HTTP logout endpoint', function (): void {
        Event::fake([UserLoggedOut::class]);

        $result = BetterAuth::signUp([
            'email' => 'ev-logout-http@example.com',
            'password' => 'password123',
        ]);

        $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/logout', [
                'refresh_token' => $result['refresh_token'],
            ])->assertStatus(200);

        Event::assertDispatched(UserLoggedOut::class);
    });

    it('is not dispatched when token does not exist', function (): void {
        Event::fake([UserLoggedOut::class]);

        BetterAuth::signOut('nonexistent-token');

        Event::assertNotDispatched(UserLoggedOut::class);
    });
});

// ---------------------------------------------------------------------------
// TokenRefreshed
// ---------------------------------------------------------------------------

describe('TokenRefreshed event', function (): void {
    it('is dispatched on token refresh', function (): void {
        Event::fake([TokenRefreshed::class]);

        $result = BetterAuth::signUp([
            'email' => 'ev-refresh@example.com',
            'password' => 'password123',
        ]);

        BetterAuth::refresh($result['refresh_token']);

        Event::assertDispatched(TokenRefreshed::class, function (TokenRefreshed $event) {
            return isset($event->tokens['access_token'])
                && isset($event->tokens['refresh_token']);
        });
    });

    it('is dispatched via HTTP refresh endpoint', function (): void {
        Event::fake([TokenRefreshed::class]);

        $result = BetterAuth::signUp([
            'email' => 'ev-refresh-http@example.com',
            'password' => 'password123',
        ]);

        $this->postJson('/auth/refresh', [
            'refresh_token' => $result['refresh_token'],
        ])->assertStatus(200);

        Event::assertDispatched(TokenRefreshed::class);
    });
});

// ---------------------------------------------------------------------------
// TokenAuthenticated
// ---------------------------------------------------------------------------

describe('TokenAuthenticated event', function (): void {
    it('is dispatched when a valid token authenticates a user', function (): void {
        Event::fake([TokenAuthenticated::class]);

        $result = BetterAuth::signUp([
            'email' => 'ev-tokenauth@example.com',
            'password' => 'password123',
        ]);

        $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->getJson('/auth/me')
            ->assertStatus(200);

        Event::assertDispatched(TokenAuthenticated::class, function (TokenAuthenticated $event) {
            return $event->user !== null
                && isset($event->payload['sub'])
                && isset($event->payload['email']);
        });
    });
});

// ---------------------------------------------------------------------------
// TokenExpired / TokenInvalid
// ---------------------------------------------------------------------------

describe('TokenInvalid event', function (): void {
    it('is dispatched when an invalid token is used', function (): void {
        Event::fake([TokenInvalid::class]);

        $this->withHeader('Authorization', 'Bearer invalidtoken.abc.def')
            ->getJson('/auth/me');

        Event::assertDispatched(TokenInvalid::class);
    });
});

// ---------------------------------------------------------------------------
// MagicLinkSent
// ---------------------------------------------------------------------------

describe('MagicLinkSent event', function (): void {
    it('is dispatched when a magic link is sent', function (): void {
        Event::fake([MagicLinkSent::class]);
        Mail::fake();

        $this->createTestUser(['email' => 'ev-magic@example.com']);

        $this->postJson('/auth/magic-link', [
            'email' => 'ev-magic@example.com',
        ])->assertStatus(200);

        Event::assertDispatched(MagicLinkSent::class);
    });
});

// ---------------------------------------------------------------------------
// MagicLinkVerified
// ---------------------------------------------------------------------------

describe('MagicLinkVerified event', function (): void {
    it('is dispatched when a magic link is verified', function (): void {
        Event::fake([MagicLinkVerified::class]);

        $this->createTestUser(['email' => 'ev-magic-verify@example.com']);

        $token = bin2hex(random_bytes(32));
        $hashedToken = hash('sha256', $token);

        \Illuminate\Support\Facades\DB::table('better_auth_magic_links')->insert([
            'id' => (string) \Illuminate\Support\Str::uuid7(),
            'email' => 'ev-magic-verify@example.com',
            'token' => $hashedToken,
            'expires_at' => now()->addMinutes(15),
            'used_at' => null,
            'created_at' => now(),
        ]);

        $this->getJson('/auth/magic-link/verify?token=' . $token)
            ->assertStatus(200);

        Event::assertDispatched(MagicLinkVerified::class);
    });
});

// ---------------------------------------------------------------------------
// TwoFactorEnabled / TwoFactorDisabled
// ---------------------------------------------------------------------------

describe('TwoFactor events', function (): void {
    it('TwoFactorEnabled is dispatched when 2FA is enabled', function (): void {
        Event::fake([TwoFactorEnabled::class]);

        $result = BetterAuth::signUp([
            'email' => 'ev-2fa-enable@example.com',
            'password' => 'password123',
        ]);

        $setupResponse = $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/setup');

        $secret = $setupResponse->json('secret');
        $code = generateTotpCodeForEvents($secret);

        $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/enable', ['code' => $code]);

        Event::assertDispatched(TwoFactorEnabled::class, function (TwoFactorEnabled $event) {
            return $event->user !== null
                && is_array($event->recoveryCodes)
                && count($event->recoveryCodes) === 8;
        });
    });

    it('TwoFactorDisabled is dispatched when 2FA is disabled', function (): void {
        Event::fake([TwoFactorDisabled::class]);

        $result = BetterAuth::signUp([
            'email' => 'ev-2fa-disable@example.com',
            'password' => 'password123',
        ]);

        $setupResponse = $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/setup');

        $secret = $setupResponse->json('secret');
        $code = generateTotpCodeForEvents($secret);

        $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/enable', ['code' => $code]);

        $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->deleteJson('/auth/2fa', ['password' => 'password123']);

        Event::assertDispatched(TwoFactorDisabled::class);
    });
});

// ---------------------------------------------------------------------------
// Event constructors / data integrity
// ---------------------------------------------------------------------------

describe('Event data integrity', function (): void {
    it('UserLoggedIn holds user data and tokens', function (): void {
        $capturedEvent = null;

        Event::listen(UserLoggedIn::class, function (UserLoggedIn $event) use (&$capturedEvent) {
            $capturedEvent = $event;
        });

        BetterAuth::signUp([
            'email' => 'ev-integrity@example.com',
            'password' => 'password123',
        ]);

        BetterAuth::signIn('ev-integrity@example.com', 'password123');

        expect($capturedEvent)->not->toBeNull();
        expect($capturedEvent->user)->toBeArray();
        expect($capturedEvent->user)->not->toHaveKey('password');
        expect($capturedEvent->tokens)->toHaveKeys(['access_token', 'refresh_token', 'token_type', 'expires_in']);
    });

    it('TokenRefreshed holds user_id and new tokens', function (): void {
        $capturedEvent = null;

        Event::listen(TokenRefreshed::class, function (TokenRefreshed $event) use (&$capturedEvent) {
            $capturedEvent = $event;
        });

        $result = BetterAuth::signUp([
            'email' => 'ev-refresh-integrity@example.com',
            'password' => 'password123',
        ]);

        BetterAuth::refresh($result['refresh_token']);

        expect($capturedEvent)->not->toBeNull();
        expect($capturedEvent->userId)->toBeString()->not->toBeEmpty();
        expect($capturedEvent->tokens)->toHaveKeys(['access_token', 'refresh_token', 'token_type', 'expires_in']);
    });
});

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

function generateTotpCodeForEvents(string $secret): string
{
    $map = array_flip(str_split('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'));
    $secret = strtoupper(str_replace('=', '', $secret));

    $buffer = 0;
    $length = 0;
    $key = '';

    foreach (str_split($secret) as $char) {
        if (! isset($map[$char])) {
            continue;
        }
        $buffer = ($buffer << 5) | $map[$char];
        $length += 5;
        if ($length >= 8) {
            $length -= 8;
            $key .= chr(($buffer >> $length) & 0xFF);
        }
    }

    $timeSlice = (int) floor(time() / 30);
    $time = pack('N*', 0, $timeSlice);
    $hmac = hash_hmac('sha1', $time, $key, true);
    $offset = ord(substr($hmac, -1)) & 0x0F;
    $binary = (ord($hmac[$offset]) & 0x7F) << 24
        | (ord($hmac[$offset + 1]) & 0xFF) << 16
        | (ord($hmac[$offset + 2]) & 0xFF) << 8
        | (ord($hmac[$offset + 3]) & 0xFF);

    return str_pad((string) ($binary % 1000000), 6, '0', STR_PAD_LEFT);
}
