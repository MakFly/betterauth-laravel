<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;

beforeEach(function () {
    // Configure for session mode testing
    Config::set('auth.defaults.guard', 'betterauth-session');
    Config::set('auth.guards.betterauth-session', [
        'driver' => 'betterauth.session',
        'provider' => 'betterauth',
    ]);
});

describe('Session Mode Authentication', function () {
    it('authenticates user with credentials', function () {
        $user = $this->createTestUser([
            'email' => 'session@example.com',
            'password' => password_hash('Password123!', PASSWORD_ARGON2ID),
        ]);

        $guard = auth('betterauth-session');
        $success = $guard->attempt([
            'email' => 'session@example.com',
            'password' => 'Password123!',
        ]);

        expect($success)->toBeTrue();
        expect($guard->check())->toBeTrue();
        expect($guard->id())->toBe($user->id);
        expect($guard->user()->email)->toBe('session@example.com');
    });

    it('fails authentication with wrong password', function () {
        $this->createTestUser([
            'email' => 'session@example.com',
            'password' => password_hash('Password123!', PASSWORD_ARGON2ID),
        ]);

        $guard = auth('betterauth-session');
        $success = $guard->attempt([
            'email' => 'session@example.com',
            'password' => 'WrongPassword!',
        ]);

        expect($success)->toBeFalse();
        expect($guard->check())->toBeFalse();
        expect($guard->guest())->toBeTrue();
    });

    it('stores session in database with metadata', function () {
        $user = $this->createTestUser([
            'email' => 'session@example.com',
            'password' => password_hash('Password123!', PASSWORD_ARGON2ID),
        ]);

        auth('betterauth-session')->attempt([
            'email' => 'session@example.com',
            'password' => 'Password123!',
        ]);

        $session = DB::table('better_auth_sessions')
            ->where('user_id', $user->id)
            ->first();

        expect($session)->not->toBeNull();
        expect($session->ip_address)->toBeString();
        expect($session->user_agent)->toBeString();
        expect($session->device_type)->toBeIn(['desktop', 'mobile', 'tablet', 'unknown']);
        // SQLite returns dates as strings, convert to Carbon for type check
        expect(\Carbon\Carbon::parse($session->expires_at))->toBeInstanceOf(\Carbon\Carbon::class);
    });

    it('detects device type correctly', function () {
        $guard = auth('betterauth-session');

        // Access private method via reflection
        $reflection = new \ReflectionClass($guard);
        $method = $reflection->getMethod('detectDeviceType');
        $method->setAccessible(true);

        expect($method->invoke($guard, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'))->toBe('desktop');
        expect($method->invoke($guard, 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)'))->toBe('mobile');
        expect($method->invoke($guard, 'Mozilla/5.0 (iPad; CPU OS 14_0 like Mac OS X)'))->toBe('tablet');
        expect($method->invoke($guard, null))->toBe('unknown');
    });

    it('gets device name from user agent', function () {
        $guard = auth('betterauth-session');

        $reflection = new \ReflectionClass($guard);
        $method = $reflection->getMethod('getDeviceName');
        $method->setAccessible(true);

        expect($method->invoke($guard, 'Mozilla/5.0 (Windows NT 10.0) Firefox/95.0'))->toBe('Firefox');
        expect($method->invoke($guard, 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0) AppleWebKit/605.1.15'))->toBe('iPhone');
        expect($method->invoke($guard, null))->toBe('Unknown Device');
    });

    it('logs out user and revokes session', function () {
        $user = $this->createTestUser([
            'email' => 'session@example.com',
            'password' => password_hash('Password123!', PASSWORD_ARGON2ID),
        ]);

        $guard = auth('betterauth-session');
        $guard->attempt([
            'email' => 'session@example.com',
            'password' => 'Password123!',
        ]);

        $sessionId = DB::table('better_auth_sessions')
            ->where('user_id', $user->id)
            ->value('id');

        $guard->logout();

        expect($guard->check())->toBeFalse();
        expect($guard->guest())->toBeTrue();

        // Session should be revoked (expired)
        $session = DB::table('better_auth_sessions')
            ->where('id', $sessionId)
            ->first();

        expect($session)->not->toBeNull();
        expect(\Carbon\Carbon::parse($session->expires_at)->isPast())->toBeTrue();
    });

    it('returns null for invalid session user', function () {
        // Set a fake user ID in session
        $guard = auth('betterauth-session');
        $guard->get_session()->put($guard->getName().'_id', (string) \Illuminate\Support\Str::uuid7());

        expect($guard->user())->toBeNull();
        expect($guard->check())->toBeFalse();
    });

    it('revokes all sessions for user', function () {
        $user = $this->createTestUser([
            'email' => 'session@example.com',
            'password' => password_hash('Password123!', PASSWORD_ARGON2ID),
        ]);

        $guard = auth('betterauth-session');
        $guard->attempt([
            'email' => 'session@example.com',
            'password' => 'Password123!',
        ]);

        // Create additional sessions
        DB::table('better_auth_sessions')->insert([
            'id' => (string) \Illuminate\Support\Str::uuid7(),
            'user_id' => $user->id,
            'ip_address' => '127.0.0.1',
            'user_agent' => 'Test',
            'device_type' => 'desktop',
            'device_name' => 'Test Device',
            'expires_at' => now()->addHour(),
            'last_activity_at' => now(),
            'created_at' => now(),
        ]);

        $revoked = $guard->revokeAllSessions();

        expect($revoked)->toBeGreaterThanOrEqual(2); // Current session + created session

        // All sessions should be expired
        $activeSessions = DB::table('better_auth_sessions')
            ->where('user_id', $user->id)
            ->where('expires_at', '>', now())
            ->count();

        expect($activeSessions)->toBe(0);
    });

    it('revokes other sessions but keeps current one', function () {
        $user = $this->createTestUser([
            'email' => 'session@example.com',
            'password' => password_hash('Password123!', PASSWORD_ARGON2ID),
        ]);

        $guard = auth('betterauth-session');
        $guard->attempt([
            'email' => 'session@example.com',
            'password' => 'Password123!',
        ]);

        $currentSessionId = $guard->get_session()->get($guard->getName().'_session_id');

        // Create additional sessions
        DB::table('better_auth_sessions')->insert([
            'id' => (string) \Illuminate\Support\Str::uuid7(),
            'user_id' => $user->id,
            'ip_address' => '127.0.0.2',
            'user_agent' => 'Other Device',
            'device_type' => 'mobile',
            'device_name' => 'iPhone',
            'expires_at' => now()->addHour(),
            'last_activity_at' => now(),
            'created_at' => now(),
        ]);

        $revoked = $guard->revokeOtherSessions();

        expect($revoked)->toBe(1);

        // Current session should still be active
        $currentSession = DB::table('better_auth_sessions')
            ->where('id', $currentSessionId)
            ->first();

        expect($currentSession)->not->toBeNull();
        expect(\Carbon\Carbon::parse($currentSession->expires_at)->isFuture())->toBeTrue();

        // Other session should be expired
        $otherSessions = DB::table('better_auth_sessions')
            ->where('user_id', $user->id)
            ->where('id', '!=', $currentSessionId)
            ->where('expires_at', '>', now())
            ->count();

        expect($otherSessions)->toBe(0);
    });

    it('updates session activity on user retrieval', function () {
        $user = $this->createTestUser([
            'email' => 'session@example.com',
            'password' => password_hash('Password123!', PASSWORD_ARGON2ID),
        ]);

        $guard = auth('betterauth-session');
        $guard->attempt([
            'email' => 'session@example.com',
            'password' => 'Password123!',
        ]);

        $initialActivity = DB::table('better_auth_sessions')
            ->where('user_id', $user->id)
            ->value('last_activity_at');

        // Sleep to ensure timestamp difference
        sleep(2);

        // Simulate a new request by clearing the cached user
        // (In real HTTP requests, the guard is instantiated fresh each time)
        $reflection = new \ReflectionClass($guard);
        $property = $reflection->getProperty('user');
        $property->setAccessible(true);
        $property->setValue($guard, null);

        // Retrieve user again (should update activity)
        $guard->user();

        $updatedActivity = DB::table('better_auth_sessions')
            ->where('user_id', $user->id)
            ->value('last_activity_at');

        // Use Carbon to compare timestamps
        expect(\Carbon\Carbon::parse($updatedActivity)->greaterThan(\Carbon\Carbon::parse($initialActivity)))->toBeTrue();
    });

    it('returns correct guard name', function () {
        $guard = auth('betterauth-session');

        expect($guard->getName())->toBe('betterauth-session');
    });

    it('sets user manually', function () {
        $user = $this->createTestUser();

        $guard = auth('betterauth-session');
        $guard->setUser($user);

        expect($guard->user()->id)->toBe($user->id);
        expect($guard->check())->toBeTrue();
        expect($guard->id())->toBe($user->id);
    });

    it('returns user provider', function () {
        $guard = auth('betterauth-session');

        expect($guard->getProvider())->toBeInstanceOf(\Illuminate\Contracts\Auth\UserProvider::class);
    });
});

describe('Session Mode vs Sanctum Comparison', function () {
    it('demonstrates enhanced session tracking vs Sanctum', function () {
        $user = $this->createTestUser([
            'email' => 'session@example.com',
            'password' => password_hash('Password123!', PASSWORD_ARGON2ID),
        ]);

        auth('betterauth-session')->attempt([
            'email' => 'session@example.com',
            'password' => 'Password123!',
        ]);

        $session = DB::table('better_auth_sessions')
            ->where('user_id', $user->id)
            ->first();

        // BetterAuth tracks: IP, user-agent, device type/name, location (future)
        expect($session->ip_address)->not->toBeNull();
        expect($session->user_agent)->not->toBeNull();
        expect($session->device_type)->not->toBeNull();
        expect($session->device_name)->not->toBeNull();
        expect($session->last_activity_at)->not->toBeNull();
        // Sanctum doesn't track these details by default
    });

    it('provides session management features Sanctum lacks', function () {
        $user = $this->createTestUser([
            'email' => 'session@example.com',
            'password' => password_hash('Password123!', PASSWORD_ARGON2ID),
        ]);

        $guard = auth('betterauth-session');
        $guard->attempt([
            'email' => 'session@example.com',
            'password' => 'Password123!',
        ]);

        // Methods available in BetterAuth but not Sanctum:
        expect(method_exists($guard, 'revokeAllSessions'))->toBeTrue();
        expect(method_exists($guard, 'revokeOtherSessions'))->toBeTrue();

        // Create additional session
        DB::table('better_auth_sessions')->insert([
            'id' => (string) \Illuminate\Support\Str::uuid7(),
            'user_id' => $user->id,
            'ip_address' => '127.0.0.2',
            'user_agent' => 'Other Device',
            'device_type' => 'mobile',
            'device_name' => 'iPhone',
            'expires_at' => now()->addHour(),
            'last_activity_at' => now(),
            'created_at' => now(),
        ]);

        // revokeOtherSessions keeps current, revokes others
        $revoked = $guard->revokeOtherSessions();
        expect($revoked)->toBe(1);

        // Current user still authenticated
        expect($guard->check())->toBeTrue();
    });
});
