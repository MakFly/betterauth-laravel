<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Guards;

use BetterAuth\Laravel\Services\BetterAuthManager;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/**
 * BetterAuth Session Guard for Laravel.
 *
 * Provides traditional session-based authentication with enhanced features:
 * - Stores session metadata in database (IP, user-agent, device)
 * - Multi-device session management
 * - Session revocation capabilities
 *
 * Unlike Laravel's default SessionGuard, this guard tracks detailed session
 * information for security and management purposes.
 */
final class BetterAuthSessionGuard implements Guard
{
    use GuardHelpers;

    private readonly string $name;
    private readonly Session $session;
    private readonly BetterAuthManager $authManager;
    private ?string $sessionId = null;
    private bool $loggedOut = false;

    public function __construct(
        string $name,
        ?UserProvider $provider,
        Session $session,
        BetterAuthManager $authManager,
    ) {
        $this->name = $name;
        $this->provider = $provider;
        $this->session = $session;
        $this->authManager = $authManager;
    }

    /**
     * Get the currently authenticated user.
     */
    public function user(): ?Authenticatable
    {
        if ($this->loggedOut) {
            return null;
        }

        // Return cached user if already retrieved
        if ($this->user !== null) {
            return $this->user;
        }

        // Get user ID from session
        $userId = $this->session->get($this->getName().'_id');

        if ($userId === null) {
            return null;
        }

        // Retrieve user from provider
        $this->user = $this->provider->retrieveById($userId);

        if ($this->user === null) {
            // User in session but not in database = invalid session
            $this->clearSessionData();
            return null;
        }

        // Update session last activity
        $this->updateSessionActivity();

        return $this->user;
    }

    /**
     * Validate a user's credentials.
     */
    public function validate(array $credentials = []): bool
    {
        $this->user = $this->provider->retrieveByCredentials($credentials);

        if ($this->user === null) {
            return false;
        }

        return $this->provider->validateCredentials($this->user, $credentials);
    }

    /**
     * Authenticate a user via credentials.
     */
    public function attempt(array $credentials = [], bool $remember = false): bool
    {
        $this->user = null;

        if ($this->validate($credentials)) {
            $this->login($this->user, $remember);

            return true;
        }

        // Clear user if validation failed (password didn't match)
        $this->user = null;

        return false;
    }

    /**
     * Log a user into the application.
     */
    public function login(Authenticatable $user, $remember = false): void
    {
        $this->clearSessionData();

        $this->setSession($user);

        // Update session activity in database
        $this->createOrUpdateSession($user);

        if ($remember) {
            $this->createRememberToken($user);
        }

        // Regenerate session ID for security
        $this->session->regenerate(true);
    }

    /**
     * Log the user out of the application.
     */
    public function logout(): void
    {
        if ($this->user) {
            // Mark session as revoked in database
            $this->revokeCurrentSession();

            // Clear remember me token if exists
            $this->clearRememberToken($this->user);
        }

        $this->clearSessionData();

        $this->user = null;
        $this->loggedOut = true;

        // Regenerate session ID
        $this->session->regenerate(true);
    }

    /**
     * Remove the user data from the session.
     */
    private function clearSessionData(): void
    {
        $this->session->remove($this->getName().'_id');
        $this->session->remove($this->getName().'_remember');
        $this->session->remove($this->getName().'_session_id');
    }

    /**
     * Set the user session data.
     */
    private function setSession(Authenticatable $user): void
    {
        $this->session->put($this->getName().'_id', $user->getAuthIdentifier());
        $this->session->put($this->getName().'_session_id', (string) Str::uuid7());
    }

    /**
     * Create or update session record in database.
     */
    private function createOrUpdateSession(Authenticatable $user): void
    {
        $sessionId = $this->session->get($this->getName().'_session_id');
        $request = request();

        DB::table(config('betterauth.tables.sessions'))->updateOrInsert(
            [
                'id' => $sessionId,
            ],
            [
                'user_id' => $user->getAuthIdentifier(),
                'ip_address' => $request->ip(),
                'user_agent' => $request->userAgent(),
                'device_type' => $this->detectDeviceType($request->userAgent()),
                'device_name' => $this->getDeviceName($request->userAgent()),
                'location' => null, // Could be enhanced with GeoIP
                'expires_at' => now()->addMinutes(config('session.lifetime', 120)),
                'last_activity_at' => now(),
                'created_at' => now(),
            ]
        );
    }

    /**
     * Update session last activity timestamp.
     */
    private function updateSessionActivity(): void
    {
        $sessionId = $this->session->get($this->getName().'_session_id');

        if ($sessionId !== null) {
            DB::table(config('betterauth.tables.sessions'))
                ->where('id', $sessionId)
                ->update(['last_activity_at' => now()]);
        }
    }

    /**
     * Revoke the current session.
     */
    private function revokeCurrentSession(): void
    {
        $sessionId = $this->session->get($this->getName().'_session_id');

        if ($sessionId !== null) {
            DB::table(config('betterauth.tables.sessions'))
                ->where('id', $sessionId)
                ->update(['expires_at' => now()->subMinute()]); // Mark as expired
        }
    }

    /**
     * Create a "remember me" token.
     */
    private function createRememberToken(Authenticatable $user): void
    {
        $token = Str::random(60);

        DB::table(config('betterauth.tables.refresh_tokens'))->insert([
            'token' => hash('sha256', $token),
            'user_id' => $user->getAuthIdentifier(),
            'expires_at' => now()->addDays(30),
            'created_at' => now(),
        ]);

        $this->session->put($this->getName().'_remember', $token);
    }

    /**
     * Clear the "remember me" token.
     */
    private function clearRememberToken(Authenticatable $user): void
    {
        $token = $this->session->get($this->getName().'_remember');

        if ($token !== null) {
            DB::table(config('betterauth.tables.refresh_tokens'))
                ->where('user_id', $user->getAuthIdentifier())
                ->where('token', hash('sha256', $token))
                ->delete();
        }
    }

    /**
     * Detect device type from user agent.
     */
    private function detectDeviceType(?string $userAgent): string
    {
        if ($userAgent === null) {
            return 'unknown';
        }

        // Check for tablet first (iPad is also matched by 'mobile' pattern)
        if (preg_match('/tablet|ipad/i', $userAgent)) {
            return 'tablet';
        }

        if (preg_match('/mobile|android|iphone/i', $userAgent)) {
            return 'mobile';
        }

        if (preg_match('/windows|macintosh|linux/i', $userAgent)) {
            return 'desktop';
        }

        return 'unknown';
    }

    /**
     * Get human-readable device name from user agent.
     */
    private function getDeviceName(?string $userAgent): string
    {
        if ($userAgent === null) {
            return 'Unknown Device';
        }

        if (preg_match('/Firefox/i', $userAgent)) {
            return 'Firefox';
        }

        if (preg_match('/Chrome/i', $userAgent) && !preg_match('/Edg/i', $userAgent)) {
            return 'Chrome';
        }

        if (preg_match('/Safari/i', $userAgent) && !preg_match('/Chrome/i', $userAgent)) {
            return 'Safari';
        }

        if (preg_match('/Edg/i', $userAgent)) {
            return 'Edge';
        }

        if (preg_match('/iPhone/i', $userAgent)) {
            return 'iPhone';
        }

        if (preg_match('/iPad/i', $userAgent)) {
            return 'iPad';
        }

        if (preg_match('/Android/i', $userAgent)) {
            return 'Android';
        }

        return 'Web Browser';
    }

    /**
     * Get the guard name.
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * Check if the user has a specific ability.
     * Currently not implemented, returns true.
     */
    public function hasAbility(array|string $ability): bool
    {
        return true;
    }

    /**
     * Determine if the current user is authenticated.
     */
    public function check(): bool
    {
        return $this->user() !== null;
    }

    /**
     * Determine if the current user is a guest.
     */
    public function guest(): bool
    {
        return !$this->check();
    }

    /**
     * Get the ID for the currently authenticated user.
     */
    public function id(): ?string
    {
        if ($this->user()) {
            return $this->user()->getAuthIdentifier();
        }

        return $this->session->get($this->getName().'_id');
    }

    /**
     * Set the current user.
     */
    public function setUser(Authenticatable $user): void
    {
        $this->user = $user;

        $this->session->put($this->getName().'_id', $user->getAuthIdentifier());
    }

    /**
     * Get the user provider used by the guard.
     */
    public function getProvider(): UserProvider
    {
        return $this->provider;
    }

    /**
     * Revoke all sessions for the current user except the current one.
     */
    public function revokeOtherSessions(): int
    {
        if (!$this->user()) {
            return 0;
        }

        $currentSessionId = $this->session->get($this->getName().'_session_id');

        return DB::table(config('betterauth.tables.sessions'))
            ->where('user_id', $this->user()->getAuthIdentifier())
            ->where('id', '!=', $currentSessionId)
            ->update(['expires_at' => now()->subMinute()]);
    }

    /**
     * Revoke all sessions for the current user.
     */
    public function revokeAllSessions(): int
    {
        if (!$this->user()) {
            return 0;
        }

        return DB::table(config('betterauth.tables.sessions'))
            ->where('user_id', $this->user()->getAuthIdentifier())
            ->update(['expires_at' => now()->subMinute()]);
    }

    /**
     * Get the session instance (for testing purposes).
     */
    public function get_session(): Session
    {
        return $this->session;
    }
}
