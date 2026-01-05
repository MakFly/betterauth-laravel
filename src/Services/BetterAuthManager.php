<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Services;

use BetterAuth\Core\Exceptions\InvalidCredentialsException;
use BetterAuth\Core\Exceptions\InvalidTokenException;
use BetterAuth\Core\Interfaces\TokenSignerInterface;
use BetterAuth\Core\PasswordHasher;
use BetterAuth\Laravel\Events\TokenRefreshed;
use BetterAuth\Laravel\Events\UserLoggedIn;
use BetterAuth\Laravel\Events\UserLoggedOut;
use BetterAuth\Laravel\Events\UserRegistered;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;

/**
 * BetterAuthManager - Pure Laravel implementation using Eloquent.
 *
 * Uses only the core primitives (TokenService, PasswordHasher) and implements
 * all auth logic with Eloquent models for maximum Laravel compatibility.
 */
final class BetterAuthManager
{
    /** @var class-string<Model&Authenticatable> */
    private string $userModel;

    private string $refreshTokenTable;

    public function __construct(
        private readonly TokenSignerInterface $tokenService,
        private readonly PasswordHasher $passwordHasher,
        /** @var array<string, mixed> */
        private readonly array $config,
    ) {
        $this->userModel = $config['user_model'] ?? 'App\\Models\\User';
        $this->refreshTokenTable = $config['tables']['refresh_tokens'] ?? 'better_auth_refresh_tokens';
    }

    /**
     * Register a new user.
     *
     * @param  array{email: string, password: string, name?: string, avatar?: string}  $data
     * @return array{user: array<string, mixed>, access_token: string, refresh_token: string, token_type: string, expires_in: int}
     */
    public function signUp(array $data): array
    {
        $hashedPassword = $this->passwordHasher->hash($data['password']);

        /** @var Model&Authenticatable $user */
        $user = new $this->userModel;

        // Generate UUID if configured
        if ($this->usesUuid()) {
            $user->{$user->getKeyName()} = (string) Str::uuid7();
        }

        $user->fill([
            'email' => $data['email'],
            'password' => $hashedPassword,
            'name' => $data['name'] ?? null,
            'avatar' => $data['avatar'] ?? null,
            'roles' => ['ROLE_USER'],
        ]);

        $user->save();

        // Create token pair
        $tokens = $this->createTokensForUser($user);

        $userArray = $this->userToArray($user);

        $result = [
            'user' => $userArray,
            'access_token' => $tokens['access_token'],
            'refresh_token' => $tokens['refresh_token'],
            'token_type' => 'Bearer',
            'expires_in' => $this->getAccessTokenLifetime(),
        ];

        Event::dispatch(new UserRegistered($userArray, $result));

        return $result;
    }

    /**
     * Authenticate a user with email and password.
     *
     * @return array{user: array<string, mixed>, access_token: string, refresh_token: string, token_type: string, expires_in: int}
     *
     * @throws InvalidCredentialsException
     */
    public function signIn(string $email, string $password): array
    {
        /** @var Model&Authenticatable|null $user */
        $user = $this->userModel::where('email', $email)->first();

        if ($user === null) {
            throw new InvalidCredentialsException('Invalid credentials');
        }

        $storedPassword = $user->getAuthPassword();

        if ($storedPassword === null || ! $this->passwordHasher->verify($password, $storedPassword)) {
            throw new InvalidCredentialsException('Invalid credentials');
        }

        $tokens = $this->createTokensForUser($user);
        $userArray = $this->userToArray($user);

        $result = [
            'user' => $userArray,
            'access_token' => $tokens['access_token'],
            'refresh_token' => $tokens['refresh_token'],
            'token_type' => 'Bearer',
            'expires_in' => $this->getAccessTokenLifetime(),
        ];

        Event::dispatch(new UserLoggedIn($userArray, $result));

        return $result;
    }

    /**
     * Sign out and revoke the refresh token.
     */
    public function signOut(string $refreshToken): void
    {
        $hashedToken = hash('sha256', $refreshToken);

        $token = DB::table($this->refreshTokenTable)
            ->where('token', $hashedToken)
            ->first();

        if ($token !== null) {
            DB::table($this->refreshTokenTable)
                ->where('token', $hashedToken)
                ->update(['revoked' => true]);

            Event::dispatch(new UserLoggedOut($token->user_id));
        }
    }

    /**
     * Refresh the access token using a refresh token.
     *
     * @return array{access_token: string, refresh_token: string, token_type: string, expires_in: int}
     *
     * @throws InvalidTokenException
     */
    public function refresh(string $refreshToken): array
    {
        $hashedToken = hash('sha256', $refreshToken);

        // Atomic consume with lock
        $token = DB::transaction(function () use ($hashedToken) {
            $token = DB::table($this->refreshTokenTable)
                ->where('token', $hashedToken)
                ->where('revoked', false)
                ->where('expires_at', '>', now())
                ->lockForUpdate()
                ->first();

            if ($token === null) {
                return null;
            }

            // Mark as revoked (one-time use)
            DB::table($this->refreshTokenTable)
                ->where('token', $hashedToken)
                ->update(['revoked' => true]);

            return $token;
        });

        if ($token === null) {
            throw new InvalidTokenException('Invalid or expired refresh token');
        }

        // Get the user
        /** @var Model&Authenticatable|null $user */
        $user = $this->userModel::find($token->user_id);

        if ($user === null) {
            throw new InvalidTokenException('User not found');
        }

        // Create new token pair
        $newTokens = $this->createTokensForUser($user);

        // Update old token with replacement reference
        DB::table($this->refreshTokenTable)
            ->where('token', $hashedToken)
            ->update(['replaced_by' => hash('sha256', $newTokens['refresh_token'])]);

        $result = [
            'access_token' => $newTokens['access_token'],
            'refresh_token' => $newTokens['refresh_token'],
            'token_type' => 'Bearer',
            'expires_in' => $this->getAccessTokenLifetime(),
        ];

        Event::dispatch(new TokenRefreshed($token->user_id, $result));

        return $result;
    }

    /**
     * Verify and decode an access token.
     *
     * @return array<string, mixed>
     *
     * @throws InvalidTokenException
     */
    public function verify(string $accessToken): array
    {
        return $this->tokenService->verify($accessToken);
    }

    /**
     * Revoke all refresh tokens for a user.
     */
    public function revokeAll(string $userId): int
    {
        return DB::table($this->refreshTokenTable)
            ->where('user_id', $userId)
            ->where('revoked', false)
            ->update(['revoked' => true]);
    }

    /**
     * Get user by ID.
     *
     * @return array<string, mixed>|null
     */
    public function getUserById(string $id): ?array
    {
        /** @var Model&Authenticatable|null $user */
        $user = $this->userModel::find($id);

        return $user ? $this->userToArray($user) : null;
    }

    /**
     * Get user by email.
     *
     * @return array<string, mixed>|null
     */
    public function getUserByEmail(string $email): ?array
    {
        /** @var Model&Authenticatable|null $user */
        $user = $this->userModel::where('email', $email)->first();

        return $user ? $this->userToArray($user) : null;
    }

    /**
     * Get user model by email (returns the Eloquent model instance).
     *
     * @return (Model&Authenticatable)|null
     */
    public function getUserModel(string $email): ?Model
    {
        /** @var (Model&Authenticatable)|null */
        return $this->userModel::where('email', $email)->first();
    }

    /**
     * Check if an email is already registered.
     */
    public function emailExists(string $email): bool
    {
        return $this->userModel::where('email', $email)->exists();
    }

    /**
     * Verify a user's email.
     */
    public function verifyEmail(string $userId): bool
    {
        return $this->userModel::where('id', $userId)
            ->update(['email_verified_at' => now()]) > 0;
    }

    /**
     * Update user's password.
     *
     * @throws InvalidCredentialsException
     */
    public function updatePassword(string $userId, string $currentPassword, string $newPassword): bool
    {
        /** @var Model&Authenticatable|null $user */
        $user = $this->userModel::find($userId);

        if ($user === null) {
            throw new InvalidCredentialsException('User not found');
        }

        $storedPassword = $user->getAuthPassword();

        if ($storedPassword === null || ! $this->passwordHasher->verify($currentPassword, $storedPassword)) {
            throw new InvalidCredentialsException('Current password is incorrect');
        }

        $user->password = $this->passwordHasher->hash($newPassword);
        $user->save();

        // Revoke all existing refresh tokens for security
        $this->revokeAll($userId);

        return true;
    }

    /**
     * Hash a password using Argon2id.
     */
    public function hashPassword(string $password): string
    {
        return $this->passwordHasher->hash($password);
    }

    /**
     * Verify a password against a hash.
     */
    public function verifyPassword(string $password, string $hash): bool
    {
        return $this->passwordHasher->verify($password, $hash);
    }

    /**
     * Get the TokenService instance.
     */
    public function getTokenService(): TokenSignerInterface
    {
        return $this->tokenService;
    }

    /**
     * Get the configuration.
     *
     * @return array<string, mixed>
     */
    public function getConfig(): array
    {
        return $this->config;
    }

    /**
     * Create tokens for a user.
     *
     * @return array{access_token: string, refresh_token: string}
     */
    public function createTokensForUser(Model&Authenticatable $user): array
    {
        $userId = (string) $user->getAuthIdentifier();
        $email = $user->getAttribute('email') ?? '';

        // Create access token
        $accessToken = $this->tokenService->sign([
            'sub' => $userId,
            'email' => $email,
            'type' => 'access',
        ], $this->getAccessTokenLifetime());

        // Create refresh token
        $refreshTokenValue = bin2hex(random_bytes(32));

        DB::table($this->refreshTokenTable)->insert([
            'token' => hash('sha256', $refreshTokenValue),
            'user_id' => $userId,
            'expires_at' => now()->addSeconds($this->getRefreshTokenLifetime()),
            'revoked' => false,
            'replaced_by' => null,
            'created_at' => now(),
        ]);

        return [
            'access_token' => $accessToken,
            'refresh_token' => $refreshTokenValue,
        ];
    }

    /**
     * Convert a user model to array (excluding sensitive data).
     *
     * @return array<string, mixed>
     */
    public function userToArray(Model&Authenticatable $user): array
    {
        $array = $user->toArray();

        // Remove sensitive fields
        unset($array['password'], $array['remember_token']);

        return $array;
    }

    /**
     * Check if using UUID strategy.
     */
    private function usesUuid(): bool
    {
        $strategy = $this->config['id_strategy'] ?? 'uuid';

        return in_array($strategy, ['uuid', 'ulid'], true);
    }

    /**
     * Get access token lifetime in seconds.
     */
    private function getAccessTokenLifetime(): int
    {
        return $this->config['tokens']['access']['lifetime']
            ?? $this->config['tokens']['access_lifetime']
            ?? 3600;
    }

    /**
     * Get refresh token lifetime in seconds.
     */
    private function getRefreshTokenLifetime(): int
    {
        return $this->config['tokens']['refresh']['lifetime']
            ?? $this->config['tokens']['refresh_lifetime']
            ?? 2592000;
    }
}
