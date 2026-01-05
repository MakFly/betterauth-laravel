<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Guards;

use BetterAuth\Core\Interfaces\TokenSignerInterface;
use BetterAuth\Laravel\Events\TokenAuthenticated;
use BetterAuth\Laravel\Events\TokenExpired;
use BetterAuth\Laravel\Events\TokenInvalid;
use BetterAuth\Laravel\Services\BetterAuthManager;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;

/**
 * BetterAuth Guard for Laravel's authentication system.
 *
 * Validates Paseto V4 tokens from the Authorization header and
 * resolves the authenticated user.
 */
final class BetterAuthGuard implements Guard
{
    use GuardHelpers;

    private ?array $decodedToken = null;
    private readonly string $name;
    private readonly Request $request;
    private readonly TokenSignerInterface $tokenService;
    private readonly BetterAuthManager $authManager;
    private readonly ?Dispatcher $events;

    public function __construct(
        string $name,
        ?UserProvider $provider,
        Request $request,
        TokenSignerInterface $tokenService,
        BetterAuthManager $authManager,
        ?Dispatcher $events = null,
    ) {
        $this->name = $name;
        $this->provider = $provider;
        $this->request = $request;
        $this->tokenService = $tokenService;
        $this->authManager = $authManager;
        $this->events = $events;
    }

    /**
     * Get the currently authenticated user.
     */
    public function user(): ?Authenticatable
    {
        if ($this->user !== null) {
            return $this->user;
        }

        $token = $this->getTokenFromRequest();

        if ($token === null) {
            return null;
        }

        try {
            $payload = $this->tokenService->verify($token);
            $this->decodedToken = $payload;

            $userId = $payload['sub'] ?? null;

            if ($userId === null) {
                $this->fireTokenInvalidEvent($token, 'Missing subject claim');

                return null;
            }

            $user = $this->provider?->retrieveById($userId);

            if ($user !== null) {
                $this->user = $user;
                $this->fireTokenAuthenticatedEvent($user, $payload);
            }

            return $this->user;

        } catch (\BetterAuth\Core\Exceptions\ExpiredTokenException $e) {
            $this->fireTokenExpiredEvent($token);

            return null;
        } catch (\BetterAuth\Core\Exceptions\InvalidTokenException $e) {
            $this->fireTokenInvalidEvent($token, $e->getMessage());

            return null;
        } catch (\Throwable $e) {
            $this->fireTokenInvalidEvent($token, $e->getMessage());

            return null;
        }
    }

    /**
     * Validate a user's credentials.
     *
     * @param  array<string, mixed>  $credentials
     */
    public function validate(array $credentials = []): bool
    {
        if (! isset($credentials['email'], $credentials['password'])) {
            return false;
        }

        try {
            $result = $this->authManager->signIn(
                $credentials['email'],
                $credentials['password']
            );

            return isset($result['access_token']);
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Get the token from the request.
     */
    public function getTokenFromRequest(): ?string
    {
        // Check Authorization header first
        $header = $this->request->header('Authorization', '');

        if (str_starts_with($header, 'Bearer ')) {
            return substr($header, 7);
        }

        // Fallback to query parameter (for WebSocket connections, etc.)
        $token = $this->request->query('token');

        if (is_string($token) && $token !== '') {
            return $token;
        }

        return null;
    }

    /**
     * Get the decoded token payload.
     *
     * @return array<string, mixed>|null
     */
    public function getDecodedToken(): ?array
    {
        if ($this->decodedToken === null) {
            // Trigger user() to decode the token
            $this->user();
        }

        return $this->decodedToken;
    }

    /**
     * Check if the token has a specific claim.
     */
    public function hasClaim(string $claim): bool
    {
        $token = $this->getDecodedToken();

        return $token !== null && array_key_exists($claim, $token);
    }

    /**
     * Get a specific claim from the token.
     */
    public function getClaim(string $claim, mixed $default = null): mixed
    {
        $token = $this->getDecodedToken();

        return $token[$claim] ?? $default;
    }

    /**
     * Set the current request instance.
     */
    public function setRequest(Request $request): static
    {
        return new self(
            $this->name,
            $this->provider,
            $request,
            $this->tokenService,
            $this->authManager,
            $this->events,
        );
    }

    /**
     * Get the guard name.
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * Fire the token authenticated event.
     *
     * @param  array<string, mixed>  $payload
     */
    private function fireTokenAuthenticatedEvent(Authenticatable $user, array $payload): void
    {
        $this->events?->dispatch(new TokenAuthenticated($user, $payload));
    }

    /**
     * Fire the token expired event.
     */
    private function fireTokenExpiredEvent(string $token): void
    {
        $this->events?->dispatch(new TokenExpired($token));
    }

    /**
     * Fire the token invalid event.
     */
    private function fireTokenInvalidEvent(string $token, string $reason): void
    {
        $this->events?->dispatch(new TokenInvalid($token, $reason));
    }
}
