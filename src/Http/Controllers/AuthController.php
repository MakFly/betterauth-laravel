<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Http\Controllers;

use BetterAuth\Laravel\Services\BetterAuthManager;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\ValidationException;

/**
 * BetterAuth API Controller.
 *
 * Handles all authentication endpoints with JSON responses.
 */
final class AuthController extends Controller
{
    public function __construct(
        private readonly BetterAuthManager $auth,
    ) {}

    /**
     * Register a new user.
     *
     * POST /auth/register
     */
    public function register(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'email' => ['required', 'email', 'max:255'],
            'password' => ['required', 'string', 'min:8', 'max:255'],
            'name' => ['sometimes', 'string', 'max:255'],
        ]);

        // Check if email already exists
        if ($this->auth->emailExists($validated['email'])) {
            throw ValidationException::withMessages([
                'email' => ['This email is already registered.'],
            ]);
        }

        $result = $this->auth->signUp($validated);

        return response()->json([
            'message' => 'Registration successful',
            'user' => $this->formatUser($result['user']),
            'access_token' => $result['access_token'],
            'refresh_token' => $result['refresh_token'],
            'token_type' => $result['token_type'],
            'expires_in' => $result['expires_in'],
        ], 201);
    }

    /**
     * Authenticate a user.
     *
     * POST /auth/login
     */
    public function login(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'email' => ['required', 'email'],
            'password' => ['required', 'string'],
        ]);

        try {
            $result = $this->auth->signIn(
                $validated['email'],
                $validated['password']
            );

            return response()->json([
                'message' => 'Login successful',
                'user' => $this->formatUser($result['user']),
                'access_token' => $result['access_token'],
                'refresh_token' => $result['refresh_token'],
                'token_type' => $result['token_type'],
                'expires_in' => $result['expires_in'],
            ]);

        } catch (\BetterAuth\Core\Exceptions\InvalidCredentialsException $e) {
            throw ValidationException::withMessages([
                'email' => ['The provided credentials are incorrect.'],
            ]);
        }
    }

    /**
     * Get current authenticated user.
     *
     * GET /auth/me
     */
    public function me(Request $request): JsonResponse
    {
        $user = Auth::guard('betterauth')->user();

        if ($user === null) {
            return response()->json([
                'message' => 'Unauthenticated',
            ], 401);
        }

        return response()->json([
            'user' => $this->formatAuthenticatable($user),
        ]);
    }

    /**
     * Refresh access token.
     *
     * POST /auth/refresh
     */
    public function refresh(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'refresh_token' => ['required', 'string'],
        ]);

        try {
            $result = $this->auth->refresh($validated['refresh_token']);

            return response()->json([
                'message' => 'Token refreshed',
                'access_token' => $result['access_token'],
                'refresh_token' => $result['refresh_token'],
                'token_type' => $result['token_type'],
                'expires_in' => $result['expires_in'],
            ]);

        } catch (\BetterAuth\Core\Exceptions\InvalidTokenException $e) {
            return response()->json([
                'message' => 'Invalid refresh token',
                'error' => 'token_invalid',
            ], 401);
        }
    }

    /**
     * Logout and revoke refresh token.
     *
     * POST /auth/logout
     */
    public function logout(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'refresh_token' => ['required', 'string'],
        ]);

        $this->auth->signOut($validated['refresh_token']);

        return response()->json([
            'message' => 'Logged out successfully',
        ]);
    }

    /**
     * Revoke all tokens for the authenticated user.
     *
     * POST /auth/revoke-all
     */
    public function revokeAll(Request $request): JsonResponse
    {
        $user = Auth::guard('betterauth')->user();

        if ($user === null) {
            return response()->json([
                'message' => 'Unauthenticated',
            ], 401);
        }

        $userId = $user->getAuthIdentifier();
        $this->auth->revokeAll((string) $userId);

        return response()->json([
            'message' => 'All tokens revoked',
        ]);
    }

    /**
     * Update password.
     *
     * PUT /auth/password
     */
    public function updatePassword(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'current_password' => ['required', 'string'],
            'password' => ['required', 'string', 'min:8', 'max:255', 'confirmed'],
        ]);

        $user = Auth::guard('betterauth')->user();

        if ($user === null) {
            return response()->json([
                'message' => 'Unauthenticated',
            ], 401);
        }

        $userId = (string) $user->getAuthIdentifier();

        try {
            $updated = $this->auth->updatePassword(
                $userId,
                $validated['current_password'],
                $validated['password']
            );

            if (! $updated) {
                throw ValidationException::withMessages([
                    'current_password' => ['The current password is incorrect.'],
                ]);
            }

            return response()->json([
                'message' => 'Password updated successfully',
            ]);

        } catch (\BetterAuth\Core\Exceptions\InvalidCredentialsException $e) {
            throw ValidationException::withMessages([
                'current_password' => ['The current password is incorrect.'],
            ]);
        }
    }

    /**
     * Redirect to OAuth provider.
     *
     * GET /auth/oauth/{provider}
     */
    public function oauthRedirect(string $provider): \Illuminate\Http\RedirectResponse
    {
        if (!config('betterauth.oauth.enabled')) {
            abort(403, 'OAuth authentication is not enabled.');
        }

        try {
            $oauthManager = app(\BetterAuth\Laravel\OAuth\OAuthManager::class);
            return $oauthManager->redirect($provider);
        } catch (\InvalidArgumentException $e) {
            abort(404, $e->getMessage());
        } catch (\Exception $e) {
            abort(500, 'OAuth redirect failed: '.$e->getMessage());
        }
    }

    /**
     * Handle OAuth callback.
     *
     * GET /auth/oauth/{provider}/callback
     */
    public function oauthCallback(Request $request, string $provider): JsonResponse
    {
        if (!config('betterauth.oauth.enabled')) {
            abort(403, 'OAuth authentication is not enabled.');
        }

        try {
            $oauthManager = app(\BetterAuth\Laravel\OAuth\OAuthManager::class);
            $result = $oauthManager->handleCallback($provider);

            $user = $result['user'];
            $isNew = $result['is_new'];

            // Generate tokens using BetterAuthManager
            $authManager = app(\BetterAuth\Laravel\Services\BetterAuthManager::class);
            $tokens = $authManager->createTokensForUser($user);

            $response = [
                'message' => $isNew ? 'Account created via OAuth' : 'Authenticated via OAuth',
                'user' => $authManager->userToArray($user),
                'provider' => $provider,
                'access_token' => $tokens['access_token'],
                'refresh_token' => $tokens['refresh_token'],
                'token_type' => 'Bearer',
                'expires_in' => config('betterauth.tokens.access.lifetime', 3600),
            ];

            return response()->json($response, $isNew ? 201 : 200);
        } catch (\RuntimeException $e) {
            return response()->json([
                'message' => 'OAuth authentication failed',
                'error' => $e->getMessage(),
            ], 422);
        } catch (\Exception $e) {
            return response()->json([
                'message' => 'OAuth callback failed',
                'error' => config('app.debug') ? $e->getMessage() : 'Authentication failed',
            ], 500);
        }
    }

    /**
     * Format user array for response.
     *
     * @param  array<string, mixed>|object  $user
     * @return array<string, mixed>
     */
    private function formatUser(array|object $user): array
    {
        if (is_object($user)) {
            $user = method_exists($user, 'toArray') ? $user->toArray() : (array) $user;
        }

        // Remove sensitive fields
        unset($user['password']);

        return $user;
    }

    /**
     * Format Authenticatable for response.
     *
     * @return array<string, mixed>
     */
    private function formatAuthenticatable(\Illuminate\Contracts\Auth\Authenticatable $user): array
    {
        $data = [
            'id' => $user->getAuthIdentifier(),
        ];

        // Add common user attributes if available
        if (method_exists($user, 'toArray')) {
            $userData = $user->toArray();
            unset($userData['password']);
            $data = array_merge($data, $userData);
        } elseif (method_exists($user, 'getAttribute')) {
            $data['email'] = $user->getAttribute('email');
            $data['name'] = $user->getAttribute('name');
            $data['avatar'] = $user->getAttribute('avatar');
            $data['email_verified_at'] = $user->getAttribute('email_verified_at');
            $data['created_at'] = $user->getAttribute('created_at');
        }

        return $data;
    }
}
