<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Http\Controllers;

use BetterAuth\Laravel\Services\AuthUserResponseFormatter;
use BetterAuth\Laravel\Services\BetterAuthManager;
use BetterAuth\Laravel\Support\ApiExceptionFactory;
use BetterAuth\Laravel\Support\ApiResponseFactory;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;

/**
 * BetterAuth API Controller.
 *
 * Handles all authentication endpoints with JSON responses.
 */
final class AuthController extends Controller
{
    /**
     * @param  BetterAuthManager  $auth  Service principal d'authentification
     * @param  AuthUserResponseFormatter  $formatter  Formatteur de payload user
     * @param  ApiResponseFactory  $responses  Factory de réponses JSON/API Platform
     * @param  ApiExceptionFactory  $exceptions  Factory d'exceptions HTTP/API
     */
    public function __construct(
        private readonly BetterAuthManager $auth,
        private readonly AuthUserResponseFormatter $formatter,
        private readonly ApiResponseFactory $responses,
        private readonly ApiExceptionFactory $exceptions,
    ) {}

    /**
     * Inscription d'un utilisateur.
     *
     * @param  Request  $request  Requête HTTP d'inscription
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    public function register(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'email' => ['required', 'email', 'max:255'],
            'password' => ['required', 'string', 'min:8', 'max:255'],
            'name' => ['sometimes', 'string', 'max:255'],
        ]);

        if ($this->auth->emailExists($validated['email'])) {
            throw $this->exceptions->validation([
                'email' => ['This email is already registered.'],
            ]);
        }

        $result = $this->auth->signUp($validated);

        return $this->responses->created([
            'message' => 'Registration successful',
            'user' => $this->formatter->formatUser($result['user']),
            'access_token' => $result['access_token'],
            'refresh_token' => $result['refresh_token'],
            'token_type' => $result['token_type'],
            'expires_in' => $result['expires_in'],
        ], $request, noStore: true);
    }

    /**
     * Authentification par credentials.
     *
     * @param  Request  $request  Requête HTTP de login
     *
     * @throws \Illuminate\Validation\ValidationException
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
                $validated['password'],
            );

            return $this->responses->ok([
                'message' => 'Login successful',
                'user' => $this->formatter->formatUser($result['user']),
                'access_token' => $result['access_token'],
                'refresh_token' => $result['refresh_token'],
                'token_type' => $result['token_type'],
                'expires_in' => $result['expires_in'],
            ], $request, noStore: true);
        } catch (\BetterAuth\Core\Exceptions\InvalidCredentialsException $e) {
            throw $this->exceptions->validation([
                'email' => ['The provided credentials are incorrect.'],
            ]);
        }
    }

    /**
     * Retourne l'utilisateur authentifié.
     *
     * @param  Request  $request  Requête HTTP
     */
    public function me(Request $request): JsonResponse
    {
        $user = Auth::guard('betterauth')->user();

        if ($user === null) {
            return $this->responses->unauthenticated($request);
        }

        return $this->responses->ok([
            'user' => $this->formatter->formatAuthenticatable($user),
        ], $request, noStore: true);
    }

    /**
     * Rafraîchit une paire de tokens à partir d'un refresh token.
     *
     * @param  Request  $request  Requête HTTP
     */
    public function refresh(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'refresh_token' => ['required', 'string'],
        ]);

        try {
            $result = $this->auth->refresh($validated['refresh_token']);

            return $this->responses->ok([
                'message' => 'Token refreshed',
                'access_token' => $result['access_token'],
                'refresh_token' => $result['refresh_token'],
                'token_type' => $result['token_type'],
                'expires_in' => $result['expires_in'],
            ], $request, noStore: true);
        } catch (\BetterAuth\Core\Exceptions\InvalidTokenException $e) {
            return $this->responses->error('Invalid refresh token', 'token_invalid', 401, $request, noStore: true);
        }
    }

    /**
     * Déconnecte l'utilisateur courant via son refresh token.
     *
     * @param  Request  $request  Requête HTTP
     */
    public function logout(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'refresh_token' => ['required', 'string'],
        ]);

        $this->auth->signOut($validated['refresh_token']);

        return $this->responses->ok([
            'message' => 'Logged out successfully',
        ], $request, noStore: true);
    }

    /**
     * Révoque tous les refresh tokens de l'utilisateur courant.
     *
     * @param  Request  $request  Requête HTTP
     */
    public function revokeAll(Request $request): JsonResponse
    {
        $user = Auth::guard('betterauth')->user();

        if ($user === null) {
            return $this->responses->unauthenticated($request);
        }

        $userId = $user->getAuthIdentifier();
        $this->auth->revokeAll((string) $userId);

        return $this->responses->ok([
            'message' => 'All tokens revoked',
        ], $request, noStore: true);
    }

    /**
     * Met à jour le mot de passe de l'utilisateur authentifié.
     *
     * @param  Request  $request  Requête HTTP
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    public function updatePassword(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'current_password' => ['required', 'string'],
            'password' => ['required', 'string', 'min:8', 'max:255', 'confirmed'],
        ]);

        $user = Auth::guard('betterauth')->user();

        if ($user === null) {
            return $this->responses->unauthenticated($request);
        }

        $userId = (string) $user->getAuthIdentifier();

        try {
            $updated = $this->auth->updatePassword(
                $userId,
                $validated['current_password'],
                $validated['password'],
            );

            if (! $updated) {
                throw $this->exceptions->validation([
                    'current_password' => ['The current password is incorrect.'],
                ]);
            }

            return $this->responses->ok([
                'message' => 'Password updated successfully',
            ], $request, noStore: true);
        } catch (\BetterAuth\Core\Exceptions\InvalidCredentialsException $e) {
            throw $this->exceptions->validation([
                'current_password' => ['The current password is incorrect.'],
            ]);
        }
    }

    /**
     * Redirige vers le provider OAuth demandé.
     *
     * @param  string  $provider  Provider OAuth
     *
     * @throws \Symfony\Component\HttpKernel\Exception\HttpException
     */
    public function oauthRedirect(string $provider): RedirectResponse
    {
        if (! config('betterauth.oauth.enabled')) {
            throw $this->exceptions->forbidden('OAuth authentication is not enabled.');
        }

        try {
            $oauthManager = app(\BetterAuth\Laravel\OAuth\OAuthManager::class);

            return $oauthManager->redirect($provider);
        } catch (\InvalidArgumentException $e) {
            throw $this->exceptions->notFound($e->getMessage());
        } catch (\Exception $e) {
            report($e);

            throw $this->exceptions->badGateway('OAuth provider temporarily unavailable.');
        }
    }

    /**
     * Traite le callback OAuth provider.
     *
     * @param  Request  $request  Requête HTTP de callback
     * @param  string  $provider  Provider OAuth
     *
     * @throws \Symfony\Component\HttpKernel\Exception\HttpException
     */
    public function oauthCallback(Request $request, string $provider): JsonResponse
    {
        if (! config('betterauth.oauth.enabled')) {
            throw $this->exceptions->forbidden('OAuth authentication is not enabled.');
        }

        try {
            $oauthManager = app(\BetterAuth\Laravel\OAuth\OAuthManager::class);
            $result = $oauthManager->handleCallback($provider);

            $user = $result['user'];
            $isNew = $result['is_new'];

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

            if ($isNew) {
                return $this->responses->created($response, $request, noStore: true);
            }

            return $this->responses->ok($response, $request, noStore: true);
        } catch (\RuntimeException $e) {
            report($e);

            return $this->responses->error('OAuth authentication failed', 'oauth_failed', 422, $request, noStore: true);
        } catch (\Exception $e) {
            report($e);

            return $this->responses->error('OAuth callback failed', 'authentication_failed', 500, $request, noStore: true);
        }
    }
}
