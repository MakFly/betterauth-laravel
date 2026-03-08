<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Http\Controllers;

use BetterAuth\Laravel\Facades\BetterAuth;
use BetterAuth\Laravel\Services\MagicLinkService;
use BetterAuth\Laravel\Support\ApiExceptionFactory;
use BetterAuth\Laravel\Support\ApiResponseFactory;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;

/**
 * Contrôleur Magic Link.
 *
 * Gère l'envoi, la vérification et le check de validité des liens magiques.
 */
final class MagicLinkController extends Controller
{
    /**
     * @param  MagicLinkService  $magicLink  Service métier magic-link
     * @param  ApiResponseFactory  $responses  Factory de réponses JSON/API Platform
     * @param  ApiExceptionFactory  $exceptions  Factory d'exceptions HTTP/API
     */
    public function __construct(
        private readonly MagicLinkService $magicLink,
        private readonly ApiResponseFactory $responses,
        private readonly ApiExceptionFactory $exceptions,
    ) {
    }

    /**
     * Envoie un lien magique.
     *
     * @param  Request  $request  Requête HTTP
     */
    public function send(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'email' => ['required', 'email', 'max:255'],
        ]);

        $this->magicLink->send($validated['email']);

        return $this->responses->ok([
            'message' => 'If an account exists with this email, you will receive a magic link shortly.',
        ], $request, noStore: true);
    }

    /**
     * Vérifie un token magic-link et authentifie l'utilisateur.
     *
     * @param  Request  $request  Requête HTTP
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    public function verify(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'token' => ['required', 'string'],
            'email' => ['sometimes', 'email'],
        ]);

        $email = $validated['email'] ?? null;
        if ($email === null) {
            $email = $this->magicLink->getEmailFromToken($validated['token']);
            if ($email === null) {
                throw $this->exceptions->validation([
                    'token' => ['Invalid or expired magic link.'],
                ]);
            }
        }

        $result = $this->magicLink->verify($validated['token'], $email);
        if ($result === null) {
            throw $this->exceptions->validation([
                'token' => ['Invalid or expired magic link.'],
            ]);
        }

        $authManager = app(\BetterAuth\Laravel\Services\BetterAuthManager::class);
        $userModel = $authManager->getUserModel($result['email']);

        if ($userModel === null) {
            $signUpResult = BetterAuth::signUp([
                'email' => $result['email'],
                'password' => bin2hex(random_bytes(32)),
            ]);

            BetterAuth::verifyEmail($signUpResult['user']['id']);

            return $this->responses->created([
                'message' => 'Account created and authenticated',
                'user' => $signUpResult['user'],
                'access_token' => $signUpResult['access_token'],
                'refresh_token' => $signUpResult['refresh_token'],
                'token_type' => 'Bearer',
                'expires_in' => $signUpResult['expires_in'],
            ], $request, noStore: true);
        }

        $tokens = $authManager->createTokensForUser($userModel);

        return $this->responses->ok([
            'message' => 'Authenticated successfully',
            'user' => $authManager->userToArray($userModel),
            'access_token' => $tokens['access_token'],
            'refresh_token' => $tokens['refresh_token'],
            'token_type' => 'Bearer',
            'expires_in' => config('betterauth.tokens.access.lifetime', 3600),
        ], $request, noStore: true);
    }

    /**
     * Vérifie la validité d'un token sans le consommer.
     *
     * @param  Request  $request  Requête HTTP
     */
    public function check(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'token' => ['required', 'string'],
            'email' => ['required', 'email'],
        ]);

        $isValid = $this->magicLink->isValid($validated['token'], $validated['email']);

        return $this->responses->ok([
            'valid' => $isValid,
        ], $request, noStore: true);
    }
}
