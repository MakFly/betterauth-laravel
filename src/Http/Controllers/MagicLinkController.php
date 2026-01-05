<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Http\Controllers;

use BetterAuth\Laravel\Facades\BetterAuth;
use BetterAuth\Laravel\Services\MagicLinkService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Validation\ValidationException;

/**
 * Magic Link Authentication Controller.
 *
 * Handles passwordless authentication via email magic links.
 */
final class MagicLinkController extends Controller
{
    public function __construct(
        private readonly MagicLinkService $magicLink,
    ) {}

    /**
     * Send a magic link to the given email.
     *
     * POST /auth/magic-link
     */
    public function send(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'email' => ['required', 'email', 'max:255'],
        ]);

        // Always return success to prevent email enumeration
        $this->magicLink->send($validated['email']);

        return response()->json([
            'message' => 'If an account exists with this email, you will receive a magic link shortly.',
        ]);
    }

    /**
     * Verify a magic link and authenticate.
     *
     * GET /auth/magic-link/verify
     */
    public function verify(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'token' => ['required', 'string'],
            'email' => ['sometimes', 'email'],
        ]);

        // Get email from token if not provided
        $email = $validated['email'] ?? null;
        if ($email === null) {
            $email = $this->magicLink->getEmailFromToken($validated['token']);
            if ($email === null) {
                throw ValidationException::withMessages([
                    'token' => ['Invalid or expired magic link.'],
                ]);
            }
        }

        $result = $this->magicLink->verify(
            $validated['token'],
            $email,
        );

        if ($result === null) {
            throw ValidationException::withMessages([
                'token' => ['Invalid or expired magic link.'],
            ]);
        }

        // Find or create user
        $authManager = app(\BetterAuth\Laravel\Services\BetterAuthManager::class);
        $userModel = $authManager->getUserModel($result['email']);

        if ($userModel === null) {
            // Auto-register user with magic link
            $signUpResult = BetterAuth::signUp([
                'email' => $result['email'],
                'password' => bin2hex(random_bytes(32)), // Random password
            ]);

            // Mark email as verified since they clicked the magic link
            BetterAuth::verifyEmail($signUpResult['user']['id']);

            return response()->json([
                'message' => 'Account created and authenticated',
                'user' => $signUpResult['user'],
                'access_token' => $signUpResult['access_token'],
                'refresh_token' => $signUpResult['refresh_token'],
                'token_type' => 'Bearer',
                'expires_in' => $signUpResult['expires_in'],
            ], 201);
        }

        // Existing user - generate tokens
        $tokens = $authManager->createTokensForUser($userModel);

        return response()->json([
            'message' => 'Authenticated successfully',
            'user' => $authManager->userToArray($userModel),
            'access_token' => $tokens['access_token'],
            'refresh_token' => $tokens['refresh_token'],
            'token_type' => 'Bearer',
            'expires_in' => config('betterauth.tokens.access.lifetime', 3600),
        ]);
    }

    /**
     * Check if a magic link is still valid.
     *
     * POST /auth/magic-link/check
     */
    public function check(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'token' => ['required', 'string'],
            'email' => ['required', 'email'],
        ]);

        $isValid = $this->magicLink->isValid(
            $validated['token'],
            $validated['email'],
        );

        return response()->json([
            'valid' => $isValid,
        ]);
    }
}
