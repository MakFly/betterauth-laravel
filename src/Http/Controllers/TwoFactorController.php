<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Http\Controllers;

use BetterAuth\Laravel\Services\TwoFactorService;
use BetterAuth\Laravel\Support\ApiResponseFactory;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;

/**
 * Two-Factor Authentication Controller.
 *
 * Handles 2FA setup, verification, and recovery.
 */
final class TwoFactorController extends Controller
{
    /**
     * @param  TwoFactorService  $twoFactor  Service métier 2FA
     * @param  ApiResponseFactory  $responses  Factory de réponses JSON/API Platform
     */
    public function __construct(
        private readonly TwoFactorService $twoFactor,
        private readonly ApiResponseFactory $responses,
    ) {
    }

    /**
     * Generate 2FA setup data.
     *
     * POST /auth/2fa/setup
     *
     * @param  Request  $request  Requête HTTP
     */
    public function setup(Request $request): JsonResponse
    {
        $user = Auth::guard('betterauth')->user();

        if ($user === null) {
            return $this->responses->unauthenticated($request);
        }

        if ($this->twoFactor->isEnabled($user)) {
            return $this->responses->json([
                'message' => '2FA is already enabled',
                'enabled' => true,
            ], 400, $request, noStore: true);
        }

        $data = $this->twoFactor->generateSecret($user);

        return $this->responses->ok([
            'message' => 'Scan the QR code with your authenticator app',
            'secret' => $data['secret'],
            'qr_code_url' => $data['qr_code_url'],
            'uri' => $data['uri'],
        ], $request, noStore: true);
    }

    /**
     * Verify code and enable 2FA.
     *
     * POST /auth/2fa/enable
     *
     * @param  Request  $request  Requête HTTP
     */
    public function enable(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'code' => ['required', 'string', 'size:6'],
        ]);

        $user = Auth::guard('betterauth')->user();

        if ($user === null) {
            return $this->responses->unauthenticated($request);
        }

        $result = $this->twoFactor->verifyAndEnable($user, $validated['code']);

        if ($result === null) {
            return $this->responses->error('Invalid verification code', 'verification_failed', 422, $request, noStore: true);
        }

        return $this->responses->ok([
            'message' => '2FA enabled successfully',
            'enabled' => true,
            'recovery_codes' => $result['recovery_codes'],
        ], $request, noStore: true);
    }

    /**
     * Verify a 2FA code during login.
     *
     * POST /auth/2fa/verify
     *
     * @param  Request  $request  Requête HTTP
     */
    public function verify(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'code' => ['required', 'string', 'size:6'],
        ]);

        $user = Auth::guard('betterauth')->user();

        if ($user === null) {
            return $this->responses->unauthenticated($request);
        }

        if (! $this->twoFactor->verify($user, $validated['code'])) {
            return $this->responses->error('Invalid 2FA code', 'invalid_2fa_code', 422, $request, noStore: true);
        }

        return $this->responses->ok([
            'message' => '2FA verification successful',
            'verified' => true,
        ], $request, noStore: true);
    }

    /**
     * Verify using a recovery code.
     *
     * POST /auth/2fa/recovery
     *
     * @param  Request  $request  Requête HTTP
     */
    public function recovery(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'code' => ['required', 'string'],
        ]);

        $user = Auth::guard('betterauth')->user();

        if ($user === null) {
            return $this->responses->unauthenticated($request);
        }

        if (! $this->twoFactor->verifyRecoveryCode($user, $validated['code'])) {
            return $this->responses->error('Invalid recovery code', 'invalid_recovery_code', 422, $request, noStore: true);
        }

        return $this->responses->ok([
            'message' => 'Recovery code verified',
            'verified' => true,
        ], $request, noStore: true);
    }

    /**
     * Disable 2FA.
     *
     * DELETE /auth/2fa
     *
     * @param  Request  $request  Requête HTTP
     */
    public function disable(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'password' => ['required', 'string'],
        ]);

        $user = Auth::guard('betterauth')->user();

        if ($user === null) {
            return $this->responses->unauthenticated($request);
        }

        // Verify password before disabling
        if (! password_verify($validated['password'], $user->getAuthPassword() ?? '')) {
            return $this->responses->error('Invalid password', 'invalid_password', 422, $request, noStore: true);
        }

        $this->twoFactor->disable($user);

        return $this->responses->ok([
            'message' => '2FA disabled successfully',
            'enabled' => false,
        ], $request, noStore: true);
    }

    /**
     * Regenerate recovery codes.
     *
     * POST /auth/2fa/recovery-codes
     *
     * @param  Request  $request  Requête HTTP
     */
    public function regenerateRecoveryCodes(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'password' => ['required', 'string'],
        ]);

        $user = Auth::guard('betterauth')->user();

        if ($user === null) {
            return $this->responses->unauthenticated($request);
        }

        // Verify password
        if (! password_verify($validated['password'], $user->getAuthPassword() ?? '')) {
            return $this->responses->error('Invalid password', 'invalid_password', 422, $request, noStore: true);
        }

        $codes = $this->twoFactor->regenerateRecoveryCodes($user);

        return $this->responses->ok([
            'message' => 'Recovery codes regenerated',
            'recovery_codes' => $codes,
        ], $request, noStore: true);
    }

    /**
     * Get 2FA status.
     *
     * GET /auth/2fa/status
     *
     * @param  Request  $request  Requête HTTP
     */
    public function status(Request $request): JsonResponse
    {
        $user = Auth::guard('betterauth')->user();

        if ($user === null) {
            return $this->responses->unauthenticated($request);
        }

        return $this->responses->ok([
            'enabled' => $this->twoFactor->isEnabled($user),
        ], $request, noStore: true);
    }
}
