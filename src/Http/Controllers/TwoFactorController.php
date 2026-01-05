<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Http\Controllers;

use BetterAuth\Laravel\Services\TwoFactorService;
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
    public function __construct(
        private readonly TwoFactorService $twoFactor,
    ) {}

    /**
     * Generate 2FA setup data.
     *
     * POST /auth/2fa/setup
     */
    public function setup(Request $request): JsonResponse
    {
        $user = Auth::guard('betterauth')->user();

        if ($user === null) {
            return response()->json(['message' => 'Unauthenticated'], 401);
        }

        if ($this->twoFactor->isEnabled($user)) {
            return response()->json([
                'message' => '2FA is already enabled',
                'enabled' => true,
            ], 400);
        }

        $data = $this->twoFactor->generateSecret($user);

        return response()->json([
            'message' => 'Scan the QR code with your authenticator app',
            'secret' => $data['secret'],
            'qr_code_url' => $data['qr_code_url'],
            'uri' => $data['uri'],
        ]);
    }

    /**
     * Verify code and enable 2FA.
     *
     * POST /auth/2fa/enable
     */
    public function enable(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'code' => ['required', 'string', 'size:6'],
        ]);

        $user = Auth::guard('betterauth')->user();

        if ($user === null) {
            return response()->json(['message' => 'Unauthenticated'], 401);
        }

        $result = $this->twoFactor->verifyAndEnable($user, $validated['code']);

        if ($result === null) {
            return response()->json([
                'message' => 'Invalid verification code',
            ], 422);
        }

        return response()->json([
            'message' => '2FA enabled successfully',
            'enabled' => true,
            'recovery_codes' => $result['recovery_codes'],
        ]);
    }

    /**
     * Verify a 2FA code during login.
     *
     * POST /auth/2fa/verify
     */
    public function verify(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'code' => ['required', 'string', 'size:6'],
        ]);

        $user = Auth::guard('betterauth')->user();

        if ($user === null) {
            return response()->json(['message' => 'Unauthenticated'], 401);
        }

        if (! $this->twoFactor->verify($user, $validated['code'])) {
            return response()->json([
                'message' => 'Invalid 2FA code',
            ], 422);
        }

        return response()->json([
            'message' => '2FA verification successful',
            'verified' => true,
        ]);
    }

    /**
     * Verify using a recovery code.
     *
     * POST /auth/2fa/recovery
     */
    public function recovery(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'code' => ['required', 'string'],
        ]);

        $user = Auth::guard('betterauth')->user();

        if ($user === null) {
            return response()->json(['message' => 'Unauthenticated'], 401);
        }

        if (! $this->twoFactor->verifyRecoveryCode($user, $validated['code'])) {
            return response()->json([
                'message' => 'Invalid recovery code',
            ], 422);
        }

        return response()->json([
            'message' => 'Recovery code verified',
            'verified' => true,
        ]);
    }

    /**
     * Disable 2FA.
     *
     * DELETE /auth/2fa
     */
    public function disable(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'password' => ['required', 'string'],
        ]);

        $user = Auth::guard('betterauth')->user();

        if ($user === null) {
            return response()->json(['message' => 'Unauthenticated'], 401);
        }

        // Verify password before disabling
        if (! password_verify($validated['password'], $user->getAuthPassword() ?? '')) {
            return response()->json([
                'message' => 'Invalid password',
            ], 422);
        }

        $this->twoFactor->disable($user);

        return response()->json([
            'message' => '2FA disabled successfully',
            'enabled' => false,
        ]);
    }

    /**
     * Regenerate recovery codes.
     *
     * POST /auth/2fa/recovery-codes
     */
    public function regenerateRecoveryCodes(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'password' => ['required', 'string'],
        ]);

        $user = Auth::guard('betterauth')->user();

        if ($user === null) {
            return response()->json(['message' => 'Unauthenticated'], 401);
        }

        // Verify password
        if (! password_verify($validated['password'], $user->getAuthPassword() ?? '')) {
            return response()->json([
                'message' => 'Invalid password',
            ], 422);
        }

        $codes = $this->twoFactor->regenerateRecoveryCodes($user);

        return response()->json([
            'message' => 'Recovery codes regenerated',
            'recovery_codes' => $codes,
        ]);
    }

    /**
     * Get 2FA status.
     *
     * GET /auth/2fa/status
     */
    public function status(Request $request): JsonResponse
    {
        $user = Auth::guard('betterauth')->user();

        if ($user === null) {
            return response()->json(['message' => 'Unauthenticated'], 401);
        }

        return response()->json([
            'enabled' => $this->twoFactor->isEnabled($user),
        ]);
    }
}
