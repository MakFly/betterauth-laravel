<?php

declare(strict_types=1);

use BetterAuth\Laravel\Events\TwoFactorDisabled;
use BetterAuth\Laravel\Events\TwoFactorEnabled;
use BetterAuth\Laravel\Facades\BetterAuth;
use BetterAuth\Laravel\Services\TwoFactorService;
use BetterAuth\Laravel\Tests\Fixtures\User;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;

beforeEach(function (): void {
    $this->artisan('migrate', ['--database' => 'testing']);
});

// ---------------------------------------------------------------------------
// TwoFactorController — HTTP endpoints
// ---------------------------------------------------------------------------

describe('2FA Setup', function (): void {
    it('returns 401 when unauthenticated', function (): void {
        $response = $this->postJson('/auth/2fa/setup');

        $response->assertStatus(401);
    });

    it('generates QR code and secret for authenticated user', function (): void {
        $result = BetterAuth::signUp([
            'email' => '2fa-setup@example.com',
            'password' => 'password123',
        ]);

        $response = $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/setup');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'message',
                'secret',
                'qr_code_url',
                'uri',
            ])
            ->assertJson([
                'message' => 'Scan the QR code with your authenticator app',
            ]);

        expect($response->json('secret'))->toBeString()->not->toBeEmpty();
        expect($response->json('uri'))->toStartWith('otpauth://totp/');
        expect($response->json('qr_code_url'))->toContain('chart.googleapis.com');
    });

    it('returns 400 if 2FA already enabled', function (): void {
        $result = BetterAuth::signUp([
            'email' => '2fa-already@example.com',
            'password' => 'password123',
        ]);

        // Setup and enable 2FA
        $setupResponse = $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/setup');

        $secret = $setupResponse->json('secret');
        $service = app(TwoFactorService::class);

        // Generate valid TOTP code
        $code = generateTotpCode($secret);

        $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/enable', ['code' => $code]);

        // Try to setup again
        $response = $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/setup');

        $response->assertStatus(400)
            ->assertJson([
                'message' => '2FA is already enabled',
                'enabled' => true,
            ]);
    });
});

describe('2FA Enable', function (): void {
    it('returns 401 when unauthenticated', function (): void {
        $response = $this->postJson('/auth/2fa/enable', ['code' => '123456']);

        $response->assertStatus(401);
    });

    it('validates code length', function (): void {
        $result = BetterAuth::signUp([
            'email' => '2fa-val@example.com',
            'password' => 'password123',
        ]);

        $response = $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/enable', ['code' => '123']); // too short

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['code']);
    });

    it('enables 2FA with valid code and returns recovery codes', function (): void {
        Event::fake([TwoFactorEnabled::class]);

        $result = BetterAuth::signUp([
            'email' => '2fa-enable@example.com',
            'password' => 'password123',
        ]);

        $setupResponse = $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/setup');

        $secret = $setupResponse->json('secret');
        $code = generateTotpCode($secret);

        $response = $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/enable', ['code' => $code]);

        $response->assertStatus(200)
            ->assertJsonStructure([
                'message',
                'enabled',
                'recovery_codes',
            ])
            ->assertJson([
                'message' => '2FA enabled successfully',
                'enabled' => true,
            ]);

        expect($response->json('recovery_codes'))->toBeArray()->toHaveCount(8);

        Event::assertDispatched(TwoFactorEnabled::class);
    });

    it('returns 422 with invalid code', function (): void {
        $result = BetterAuth::signUp([
            'email' => '2fa-invalid@example.com',
            'password' => 'password123',
        ]);

        $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/setup');

        $response = $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/enable', ['code' => '000000']);

        $response->assertStatus(422)
            ->assertJson(['message' => 'Invalid verification code']);
    });
});

describe('2FA Verify', function (): void {
    it('returns 401 when unauthenticated', function (): void {
        $response = $this->postJson('/auth/2fa/verify', ['code' => '123456']);

        $response->assertStatus(401);
    });

    it('verifies a valid TOTP code', function (): void {
        $result = BetterAuth::signUp([
            'email' => '2fa-verify@example.com',
            'password' => 'password123',
        ]);

        $setupResponse = $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/setup');

        $secret = $setupResponse->json('secret');
        $code = generateTotpCode($secret);

        $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/enable', ['code' => $code]);

        // Get a fresh code for verify
        $freshCode = generateTotpCode($secret);

        $response = $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/verify', ['code' => $freshCode]);

        $response->assertStatus(200)
            ->assertJson([
                'message' => '2FA verification successful',
                'verified' => true,
            ]);
    });

    it('returns 422 with invalid code', function (): void {
        $result = BetterAuth::signUp([
            'email' => '2fa-verify-fail@example.com',
            'password' => 'password123',
        ]);

        $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/setup');

        $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/enable', ['code' => generateTotpCode(
                $this->withHeader('Authorization', "Bearer {$result['access_token']}")
                    ->postJson('/auth/2fa/setup')
                    ->json('secret'),
            )]);

        $response = $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/verify', ['code' => '000000']);

        $response->assertStatus(422);
    });

    it('returns 422 when 2FA is not enabled', function (): void {
        $result = BetterAuth::signUp([
            'email' => '2fa-not-enabled@example.com',
            'password' => 'password123',
        ]);

        $response = $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/verify', ['code' => '123456']);

        $response->assertStatus(422);
    });
});

describe('2FA Disable', function (): void {
    it('returns 401 when unauthenticated', function (): void {
        $response = $this->deleteJson('/auth/2fa', ['password' => 'password123']);

        $response->assertStatus(401);
    });

    it('disables 2FA with correct password', function (): void {
        Event::fake([TwoFactorDisabled::class]);

        $result = BetterAuth::signUp([
            'email' => '2fa-disable@example.com',
            'password' => 'password123',
        ]);

        $setupResponse = $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/setup');

        $secret = $setupResponse->json('secret');
        $code = generateTotpCode($secret);

        $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/enable', ['code' => $code]);

        $response = $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->deleteJson('/auth/2fa', ['password' => 'password123']);

        $response->assertStatus(200)
            ->assertJson([
                'message' => '2FA disabled successfully',
                'enabled' => false,
            ]);

        Event::assertDispatched(TwoFactorDisabled::class);
    });

    it('returns 422 with wrong password', function (): void {
        $result = BetterAuth::signUp([
            'email' => '2fa-disable-fail@example.com',
            'password' => 'password123',
        ]);

        $setupResponse = $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/setup');

        $secret = $setupResponse->json('secret');
        $code = generateTotpCode($secret);

        $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/enable', ['code' => $code]);

        $response = $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->deleteJson('/auth/2fa', ['password' => 'wrongpassword']);

        $response->assertStatus(422)
            ->assertJson(['message' => 'Invalid password']);
    });
});

describe('2FA Status', function (): void {
    it('returns 401 when unauthenticated', function (): void {
        $response = $this->getJson('/auth/2fa/status');

        $response->assertStatus(401);
    });

    it('returns disabled status when 2FA is not set up', function (): void {
        $result = BetterAuth::signUp([
            'email' => '2fa-status-off@example.com',
            'password' => 'password123',
        ]);

        $response = $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->getJson('/auth/2fa/status');

        $response->assertStatus(200)
            ->assertJson(['enabled' => false]);
    });

    it('returns enabled status when 2FA is active', function (): void {
        $result = BetterAuth::signUp([
            'email' => '2fa-status-on@example.com',
            'password' => 'password123',
        ]);

        $setupResponse = $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/setup');

        $secret = $setupResponse->json('secret');
        $code = generateTotpCode($secret);

        $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/enable', ['code' => $code]);

        $response = $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->getJson('/auth/2fa/status');

        $response->assertStatus(200)
            ->assertJson(['enabled' => true]);
    });
});

describe('2FA Recovery Codes', function (): void {
    it('verifies a valid recovery code', function (): void {
        $result = BetterAuth::signUp([
            'email' => '2fa-recovery@example.com',
            'password' => 'password123',
        ]);

        $setupResponse = $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/setup');

        $secret = $setupResponse->json('secret');
        $code = generateTotpCode($secret);

        $enableResponse = $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/enable', ['code' => $code]);

        $recoveryCodes = $enableResponse->json('recovery_codes');
        $recoveryCode = $recoveryCodes[0];

        $response = $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/recovery', ['code' => $recoveryCode]);

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'Recovery code verified',
                'verified' => true,
            ]);
    });

    it('fails with invalid recovery code', function (): void {
        $result = BetterAuth::signUp([
            'email' => '2fa-recovery-fail@example.com',
            'password' => 'password123',
        ]);

        $setupResponse = $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/setup');

        $secret = $setupResponse->json('secret');
        $code = generateTotpCode($secret);

        $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/enable', ['code' => $code]);

        $response = $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/recovery', ['code' => 'INVALIDCODE']);

        $response->assertStatus(422)
            ->assertJson(['message' => 'Invalid recovery code']);
    });

    it('consumes the recovery code (one-time use)', function (): void {
        $result = BetterAuth::signUp([
            'email' => '2fa-recovery-otp@example.com',
            'password' => 'password123',
        ]);

        $setupResponse = $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/setup');

        $secret = $setupResponse->json('secret');
        $code = generateTotpCode($secret);

        $enableResponse = $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/enable', ['code' => $code]);

        $recoveryCode = $enableResponse->json('recovery_codes.0');

        // First use: should succeed
        $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/recovery', ['code' => $recoveryCode])
            ->assertStatus(200);

        // Second use: should fail (code consumed)
        $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/recovery', ['code' => $recoveryCode])
            ->assertStatus(422);
    });

    it('regenerates recovery codes with correct password', function (): void {
        $result = BetterAuth::signUp([
            'email' => '2fa-regen@example.com',
            'password' => 'password123',
        ]);

        $setupResponse = $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/setup');

        $secret = $setupResponse->json('secret');
        $code = generateTotpCode($secret);

        $enableResponse = $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/enable', ['code' => $code]);

        $originalCodes = $enableResponse->json('recovery_codes');

        $response = $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/recovery-codes', ['password' => 'password123']);

        $response->assertStatus(200)
            ->assertJsonStructure(['message', 'recovery_codes']);

        $newCodes = $response->json('recovery_codes');

        expect($newCodes)->toBeArray()->toHaveCount(8);
        // New codes should differ from original
        expect($newCodes)->not->toBe($originalCodes);
    });

    it('fails recovery codes regeneration with wrong password', function (): void {
        $result = BetterAuth::signUp([
            'email' => '2fa-regen-fail@example.com',
            'password' => 'password123',
        ]);

        $setupResponse = $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/setup');

        $secret = $setupResponse->json('secret');
        $code = generateTotpCode($secret);

        $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/enable', ['code' => $code]);

        $response = $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/2fa/recovery-codes', ['password' => 'wrongpassword']);

        $response->assertStatus(422);
    });
});

// ---------------------------------------------------------------------------
// TwoFactorService — unit tests
// ---------------------------------------------------------------------------

describe('TwoFactorService', function (): void {
    it('generates a 32-character base32 secret', function (): void {
        $service = app(TwoFactorService::class);
        $user = createTestUser('2fa-svc-secret@example.com');

        $data = $service->generateSecret($user);

        expect($data['secret'])->toBeString();
        expect(strlen($data['secret']))->toBeGreaterThanOrEqual(16);
        // Secret must only contain valid base32 characters
        expect(preg_match('/^[A-Z2-7]+$/', $data['secret']))->toBe(1);
    });

    it('builds a valid TOTP URI', function (): void {
        $service = app(TwoFactorService::class);
        $user = createTestUser('2fa-svc-uri@example.com');

        $data = $service->generateSecret($user);

        expect($data['uri'])->toStartWith('otpauth://totp/');
        expect($data['uri'])->toContain('secret=');
        expect($data['uri'])->toContain('issuer=');
    });

    it('marks 2FA as not enabled before verification', function (): void {
        $service = app(TwoFactorService::class);
        $user = createTestUser('2fa-svc-notenabled@example.com');

        $service->generateSecret($user);

        expect($service->isEnabled($user))->toBeFalse();
    });

    it('enables 2FA after verifyAndEnable with correct code', function (): void {
        $service = app(TwoFactorService::class);
        $user = createTestUser('2fa-svc-enable@example.com');

        $data = $service->generateSecret($user);
        $code = generateTotpCode($data['secret']);

        $result = $service->verifyAndEnable($user, $code);

        expect($result)->not->toBeNull();
        expect($result['enabled'])->toBeTrue();
        expect($result['recovery_codes'])->toBeArray()->toHaveCount(8);
        expect($service->isEnabled($user))->toBeTrue();
    });

    it('returns null from verifyAndEnable with wrong code', function (): void {
        $service = app(TwoFactorService::class);
        $user = createTestUser('2fa-svc-wrongcode@example.com');

        $service->generateSecret($user);

        $result = $service->verifyAndEnable($user, '000000');

        expect($result)->toBeNull();
        expect($service->isEnabled($user))->toBeFalse();
    });

    it('returns null from verifyAndEnable when no secret generated', function (): void {
        $service = app(TwoFactorService::class);
        $user = createTestUser('2fa-svc-nosecret@example.com');

        $result = $service->verifyAndEnable($user, '123456');

        expect($result)->toBeNull();
    });

    it('verifies TOTP code when 2FA is enabled', function (): void {
        $service = app(TwoFactorService::class);
        $user = createTestUser('2fa-svc-verify@example.com');

        $data = $service->generateSecret($user);
        $code = generateTotpCode($data['secret']);
        $service->verifyAndEnable($user, $code);

        $freshCode = generateTotpCode($data['secret']);
        expect($service->verify($user, $freshCode))->toBeTrue();
        expect($service->verify($user, '000000'))->toBeFalse();
    });

    it('returns false from verify when 2FA is not enabled', function (): void {
        $service = app(TwoFactorService::class);
        $user = createTestUser('2fa-svc-notactive@example.com');

        $service->generateSecret($user);

        expect($service->verify($user, '123456'))->toBeFalse();
    });

    it('disables 2FA and dispatches event', function (): void {
        Event::fake([TwoFactorDisabled::class]);

        $service = app(TwoFactorService::class);
        $user = createTestUser('2fa-svc-disable@example.com');

        $data = $service->generateSecret($user);
        $code = generateTotpCode($data['secret']);
        $service->verifyAndEnable($user, $code);

        $disabled = $service->disable($user);

        expect($disabled)->toBeTrue();
        expect($service->isEnabled($user))->toBeFalse();

        Event::assertDispatched(TwoFactorDisabled::class);
    });

    it('regenerates recovery codes', function (): void {
        $service = app(TwoFactorService::class);
        $user = createTestUser('2fa-svc-regen@example.com');

        $data = $service->generateSecret($user);
        $code = generateTotpCode($data['secret']);
        $result = $service->verifyAndEnable($user, $code);

        $originalCodes = $result['recovery_codes'];
        $newCodes = $service->regenerateRecoveryCodes($user);

        expect($newCodes)->toBeArray()->toHaveCount(8);
        expect($newCodes)->not->toBe($originalCodes);
    });

    it('verifies and consumes a recovery code', function (): void {
        $service = app(TwoFactorService::class);
        $user = createTestUser('2fa-svc-recovery@example.com');

        $data = $service->generateSecret($user);
        $code = generateTotpCode($data['secret']);
        $result = $service->verifyAndEnable($user, $code);

        $recoveryCode = $result['recovery_codes'][0];

        expect($service->verifyRecoveryCode($user, $recoveryCode))->toBeTrue();
        // Second use should fail
        expect($service->verifyRecoveryCode($user, $recoveryCode))->toBeFalse();
    });

    it('returns false for recovery code when 2FA is not enabled', function (): void {
        $service = app(TwoFactorService::class);
        $user = createTestUser('2fa-svc-recovery-off@example.com');

        expect($service->verifyRecoveryCode($user, 'SOMECODE'))->toBeFalse();
    });
});

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/**
 * Generate a valid TOTP code from a base32 secret (mirrors TwoFactorService internals).
 */
function generateTotpCode(string $secret): string
{
    $map = array_flip(str_split('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'));
    $secret = strtoupper($secret);
    $secret = str_replace('=', '', $secret);

    $buffer = 0;
    $length = 0;
    $key = '';

    foreach (str_split($secret) as $char) {
        if (! isset($map[$char])) {
            continue;
        }
        $buffer = ($buffer << 5) | $map[$char];
        $length += 5;
        if ($length >= 8) {
            $length -= 8;
            $key .= chr(($buffer >> $length) & 0xFF);
        }
    }

    $timeSlice = (int) floor(time() / 30);
    $time = pack('N*', 0, $timeSlice);
    $hmac = hash_hmac('sha1', $time, $key, true);
    $offset = ord(substr($hmac, -1)) & 0x0F;
    $binary = (ord($hmac[$offset]) & 0x7F) << 24
        | (ord($hmac[$offset + 1]) & 0xFF) << 16
        | (ord($hmac[$offset + 2]) & 0xFF) << 8
        | (ord($hmac[$offset + 3]) & 0xFF);

    return str_pad((string) ($binary % 1000000), 6, '0', STR_PAD_LEFT);
}

/**
 * Create and persist a test user for unit-level service tests.
 */
function createTestUser(string $email): User
{
    return User::create([
        'id' => (string) Str::uuid7(),
        'email' => $email,
        'password' => password_hash('password123', PASSWORD_ARGON2ID),
        'name' => 'Test User',
        'roles' => ['ROLE_USER'],
        'email_verified_at' => now(),
    ]);
}
