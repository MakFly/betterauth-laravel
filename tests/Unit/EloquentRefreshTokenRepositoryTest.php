<?php

declare(strict_types=1);

use BetterAuth\Core\Entities\RefreshToken;
use BetterAuth\Laravel\Repositories\EloquentRefreshTokenRepository;
use BetterAuth\Laravel\Tests\Fixtures\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

beforeEach(function (): void {
    $this->artisan('migrate', ['--database' => 'testing']);
    $this->repository = new EloquentRefreshTokenRepository('better_auth_refresh_tokens');

    $this->userId = (string) Str::uuid7();
    User::create([
        'id' => $this->userId,
        'email' => 'user@example.com',
        'password' => password_hash('password', PASSWORD_ARGON2ID),
        'roles' => ['ROLE_USER'],
    ]);
});

function insertRawToken(string $token, string $userId, bool $revoked = false, string $expiresAt = '+30 days'): void
{
    DB::table('better_auth_refresh_tokens')->insert([
        'token' => hash('sha256', $token),
        'user_id' => $userId,
        'expires_at' => now()->modify($expiresAt),
        'created_at' => now(),
        'revoked' => $revoked,
        'replaced_by' => null,
    ]);
}

describe('EloquentRefreshTokenRepository - findByToken', function (): void {
    it('returns null when token not found', function (): void {
        expect($this->repository->findByToken('nonexistent'))->toBeNull();
    });

    it('returns null for revoked token', function (): void {
        insertRawToken('revoked-token', $this->userId, revoked: true);

        expect($this->repository->findByToken('revoked-token'))->toBeNull();
    });

    it('returns null for expired token', function (): void {
        insertRawToken('expired-token', $this->userId, expiresAt: '-1 day');

        expect($this->repository->findByToken('expired-token'))->toBeNull();
    });

    it('returns RefreshToken entity for valid token', function (): void {
        insertRawToken('valid-token', $this->userId);

        $token = $this->repository->findByToken('valid-token');

        expect($token)->toBeInstanceOf(RefreshToken::class);
    });
});

describe('EloquentRefreshTokenRepository - findByUserId', function (): void {
    it('returns empty array when no active tokens', function (): void {
        expect($this->repository->findByUserId($this->userId))->toBeArray()->toBeEmpty();
    });

    it('returns active tokens for user', function (): void {
        insertRawToken('tok-a', $this->userId);
        insertRawToken('tok-b', $this->userId);
        insertRawToken('tok-revoked', $this->userId, revoked: true);

        $tokens = $this->repository->findByUserId($this->userId);

        expect($tokens)->toHaveCount(2);
        expect($tokens[0])->toBeInstanceOf(RefreshToken::class);
    });
});

describe('EloquentRefreshTokenRepository - create', function (): void {
    it('creates a token record and returns entity', function (): void {
        $token = $this->repository->create([
            'token' => 'new-refresh-token',
            'user_id' => $this->userId,
            'expires_at' => now()->addDays(30)->toDateTimeString(),
            'created_at' => now()->toDateTimeString(),
        ]);

        expect($token)->toBeInstanceOf(RefreshToken::class);
        expect($token->getToken())->toBe('new-refresh-token');

        // create() stores the raw token (not hashed) - see EloquentRefreshTokenRepository::create()
        $record = DB::table('better_auth_refresh_tokens')
            ->where('token', 'new-refresh-token')
            ->first();
        expect($record)->not->toBeNull();
    });
});

describe('EloquentRefreshTokenRepository - revoke', function (): void {
    it('returns false when token not found', function (): void {
        expect($this->repository->revoke('nonexistent'))->toBeFalse();
    });

    it('revokes an existing token and returns true', function (): void {
        insertRawToken('to-revoke', $this->userId);

        $result = $this->repository->revoke('to-revoke');

        expect($result)->toBeTrue();

        $record = DB::table('better_auth_refresh_tokens')
            ->where('token', hash('sha256', 'to-revoke'))
            ->first();
        expect((bool) $record->revoked)->toBeTrue();
    });

    it('stores replacedBy value when provided', function (): void {
        insertRawToken('old-tok', $this->userId);

        $this->repository->revoke('old-tok', 'new-tok');

        $record = DB::table('better_auth_refresh_tokens')
            ->where('token', hash('sha256', 'old-tok'))
            ->first();
        expect($record->replaced_by)->toBe('new-tok');
    });
});

describe('EloquentRefreshTokenRepository - revokeAllForUser', function (): void {
    it('returns 0 when no active tokens', function (): void {
        expect($this->repository->revokeAllForUser($this->userId))->toBe(0);
    });

    it('revokes all active tokens for user and returns count', function (): void {
        insertRawToken('tok-1', $this->userId);
        insertRawToken('tok-2', $this->userId);
        insertRawToken('tok-revoked', $this->userId, revoked: true);

        $count = $this->repository->revokeAllForUser($this->userId);

        expect($count)->toBe(2);
    });
});

describe('EloquentRefreshTokenRepository - deleteExpired', function (): void {
    it('deletes expired tokens and returns count', function (): void {
        insertRawToken('expired-1', $this->userId, expiresAt: '-1 day');
        insertRawToken('expired-2', $this->userId, expiresAt: '-2 days');
        insertRawToken('active-1', $this->userId);

        $count = $this->repository->deleteExpired();

        expect($count)->toBe(2);
        expect(DB::table('better_auth_refresh_tokens')->count())->toBe(1);
    });

    it('returns 0 when no expired tokens', function (): void {
        insertRawToken('active-1', $this->userId);

        expect($this->repository->deleteExpired())->toBe(0);
    });
});

describe('EloquentRefreshTokenRepository - consume', function (): void {
    it('returns null when token already revoked', function (): void {
        insertRawToken('revoked-consume', $this->userId, revoked: true);

        expect($this->repository->consume('revoked-consume'))->toBeNull();
    });

    it('returns null when token not found', function (): void {
        expect($this->repository->consume('nonexistent'))->toBeNull();
    });

    it('marks token as revoked and returns entity', function (): void {
        insertRawToken('consume-me', $this->userId);

        $token = $this->repository->consume('consume-me');

        expect($token)->toBeInstanceOf(RefreshToken::class);

        $record = DB::table('better_auth_refresh_tokens')
            ->where('token', hash('sha256', 'consume-me'))
            ->first();
        expect((bool) $record->revoked)->toBeTrue();
    });

    it('prevents double consume (one-time use)', function (): void {
        insertRawToken('one-time', $this->userId);

        $first = $this->repository->consume('one-time');
        $second = $this->repository->consume('one-time');

        expect($first)->toBeInstanceOf(RefreshToken::class);
        expect($second)->toBeNull();
    });
});
