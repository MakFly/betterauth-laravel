<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Facades;

use BetterAuth\Laravel\Services\BetterAuthManager;
use Illuminate\Support\Facades\Facade;

/**
 * BetterAuth Facade.
 *
 * @method static array signUp(array $data)
 * @method static array signIn(string $email, string $password)
 * @method static void signOut(string $refreshToken)
 * @method static array refresh(string $refreshToken)
 * @method static array verify(string $accessToken)
 * @method static void revokeAll(string $userId)
 * @method static array|null getUserById(string $id)
 * @method static array|null getUserByEmail(string $email)
 * @method static bool emailExists(string $email)
 * @method static bool verifyEmail(string $userId)
 * @method static bool updatePassword(string $userId, string $currentPassword, string $newPassword)
 * @method static string hashPassword(string $password)
 * @method static bool verifyPassword(string $password, string $hash)
 * @method static \BetterAuth\Core\Interfaces\TokenSignerInterface getTokenService()
 * @method static array getConfig()
 * @method static array createTokensForUser(\Illuminate\Database\Eloquent\Model&\Illuminate\Contracts\Auth\Authenticatable $user)
 *
 * @see \BetterAuth\Laravel\Services\BetterAuthManager
 */
final class BetterAuth extends Facade
{
    /**
     * Get the registered name of the component.
     */
    protected static function getFacadeAccessor(): string
    {
        return BetterAuthManager::class;
    }
}
