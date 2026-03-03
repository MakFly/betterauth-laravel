<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Services;

use Illuminate\Contracts\Auth\Authenticatable;

final class AuthUserResponseFormatter
{
    /**
     * @param  array<string, mixed>|object  $user
     * @return array<string, mixed>
     */
    public function formatUser(array|object $user): array
    {
        if (is_object($user)) {
            $user = method_exists($user, 'toArray') ? $user->toArray() : (array) $user;
        }

        unset($user['password']);

        return $user;
    }

    /**
     * @return array<string, mixed>
     */
    public function formatAuthenticatable(Authenticatable $user): array
    {
        $data = [
            'id' => $user->getAuthIdentifier(),
        ];

        if (method_exists($user, 'toArray')) {
            $userData = $user->toArray();
            unset($userData['password']);

            return array_merge($data, $userData);
        }

        if (method_exists($user, 'getAttribute')) {
            $data['email'] = $user->getAttribute('email');
            $data['name'] = $user->getAttribute('name');
            $data['avatar'] = $user->getAttribute('avatar');
            $data['email_verified_at'] = $user->getAttribute('email_verified_at');
            $data['created_at'] = $user->getAttribute('created_at');
        }

        return $data;
    }
}
