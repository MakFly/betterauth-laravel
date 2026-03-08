<?php

declare(strict_types=1);

namespace BetterAuth\Core\DTO;

use BetterAuth\Core\Entities\User;

/**
 * Sign-in response DTO containing user and tokens.
 */
class SignInResponseDto
{
    public function __construct(
        public readonly UserDto $user,
        public readonly ?string $accessToken = null,
        public readonly ?string $refreshToken = null,
        public readonly ?string $sessionToken = null,
        public readonly string $tokenType = 'Bearer',
        public readonly int $expiresIn = 3600,
        public readonly bool $requiresTwoFactor = false,
    ) {
    }

    /**
     * Create from token-based authentication result.
     *
     * @param array{user: User, access_token: string, refresh_token: string, expires_in?: int, token_type?: string} $result
     */
    public static function fromTokenResult(array $result): self
    {
        return new self(
            user: UserDto::fromUser($result['user']),
            accessToken: $result['access_token'],
            refreshToken: $result['refresh_token'],
            tokenType: $result['token_type'] ?? 'Bearer',
            expiresIn: $result['expires_in'] ?? 3600,
        );
    }

    /**
     * Create from session-based authentication result.
     *
     * @param array{user: User, session: \BetterAuth\Core\Entities\Session} $result
     */
    public static function fromSessionResult(array $result): self
    {
        return new self(
            user: UserDto::fromUser($result['user']),
            sessionToken: $result['session']->getToken(),
            expiresIn: 604800, // 7 days default for sessions
        );
    }

    /**
     * Create a 2FA required response.
     */
    public static function requiresTwoFactor(User $user): self
    {
        return new self(
            user: UserDto::fromUser($user),
            requiresTwoFactor: true,
        );
    }

    /**
     * Convert to array for API response.
     *
     * @param string[] $userIncludeFields Fields to include in user DTO
     * @param string[] $userExcludeFields Fields to exclude from user DTO
     */
    public function toArray(array $userIncludeFields = [], array $userExcludeFields = []): array
    {
        $response = [
            'user' => $this->user->toArray($userIncludeFields, $userExcludeFields),
        ];

        if ($this->requiresTwoFactor) {
            $response['requires_two_factor'] = true;

            return $response;
        }

        if ($this->accessToken !== null) {
            $response['access_token'] = $this->accessToken;
            $response['refresh_token'] = $this->refreshToken;
            $response['token_type'] = $this->tokenType;
            $response['expires_in'] = $this->expiresIn;
        }

        if ($this->sessionToken !== null) {
            $response['session_token'] = $this->sessionToken;
            $response['expires_in'] = $this->expiresIn;
        }

        return $response;
    }
}
